#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""H.1 异步滥用体检（静态分析，不改引擎行为）。

任务清单 v2 组 H：网络 I/O 全异步是合理的，但把 CPU 密集逻辑（正则重扫、
大循环、编解码、同步 sleep/IO）塞进 async def 会**阻塞事件循环**，拖慢整个
DAG 调度。DeepSeek 建议"全局重构"——本脚本只做体检、出清单，不做重构。

做法：AST 静态扫描 engines/*.py 中引擎类的 check()/scan()（含 _check/_scan），
统计 CPU 密集特征并打分，输出 top10 热路径报告，供 H.2 精准做线程池隔离。

用法：
    python scripts/async_profile.py [--top 10]
输出：
    docs/async_hotpath_report.md
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "vulnclaw"
ENG = SRC / "engines"
OUT = ROOT / "docs" / "async_hotpath_report.md"

# CPU 密集特征：特征名 -> (匹配的函数/属性名片段, 单项权重)
FEATURES = {
    "regex": (("re.compile", "re.search", "re.match", "re.finditer",
               "re.findall", "re.sub", ".search(", ".match(",
               ".finditer(", ".findall("), 1.0),
    "decode": (("b64decode", "b64encode", "base64", "json.loads",
                "json.dumps", ".decode(", ".encode("), 1.0),
    "blocking_sleep": (("time.sleep", "sleep("), 10.0),
    "sync_io": (("open(", ".read()", ".write("), 5.0),
    "hash": (("hashlib", "md5", "sha1", "sha256"), 0.5),
}

TARGET_METHODS = {"check", "scan", "_check", "_scan", "run"}


def _loop_stats(fn: ast.AST) -> tuple[int, int]:
    """返回 (循环总数, 最大嵌套深度)。"""

    total = 0
    max_depth = 0

    def walk(node, depth):
        nonlocal total, max_depth
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.For, ast.While, ast.AsyncFor)):
                total += 1
                d = depth + 1
                max_depth = max(max_depth, d)
                walk(child, d)
            else:
                walk(child, depth)

    walk(fn, 0)
    return total, max_depth


def _call_names(fn: ast.AST) -> list[str]:
    """收集函数内所有调用的"可读名"（a.b.c 形式）。"""
    names = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        parts = []
        while isinstance(f, ast.Attribute):
            parts.append(f.attr)
            f = f.value
        if isinstance(f, ast.Name):
            parts.append(f.id)
        if parts:
            names.append(".".join(reversed(parts)))
    return names


def analyze() -> list[dict]:
    rows: list[dict] = []
    for f in sorted(ENG.glob("*.py")):
        if f.name.startswith("_"):
            continue
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except Exception:  # noqa: BLE001
            continue
        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            cname = None
            for st in cls.body:
                if isinstance(st, ast.Assign):
                    for t in st.targets:
                        if isinstance(t, ast.Name) and t.id == "name" and isinstance(st.value, ast.Constant):
                            cname = st.value.value
            for fn in cls.body:
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if fn.name not in TARGET_METHODS:
                    continue
                loops, depth = _loop_stats(fn)
                calls = _call_names(fn)
                feats = {}
                score = loops * 2.0 + depth * 3.0
                for feat, (pats, w) in FEATURES.items():
                    n = sum(1 for c in calls if any(p in c for p in pats))
                    if n:
                        feats[feat] = n
                        score += n * w
                rows.append({
                    "engine": cname or cls.name,
                    "cls": cls.name,
                    "file": f.name,
                    "method": fn.name,
                    "is_async": isinstance(fn, ast.AsyncFunctionDef),
                    "loops": loops,
                    "depth": depth,
                    "features": feats,
                    "score": round(score, 1),
                })
    rows.sort(key=lambda r: -r["score"])
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=10)
    args = ap.parse_args()

    rows = analyze()
    if not rows:
        print("NO_METHOD_FOUND")
        return 2
    top = rows[: max(1, args.top)]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# 异步热路径体检报告（H.1）",
        "",
        f"分析方法：AST 静态扫描 `engines/*.py` 中引擎类的 `check/scan/_check/_scan/run`，"
        f"统计循环、嵌套、正则、编解码、阻塞 sleep、同步 IO、哈希等 CPU 密集特征并打分。  ",
        f"**本报告只体检、不修改任何引擎行为**（重构成果见 H.2）。",
        "",
        "## Top 热路径",
        "",
        "| # | 引擎 | 类.方法 | 文件 | 是否 async | 循环 | 最大嵌套 | 密集特征 | 分值 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(top, 1):
        feat = ", ".join(f"{k}×{v}" for k, v in sorted(r["features"].items())) or "-"
        lines.append(
            f"| {i} | `{r['engine']}` | {r['cls']}.{r['method']} | {r['file']} | "
            f"{'是' if r['is_async'] else '否'} | {r['loops']} | {r['depth']} | {feat} | {r['score']} |"
        )
    lines += [
        "",
        "## 判读建议",
        "",
        "- **async 但含阻塞 sleep / 同步 IO**：直接阻塞事件循环，优先改为 `asyncio.to_thread`。",
        "- **async 且循环深 + 正则重扫**：CPU 段长，优先把纯计算段挪到线程池（H.2）。",
        "- **非 async 的 check/scan**：本身在线程/子进程执行的可能性需结合调用点确认，"
        "若在主事件循环里同步调用同样有风险。",
        "- 分值只用于**排序定位**，不代表绝对耗时；真实耗时以 H.2 修复前后的 "
        "DAG 看板 tick 间隔对照为准。",
        "",
        "## 下一步（H.2）",
        "",
        "对上表 top3 引擎的纯 CPU 段改用 `asyncio.to_thread` 执行，"
        "修复后对照 DAG 看板 tick 间隔，确认引擎密集阶段不再劣化。",
        "",
    ]
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"METHODS={len(rows)} TOP={len(top)}")
    for r in top[:3]:
        print(f"  HOT {r['engine']}.{r['method']} score={r['score']} async={r['is_async']}")
    print(f"REPORT={OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
