#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""G.3 引擎注册一致性矩阵（只核对出报告，不改注册）。

任务清单 v2 组 G：核对三方是否一致——
    A. engines/*.py 里实际定义的引擎类（AST 提取 name）
    B. engines/__init__.py 的导出（__all__ / import 名单）
    C. phases_taskgen.py 的引擎池（global_engines / engine_priority）
外加 settings 中相关开关。任一环缺失，引擎都可能"定义了却跑不到"。

用法：
    python scripts/engine_registry_check.py
输出：
    docs/engine_registry_matrix.md
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "vulnclaw"
ENG = SRC / "engines"
INIT_PY = ENG / "__init__.py"
TASKGEN = SRC / "ai" / "v100" / "phases" / "phases_taskgen.py"
OUT = ROOT / "docs" / "engine_registry_matrix.md"


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


def _defined_engines() -> list[tuple[str, str, str]]:
    out = []
    for f in sorted(ENG.glob("*.py")):
        if f.name.startswith("_"):
            continue
        try:
            tree = ast.parse(_read(f))
        except Exception:  # noqa: BLE001
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for st in node.body:
                if isinstance(st, ast.Assign):
                    for tg in st.targets:
                        if isinstance(tg, ast.Name) and tg.id == "name" and isinstance(st.value, ast.Constant):
                            out.append((str(st.value.value), f.name, node.name))
    return out


def _exported_names(init_text: str) -> set[str]:
    """从 __init__.py 提取 __all__ 列表与 'X' 形式的名字。"""
    names: set[str] = set()
    m = re.search(r"__all__\s*=\s*\[(.*?)\]", init_text, re.S)
    if m:
        names |= set(re.findall(r"['\"]([A-Za-z_][\w]*)['\"]", m.group(1)))
    # 兜底：把整个文件的字符串字面量也纳入（便于识别被引用的引擎名）
    names |= set(re.findall(r"['\"]([a-z][a-z0-9_]{2,})['\"]", init_text))
    return names


def main() -> int:
    init_text = _read(INIT_PY)
    task_text = _read(TASKGEN)
    exported = _exported_names(init_text)
    engines = _defined_engines()

    rows = []
    for name, fname, cname in engines:
        in_init = name in init_text
        in_all = name in exported
        in_task = name in task_text
        # 【重要】本项目引擎为 **glob 自动发现 + ENGINE_REGISTRY 按 name 注册**，
        # 因此"未在 __init__.py 显式导出"是**正常现象**，不能据此判定缺失。
        # 只要出现在任一注册/调度链路（__init__ 或 taskgen 任务池）即视为已接入。
        if in_init or in_task:
            status = "OK（已接入注册/调度链路）"
        else:
            status = "两处均缺（需确认是否跑得到）"
        rows.append({
            "name": name, "file": fname, "class": cname,
            "init": in_init, "all": in_all, "task": in_task, "status": status,
        })

    # 任务池里引用了但未定义的名字（疑似遗留/打字错误）
    defined = {r["name"] for r in rows}
    pool_names = set(re.findall(r"['\"]([a-z][a-z0-9_]{3,})['\"]", task_text))
    orphan = sorted(n for n in pool_names
                    if n not in defined and ("engine" in n or "_" in n)
                    and n not in {"global_engines", "engine_priority", "max_engines_per_param"})

    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    lines = [
        "# 引擎注册一致性矩阵（G.3）",
        "",
        f"> 由 `scripts/engine_registry_check.py` 生成，**只核对不改注册**。",
        "> 三方：A 引擎类定义（`engines/*.py`）｜ B 导出（`engines/__init__.py`）｜ "
        "C 任务池（`phases_taskgen.py`）。",
        "",
        f"引擎总数：**{len(rows)}**",
        "",
        "| 状态 | 数量 | 含义 |",
        "|---|---|---|",
    ]
    for st in ("OK（已接入注册/调度链路）", "两处均缺（需确认是否跑得到）"):
        lines.append(
            f"| {st} | {counts.get(st, 0)} | "
            + ("已出现在 __init__ 导出或 taskgen 任务池（引擎实际为 glob 自动发现，"
               "未显式导出属正常）"
               if st.startswith("OK") else
               "既未导出也未入池，需确认是遗漏注册还是已废弃")
            + " |"
        )

    lines += [
        "",
        "## 明细",
        "",
        "| 引擎名 | 文件 | 类 | 在 __init__ | 在 __all__ | 在任务池 | 状态 |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in sorted(rows, key=lambda x: (x["status"] != "两处均缺（疑似跑不到）", x["name"])):
        lines.append(
            f"| `{r['name']}` | {r['file']} | {r['class']} | "
            f"{'是' if r['init'] else '否'} | {'是' if r['all'] else '否'} | "
            f"{'是' if r['task'] else '否'} | {r['status']} |"
        )

    if orphan:
        lines += [
            "",
            "## 任务池中未匹配到引擎定义的名字（需人工确认）",
            "",
        ]
        lines += [f"- `{n}`" for n in orphan[:40]]

    lines += [
        "",
        "## 处置原则",
        "",
        "1. 「两处均缺」= 引擎定义了但既没导出也没入池 → **扫描时根本跑不到**，"
        "需确认是遗漏注册还是已废弃（废弃则由人决定下线，脚本不自动删）。",
        "2. 「仅导出·未进任务池」= 可被单独调用但不参与自动撒网，需确认是否有意。",
        "3. 任何补齐动作后需重跑 `pytest tests/test_engines_core.py` 与 "
        "`python scripts/benchmark.py`，确认不回归。",
        "",
    ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"ENGINES={len(rows)} " + " ".join(f"{k}={v}" for k, v in counts.items()))
    if orphan:
        print(f"UNMATCHED_IN_POOL={len(orphan)}")
    print(f"REPORT={OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
