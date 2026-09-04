# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.
"""SP9 融合终验：基线固化 + 交付后一键对比（主 Agent 侧，不依赖对面产物）。

用法（在项目根目录，venv 下执行）：
    python scripts/fusion_acceptance.py baseline    # 对面交付前：固化当前基线
    python scripts/fusion_acceptance.py compare     # 对面交付后：重跑同口径并对比

口径（全部机器事实，无 LLM）：
    - git HEAD
    - 引擎注册数（global_engines）
    - pytest 统计（收集/通过/跳过/失败）
    - 关键交付物存在性（E1 攻击图 / SP1-SP4 模块 / 对应测试）
    - 里程碑状态（docs/TASKLIST_BEYOND_STRIX.md 第 8 节 SP 完成度）
可选 --bench：追加 benchmark.py --mode eval 检出率（recall/precision），
会跑引擎检测、耗时较长，默认不启用。

compare 红线（任一不满足 -> exit 1）：
    1. pytest 通过数不得低于基线
    2. 关键交付物不得缺失
"""
import argparse
import io
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METRICS_DIR = ROOT / "_runtime_cache" / "metrics"
BASELINE_FILE = METRICS_DIR / "fusion_baseline.json"
KEY_FILES = [
    "src/vulnclaw/core/attack_graph.py",
    "src/vulnclaw/core/sandbox_runner.py",
    "src/vulnclaw/core/dedupe.py",
    "src/vulnclaw/core/coverage.py",
    "tests/test_attack_graph.py",
    "tests/test_sandbox_runner.py",
    "tests/test_dedupe_core.py",
    "tests/test_coverage_ledger.py",
    "tests/test_sarif_attack_graph.py",
]
SP_MARKERS = {name: "[x] **" + name + "**" for name in
    ["SP1", "SP2", "SP3", "SP4", "SP5", "SP6", "SP7", "SP8", "SP9"]}


def _run(cmd: list, timeout: int = 600) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              cwd=str(ROOT), timeout=timeout,
                              encoding="utf-8", errors="replace")
        return (proc.stdout or "") + (proc.stderr or "")
    except Exception as exc:  # noqa: BLE001
        return "ERR:" + str(exc)


def _git_head() -> str:
    import subprocess as sp
    out = sp.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                 text=True, cwd=str(ROOT)).stdout.strip() or "n/a"
    return out


def _engine_count() -> int:
    """引擎总数机器事实：engines 包内注册的 BaseEngine 子类数（排除基类）。"""
    try:
        import vulnclaw.engines as eng
        from vulnclaw.engines.base import BaseEngine
    except Exception as e:  # noqa: BLE001
        return -1
    n = 0
    for name in dir(eng):
        obj = getattr(eng, name)
        try:
            if isinstance(obj, type) and issubclass(obj, BaseEngine) and obj is not BaseEngine:
                n += 1
        except TypeError:
            continue
    return n


def _pytest_stats() -> dict:
    """pytest -q 进度行符号统计（. 通过 / F 失败 / E 错误 / s 跳过 / x X 预失败）。

    终端插件会吞掉摘要行，不依赖；逐进度行统计符号，适配 pytest 7/8 全版本。
    """
    out = _run([sys.executable, "-m", "pytest", "tests/", "-q", "-p", "no:warnings",
                "--tb=no"])
    stats = {"passed": 0, "failed": 0, "error": 0, "skipped": 0, "xfailed": 0}
    prog = re.compile(r"^[.sFxXEu]")
    txt = ""
    for line in out.splitlines():
        seg = []
        for ch in line:
            if re.match(r"[.sFxXEu]", ch):
                seg.append(ch)
            elif ch == "[" or ch.isspace() or ch == ",":
                continue
            else:
                break
        if not seg:
            continue
        if len(seg) <= 2:
            continue  # 防止把百分比数字误当作符号
        stats["passed"] += seg.count(".")
        stats["failed"] += seg.count("F")
        stats["error"] += seg.count("E")
        stats["skipped"] += seg.count("s")
        stats["xfailed"] += seg.count("x") + seg.count("X")
        txt = "".join(seg)
    passed, failed, error, skipped = stats["passed"], stats["failed"], stats["error"], stats["skipped"]
    skipped += stats["xfailed"]
    if passed + failed + error + skipped == 0:
        txt = (out or "NO-OUTPUT").strip()[-160:]
    return {
        "collected": passed + failed + error + skipped,
        "passed": passed,
        "failed": failed,
        "error": error,
        "skipped": skipped,
        "raw": txt[-80:],
    }


def _key_files_status() -> list:
    out = []
    for rel in KEY_FILES:
        out.append({"file": rel, "exists": (ROOT / rel).is_file()})
    return out


def _sp_status() -> dict:
    doc = ROOT / "docs" / "TASKLIST_BEYOND_STRIX.md"
    if not doc.is_file():
        return {"present": False, "done": []}
    text = doc.read_text(encoding="utf-8", errors="replace")
    return {
        "present": True,
        "done": [name for name, marker in SP_MARKERS.items() if marker in text],
        "total": len(SP_MARKERS),
    }


def _benchmark_eval() -> dict:
    out = _run([sys.executable, "benchmark.py", "--mode", "eval"], timeout=1800)
    summary = [l for l in out.splitlines() if re.search(r"recall|precision|F1|检出", l, re.I)]
    return {"raw_head": out[:600], "summary_lines": summary[-8:]}


def collect(with_bench: bool = False) -> dict:
    st = _pytest_stats()
    sps = _sp_status()
    return {
        "collected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "git_head": _git_head(),
        "engines_registered": _engine_count(),
        "pytest": st,
        "key_files": _key_files_status(),
        "sp_status": sps,
        "benchmark": _benchmark_eval() if with_bench else None,
    }


def _red_checks(base: dict, cur: dict) -> list:
    """终验红线：不满足则 compare 返回非零。"""
    problems = []
    if cur["pytest"]["passed"] < base["pytest"]["passed"]:
        problems.append("pytest 通过数回退: {} -> {}".format(
            base["pytest"]["passed"], cur["pytest"]["passed"]))
    if cur["pytest"]["failed"] > 0:
        problems.append("pytest 存在失败: {}".format(cur["pytest"]["failed"]))
    for k in base["key_files"]:
        hit = next((x for x in cur["key_files"] if x["file"] == k["file"]), None)
        if not hit or not hit["exists"]:
            problems.append("关键交付物缺失: {}".format(k["file"]))
    if cur["sp_status"].get("present") and len(cur["sp_status"].get("done", [])) < 9:
        problems.append("SP9 未全数完成: done={}".format(len(cur["sp_status"].get("done", []))))
    return problems


def _print_report(tag: str, data: dict) -> None:
    print("=" * 64)
    print("FUSION ACCEPTANCE [%s] @ %s" % (tag, data["git_head"]))
    print("=" * 64)
    print("pytest      : %(passed)s passed / %(failed)s failed / %(skipped)s skipped" % data["pytest"])
    print("engines     : %d registered" % data["engines_registered"])
    missing = [k["file"] for k in data["key_files"] if not k["exists"]]
    print("key files   : %d/%d present%s" % (
        len(data["key_files"]) - len(missing), len(data["key_files"]),
        "  MISSING: " + "; ".join(missing) if missing else ""))
    sps = data["sp_status"]
    if sps.get("present"):
        print("SP status   : %d/9 done - %s" % (len(sps.get("done", [])), ", ".join(sps.get("done", []))))
    if data.get("benchmark") and data["benchmark"].get("summary_lines"):
        print("benchmark   :")
        for l in data["benchmark"]["summary_lines"]:
            print("    " + l)
    if data.get("pytest", {}).get("raw"):
        print("raw tail    : " + data["pytest"]["raw"])


def main() -> int:
    ap = argparse.ArgumentParser(description="SP9 融合终验")
    ap.add_argument("mode", choices=["baseline", "compare"])
    ap.add_argument("--bench", action="store_true", help="追加跑 benchmark eval（慢）")
    args = ap.parse_args()

    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    if args.mode == "baseline":
        data = collect(with_bench=args.bench)
        with io.open(BASELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        _print_report("BASELINE", data)
        print("\n基线已固化 -> %s" % BASELINE_FILE)
        return 0

    if not BASELINE_FILE.is_file():
        print("无基线文件，请先执行 baseline。")
        return 2
    base = json.load(io.open(BASELINE_FILE, encoding="utf-8"))
    cur = collect(with_bench=args.bench)
    _print_report("CURRENT", cur)
    print("-" * 64)
    changed = cur["git_head"] != base["git_head"]
    print("HEAD 变更: %s -> %s" % (base["git_head"], cur["git_head"]) if changed else "HEAD 未变: " + cur["git_head"])
    problems = _red_checks(base, cur)
    if problems:
        print("\n[REDLINE] %d 项不满足:" % len(problems))
        for p in problems:
            print("  - " + p)
        return 1
    print("\n[OK] 终验红线全部通过，可发布。")
    if args.bench and cur.get("benchmark") and base.get("benchmark"):
        print("benchmark 对比（当前 vs 基线）:")
        print("  current  recall/precision 见上，基线见 %s" % BASELINE_FILE)
    return 0


if __name__ == "__main__":
    sys.exit(main())