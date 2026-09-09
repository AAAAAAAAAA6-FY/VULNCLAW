#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""F.3 决策回放（闭环 F.1）。

F.1 已在 `ReActAgent` 每轮 think/decide 把决策以 JSONL 落盘到
`_runtime_cache/agent_decisions/*.jsonl`。本脚本读取这些审计记录，按时间线
重放某次扫描的 AI 决策路径，标注 `source=deterministic_fallback` 的降级点，
用于复盘「LLM 走了哪条路、何时因超时/解析失败回退到确定性策略」。

这正是评审点 1「AI 不可审计」的对症解药：任何一次扫描都可事后回放决策链。

用法：
    python scripts/replay_decisions.py                 # 回放最新一次审计
    python scripts/replay_decisions.py --scan <f>      # 指定审计文件
    python scripts/replay_decisions.py --target <host> # 只看某 target
输出：
    决策时间线 + fallback 计数（便于 grep 审计/合规）
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "_runtime_cache" / "agent_decisions"


def _latest() -> Path | None:
    files = sorted(AUDIT.glob("*.jsonl"))
    return files[-1] if files else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", default="", help="审计 JSONL 路径（默认最新）")
    ap.add_argument("--target", default="", help="只回放含该 host 的决策")
    args = ap.parse_args()

    p = Path(args.scan) if args.scan else _latest()
    if not p or not p.exists():
        print("NO_AUDIT_FILE (先跑一次扫描以产生 F.1 审计记录)")
        return 0

    rows: list[dict] = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:  # noqa: BLE001
            continue

    if args.target:
        rows = [r for r in rows if args.target in str(r.get("target", ""))]
    if not rows:
        print(f"EMPTY target={args.target} file={p.name}")
        return 0

    fallback = [r for r in rows if r.get("source") == "deterministic_fallback"]
    print(f"FILE={p.name} STEPS={len(rows)} FALLBACK={len(fallback)}")
    print(f"{'ts':>12}  {'kind':<8} {'source':<22} tool/action")
    print("-" * 76)
    for r in rows:
        ts = r.get("ts", 0) or 0
        act = r.get("action")
        if isinstance(act, dict):
            tool = f"{act.get('tool','')}({act.get('param','')})"
        else:
            tool = str(act)[:28]
        print(f"{float(ts):>12.2f}  {str(r.get('kind','')):<8} "
              f"{str(r.get('source','')):<22} {tool}")
    if fallback:
        print("-" * 76)
        print(f"fallback:deterministic x{len(fallback)} "
              f"-> 这些步骤 LLM 未决策，走确定性降级（不影响扫描，仅记录）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
