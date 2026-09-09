#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""J.2 失败根因 / 稳定性统计（只读报告，不重扫）。

任务清单 v2 组 J：评审关注「LLM 调用失败率/Tool 失败率」但无量化。本脚本读取最新
扫描报告（兼容 list 或 {"findings":[...]} 两种形态），输出：
  1. finding 总量与按 severity 分布；
  2. 按 type 的 Top 分布（定位重复/集中面）；
  3. 低置信度 finding（confidence != high 或 ai_verdict 为「中」）——稳定性风险点；
  4. 疑似重复（type+url 相同）数量——去重是否生效的探针。

同时输出一行 `STABILITY` 指标便于趋势对比（JSONL 追加到 _runtime_cache 供后续画图）。

用法：
    python scripts/failure_rootcause_audit.py
    python scripts/failure_rootcause_audit.py --report <path>
输出：
    控制台表格 + 追加 _runtime_cache/stability_metrics.jsonl
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "_runtime_cache" / "reports"
METRICS = ROOT / "_runtime_cache" / "stability_metrics.jsonl"


def _latest_report() -> str | None:
    files = sorted(glob.glob(str(REPORTS / "*.json")))
    return files[-1] if files else None


def _load(path: str) -> list[dict]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("findings") or data.get("results") or []
    return []


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default="", help="报告 JSON 路径（默认最新）")
    args = ap.parse_args()

    rp = args.report or _latest_report()
    if not rp:
        print("NO_REPORT_FILE (先跑一次扫描以产生报告)")
        return 0

    findings = _load(rp)
    total = len(findings)
    by_sev: dict[str, int] = {}
    by_type: dict[str, int] = {}
    low_conf = 0
    seen = set()
    dups = 0
    for f in findings:
        sev = str(f.get("severity", "Unknown"))
        by_sev[sev] = by_sev.get(sev, 0) + 1
        t = str(f.get("type", f.get("title", "Unknown")))
        by_type[t] = by_type.get(t, 0) + 1
        conf = str(f.get("confidence", "")).lower()
        verdict = str(f.get("ai_verdict", ""))
        if conf and conf != "high":
            low_conf += 1
        elif verdict == "中":
            low_conf += 1
        key = (t, str(f.get("url", "")))
        if key in seen:
            dups += 1
        else:
            seen.add(key)

    print(f"REPORT={Path(rp).name} FINDINGS={total}")
    print("| severity | count |")
    print("|---|---|")
    for k in ("Critical", "High", "Medium", "Low", "Unknown"):
        if by_sev.get(k):
            print(f"| {k} | {by_sev[k]} |")
    print("| type | count |")
    print("|---|---|")
    for t, c in sorted(by_type.items(), key=lambda x: -x[1])[:12]:
        print(f"| `{t}` | {c} |")
    print(f"LOW_CONF={low_conf} DUPLICATE={dups}")
    stability = {
        "findings": total,
        "critical": by_sev.get("Critical", 0),
        "high": by_sev.get("High", 0),
        "low_conf": low_conf,
        "duplicate": dups,
    }
    print(f"STABILITY={json.dumps(stability, ensure_ascii=False)}")

    try:
        METRICS.parent.mkdir(parents=True, exist_ok=True)
        with open(METRICS, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"report": Path(rp).name, **stability},
                                 ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
