# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""VULNCLAW 检出率基准（D7.2）：剧本化靶场评估 + 吞吐基准。

两种模式：
  --mode throughput   原 asyncio 并发吞吐基准（默认）
  --mode eval         给定剧本(expected) + 扫描报告(report)，计算检出率(recall/precision)并对照红线

用法示例：
  python scripts/benchmark.py --mode eval \
      --scenarios-dir scripts/benchmarks \
      --report scripts/benchmarks/baseline_report.json \
      --min-recall 0.8
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field
from statistics import mean
from typing import Dict, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


# ---------------- throughput 基准（保留原有能力） ----------------
async def simulate_request(request_id: int, delay: float = 0.05) -> dict:
    await asyncio.sleep(delay)
    return {"id": request_id, "status": "ok"}


async def run_benchmark(total_requests: int = 200, concurrency: int = 20) -> float:
    sem = asyncio.Semaphore(concurrency)

    async def worker(rid: int) -> dict:
        async with sem:
            return await simulate_request(rid)

    start = time.perf_counter()
    results = await asyncio.gather(*(worker(i) for i in range(total_requests)))
    elapsed = time.perf_counter() - start
    return elapsed if results else 0.0


async def _throughput(scenarios) -> None:
    timings = []
    for total, conc in scenarios:
        elapsed = await run_benchmark(total, conc)
        timings.append((total, conc, elapsed))
        rps = total / elapsed if elapsed else 0.0
        print(f"requests={total:>3} concurrency={conc:>2} elapsed={elapsed:.3f}s rps={rps:.2f}")
    print(f"average_elapsed={mean(d for _, _, d in timings):.3f}s")


# ---------------- 剧本化评估 ----------------
@dataclass
class TargetScenario:
    name: str
    target: str
    expected_vulns: List[str] = field(default_factory=list)
    auth: Optional[dict] = None

    @classmethod
    def from_dict(cls, d: dict) -> "TargetScenario":
        return cls(
            name=d.get("name", d.get("target", "unnamed")),
            target=d["target"],
            expected_vulns=d.get("expected_vulns", []),
            auth=d.get("auth"),
        )


def load_scenarios(path: str) -> List[TargetScenario]:
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    if os.path.isdir(path):
        out: List[TargetScenario] = []
        for fn in sorted(os.listdir(path)):
            if fn.endswith((".yaml", ".yml")):
                out.extend(load_scenarios(os.path.join(path, fn)))
        return out
    if yaml is None:
        raise RuntimeError("PyYAML 未安装，无法解析剧本")
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or []
    return [TargetScenario.from_dict(d) for d in data]


def _report_findings(report: dict) -> List[dict]:
    if isinstance(report, dict):
        return report.get("findings") or report.get("results") or []
    return []


def evaluate_report(report: dict, scenarios: List[TargetScenario]) -> Dict:
    """计算所有剧本期望漏洞的召回率/精确率。"""
    found_types = set()
    for f in _report_findings(report):
        vt = f.get("type") or f.get("vuln_type") or f.get("name")
        if vt:
            found_types.add(vt)
    expected = set()
    for s in scenarios:
        expected.update(s.expected_vulns)
    tp = expected & found_types
    fn = expected - found_types
    fp = found_types - expected
    recall = len(tp) / len(expected) if expected else 1.0
    precision = len(tp) / len(found_types) if found_types else 1.0
    return {
        "expected": sorted(expected),
        "found": sorted(found_types),
        "recall": recall,
        "precision": precision,
        "missed": sorted(fn),
        "extra": sorted(fp),
    }


async def _eval_mode(scenarios_dir: str, report_path: str, min_recall: float) -> None:
    scenarios = load_scenarios(scenarios_dir)
    with open(report_path, "r", encoding="utf-8") as fh:
        report = json.load(fh)
    res = evaluate_report(report, scenarios)
    print("=" * 60)
    print(f"剧本数={len(scenarios)} 期望漏洞={len(res['expected'])} 检出={len(res['found'])}")
    print(f"recall={res['recall']:.2%}  precision={res['precision']:.2%}")
    if res["missed"]:
        print(f"未检出(missed): {res['missed']}")
    if res["extra"]:
        print(f"额外检出(extra): {res['extra']}")
    print("=" * 60)
    if min_recall is not None and res["recall"] < min_recall:
        print(f"[FAIL] 检出率 {res['recall']:.2%} 低于红线 {min_recall:.2%}")
        sys.exit(1)
    print("[OK] 检出率达标")


def main() -> None:
    ap = argparse.ArgumentParser(description="VULNCLAW 检出率基准")
    ap.add_argument("--mode", choices=["throughput", "eval"], default="throughput")
    ap.add_argument("--scenarios-dir", default="scripts/benchmarks")
    ap.add_argument("--report", default="artifacts/report.json")
    ap.add_argument("--min-recall", type=float, default=0.8)
    args = ap.parse_args()
    if args.mode == "eval":
        asyncio.run(_eval_mode(args.scenarios_dir, args.report, args.min_recall))
    else:
        asyncio.run(_throughput([(100, 10), (200, 20), (400, 40)]))


if __name__ == "__main__":
    main()
