#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""数据集指标门禁：读 JSONL 真实结果数据集，统计 TP/FN/FP/TN 并计算六指标。

口径见 docs/DATASET_SPEC.md，要点：
  - environment_error / unknown 不计入任何 TP/TN/FP/FN 分母，单独计数报告；
  - 未验证（unknown / 坏行 / 缺字段）绝不能当 TN；
  - reproduction 缺失视为未提供，reproduction_rate 仅报告不设门禁；
  - 分母为 0 的指标记 None（NA），对非零门禁阈值视为不通过。

用法：
    python scripts/dataset_metrics.py --dataset _runtime_cache/datasets/real_results_v1.jsonl \
        [--min-recall 0.8] [--max-false-rate 0.2] [--min-evidence-rate 0.5]

退出码：0 = 门禁通过；2 = 门禁不达标或数据集不可用。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# category → 计数桶（写死口径，与 docs/DATASET_SPEC.md 一致）
CATEGORY_TO_VERDICT = {
    "true_positive_verified": "TP",
    "false_negative": "FN",
    "false_positive": "FP",
    "true_negative_safe": "TN",
}
EXCLUDED_CATEGORIES = ("environment_error", "unknown")
ALL_CATEGORIES = list(CATEGORY_TO_VERDICT) + list(EXCLUDED_CATEGORIES)
REQUIRED_FIELDS = ("id", "category")


def _nonempty(value) -> bool:
    """字符串 strip 后非空才算"有"。"""
    return isinstance(value, str) and bool(value.strip())


def load_dataset(path) -> Tuple[List[dict], Dict[str, int]]:
    """读 JSONL：返回 (合法记录列表, 各 category 计数)。

    坏行（JSON 失败/非对象/缺必填字段/category 不在枚举）计入 unknown 并告警。
    """
    counts = {c: 0 for c in ALL_CATEGORIES}
    records: List[dict] = []
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"dataset not found: {p}")
    with p.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if not isinstance(rec, dict):
                    raise ValueError("line is not a JSON object")
                missing = [f for f in REQUIRED_FIELDS if not _nonempty(rec.get(f))]
                if missing:
                    raise ValueError(f"missing required field(s): {missing}")
                cat = str(rec["category"]).strip()
                if cat not in counts:
                    raise ValueError(f"category not in enum: {cat!r}")
            except (ValueError, json.JSONDecodeError) as exc:
                counts["unknown"] += 1
                print(f"[!] line {lineno}: malformed -> unknown ({exc})", file=sys.stderr)
                continue
            counts[cat] += 1
            records.append(rec)
    return records, counts


def compute_dataset_metrics(records: List[dict], counts: Dict[str, int]) -> dict:
    """汇总计数与六指标（evidence/reproduction 基于记录级非空判断，仅 TP 参与分母）。"""
    tp = counts["true_positive_verified"]
    fn = counts["false_negative"]
    fp = counts["false_positive"]
    tn = counts["true_negative_safe"]

    def _ratio(num: int, den: int) -> Optional[float]:
        return (num / den) if den else None

    tp_records = [r for r in records if r.get("category") == "true_positive_verified"]
    return {
        "counts": {
            "TP": tp,
            "FN": fn,
            "FP": fp,
            "TN": tn,
            "environment_error": counts["environment_error"],
            "unknown": counts["unknown"],
            "total": sum(counts.values()),
        },
        "metrics": {
            "recall": _ratio(tp, tp + fn),
            "precision": _ratio(tp, tp + fp),
            "fp_rate": _ratio(fp, fp + tn),
            "fn_rate": _ratio(fn, tp + fn),
            "evidence_rate": _ratio(
                sum(1 for r in tp_records if _nonempty(r.get("evidence"))), tp
            ),
            "reproduction_rate": _ratio(
                sum(1 for r in tp_records if _nonempty(r.get("reproduction"))), tp
            ),
        },
    }


def _fmt(value) -> str:
    return f"{value:.4f}" if isinstance(value, (int, float)) else "NA"


def evaluate_gates(metrics: Dict[str, Optional[float]], thresholds: dict) -> Dict[str, bool]:
    """门禁判定：阈值 <=0（或 false-rate >=1）视为该门禁关闭；缺失数据(None)不能通过非零门禁。"""
    def _ok_ge(value, minimum) -> bool:
        return minimum <= 0.0 or (isinstance(value, (int, float)) and value >= minimum)

    def _ok_le(value, maximum) -> bool:
        return maximum >= 1.0 or (isinstance(value, (int, float)) and value <= maximum)

    return {
        "recall": _ok_ge(metrics["recall"], thresholds["min_recall"]),
        "precision": _ok_ge(metrics["precision"], thresholds["min_precision"]),
        "false_rate": _ok_le(metrics["fp_rate"], thresholds["max_false_rate"]),
        "evidence_rate": _ok_ge(metrics["evidence_rate"], thresholds["min_evidence_rate"]),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="数据集指标门禁（口径见 docs/DATASET_SPEC.md）")
    ap.add_argument("--dataset", required=True, help="JSONL 数据集路径（版本化，如 real_results_v1.jsonl）")
    ap.add_argument("--min-recall", type=float, default=0.0, help="最低召回率 recall=TP/(TP+FN)")
    ap.add_argument("--min-precision", type=float, default=0.0, help="最低精确率 precision=TP/(TP+FP)")
    ap.add_argument("--max-false-rate", type=float, default=1.0, help="最高误报率 fp_rate=FP/(FP+TN)")
    ap.add_argument("--min-evidence-rate", type=float, default=0.0, help="最低证据率（TP 有非空 evidence 占比）")
    ap.add_argument("--json-out", default="", help="把统计结果（含环境信息）写入 JSON 文件，供 nightly 归档/版本对比")
    args = ap.parse_args()

    try:
        records, counts = load_dataset(args.dataset)
    except (OSError, ValueError) as exc:
        print(f"DATASET_UNAVAILABLE {exc}")
        return 2
    if not records and counts["unknown"] == 0:
        print(f"DATASET_EMPTY {args.dataset}")
        return 2

    result = compute_dataset_metrics(records, counts)
    thresholds = {
        "min_recall": args.min_recall,
        "min_precision": args.min_precision,
        "max_false_rate": args.max_false_rate,
        "min_evidence_rate": args.min_evidence_rate,
    }
    gates = evaluate_gates(result["metrics"], thresholds)
    passed = all(gates.values())
    result["gates"] = gates
    result["thresholds"] = thresholds
    result["passed"] = passed

    # 工作流4：统计报告落盘（含环境信息，供 nightly 归档与跨版本对比）
    if args.json_out:
        try:
            import platform as _platform
            report = dict(result)
            report["environment"] = {
                "python": sys.version.split()[0],
                "platform": _platform.platform(),
                "dataset": str(Path(args.dataset).resolve()),
                "generated_at": datetime.now().isoformat(timespec="seconds"),
                "commit": (os.environ.get("GITHUB_SHA") or "")[:12],
                "run_id": os.environ.get("GITHUB_RUN_ID", ""),
                "trigger": os.environ.get("GITHUB_EVENT_NAME", "local"),
            }
            Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump(report, fh, ensure_ascii=False, indent=2)
            print(f"[dataset-metrics] 统计报告已写入 {args.json_out}")
        except (OSError, TypeError, ValueError) as exc:
            print(f"[dataset-metrics] 统计报告写入失败（不影响门禁）: {exc}")

    # 统计 JSON（单行，供机器读取）
    print(json.dumps(result, ensure_ascii=False))

    # 人类可读摘要
    c = result["counts"]
    m = result["metrics"]
    print("=" * 72)
    print(f" 数据集指标：{args.dataset}")
    print("=" * 72)
    print(
        f" TP={c['TP']}  FN={c['FN']}  FP={c['FP']}  TN={c['TN']}"
        f"  |  排除分母: environment_error={c['environment_error']}  unknown={c['unknown']}"
        f"  (total={c['total']})"
    )
    print(
        f" recall={_fmt(m['recall'])}  precision={_fmt(m['precision'])}  "
        f"fp_rate={_fmt(m['fp_rate'])}  fn_rate={_fmt(m['fn_rate'])}"
    )
    print(
        f" evidence_rate={_fmt(m['evidence_rate'])}"
        f"  reproduction_rate={_fmt(m['reproduction_rate'])} (仅报告，不设门禁)"
    )
    print(
        f" 门禁: recall>={args.min_recall}  fp_rate<={args.max_false_rate}"
        f"  evidence_rate>={args.min_evidence_rate}"
        f"  ->  {'PASS' if passed else 'FAIL'}"
    )
    print("=" * 72)
    return 0 if passed else 2


if __name__ == "__main__":
    sys.exit(main())
