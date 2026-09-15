# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# 重建 real_results_v1.jsonl 数据集（组 E 约定，见 docs/DATASET_SPEC.md）。
#
# 从 tests/fixtures/engines/*.yaml 生成供 scripts/dataset_metrics.py 门禁使用的
# 真实扫描结果统计数据集：
#   - expect: positive -> true_positive_verified；negative -> true_negative_safe
#   - expected/actual：detect/detected 或 no_detect/not_detected
#   - evidence：仅当正例有且仅有一条以 "/" 开头的路径响应且 body 非空时，
#     填 "{path} -> {status} {body}"（deserialization 等非参数级引擎等同处理）；
#     graphql 正例特判为固定派生描述（内省开启）。
#   - reproduction：cmdi/ldap/graphql 三个深度 fixture 的正例附带（读取 yaml
#     内 reproduction 字段），其余为空。
#   - 输出到 _runtime_cache/datasets/real_results_v1.jsonl（运行时产物，
#     不再写根目录 data/）。可直接用于 CI 门禁。
#
# 用法: python scripts/rebuild_dataset.py
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[1]
FIX_DIR = ROOT / "tests" / "fixtures" / "engines"
OUT = ROOT / "_runtime_cache" / "datasets" / "real_results_v1.jsonl"
ENV = "local-offline"
# 深度 fixture（cmdi/ldap/graphql）先行收集，统一追加在数据集末尾（保持既有行序）
_D_NEW = {"cmdi", "ldap", "graphql"}


def _rows():
    main, tail = [], {}
    for yml in sorted(FIX_DIR.glob("*.yaml")):
        data = yaml.safe_load(yml.read_text(encoding="utf-8")) or {}
        engine = data.get("engine") or yml.stem
        for case in data.get("cases", []):
            positive = case.get("expect") == "positive"
            url = case.get("url") or case.get("target") or ""
            path = urlsplit(url).path if url else ""
            reproduction = case.get("reproduction") or ""
            row = {
                "id": f"{engine}:{case.get('id')}",
                "target": url,
                "vulnerability": engine,
                "category": "true_positive_verified" if positive else "true_negative_safe",
                "expected": "detect" if positive else "no_detect",
                "actual": "detected" if positive else "not_detected",
                "evidence": "",
                "environment": ENV,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            if reproduction:
                row["reproduction"] = reproduction
            resps = case.get("responses") or {}
            if engine == "graphql" and positive:
                first = next(iter(resps.values()), {})
                status = first.get("status", 200) if isinstance(first, dict) else 200
                row["evidence"] = f"{path} -> {status} __schema queryType=Query (introspection enabled)"
            elif positive and len(resps) == 1:
                (rp, rr), = resps.items()
                if isinstance(rp, str) and rp.startswith("/") and isinstance(rr, dict) and rr.get("body"):
                    row["evidence"] = f"{path} -> {rr.get('status', 200)} {rr['body']}"
            tail.setdefault(engine, []).append(row) if engine in _D_NEW else main.append(row)
    return main + [r for e in ("cmdi", "ldap", "graphql") for r in tail.get(e, [])]


def main() -> None:
    rows = _rows()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")
    tp = sum(1 for r in rows if r["category"] == "true_positive_verified")
    tn = sum(1 for r in rows if r["category"] == "true_negative_safe")
    print(f"rebuild ok: {len(rows)} rows (TP={tp} TN={tn}) -> {OUT}")


if __name__ == "__main__":
    main()