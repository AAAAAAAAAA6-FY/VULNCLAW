# -*- coding: utf-8 -*-
"""DATASET_SPEC v1 指标门禁回归（离线确定性，进程内调用，不起子进程）。

锁定口径：
  - environment_error / unknown 不进任何 TP/TN/FP/FN 分母；
  - 六指标数值精确；
  - 门禁边界（刚好达标 / 刚好不达标）与退出码；
  - reproduction 缺失容忍（计 0，仅报告）；
  - 坏行 → unknown，绝不当 TN。
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "dataset_metrics", ROOT / "scripts" / "dataset_metrics.py"
)
dm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dm)

TS = "2026-09-13T00:00:00Z"


def _rec(cid, category, evidence="", **extra):
    rec = {
        "id": cid,
        "target": "http://127.0.0.1:8090/a",
        "vulnerability": "xss",
        "category": category,
        "expected": "detect" if category == "true_positive_verified" else "no_detect",
        "actual": "detected" if category == "true_positive_verified" else "not_detected",
        "evidence": evidence,
        "environment": "local-offline",
        "timestamp": TS,
    }
    rec.update(extra)
    return rec


def _write(tmp_path, records, raw_lines=()):
    p = tmp_path / "ds.jsonl"
    lines = [json.dumps(r, ensure_ascii=False) for r in records] + list(raw_lines)
    p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return p


def _run_cli(monkeypatch, capsys, p, *extra):
    """进程内调用 main()：返回 (exit_code, stdout)。避开本环境 pytest+subprocess 句柄问题。"""
    argv = ["dataset_metrics.py", "--dataset", str(p), *extra]
    monkeypatch.setattr(sys, "argv", argv)
    code = dm.main()
    out = capsys.readouterr().out
    return code, out


def _stats(out):
    return json.loads(out.splitlines()[0])


# ---------- 分母排除铁律 ----------

def test_environment_error_and_unknown_excluded_from_denominators(tmp_path, monkeypatch, capsys):
    records = [
        _rec("t1", "true_positive_verified", evidence="resp body <script>"),
        _rec("t2", "true_negative_safe"),
        _rec("e1", "environment_error"),
        _rec("u1", "unknown"),
    ]
    p = _write(tmp_path, records)
    code, out = _run_cli(monkeypatch, capsys, p, "--min-recall", "0.8",
                         "--max-false-rate", "0.2", "--min-evidence-rate", "0.5")
    assert code == 0
    stats = _stats(out)
    assert stats["counts"] == {
        "TP": 1, "FN": 0, "FP": 0, "TN": 1,
        "environment_error": 1, "unknown": 1, "total": 4,
    }
    # recall = 1/(1+0) = 1.0，environment_error/unknown 不在分母
    assert stats["metrics"]["recall"] == 1.0
    assert stats["metrics"]["fp_rate"] == 0.0


def test_unverified_never_counts_as_tn(tmp_path, monkeypatch, capsys):
    # 只有 environment_error + unknown：TP/TN/FP/FN 全 0，指标为 NA 且门禁不过
    p = _write(tmp_path, [_rec("e1", "environment_error"), _rec("u1", "unknown")])
    code, out = _run_cli(monkeypatch, capsys, p, "--min-recall", "0.8")
    assert code == 2
    stats = _stats(out)
    assert stats["counts"]["TP"] == 0 and stats["counts"]["TN"] == 0
    assert stats["metrics"]["recall"] is None


def test_malformed_line_counts_as_unknown_not_tn(tmp_path):
    p = _write(tmp_path, [_rec("t1", "true_negative_safe")],
               raw_lines=["{not json", '{"id":"x"}', '{"id":"y","category":"bogus"}'])
    records, counts = dm.load_dataset(p)
    assert counts["true_negative_safe"] == 1
    assert counts["unknown"] == 3  # 坏行/缺 category/非法枚举 全部归 unknown


# ---------- 指标数值精确 ----------

def test_metric_values_exact(tmp_path):
    records = [
        _rec("t1", "true_positive_verified", evidence="ev1"),
        _rec("t2", "true_positive_verified"),  # 无证据
        _rec("t3", "true_positive_verified", evidence="ev3"),
        _rec("f1", "false_negative"),
        _rec("p1", "false_positive"),
        _rec("n1", "true_negative_safe"),
        _rec("n2", "true_negative_safe"),
        _rec("n3", "true_negative_safe"),
        _rec("e1", "environment_error"),
        _rec("u1", "unknown"),
    ]
    records, counts = dm.load_dataset(_write(tmp_path, records))
    result = dm.compute_dataset_metrics(records, counts)
    m = result["metrics"]
    assert result["counts"] == {
        "TP": 3, "FN": 1, "FP": 1, "TN": 3,
        "environment_error": 1, "unknown": 1, "total": 10,
    }
    assert m["recall"] == 3 / 4            # TP/(TP+FN)
    assert m["precision"] == 3 / 4          # TP/(TP+FP)
    assert m["fp_rate"] == 1 / 4            # FP/(FP+TN)
    assert m["fn_rate"] == 1 / 4            # FN/(TP+FN)
    assert m["evidence_rate"] == 2 / 3      # 有非空 evidence 的 TP / TP
    assert m["reproduction_rate"] == 0.0    # 缺失 reproduction → 未提供，计 0


def test_reproduction_field_missing_tolerated(tmp_path, monkeypatch, capsys):
    # reproduction 字段完全缺失也必须容忍（并行组 D 会后补该字段）
    p = _write(tmp_path, [_rec("t1", "true_positive_verified", evidence="ev")])
    code, out = _run_cli(monkeypatch, capsys, p)
    assert code == 0
    assert _stats(out)["metrics"]["reproduction_rate"] == 0.0


def test_reproduction_rate_counts_nonempty_only(tmp_path):
    records, counts = dm.load_dataset(_write(tmp_path, [
        _rec("t1", "true_positive_verified", evidence="e", reproduction="steps..."),
        _rec("t2", "true_positive_verified", evidence="e", reproduction="  "),  # 空白=未提供
        _rec("t3", "true_positive_verified", evidence="e", reproduction="steps2"),
    ]))
    m = dm.compute_dataset_metrics(records, counts)["metrics"]
    assert m["reproduction_rate"] == 2 / 3


# ---------- 门禁边界与退出码 ----------

def test_gate_boundary_exactly_meets_recall(tmp_path, monkeypatch, capsys):
    # TP=4, FN=1 → recall=0.8，--min-recall 0.8 恰好达标 → exit 0
    records = [_rec(f"t{i}", "true_positive_verified", evidence="e") for i in range(4)]
    records.append(_rec("f1", "false_negative"))
    code, _ = _run_cli(monkeypatch, capsys, _write(tmp_path, records), "--min-recall", "0.8")
    assert code == 0


def test_gate_boundary_just_below_recall(tmp_path, monkeypatch, capsys):
    # TP=4, FN=1 → recall=0.8 < 0.800001 → exit 2
    records = [_rec(f"t{i}", "true_positive_verified", evidence="e") for i in range(4)]
    records.append(_rec("f1", "false_negative"))
    code, _ = _run_cli(monkeypatch, capsys, _write(tmp_path, records),
                       "--min-recall", "0.800001")
    assert code == 2


def test_gate_boundary_exactly_meets_false_rate(tmp_path, monkeypatch, capsys):
    # FP=1, TN=4 → fp_rate=0.2，--max-false-rate 0.2 恰好达标 → exit 0
    records = [_rec("p1", "false_positive")]
    records += [_rec(f"n{i}", "true_negative_safe") for i in range(4)]
    records += [_rec(f"t{i}", "true_positive_verified", evidence="e") for i in range(2)]
    code, _ = _run_cli(monkeypatch, capsys, _write(tmp_path, records),
                       "--max-false-rate", "0.2", "--min-recall", "0.0")
    assert code == 0


def test_gate_boundary_just_above_false_rate(tmp_path, monkeypatch, capsys):
    # FP=1, TN=3 → fp_rate=0.25 > 0.2 → exit 2
    records = [_rec("p1", "false_positive")]
    records += [_rec(f"n{i}", "true_negative_safe") for i in range(3)]
    records += [_rec(f"t{i}", "true_positive_verified", evidence="e") for i in range(2)]
    code, _ = _run_cli(monkeypatch, capsys, _write(tmp_path, records),
                       "--max-false-rate", "0.2", "--min-recall", "0.0")
    assert code == 2


def test_gate_boundary_exactly_meets_evidence_rate(tmp_path, monkeypatch, capsys):
    # 1/2 TP 有证据 → evidence_rate=0.5，--min-evidence-rate 0.5 恰好达标 → exit 0
    records = [
        _rec("t1", "true_positive_verified", evidence="e"),
        _rec("t2", "true_positive_verified"),
    ]
    code, _ = _run_cli(monkeypatch, capsys, _write(tmp_path, records),
                       "--min-evidence-rate", "0.5", "--min-recall", "0.0")
    assert code == 0


def test_gate_missing_evidence_data_fails_nonzero_threshold(tmp_path, monkeypatch, capsys):
    # evidence_rate=0.0（数据存在但全空）< 0.5 → exit 2（None/0 都不能凑非零门禁）
    records = [_rec("t1", "true_positive_verified")]
    code, _ = _run_cli(monkeypatch, capsys, _write(tmp_path, records),
                       "--min-evidence-rate", "0.5", "--min-recall", "0.0")
    assert code == 2


def test_missing_dataset_file_exit_2(tmp_path, monkeypatch, capsys):
    code, _ = _run_cli(monkeypatch, capsys, tmp_path / "nope.jsonl")
    assert code == 2


@pytest.mark.parametrize("category,verdict", [
    ("true_positive_verified", "TP"),
    ("false_negative", "FN"),
    ("false_positive", "FP"),
    ("true_negative_safe", "TN"),
])
def test_category_enum_mapping_locked(category, verdict):
    """枚举→计数桶映射写死（spec 第 2 节），防止误改口径。"""
    assert dm.CATEGORY_TO_VERDICT[category] == verdict
    for excluded in ("environment_error", "unknown"):
        assert excluded not in dm.CATEGORY_TO_VERDICT
