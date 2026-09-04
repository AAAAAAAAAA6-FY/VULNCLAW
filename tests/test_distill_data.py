# -*- coding: utf-8 -*-
"""方向4 蒸馏数据管线：过滤门槛 / 去重 / 格式 / 算力探测。"""
import json

from vulnclaw.growth import distill_data as dd


def _write_ledger(path, rows):
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def _finding(vuln_type="xss", verdict="confirm", confidence="high",
             payload="<script>", param="q", evidence="反射<script>到响应"):
    return {
        "kind": "finding", "vuln_type": vuln_type, "verdict": verdict,
        "confidence": confidence, "payload": payload, "param": param,
        "evidence": evidence, "severity": "medium",
    }


class TestFilterThreshold:
    def test_confirm_high_exported(self, tmp_path):
        ledger = tmp_path / "ledger.jsonl"
        out = tmp_path / "ds.jsonl"
        _write_ledger(ledger, [_finding()])
        res = dd.export_training_data(str(ledger), str(out))
        assert res["exported"] == 1
        assert res["total_records"] == 1

    def test_fp_skipped(self, tmp_path):
        ledger = tmp_path / "ledger.jsonl"
        out = tmp_path / "ds.jsonl"
        _write_ledger(ledger, [_finding(verdict="fp")])
        res = dd.export_training_data(str(ledger), str(out))
        assert res["exported"] == 0

    def test_low_confidence_skipped(self, tmp_path):
        ledger = tmp_path / "ledger.jsonl"
        out = tmp_path / "ds.jsonl"
        _write_ledger(ledger, [_finding(confidence="low")])
        res = dd.export_training_data(str(ledger), str(out))
        assert res["exported"] == 0

    def test_reconfirmed_and_fixed_ok(self, tmp_path):
        ledger = tmp_path / "ledger.jsonl"
        out = tmp_path / "ds.jsonl"
        _write_ledger(ledger, [
            _finding(verdict="reconfirmed", evidence="A"),
            _finding(verdict="fixed", evidence="B"),
        ])
        res = dd.export_training_data(str(ledger), str(out))
        assert res["exported"] == 2


class TestFormatAndDedup:
    def test_messages_format(self, tmp_path):
        ledger = tmp_path / "ledger.jsonl"
        out = tmp_path / "ds.jsonl"
        _write_ledger(ledger, [_finding()])
        dd.export_training_data(str(ledger), str(out))
        with open(out, "r", encoding="utf-8") as fh:
            rec = json.loads(fh.readline())
        assert {"system", "user", "assistant"} == {m["role"] for m in rec["messages"]}
        assert "确认（xss）" in rec["messages"][-1]["content"]

    def test_duplicate_fingerprint_not_reexported(self, tmp_path):
        ledger = tmp_path / "ledger.jsonl"
        out = tmp_path / "ds.jsonl"
        _write_ledger(ledger, [_finding(), _finding()])  # 完全相同两条
        res = dd.export_training_data(str(ledger), str(out))
        assert res["exported"] == 1
        assert res["total_records"] == 1

    def test_missing_ledger_raises(self, tmp_path):
        import pytest
        with pytest.raises(FileNotFoundError):
            dd.export_training_data(str(tmp_path / "nope.jsonl"), str(tmp_path / "ds.jsonl"))


class TestGpuProbe:
    def test_gpu_available_is_bool(self):
        assert isinstance(dd.gpu_available(), bool)

    def test_train_without_gpu_reports_reason(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dd, "gpu_available", lambda: False)
        ds = tmp_path / "ds.jsonl"
        ds.write_text('{"messages": []}\n', encoding="utf-8")
        res = dd.train_lor_a(str(ds))
        assert res["trained"] is False
        assert "GPU" in res["reason"]

    def test_status_never_raises(self, tmp_path):
        status = dd.distill_status()
        assert "dataset_records" in status
        assert "gpu_available" in status