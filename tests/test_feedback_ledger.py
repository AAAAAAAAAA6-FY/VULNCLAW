# -*- coding: utf-8 -*-
"""方向2：实战回灌账本测试。

覆盖：record 追加 / absorb_finding 结构 / absorb_scan 批量判定；
recommend_payloads 命中排序 + 误报污染剔除；suppressed_signatures 阈值；
snapshot 摘要；跨实例持久化。
"""
import os

import pytest

from vulnclaw.growth.feedback_ledger import FeedbackLedger, get_feedback_ledger, reset_feedback_ledger


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    reset_feedback_ledger()
    p = tmp_path / "feedback.jsonl"
    l = FeedbackLedger(str(p))
    monkeypatch.setattr("vulnclaw.growth.feedback_ledger._FEEDBACK_PATH", str(p))
    yield l
    reset_feedback_ledger()


def _f(vuln_type="lfi", param="file", payload="/etc/passwd", severity="High", conf=1):
    return {"type": vuln_type, "parameter": param, "payload": payload,
            "severity": severity, "confidence": conf, "id": "f-" + vuln_type}


class TestRecord:
    def test_record_appends_single_fact(self, ledger):
        ledger.record({"kind": "finding", "vuln_type": "xss"})
        assert len(ledger.rows()) == 1

    def test_record_auto_fills_ts_and_id(self, ledger):
        ledger.record({"kind": "finding"})
        r = ledger.rows()[0]
        assert r["ts"] and r["id"]

    def test_absorb_finding_normalizes(self, ledger):
        ledger.absorb_finding(_f(), tech_stack=["nginx", "php"], verdict="confirm",
                              target="https://a.example.com/path?x=1")
        r = ledger.rows()[0]
        assert r["vuln_type"] == "lfi"
        assert r["tech_stack"] == ["nginx", "php"]
        assert r["target_host"] == "a.example.com"
        assert r["verdict"] == "confirm"


class TestRecommend:
    def test_recommend_ranks_by_hits(self, ledger):
        for i in range(3):
            ledger.absorb_finding(_f(payload="/etc/passwd"), tech_stack=["php"], verdict="confirm")
        ledger.absorb_finding(_f(payload="/etc/hosts"), tech_stack=["php"], verdict="confirm")
        got = ledger.recommend_payloads("lfi", tech_stack=["php"], k=3)
        assert got[0] == "/etc/passwd"
        assert got[1] == "/etc/hosts"

    def test_recommend_filters_polluted_payload(self, ledger):
        ledger.absorb_finding(_f(payload="/etc/hosts"), tech_stack=["php"], verdict="confirm")
        ledger.absorb_finding(_f(payload="/etc/hosts"), tech_stack=["php"], verdict="fp")
        got = ledger.recommend_payloads("lfi", tech_stack=["php"], k=3)
        assert "/etc/hosts" not in got

    def test_recommend_respects_tech_stack(self, ledger):
        ledger.absorb_finding(_f(payload="/etc/passwd"), tech_stack=["java"], verdict="confirm")
        got = ledger.recommend_payloads("lfi", tech_stack=["php"], k=3)
        assert got == []


class TestSuppress:
    def test_suppress_threshold(self, ledger):
        # 同一 type+归一化参数 两次 fp -> 进入抑制名单（不同 uuid 归一化后相同）
        ledger.absorb_finding(_f(vuln_type="sqli", param="cb-9f1e2a3b-4c5d"),
                              verdict="fp")
        ledger.absorb_finding(_f(vuln_type="sqli", param="cb-1a2b3c4d-5e6f"),
                              verdict="fp")
        sigs = ledger.suppressed_signatures(min_shadow=2)
        assert "sqli|cb-x" in sigs

    def test_norm_param_strips_uuid(self, ledger):
        ledger.absorb_finding(_f(vuln_type="sqli", param="tok-abcd1234-5678"),
                              verdict="fp")
        ledger.absorb_finding(_f(vuln_type="sqli", param="tok-abcd1234-90ab"),
                              verdict="fp")
        sigs = ledger.suppressed_signatures(min_shadow=2)
        assert "sqli|tok-x" in sigs

    def test_no_fp_no_suppress(self, ledger):
        ledger.absorb_finding(_f(), verdict="confirm")
        assert ledger.suppressed_signatures() == []


class TestBatchAndPersistence:
    def test_absorb_scan_bulk(self, ledger):
        n = ledger.absorb_scan(
            [dict(_f("sqli"), verified=False), dict(_f("rce"), confirmed=True),
             dict(_f("xss"), confidence=0.4)],
            tech_stack=["php"], target="http://t.example.com",
        )
        assert n == 3
        verdicts = [r["verdict"] for r in ledger.rows()]
        assert "fp" in verdicts and "confirm" in verdicts and "miss" in verdicts

    def test_persistence_across_instances(self, tmp_path):
        p = str(tmp_path / "fb.jsonl")
        a = FeedbackLedger(p)
        a.absorb_finding(_f(), tech_stack=["py"], verdict="confirm")
        b = FeedbackLedger(p)
        assert len(b.rows()) == 1

    def test_snapshot_summary(self, ledger):
        ledger.absorb_finding(_f(payload="p1"), verdict="confirm")
        ledger.absorb_finding(_f(payload="p2"), verdict="fp")
        s = ledger.snapshot()
        assert s["facts"] == 2
        assert s["by_verdict"]["fp"] == 1

    def test_singleton(self, tmp_path, monkeypatch):
        reset_feedback_ledger()
        import vulnclaw.growth.feedback_ledger as mod
        monkeypatch.setattr(mod, "_FEEDBACK_PATH", str(tmp_path / "fb.jsonl"))
        assert get_feedback_ledger() is get_feedback_ledger()
        reset_feedback_ledger()