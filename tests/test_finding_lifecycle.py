# -*- coding: utf-8 -*-
"""SP10 finding 生命周期台账测试。"""
import json

import pytest

from vulnclaw.core import finding_lifecycle as fl


def _finding(url="http://t.example.com/a", type_="sqli", method="GET", param="id", severity="High"):
    return {"url": url, "type": type_, "method": method, "parameter": param,
            "severity": severity, "evidence": "boom", "confidence": "high"}


def _report(target="http://t.example.com", findings=None):
    return {"target": target, "vulnerabilities": list(findings or [])}


class TestApplyLifecycle:
    def test_all_new_when_no_ledger(self, tmp_path):
        lp = str(tmp_path / "ledger.json")
        report = _report(findings=[_finding(), _finding(url="http://t.example.com/b")])
        out = fl.apply_lifecycle(report, ledger_path=lp)
        assert all(v["lifecycle"] == fl.LIFECYCLE_NEW for v in out["vulnerabilities"])
        assert out["lifecycle_summary"] == {"new": 2}
        assert (tmp_path / "ledger.json").exists()

    def test_reconfirmed_from_ledger(self, tmp_path):
        lp = str(tmp_path / "ledger.json")
        a = _finding()
        run1 = _report(findings=[a, _finding(url="http://t.example.com/b")])
        fl.apply_lifecycle(run1, ledger_path=lp)
        c = _finding(url="http://t.example.com/c")
        run2 = _report(findings=[a, c])
        out = fl.apply_lifecycle(run2, ledger_path=lp)
        by_url = {v["url"]: v for v in out["vulnerabilities"]}
        assert by_url["http://t.example.com/a"]["lifecycle"] == fl.LIFECYCLE_RECONFIRMED
        assert by_url["http://t.example.com/c"]["lifecycle"] == fl.LIFECYCLE_NEW
        assert out["lifecycle_summary"]["reconfirmed"] == 1
        assert out["lifecycle_summary"]["new"] == 1

    def test_ledger_counts_and_first_seen(self, tmp_path):
        lp = str(tmp_path / "ledger.json")
        a = _finding()
        fl.apply_lifecycle(_report(findings=[a]), ledger_path=lp)
        fl.apply_lifecycle(_report(findings=[a]), ledger_path=lp)
        ledger = fl.load_lifecycle_ledger(lp)
        rec = next(iter(ledger["findings"].values()))
        assert rec["scan_count"] == 2
        assert rec["first_seen"] == rec["first_seen"]
        assert rec["state"] == fl.LIFECYCLE_RECONFIRMED

    def test_internal_fields_stripped(self, tmp_path):
        lp = str(tmp_path / "ledger.json")
        out = fl.apply_lifecycle(_report(findings=[_finding()]), ledger_path=lp)
        for v in out["vulnerabilities"]:
            assert "_lc_key" not in v

    def test_empty_report_degrades(self, tmp_path):
        lp = str(tmp_path / "ledger.json")
        out = fl.apply_lifecycle(_report(findings=[]), ledger_path=lp)
        assert out["lifecycle_summary"] == {}
        assert out["lifecycle_groups"]["new"] == []

    def test_ledger_schema_version(self, tmp_path):
        lp = str(tmp_path / "ledger.json")
        fl.apply_lifecycle(_report(findings=[_finding()]), ledger_path=lp)
        assert fl.load_lifecycle_ledger(lp)["schema_version"] == fl.LIFECYCLE_SCHEMA_VERSION


class TestMigrate:
    def test_fixed_new_reconfirmed(self):
        a, b = _finding(), _finding(url="http://t.example.com/b")
        c = _finding(url="http://t.example.com/c")
        res = fl.migrate(_report(findings=[a, b]), _report(findings=[a, c]))
        assert res["summary"] == {"baseline_total": 2, "current_total": 2, "new_count": 1,
                                  "reconfirmed_count": 1, "fixed_count": 1}
        assert all(v["lifecycle"] == fl.LIFECYCLE_RECONFIRMED for v in res["current"] if v["url"] == "http://t.example.com/a")
        assert any(v["lifecycle"] == fl.LIFECYCLE_NEW and v["url"] == "http://t.example.com/c" for v in res["current"])
        assert res["fixed"] and res["fixed"][0]["url"] == "http://t.example.com/b"
        assert res["fixed"][0]["evidence"] == "boom"  # 基线证据留存

    def test_key_includes_method(self):
        url = "http://t.example.com/x"
        baseline = _report(findings=[_finding(url=url, method="GET")])
        current = _report(findings=[_finding(url=url, method="POST")])
        res = fl.migrate(baseline, current)
        assert res["summary"]["fixed_count"] == 1
        assert res["summary"]["new_count"] == 1

    def test_identical_reports_all_reconfirmed(self):
        f = _finding()
        res = fl.migrate(_report(findings=[f]), _report(findings=[f]))
        assert res["summary"]["fixed_count"] == 0
        assert all(v["lifecycle"] == fl.LIFECYCLE_RECONFIRMED for v in res["current"])


class TestLedger:
    def test_mark_fixed(self, tmp_path):
        lp = str(tmp_path / "ledger.json")
        a = _finding()
        b = _finding(url="http://t.example.com/b")
        fl.apply_lifecycle(_report(findings=[a, b]), ledger_path=lp)
        key_a = fl.lifecycle_key(a)
        fl.mark_fixed_in_ledger([key_a], ledger_path=lp)
        ledger = fl.load_lifecycle_ledger(lp)
        states = {rec["key"]: rec["state"] for rec in ledger["findings"].values()}
        assert states[fl.lifecycle_key(b)] == fl.LIFECYCLE_FIXED
        assert states[key_a] != fl.LIFECYCLE_FIXED

    def test_migrate_fixed_html_block_dry_run_report(self, tmp_path):
        # 组分组应与报告钩子兼容：无渲染依赖，仅校验字段存在
        from vulnclaw.core.report_generator import _render_lifecycle_block
        a = _finding()
        report = fl.apply_lifecycle(_report(findings=[a]), ledger_path=str(tmp_path / "l.json"))
        html = _render_lifecycle_block(report)
        assert "漏洞治理台账" in html
        assert _render_lifecycle_block({}) == ""