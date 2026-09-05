# SPDX-License-Identifier: AGPL-3.0-or-later
"""SP17.4 企业级报告增强（A 线）单元测试。

- distribution：按 (type, severity) 交叉统计 + 排名目标；空 findings 空结构不抛错
- suggest_remediation：四级分级模板；已有 remediation 时 append 不覆盖
- enrich_report：只新增字段，既有键（scan_id/configuration/apps 等）保持不变
"""
import pytest

from vulnclaw.core.report_generator import (
    build_distribution,
    enrich_report,
    generate_sarif,
    suggest_remediation,
)


def _finding(url, type_, severity, remediation=None):
    f = {"url": url, "type": type_, "severity": severity, "evidence": "proof"}
    if remediation is not None:
        f["remediation"] = remediation
    return f


def _report(findings, extra=None):
    report = {
        "scan_id": "scan-abc-123",
        "configuration": {"scope": "demo"},
        "apps": {"web": True},
        "target": "http://t.example.com",
        "vulnerabilities": list(findings),
    }
    if extra:
        report.update(extra)
    return report


class TestDistribution:
    def test_2x2_cross_count(self):
        findings = [
            _finding("http://host-a.example.com/p", "SQL注入", "Critical"),
            _finding("http://host-a.example.com/q", "SQL注入", "High"),
            _finding("http://host-b.example.com/x", "XSS", "High"),
            _finding("http://host-b.example.com/y", "XSS", "Low"),
            _finding("http://host-a.example.com/z", "SQL注入", "Critical"),
        ]
        dist = build_distribution(findings)
        assert dist["by_type"]["SQL注入"]["critical"] == 2
        assert dist["by_type"]["SQL注入"]["high"] == 1
        assert dist["by_type"]["XSS"]["high"] == 1
        assert dist["by_type"]["XSS"]["low"] == 1
        assert dist["by_severity"]["critical"] == 2
        assert dist["by_severity"]["high"] == 2
        assert dist["by_severity"]["low"] == 1
        # ranked_targets 按计数降序
        hosts = [t["host"] for t in dist["ranked_targets"]]
        assert hosts == ["host-a.example.com", "host-b.example.com"]
        assert dist["ranked_targets"][0]["count"] == 3

    def test_empty_findings_empty_structure(self):
        dist = build_distribution([])
        assert dist == {"by_type": {}, "by_severity": {}, "ranked_targets": []}
        # enrich_report 空 findings 不抛错
        report = _report([])
        out = enrich_report(report)
        assert out["distribution"] == {"by_type": {}, "by_severity": {}, "ranked_targets": []}

    def test_missing_severity_defaults(self):
        findings = [_finding("http://h.example.com/x", "Info", "")] + [
            {"type": "Misc", "url": "http://h.example.com/y"}
        ]
        dist = build_distribution(findings)
        assert dist["by_type"]["Info"]["unknown"] == 1
        assert dist["by_type"]["Misc"]["unknown"] == 1


class TestSuggestRemediation:
    @pytest.mark.parametrize("sev,prefix", [
        ("critical", "立即修复"),
        ("Critical", "立即修复"),
        ("high", "限期修复"),
        ("medium", "计划修复"),
        ("low", "观察项"),
    ])
    def test_level_templates(self, sev, prefix):
        out = suggest_remediation(sev)
        assert out.startswith(prefix)

    def test_existing_remediation_appended_not_overwritten(self):
        existing = "已有：参数化查询"
        out = suggest_remediation("Critical", existing)
        assert out.startswith(existing)
        assert "；立即修复" in out
        assert out != suggest_remediation("Critical", "")

    def test_unknown_severity_falls_back(self):
        out = suggest_remediation("whatever")
        assert out.startswith("计划修复")


class TestEnrichReport:
    def test_remediation_tier_added_per_finding(self):
        findings = [
            _finding("http://h.example.com/a", "SQL注入", "Critical", remediation="已有修复文本"),
            _finding("http://h.example.com/b", "XSS", "High"),
            _finding("http://h.example.com/c", "Cmd", "Medium"),
            _finding("http://h.example.com/d", "Info", "Low"),
        ]
        report = _report(findings)
        enrich_report(report)
        assert report["vulnerabilities"][0]["remediation_tier"].startswith("已有修复文本")
        assert report["vulnerabilities"][1]["remediation_tier"].startswith("限期修复")
        assert report["vulnerabilities"][2]["remediation_tier"].startswith("计划修复")
        assert report["vulnerabilities"][3]["remediation_tier"].startswith("观察项")

    def test_existing_keys_untouched(self):
        report = _report([
            _finding("http://h.example.com/a", "SQL注入", "Critical"),
        ])
        before = dict(report)
        enrich_report(report)
        assert report["scan_id"] == before["scan_id"] == "scan-abc-123"
        assert report["configuration"] == before["configuration"]
        assert report["apps"] == before["apps"]
        assert report["target"] == before["target"]

    def test_idempotent(self):
        report = _report([
            _finding("http://h.example.com/a", "SQL注入", "Critical", remediation="已有"),
        ])
        enrich_report(report)
        first = dict(report)
        enrich_report(report)
        assert report["distribution"] == first["distribution"]
        assert report["vulnerabilities"][0]["remediation_tier"] == first["vulnerabilities"][0]["remediation_tier"]

    def test_sarif_path_injects_distribution(self):
        report = _report([
            _finding("http://h.example.com/a", "SQL注入", "Critical"),
        ])
        generate_sarif(report)
        assert "distribution" in report
        assert report["vulnerabilities"][0]["remediation_tier"].startswith("立即修复")