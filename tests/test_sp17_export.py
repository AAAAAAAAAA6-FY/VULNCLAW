# SPDX-License-Identifier: AGPL-3.0-or-later
"""SP17.4.3 报告导出：CSV / PDF 双格式（A 线）。

- export_csv：把 findings 明细导出 CSV（UTF-8 BOM，Excel 友好），可被 csv.reader 读回
- export_pdf：优先 weasyprint / reportlab（可选依赖）；未装时优雅降级返回 None 不抛错
"""
import csv
import importlib.util
import io

import pytest

from vulnclaw.core.report_generator import (
    enrich_report,
    export_csv,
    export_pdf,
)


def _finding(url, type_, severity, extra=None):
    f = {"url": url, "type": type_, "severity": severity}
    if extra:
        f.update(extra)
    return f


def _report(findings=None):
    findings = findings if findings is not None else [
        _finding("http://a.example.com/p?q=1", "SQL注入", "Critical",
                 {"parameter": "q", "method": "GET",
                  "remediation": "参数化查询", "source": "param_mining"}),
        _finding("http://b.example.com/x", "XSS", "High",
                 {"method": "POST", "source": "live:render"}),
    ]
    report = {
        "scan_id": "scan-sp17",
        "configuration": {"scope": "demo"},
        "apps": {"web": True},
        "target": "http://t.example.com",
        "vulnerabilities": findings,
    }
    enrich_report(report)
    return report


def _pdf_backend_usable() -> bool:
    """探测与运行时一致：只有能真实导入才认为后端可用（避免 find_spec 假阳性）。"""
    import importlib
    for _m in ("weasyprint", "reportlab"):
        try:
            importlib.import_module(_m)
            return True
        except Exception:  # noqa: BLE001 - import 失败（如系统库缺失）视为不可用
            continue
    return False


class TestExportCsv:
    def test_rows_and_fields(self, tmp_path):
        report = _report()
        out = tmp_path / "report.csv"
        result = export_csv(report, str(out))
        assert result == str(out.resolve())
        assert out.exists()
        assert out.stat().st_size > 0
        with io.open(str(out), encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.reader(fh))
        assert rows[0] == ["type", "severity", "url", "parameter", "method",
                           "source", "remediation_tier", "remediation"]
        assert len(rows) == 1 + len(report["vulnerabilities"])
        row0 = dict(zip(rows[0], rows[1]))
        assert row0["type"] == "SQL注入"
        assert row0["severity"] == "Critical"
        assert row0["url"] == "http://a.example.com/p?q=1"
        assert row0["parameter"] == "q"
        assert row0["method"] == "GET"
        assert row0["source"] == "param_mining"
        assert row0["remediation_tier"].startswith("参数化查询")
        assert "立即修复" in row0["remediation_tier"]
        assert row0["remediation"] == "参数化查询"

    def test_missing_fields_empty(self, tmp_path):
        report = _report([
            _finding("http://c.example.com/z", "LFI", "Low"),
        ])
        out = tmp_path / "r.csv"
        export_csv(report, str(out))
        with io.open(str(out), encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.reader(fh))
        row0 = dict(zip(rows[0], rows[1]))
        assert row0["parameter"] == ""
        assert row0["method"] == ""
        assert row0["source"] == ""
        assert row0["remediation_tier"]  # enrich_report 总会注入

    def test_empty_findings_only_header(self, tmp_path):
        report = _report([])
        out = tmp_path / "e.csv"
        export_csv(report, str(out))
        with io.open(str(out), encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.reader(fh))
        assert len(rows) == 1  # 只有表头
        assert rows[0][0] == "type"


class TestExportPdf:
    def test_graceful_degrade_when_unavailable(self, tmp_path):
        """未装可选 PDF 后端时返回 None 不抛错（始终运行，不硬卡 CI）。"""
        report = _report()
        out = tmp_path / "r.pdf"
        result = export_pdf(report, str(out))
        avail = _pdf_backend_usable()
        if not avail:
            assert result is None
            assert not out.exists()
        else:
            assert result is not None
            assert out.exists() and out.stat().st_size > 0

    def test_empty_findings_pdf_does_not_crash(self, tmp_path):
        """空 findings 时 PDF 不崩（无论后端可用与否都必须无异常返回）。"""
        report = _report([])
        out = tmp_path / "e.pdf"
        result = export_pdf(report, str(out))
        avail = _pdf_backend_usable()
        if avail:
            assert result is not None
            assert out.exists() and out.stat().st_size > 0
        else:
            assert result is None
            assert not out.exists()

    def test_pdf_written_when_backend_available(self, tmp_path):
        """装了可选 PDF 后端时输出文件存在且非空；未装则整用例跳过。"""
        if not _pdf_backend_usable():
            pytest.skip("no usable PDF backend (weasyprint/reportlab missing or system lib absent)")
        report = _report()
        out = tmp_path / "r.pdf"
        result = export_pdf(report, str(out))
        assert result is not None
        assert str(out.resolve())
        assert out.exists() and out.stat().st_size > 0