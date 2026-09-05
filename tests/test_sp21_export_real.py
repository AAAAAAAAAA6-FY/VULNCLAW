# SPDX-License-Identifier: AGPL-3.0-or-later
"""SP21 验证批次 A 线：PDF / CSV 报告的"真实后端"验证。

- PDF：reportlab 可用时断言产物是真实 PDF（%PDF magic + 非空）；不可用则整用例 skip。
- CSV：始终运行，断言 UTF-8 BOM 开头、可被 csv.reader 读回且表头正确。
纯同步用例，风格同 tests/test_sp17_export.py。
"""
import csv
import importlib

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
        "scan_id": "scan-sp21",
        "configuration": {"scope": "demo"},
        "apps": {"web": True},
        "target": "http://t.example.com",
        "vulnerabilities": findings,
    }
    enrich_report(report)
    return report


def _reportlab_usable() -> bool:
    """探测与运行时一致：能真实 import 才能用于 PDF 后端。"""
    try:
        importlib.import_module("reportlab")
    except Exception:  # noqa: BLE001
        return False
    return True


class TestExportPdfReal:
    @pytest.mark.skipif(not _reportlab_usable(), reason="reportlab 未安装")
    def test_real_pdf_magic_and_nonempty(self, tmp_path):
        """reportlab 后端真实输出：%PDF magic 开头、非空、返回绝对路径。"""
        report = _report()
        out = tmp_path / "real.pdf"
        result = export_pdf(report, str(out))
        assert result is not None
        assert result == str(out.resolve())
        assert out.exists()
        assert out.stat().st_size > 0
        with open(str(out), "rb") as fh:
            head = fh.read(5)
        assert head == b"%PDF-"


class TestExportCsvReal:
    def test_real_utf8_bom_header(self, tmp_path):
        """真实输出：开头为 UTF-8 BOM，表头正确，可被 csv.reader 读回。"""
        report = _report()
        out = tmp_path / "real.csv"
        result = export_csv(report, str(out))
        assert result == str(out.resolve())
        assert out.exists()
        with open(str(out), "rb") as fh:
            bom = fh.read(3)
        assert bom == b"\xef\xbb\xbf"
        with open(str(out), encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.reader(fh))
        assert rows[0] == ["type", "severity", "url", "parameter", "method",
                           "source", "remediation_tier", "remediation"]
        assert len(rows) == 1 + len(report["vulnerabilities"])
        row0 = dict(zip(rows[0], rows[1]))
        assert row0["type"] == "SQL注入"
        assert row0["severity"] == "Critical"