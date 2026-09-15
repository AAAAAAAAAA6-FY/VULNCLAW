# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""E1 验收：工具互导（core/interop.py）——导入/导出/字段映射/round-trip。

全部离线确定性：样本字符串内嵌，不读外部文件、不联网。
"""
import json

import pytest

from vulnclaw import cli
from vulnclaw.core.interop import (
    FIELD_MAPPING,
    LOSSY_EXCLUDED_FIELDS,
    UNIFIED_FIELDS,
    UnifiedFinding,
    export_any,
    export_burp_xml,
    export_csv,
    export_jsonl,
    export_nuclei_jsonl,
    export_sarif,
    export_vulnclaw_json,
    import_any,
    import_burp_xml,
    import_csv,
    import_jsonl,
    import_nuclei_jsonl,
    import_raw_http,
    import_sarif,
    import_vulnclaw_json,
    import_zap_json,
    normalize_confidence,
    normalize_severity,
    supported_formats,
)

# ============================================================
# 内嵌最小样本
# ============================================================
NUCLEI_SAMPLE = json.dumps({
    "template-id": "CVE-2021-44228",
    "info": {"name": "Log4Shell", "severity": "critical",
             "description": "JNDI injection"},
    "type": "http",
    "host": "t.example",
    "matched-at": "http://t.example/api",
    "matcher-name": "word",
    "extracted-results": ["callback-ok"],
})

BURP_SAMPLE = (
    "<issues><issue>"
    "<type>1049088</type><name>SQL injection</name>"
    "<host>http://t.example</host><path>/a</path><location>/a?id=1</location>"
    "<severity>High</severity><confidence>Certain</confidence>"
    "<issueDetail>SQL syntax error near id</issueDetail>"
    "<requestresponse>"
    "<request base64=\"false\">GET /a?id=1 HTTP/1.1\r\nHost: t.example\r\n\r\n</request>"
    "<response base64=\"false\">HTTP/1.1 200 OK\r\n\r\nSQL syntax error</response>"
    "</requestresponse></issue></issues>"
)

ZAP_SAMPLE = json.dumps({
    "site": [{
        "@name": "http://t.example",
        "alerts": [{
            "alertRef": "40018",
            "alert": "SQL Injection",
            "riskcode": "3",
            "riskdesc": "High (High)",
            "desc": "SQL injection may be possible.",
            "instances": [{
                "uri": "http://t.example/a?id=1",
                "method": "GET",
                "param": "id",
                "evidence": "SQL syntax error",
            }],
        }],
    }]
})

SARIF_SAMPLE = json.dumps({
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{
        "tool": {"driver": {"name": "vulnclaw", "rules": [
            {"id": "VULNCLAW-0001", "name": "SQLi",
             "shortDescription": {"text": "SQL injection"}}
        ]}},
        "results": [{
            "ruleId": "VULNCLAW-0001",
            "level": "error",
            "message": {"text": "SQL syntax error near id"},
            "properties": {"type": "SQL注入", "method": "GET", "parameter": "id"},
            "locations": [{"physicalLocation": {"artifactLocation": {
                "uri": "http://t.example/a?id=1"}}}],
        }],
    }],
})

RAW_HTTP_SAMPLE = (
    "GET /a?id=1 HTTP/1.1\r\n"
    "Host: t.example\r\n"
    "Cookie: sid=abc\r\n"
    "\r\n"
)


def _finding(**kw):
    base = dict(source="vulnclaw", scanner="vulnclaw", rule_id="r1",
                title="SQL注入", severity="high", confidence="medium",
                url="http://t.example/a?id=1", method="GET", parameter="id",
                evidence="SQL syntax error near id")
    base.update(kw)
    return UnifiedFinding(**base)


# ============================================================
# 1. 归一化
# ============================================================
class TestNormalize:
    @pytest.mark.parametrize("raw,expected", [
        ("critical", "critical"), ("High", "high"), ("HIGH", "high"),
        ("error", "high"),          # SARIF level
        ("3", "high"),              # ZAP riskcode
        ("2", "medium"), ("warning", "medium"),
        ("1", "low"), ("note", "low"),
        ("0", "info"), ("Information", "info"),
        ("", ""), (None, ""),
        ("totally-unknown", ""),    # 不可识别 → ""（不得伪装成 info）
    ])
    def test_severity_mapping(self, raw, expected):
        assert normalize_severity(raw) == expected

    @pytest.mark.parametrize("raw,expected", [
        ("Certain", "high"), ("Firm", "medium"), ("Tentative", "low"),
        ("medium", "medium"), ("", ""), ("bogus", ""),
    ])
    def test_confidence_mapping(self, raw, expected):
        assert normalize_confidence(raw) == expected


# ============================================================
# 2. 映射表完整性（锁死，防字段漏映射）
# ============================================================
class TestFieldMapping:
    def test_every_format_covers_every_unified_field(self):
        assert FIELD_MAPPING, "映射表不得为空"
        for fmt, mapping in FIELD_MAPPING.items():
            assert set(mapping) == set(UNIFIED_FIELDS), f"{fmt} 字段映射不完整"

    def test_expected_formats_present(self):
        for fmt in ("vulnclaw_json", "jsonl", "nuclei_jsonl", "burp_xml",
                    "zap_json", "sarif", "csv", "raw_http"):
            assert fmt in FIELD_MAPPING, f"缺格式映射: {fmt}"

    def test_raw_is_lossy_excluded(self):
        assert LOSSY_EXCLUDED_FIELDS == ("raw",)


# ============================================================
# 3. 导入器
# ============================================================
class TestImporters:
    def test_nuclei_jsonl(self):
        res = import_nuclei_jsonl(NUCLEI_SAMPLE)
        assert len(res) == 1 and res.skipped == 0
        f = res[0]
        assert f.rule_id == "CVE-2021-44228"
        assert f.severity == "critical"
        assert f.url == "http://t.example/api"
        assert "Log4Shell" in f.title
        assert "callback-ok" in f.evidence
        assert f.method == "GET"  # 无 method 字段 → 回退 GET

    def test_nuclei_bad_line_skipped(self):
        res = import_nuclei_jsonl("not-json-at-all")
        assert res == [] and res.skipped >= 1 and res.errors

    def test_burp_xml(self):
        res = import_burp_xml(BURP_SAMPLE)
        assert len(res) == 1, f"Burp 样本应解析出 1 条: {res.errors}"
        f = res[0]
        assert f.severity == "high"
        assert f.confidence == "high"          # Certain → high
        assert "t.example/a" in f.url
        assert "GET /a" in f.request
        assert "SQL syntax" in f.evidence

    def test_burp_bad_xml_skipped(self):
        res = import_burp_xml("<not-xml")
        assert res == [] and res.skipped >= 1

    def test_zap_json(self):
        res = import_zap_json(ZAP_SAMPLE)
        assert len(res) == 1
        f = res[0]
        assert f.severity == "high"            # riskcode 3
        assert f.url == "http://t.example/a?id=1"
        assert f.parameter == "id"
        assert "SQL syntax" in f.evidence
        assert f.source == "zap"

    def test_sarif(self):
        res = import_sarif(SARIF_SAMPLE)
        assert len(res) == 1
        f = res[0]
        assert f.severity == "high"            # level=error
        assert f.rule_id == "VULNCLAW-0001"
        assert f.url == "http://t.example/a?id=1"
        assert "SQL syntax" in f.evidence
        assert f.parameter == "id"

    def test_raw_http(self):
        res = import_raw_http(RAW_HTTP_SAMPLE)
        assert len(res) == 1
        f = res[0]
        assert f.method == "GET"
        assert f.url == "http://t.example/a?id=1"
        assert f.parameter == "id"
        assert "Cookie: sid=abc" in f.request

    def test_non_string_input_fails_closed(self):
        for importer in (import_nuclei_jsonl, import_burp_xml, import_zap_json,
                         import_sarif, import_csv, import_raw_http):
            res = importer(None)
            assert res == [], f"{importer.__name__} 非字符串输入必须返回空（不抛异常）"
            assert isinstance(res.skipped, int), "跳过计数必须可读"


# ============================================================
# 4. 导出 → 导入 round-trip（扩展位保真）
# ============================================================
class TestRoundTrip:
    def _roundtrip(self, export_fn, import_fn, **overrides):
        original = [_finding(**overrides)]
        text = export_fn(original)
        assert isinstance(text, str) and text.strip()
        back = import_fn(text)
        assert len(back) == 1, f"round-trip 丢条目: {getattr(back, 'errors', None)}"
        return back[0]

    def test_jsonl_roundtrip(self):
        f = self._roundtrip(export_jsonl, import_jsonl, verification="burp_verified")
        assert f.title == "SQL注入" and f.severity == "high"
        assert f.evidence == "SQL syntax error near id"
        assert f.verification == "burp_verified", "扩展字段必须无损往返"
        assert f.resolve_id() == _finding(verification="burp_verified").resolve_id()

    def test_vulnclaw_json_roundtrip(self):
        f = self._roundtrip(export_vulnclaw_json, import_vulnclaw_json,
                            reproduction="curl 'http://t.example/a?id=1''")
        assert f.reproduction == "curl 'http://t.example/a?id=1''"
        assert f.url == "http://t.example/a?id=1"

    def test_sarif_roundtrip(self):
        f = self._roundtrip(export_sarif, import_sarif, oob="dns callback ok")
        assert f.severity == "high"
        assert f.oob == "dns callback ok", "SARIF 扩展位必须承载 oob 往返"

    def test_csv_roundtrip(self):
        f = self._roundtrip(export_csv, import_csv)
        assert f.title == "SQL注入" and f.severity == "high"
        assert f.url == "http://t.example/a?id=1"

    def test_nuclei_roundtrip(self):
        f = self._roundtrip(export_nuclei_jsonl, import_nuclei_jsonl,
                            method="POST", parameter="id")
        assert f.severity == "high"
        assert f.method == "POST", "Nuclei 顶层扩展位必须保 method"
        assert f.parameter == "id"

    def test_burp_roundtrip(self):
        f = self._roundtrip(export_burp_xml, import_burp_xml)
        assert f.severity == "high"
        assert "t.example" in f.url

    def test_multi_findings_roundtrip(self):
        findings = [
            _finding(title="SQL注入", url="http://t.example/a?id=1"),
            _finding(title="XSS", url="http://t.example/b?q=<x>", parameter="q"),
        ]
        back = import_jsonl(export_jsonl(findings))
        assert len(back) == 2
        assert {f.title for f in back} == {"SQL注入", "XSS"}


# ============================================================
# 5. 统一分派与工具函数
# ============================================================
class TestAnyAndHelpers:
    def test_supported_formats_non_empty(self):
        fmts = supported_formats()
        assert fmts and "jsonl" in fmts and "sarif" in fmts

    def test_import_any_and_export_any(self):
        findings = [_finding()]
        text = export_any(findings, "jsonl")
        back = import_any(text, "jsonl")
        assert len(back) == 1 and back[0].title == "SQL注入"

    def test_unknown_format_raises(self):
        with pytest.raises(Exception):
            import_any("{}}", "definitely-not-a-format")

    def test_to_native_alignment(self):
        native = _finding().to_native()
        for key in ("type", "severity", "url", "method", "parameter",
                    "evidence", "confidence", "source"):
            assert key in native, f"报告口径缺字段: {key}"
        assert native["type"] == "SQL注入"
        assert native["finding_id"].startswith("f1-")


# ============================================================
# 6. CLI 接线（workflow7：vulnclaw interop formats/import/export）
# ============================================================
class TestCliInterop:
    def _run(self, argv, stdin_text=None, monkeypatch=None):
        import io
        import sys
        if stdin_text is not None:
            monkeypatch.setattr(sys, "stdin", io.StringIO(stdin_text))
        with pytest.raises(SystemExit) as ei:
            cli.main(argv)
        return ei.value.code

    def test_formats_matrix(self, capsys):
        code = self._run(["interop", "formats"])
        assert code == 0
        out = capsys.readouterr().out
        assert "jsonl" in out and "sarif" in out
        assert "import, export" in out

    def test_import_file_to_jsonl(self, capsys, tmp_path):
        p = tmp_path / "n.jsonl"
        p.write_text(NUCLEI_SAMPLE, encoding="utf-8")
        code = self._run(["interop", "import", "nuclei_jsonl", str(p)])
        assert code == 0
        out = capsys.readouterr().out
        lines = [l for l in out.splitlines() if l.strip()]
        assert lines, "导入成功后 stdout 应按统一 JSONL 输出"
        assert json.loads(lines[0]).get("rule_id") == "CVE-2021-44228"

    def test_import_export_chain(self, capsys, tmp_path):
        p = tmp_path / "n.jsonl"
        p.write_text(NUCLEI_SAMPLE, encoding="utf-8")
        code = self._run(["interop", "import", "nuclei_jsonl", str(p), "--export", "sarif"])
        assert code == 0
        out = capsys.readouterr().out
        assert json.loads(out).get("version") == "2.1.0"

    def test_import_stdin(self, capsys, monkeypatch):
        body = json.dumps({"type": "SQL注入", "severity": "high",
                           "url": "http://t.example/a?id=1"})
        code = self._run(["interop", "import", "vulnclaw_json", "-"],
                         stdin_text=body, monkeypatch=monkeypatch)
        assert code == 0
        out = capsys.readouterr().out
        assert "SQL注入" in out

    def test_export_stdin(self, capsys, monkeypatch):
        code = self._run(["interop", "export", "csv", "-"],
                         stdin_text=export_jsonl([_finding()]), monkeypatch=monkeypatch)
        assert code == 0
        out = capsys.readouterr().out
        assert out.startswith("source,scanner,rule_id")

    def test_missing_file_exit_2(self, capsys, tmp_path):
        code = self._run(["interop", "import", "jsonl", str(tmp_path / "nope.jsonl")])
        assert code == 2
        assert "不存在" in capsys.readouterr().err

    def test_unknown_format_exit_2(self, capsys, tmp_path):
        p = tmp_path / "x.jsonl"
        p.write_text("{}", encoding="utf-8")
        code = self._run(["interop", "import", "bogus-fmt", str(p)])
        assert code == 2
        assert "不支持的导入格式" in capsys.readouterr().err
