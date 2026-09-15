"""D7.2 剧本化评测场专项测试。

覆盖：类型别名归一化（剧本自然语言名 ↔ 引擎规范类名）、召回率/精确率计算、
红线门禁语义、剧本文件加载。
"""
import os
import shutil
import sys
from pathlib import Path

import pytest

# 防止 import scripts/benchmark 时向 scripts/ 写 __pycache__（布局守卫禁再生）。
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
sys.dont_write_bytecode = True

# scripts/ 目录加入可导入路径（benchmark.py 是脚本区工具，非 src 包）
SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

# 稳妥起见：导入前清掉 scripts/__pycache__（布局守卫要求 scripts/ 无 pyc）。
# 注意：某些环境（IDE 注入的 sitecustomize safe-delete 钩子）会让 shutil.rmtree
# 在导入期抛 SystemExit 并炸掉整个 pytest 收集——清理失败必须兜底，不能致命。
_pycache = SCRIPTS_DIR / "__pycache__"
if _pycache.exists():
    try:
        shutil.rmtree(_pycache, ignore_errors=True)
    except (Exception, SystemExit):  # noqa: BLE001 — 清不掉就退化为"不再写新 pyc"
        sys.dont_write_bytecode = True

from benchmark import (
    TargetScenario,
    evaluate_report,
    load_scenarios,
    normalize_vuln_type,
)


class TestNormalize:
    def test_exact_alias(self):
        assert normalize_vuln_type("XSS") == "xss"
        assert normalize_vuln_type("SQL Injection") == "sqli"
        assert normalize_vuln_type("File Upload") == "file_upload"
        assert normalize_vuln_type("SQL注入") == "sqli"
        assert normalize_vuln_type("模板注入") == "ssti"

    def test_unknown_passthrough(self):
        assert normalize_vuln_type("log4shell") == "log4shell"
        assert normalize_vuln_type(None) == ""
        assert normalize_vuln_type("") == ""

    def test_fuzzy_substring(self):
        assert normalize_vuln_type("SQL Injection at login") == "sqli"

    def test_information_disclosure_aliases(self):
        assert normalize_vuln_type("Info Disclosure") == "info_leak"
        assert normalize_vuln_type("Information Disclosure") == "info_leak"


class TestEvaluate:
    def _scenario(self):
        return [TargetScenario(
            name="lab", target="http://127.0.0.1:8090",
            expected_vulns=["XSS", "SQL Injection", "File Upload"],
        )]

    def test_full_recall(self):
        # 归一化前："XSS" vs "xss" 集合交集恒空 → recall 0（缺口）
        # 归一化后应正确交集
        report = {"findings": [
            {"type": "xss"}, {"type": "sqli"}, {"type": "file_upload"},
        ]}
        res = evaluate_report(report, self._scenario())
        assert res["recall"] == 1.0
        assert res["precision"] == 1.0
        assert res["missed"] == []

    def test_partial_recall(self):
        report = {"findings": [{"type": "xss"}]}
        res = evaluate_report(report, self._scenario())
        assert res["recall"] == pytest.approx(1 / 3)
        assert res["precision"] == 1.0
        assert len(res["missed"]) == 2

    def test_extra_fps_lower_precision(self):
        report = {"findings": [
            {"type": "xss"}, {"type": "sqli"}, {"type": "file_upload"}, {"type": "log4shell"},
        ]}
        res = evaluate_report(report, self._scenario())
        assert res["recall"] == 1.0
        assert res["precision"] == pytest.approx(3 / 4)

    def test_empty_report(self):
        res = evaluate_report({}, self._scenario())
        assert res["recall"] == 0.0
        assert res["quality"]["finding_count"] == 0
        assert res["quality"]["evidence_rate"] is None
        assert res["quality"]["reproduction_rate"] is None

    def test_quality_metrics_are_reported_without_inventing_missing_values(self):
        report = {
            "total_engine_calls": 12,
            "elapsed_seconds": 3.5,
            "findings": [
                {"type": "xss", "evidence": "reflected marker", "exploit_verified": True},
                {"type": "sqli"},
            ],
        }
        res = evaluate_report(report, self._scenario())
        assert res["quality"] == {
            "finding_count": 2,
            "evidence_count": 1,
            "evidence_rate": 0.5,
            "reproduced_count": 1,
            "reproduction_rate": 0.5,
            "request_count": 12,
            "elapsed_seconds": 3.5,
        }

    def test_metric_formatters_mark_unavailable_values(self):
        from benchmark import (
            _format_metric,
            _format_optional_metric,
            _meets_quality_gate,
        )

        assert _format_metric(0.5) == "0.5000"
        assert _format_metric(None) == "NA"
        assert _format_optional_metric(12) == "12"
        assert _format_optional_metric(None) == "NA"
        assert _meets_quality_gate(None, 0.0)
        assert not _meets_quality_gate(None, 0.1)
        assert _meets_quality_gate(0.5, 0.5)
        assert not _meets_quality_gate(0.4, 0.5)

    def test_reproduction_now_counts_canonical_and_oob_signals(self):
        """G 组回归：reproduction_rate 为 0 的数据缺口修复——
        规范字段 `reproduced`、验证层落锤 `exploited`、OOB 回调都应计入复现。"""
        res = evaluate_report({"findings": [
            # ① 规范字段直接标记复现成功（apply_evidence_schema 产物）
            {"type": "rce", "evidence": "uid=0(root)", "reproduced": True, "verified": True},
            # ② 验证层落锤：exploited=True（SafeExploit 独立重打命中）
            {"type": "sqli", "evidence": "syntax error", "exploited": True, "verified": True},
            # ③ OOB 回调：oob_confirmed 属复现实锤（SSRF/XXE 带外通道）
            {"type": "xxe", "evidence": "dnslog callback", "oob_confirmed": True, "verified": True},
            # ④ 仅响应证据、未复现 → 不计入复现
            {"type": "xss", "evidence": "reflected marker"},
        ]}, [])
        q = res["quality"]
        assert q["finding_count"] == 4
        assert q["evidence_count"] == 4
        assert q["reproduced_count"] == 3
        assert q["reproduction_rate"] == 0.75

    def test_schema_applied_report_counts_canonical_fields(self):
        """报告路径 normalize_vulns 之后（报告 dict 已带规范字段）直接可统计。"""
        from vulnclaw.core.models import apply_evidence_schema
        findings = [apply_evidence_schema({"type": "lfi", "url": "http://t/x",
                                           "evidence": "root:x:0:0", "blind_repro": "confirmed"}),
                    apply_evidence_schema({"type": "info_leak", "url": "http://t/y",
                                           "evidence": "堆栈回显"})]
        res = evaluate_report({"vulnerabilities": [dict(f) for f in findings]}, [])
        q = res["quality"]
        assert q["reproduced_count"] == 1
        assert q["reproduction_rate"] == 0.5
        assert q["evidence_count"] == 2

    def test_fixture_thresholds_are_exposed_by_cli(self):
        from benchmark import _passes_fixture_gate

        assert _passes_fixture_gate(0.8, 0.2, 0.8, 0.2)
        assert not _passes_fixture_gate(0.7, 0.2, 0.8, 0.2)
        assert not _passes_fixture_gate(0.8, 0.21, 0.8, 0.2)


class TestScenarioLoad:
    def test_load_yaml_dir(self, tmp_path):
        import yaml
        (tmp_path / "a.yaml").write_text(
            yaml.safe_dump([{"name": "l", "target": "http://t", "expected_vulns": ["XSS"]}]),
            encoding="utf-8",
        )
        sc = load_scenarios(str(tmp_path))
        assert len(sc) == 1
        assert sc[0].name == "l"


class TestFixtureRunner:
    def test_check_fixture_supports_parameter_engines(self):
        import asyncio
        import benchmark
        from vulnclaw.engines import net_engines
        from vulnclaw.engines.net_engines import SSRFEngine

        case = {
            "method": "check",
            "url": "http://127.0.0.1:8080/fetch",
            "param": "url",
            "parsed_query": "url=https%3A%2F%2Fexample.com",
            "normal_resp": [200, "ok", {}],
            "responses": {
                "127.0.0.1": {"status": 200, "body": "internal_secret=fixture"}
            },
        }
        loop = asyncio.new_event_loop()
        original_async_get = net_engines.async_get
        try:
            findings = benchmark._run_case(case, SSRFEngine(), loop)
        finally:
            loop.close()
        assert findings
        assert net_engines.async_get is original_async_get

    def test_check_fixture_restores_post_transport(self):
        import asyncio
        import benchmark
        from vulnclaw.engines import api_security_engines
        from vulnclaw.engines.api_security_engines import APISecurityEngine

        case = {
            "method": "check",
            "url": "http://127.0.0.1:8080/graphql",
            "param": "query",
            "normal_resp": [200, "", {}],
            "responses": {
                "/graphql": {
                    "status": 200,
                    "body": '{"data":{"__typename":"Query"}}',
                }
            },
        }
        original_async_post = api_security_engines.async_post
        loop = asyncio.new_event_loop()
        try:
            findings = benchmark._run_case(case, APISecurityEngine(), loop)
        finally:
            loop.close()
        assert findings
        assert api_security_engines.async_post is original_async_post

    def test_deserialization_fixture_uses_passive_response_detection(self):
        import asyncio
        import benchmark
        from vulnclaw.engines.deserialization import DeserializationEngine

        case = {
            "module": "vulnclaw.engines.deserialization",
            "target": "http://127.0.0.1:8080/deser",
            "responses": {
                "/deser": {
                    "status": 500,
                    "body": "java.lang.Runtime serialization handler",
                }
            },
        }
        loop = asyncio.new_event_loop()
        try:
            findings = benchmark._run_case(case, DeserializationEngine(), loop)
        finally:
            loop.close()
        assert findings
        assert findings[0]["method"] == "deserialization"


class TestSarifInput:
    def _sarif(self):
        return {"runs": [{"results": [
            {"ruleId": "xss", "level": "error",
             "properties": {"parameter": "s", "evidence": "xss in response", "severity": "high"}},
            {"ruleId": "sqli", "level": "warning", "properties": {}},
        ]}]}

    def test_sarif_findings_extracted(self):
        from benchmark import _report_findings
        finds = _report_findings(self._sarif())
        assert len(finds) == 2
        assert finds[0]["type"] == "xss"
        assert finds[0]["parameter"] == "s"
        assert finds[1]["type"] == "sqli"

    def test_sarif_eval_recall(self):
        from benchmark import TargetScenario as TS
        from benchmark import evaluate_report
        sc = [TS(name="lab", target="http://t", expected_vulns=["XSS", "SQL Injection"])]
        res = evaluate_report(self._sarif(), sc)
        assert res["recall"] == 1.0

    def test_sarif_properties_missing_ok(self):
        # properties 缺失时仍能提取 ruleId，不抛错
        from benchmark import _report_findings
        d = {"runs": [{"results": [{"ruleId": "lfi"}]}]}
        assert _report_findings(d)[0]["type"] == "lfi"


class TestPlatformReportInput:
    """scan_runner 真实 JSON 产物形态：vulnerabilities 主字段 + *_findings 分桶兜底。"""

    def _platform_report(self):
        return {"target": "http://127.0.0.1:8090", "vulnerabilities": [
            {"type": "XSS-反射型(基础script标签(混淆))", "url": "http://t/xss", "parameter": "q"},
            {"type": "文件上传-可访问/可执行(PHP文件)", "url": "http://t/upload", "parameter": "file"},
        ]}

    def test_vulnerabilities_extracted(self):
        from benchmark import _report_findings
        finds = _report_findings(self._platform_report())
        assert len(finds) == 2
        assert finds[0]["type"].startswith("XSS")

    def test_vulnerabilities_eval_recall(self):
        from benchmark import TargetScenario as TS
        from benchmark import evaluate_report
        # XSS/文件上传经模糊归一命中；SQLi 未检出 → recall 2/3
        sc = [TS(name="lab", target="http://t", expected_vulns=["XSS", "SQL Injection", "File Upload"])]
        res = evaluate_report(self._platform_report(), sc)
        assert res["recall"] == pytest.approx(2 / 3)
        assert res["missed"] == ["sqli"]

    def test_platform_bucket_fallbacks(self):
        # 无 vulnerabilities 字段但存在 *_findings 分桶时也归一
        from benchmark import _report_findings
        d = {"target": "http://t", "direct_findings": [{"type": "CRLF注入-响应拆分(基础CRLF)"}],
             "nuclei_findings": [{"type": "sqli"}]}
        finds = _report_findings(d)
        assert len(finds) == 2

    def test_platform_bucket_plus_vulns_prefer_vulns(self):
        # vulnerabilities 存在时优先用它，不混入分桶
        from benchmark import _report_findings
        d = {"vulnerabilities": [{"type": "xss"}], "nuclei_findings": [{"type": "sqli"}]}
        finds = _report_findings(d)
        assert len(finds) == 1
        assert finds[0]["type"] == "xss"

# ---------------- 收尾：清理本模块可能引入的 scripts/__pycache__ ----------------
def _purge_scripts_pycache():
    p = SCRIPTS_DIR / "__pycache__"
    if p.exists():
        try:
            shutil.rmtree(p, ignore_errors=True)
        except (Exception, SystemExit):  # IDE safe-delete 钩子会抛 SystemExit，兜底
            pass


_purge_scripts_pycache()
