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

# 稳妥起见：导入前清掉 scripts/__pycache__（布局守卫要求 scripts/ 无 pyc）
_pycache = SCRIPTS_DIR / "__pycache__"
if _pycache.exists():
    shutil.rmtree(_pycache, ignore_errors=True)

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
        shutil.rmtree(p, ignore_errors=True)


_purge_scripts_pycache()
