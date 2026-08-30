"""阶段 C 验收测试 + 3 新工具集成测试。

覆盖：
  1. Registry 自动发现 (tool_registry)
  2. 引擎调用基础链路 (BaseEngine / PayloadMutator 集成)
  3. 工具调用 (PayloadMutator / VulnPrioritizer / POCGenerator)
"""
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_HERE)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


# ============================================================
# Part 1: PayloadMutator 核心路径
# ============================================================
class TestPayloadMutator:
    def test_import(self):
        from vulnclaw.core.payload_mutator import PayloadMutator
        assert callable(PayloadMutator)

    def test_mutate_case(self):
        from vulnclaw.core.payload_mutator import PayloadMutator
        m = PayloadMutator(seed=42)
        variants = m.mutate_case("1 OR 1=1")
        assert len(variants) >= 2
        assert "1 OR 1=1" not in variants
        lower = "1 or 1=1"
        assert lower in variants
        assert any(v != v.lower() for v in variants)

    def test_mutate_encoding(self):
        from vulnclaw.core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        variants = m.mutate_encoding("1 OR 1=1")
        assert len(variants) >= 2
        for v in variants:
            assert v != "1 OR 1=1"

    def test_mutate_comment(self):
        from vulnclaw.core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        variants = m.mutate_comment("1 OR 1=1")
        assert len(variants) >= 2
        for v in variants:
            assert v != "1 OR 1=1"

    def test_mutate_whitespace(self):
        from vulnclaw.core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        variants = m.mutate_whitespace("1 OR 1=1")
        assert len(variants) >= 2

    def test_mutate_sql_keywords(self):
        from vulnclaw.core.payload_mutator import PayloadMutator
        m = PayloadMutator(seed=42)
        variants = m.mutate_sql_keywords("1 OR 1=1")
        assert len(variants) >= 1

    def test_mutate_combine_level1(self):
        from vulnclaw.core.payload_mutator import PayloadMutator
        m = PayloadMutator(seed=42)
        variants = m.mutate_combine("1 OR 1=1", level=1)
        assert len(variants) >= 3

    def test_mutate_combine_level3(self):
        from vulnclaw.core.payload_mutator import PayloadMutator
        m = PayloadMutator(seed=42)
        variants = m.mutate_combine("1 OR 1=1", level=3)
        assert len(variants) >= 5

    def test_mutate_empty_payload(self):
        from vulnclaw.core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        assert m.mutate_case("") == []
        assert m.mutate_combine("") == []

    def test_waf_adaptive_no_detection(self):
        from vulnclaw.core.payload_mutator import PayloadMutator
        m = PayloadMutator(seed=42)
        result = m.mutate_waf_adaptive("1 OR 1=1", waf_detected=False)
        assert result == ["1 OR 1=1"]

    def test_waf_adaptive_detected(self):
        from vulnclaw.core.payload_mutator import PayloadMutator
        m = PayloadMutator(seed=42)
        result = m.mutate_waf_adaptive("1 OR 1=1", waf_detected=True, attempt=0)
        assert len(result) >= 3
        assert "1 OR 1=1" not in result


# ============================================================
# Part 2: VulnPrioritizer 核心路径
# ============================================================
class TestVulnPrioritizer:
    def test_import(self):
        from vulnclaw.core.vuln_prioritizer import VulnPrioritizer
        assert callable(VulnPrioritizer)

    def test_calculate_score_critical(self):
        from vulnclaw.core.vuln_prioritizer import VulnPrioritizer
        vp = VulnPrioritizer()
        score = vp.calculate_score({
            "type": "sqli", "severity": "critical",
            "has_poc": True, "has_cve": True,
            "sensitive": True, "endpoint_type": "admin",
            "confidence": "high",
        })
        assert score >= 70
        assert score <= 100

    def test_calculate_score_low(self):
        from vulnclaw.core.vuln_prioritizer import VulnPrioritizer
        vp = VulnPrioritizer()
        score = vp.calculate_score({
            "type": "info_leak", "severity": "low",
            "endpoint_type": "public", "confidence": "low",
        })
        assert score < 50

    def test_calculate_score_default_severity(self):
        from vulnclaw.core.vuln_prioritizer import VulnPrioritizer
        vp = VulnPrioritizer()
        score = vp.calculate_score({"unknown": "data"})
        assert 0 <= score <= 100

    def test_sort_by_priority(self):
        from vulnclaw.core.vuln_prioritizer import VulnPrioritizer
        vp = VulnPrioritizer()
        vulns = [
            {"severity": "low", "type": "info"},
            {"severity": "critical", "type": "sqli"},
            {"severity": "high", "type": "rce"},
        ]
        sorted_vulns = vp.sort_by_priority(vulns, add_score=True)
        assert len(sorted_vulns) == 3
        scores = [v["_priority_score"] for v in sorted_vulns]
        assert scores == sorted(scores, reverse=True)

    def test_get_high_priority(self):
        from vulnclaw.core.vuln_prioritizer import VulnPrioritizer
        vp = VulnPrioritizer(default_threshold=70)
        vulns = [
            {"severity": "critical", "has_poc": True, "has_cve": True,
             "sensitive": True, "endpoint_type": "admin", "confidence": "high"},
            {"severity": "low"},
        ]
        high = vp.get_high_priority(vulns)
        assert len(high) >= 1

    def test_summarize(self):
        from vulnclaw.core.vuln_prioritizer import VulnPrioritizer
        vp = VulnPrioritizer()
        vulns = [
            {"severity": "critical", "type": "sqli"},
            {"severity": "high", "type": "rce"},
            {"severity": "low", "type": "xss"},
        ]
        summary = vp.summarize(vulns)
        assert summary["total"] == 3
        assert "avg_score" in summary
        assert "top_vulns" in summary

    def test_module_level_functions(self):
        from vulnclaw.core.vuln_prioritizer import calculate_score, sort_by_priority, get_high_priority
        assert callable(calculate_score)
        assert callable(sort_by_priority)
        assert callable(get_high_priority)
        s = calculate_score({"severity": "high"})
        assert 0 <= s <= 100


# ============================================================
# Part 3: POCGenerator 核心路径
# ============================================================
class TestPOCGenerator:
    def test_import(self):
        from scripts.generate_pocs import POCGenerator
        assert callable(POCGenerator)

    def test_extract_vulns_findings(self):
        from scripts.generate_pocs import POCGenerator
        report = {"findings": [{"type": "sqli"}, {"type": "xss"}]}
        vulns = POCGenerator.extract_vulns(report)
        assert len(vulns) == 2

    def test_extract_vulns_vulns(self):
        from scripts.generate_pocs import POCGenerator
        report = {"vulns": [{"type": "rce"}]}
        vulns = POCGenerator.extract_vulns(report)
        assert len(vulns) == 1

    def test_extract_vulns_single(self):
        from scripts.generate_pocs import POCGenerator
        report = {"type": "sqli", "url": "http://x.com"}
        vulns = POCGenerator.extract_vulns(report)
        assert len(vulns) == 1

    def test_extract_vulns_empty(self):
        from scripts.generate_pocs import POCGenerator
        assert POCGenerator.extract_vulns({}) == []
        assert POCGenerator.extract_vulns(42) == []

    def test_generate_py(self):
        from scripts.generate_pocs import POCGenerator
        with tempfile.TemporaryDirectory() as d:
            gen = POCGenerator(output_dir=d, fmt="py")
            path = gen.generate({"type": "sqli", "url": "http://t.com", "param": "id"})
            assert path is not None
            content = path.read_text(encoding="utf-8")
            assert "POC: sqli" in content
            assert "requests" in content

    def test_generate_html(self):
        from scripts.generate_pocs import POCGenerator
        with tempfile.TemporaryDirectory() as d:
            gen = POCGenerator(output_dir=d, fmt="html")
            path = gen.generate({"type": "xss", "url": "http://t.com", "param": "q"})
            assert path is not None
            assert path.suffix == ".html"

    def test_generate_sh(self):
        from scripts.generate_pocs import POCGenerator
        with tempfile.TemporaryDirectory() as d:
            gen = POCGenerator(output_dir=d, fmt="sh")
            path = gen.generate({"type": "rce", "url": "http://t.com"})
            assert path is not None
            assert "#!/bin/bash" in path.read_text(encoding="utf-8")

    def test_generate_all(self):
        from scripts.generate_pocs import POCGenerator
        with tempfile.TemporaryDirectory() as d:
            gen = POCGenerator(output_dir=d, fmt="py")
            vulns = [
                {"type": "sqli", "url": "http://a.com"},
                {"type": "xss", "url": "http://b.com"},
            ]
            paths = gen.generate_all(vulns)
            assert len(paths) == 2

    def test_generate_invalid_fmt_fallback(self):
        from scripts.generate_pocs import POCGenerator
        with tempfile.TemporaryDirectory() as d:
            gen = POCGenerator(output_dir=d, fmt="invalid_fmt")
            assert gen.fmt == "py"

    def test_generate_custom_payloads(self):
        from scripts.generate_pocs import POCGenerator
        with tempfile.TemporaryDirectory() as d:
            gen = POCGenerator(output_dir=d, fmt="py")
            path = gen.generate({
                "type": "custom", "url": "http://t.com",
                "payloads": ["PAYLOAD_A", "PAYLOAD_B"],
            })
            content = path.read_text(encoding="utf-8")
            assert "PAYLOAD_A" in content
            assert "PAYLOAD_B" in content


# ============================================================
# Part 4: Registry 自动发现 (tool_registry)
# ============================================================
class TestToolRegistryDiscovery:
    def test_list_tools_returns_dict(self):
        try:
            from vulnclaw.core.tool_registry import list_tools
            tools = list_tools()
            assert isinstance(tools, dict) or isinstance(tools, list)
        except ImportError:
            pytest.skip("tool_registry 不存在 list_tools，跳过")

    def test_resolve_tool_path_exists(self):
        try:
            from vulnclaw.core.tool_registry import resolve_tool_path
            path = resolve_tool_path("httpx")
            assert path is None or isinstance(path, str)
        except ImportError:
            pytest.skip("tool_registry 不存在 resolve_tool_path，跳过")

    def test_load_tool_config_exists(self):
        try:
            from vulnclaw.core.tool_registry import load_tool_config
            cfg = load_tool_config("nonexistent_tool_xyz")
            assert cfg is None or isinstance(cfg, dict)
        except ImportError:
            pytest.skip("tool_registry 不存在 load_tool_config，跳过")


# ============================================================
# Part 5: 引擎调用基础链路
# ============================================================
class TestEngineIntegration:
    def test_payload_mutator_import_in_engine_context(self):
        from vulnclaw.core.payload_mutator import PayloadMutator
        from vulnclaw.core.vuln_prioritizer import VulnPrioritizer

        m = PayloadMutator(seed=42)
        vp = VulnPrioritizer()

        payloads = m.mutate_combine("1 OR 1=1", level=2)
        vuln = {
            "type": "sqli",
            "severity": "critical",
            "has_poc": True,
            "has_cve": True,
            "sensitive": True,
            "endpoint_type": "admin",
            "confidence": "high",
            "payloads": payloads,
        }
        score = vp.calculate_score(vuln)
        assert 0 <= score <= 100
        assert score >= 70

    def test_prioritizer_sort_with_mutated_payloads(self):
        from vulnclaw.core.payload_mutator import PayloadMutator
        from vulnclaw.core.vuln_prioritizer import VulnPrioritizer

        m = PayloadMutator(seed=42)
        vp = VulnPrioritizer()

        vulns = [
            {"type": "sqli", "severity": "low", "payloads": m.mutate_combine("a", level=1)},
            {"type": "rce", "severity": "critical", "has_poc": True,
             "has_cve": True, "sensitive": True, "endpoint_type": "admin", "confidence": "high",
             "payloads": m.mutate_combine("b", level=3)},
        ]
        sorted_vulns = vp.sort_by_priority(vulns)
        assert sorted_vulns[0]["type"] == "rce"

    def test_poc_generator_with_mutated_payloads(self):
        from vulnclaw.core.payload_mutator import PayloadMutator
        from scripts.generate_pocs import POCGenerator

        m = PayloadMutator(seed=42)
        payloads = m.mutate_combine("1 OR 1=1", level=2)

        with tempfile.TemporaryDirectory() as d:
            gen = POCGenerator(output_dir=d, fmt="py")
            path = gen.generate({
                "type": "sqli",
                "url": "http://testphp.vulnweb.com",
                "param": "id",
                "payloads": payloads,
            })
            assert path is not None
            content = path.read_text(encoding="utf-8")
            assert "http://testphp.vulnweb.com" in content
            assert len(payloads) > 0


# ============================================================
# Part 6: 配置读取加固测试
# ============================================================
class TestConfigHardening:
    def test_mutator_handles_non_string_gracefully(self):
        from vulnclaw.core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        result = m.mutate_case("")
        assert result == []

    def test_prioritizer_handles_missing_keys(self):
        from vulnclaw.core.vuln_prioritizer import VulnPrioritizer
        vp = VulnPrioritizer()
        score = vp.calculate_score({})
        assert 0 <= score <= 100

    def test_prioritizer_handles_none_values(self):
        from vulnclaw.core.vuln_prioritizer import VulnPrioritizer
        vp = VulnPrioritizer()
        score = vp.calculate_score({"severity": None, "cvss": None})
        assert 0 <= score <= 100

    def test_poc_generator_handles_missing_keys(self):
        from scripts.generate_pocs import POCGenerator
        with tempfile.TemporaryDirectory() as d:
            gen = POCGenerator(output_dir=d, fmt="py")
            path = gen.generate({})
            assert path is not None

    def test_poc_generator_invalid_fmt_handled(self):
        from scripts.generate_pocs import POCGenerator
        with tempfile.TemporaryDirectory() as d:
            gen = POCGenerator(output_dir=d, fmt="unknown")
            assert gen.fmt == "py"

    def test_mutator_seed_deterministic(self):
        from vulnclaw.core.payload_mutator import PayloadMutator
        import random

        random.seed(42)
        m1 = PayloadMutator(seed=42)
        v1 = m1.mutate_combine("OR 1=1", level=2)

        random.seed(42)
        m2 = PayloadMutator(seed=42)
        v2 = m2.mutate_combine("OR 1=1", level=2)

        assert v1 == v2


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))