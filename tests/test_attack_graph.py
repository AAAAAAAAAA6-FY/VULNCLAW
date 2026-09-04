# -*- coding: utf-8 -*-
"""E1 攻击图与路径计算单测：模型构建 / 级联 / TOP 路径 / 导出 / E1.4 打通。"""
import json

import networkx as nx
import pytest

from vulnclaw.core.attack_graph import (
    AttackGraph,
    _confidence_prob,
    _severity_weight,
    _is_target_vuln,
)

VULNS = [
    {"url": "http://t.example.com/a.php", "type": "LFI", "severity": "High",
     "confidence": "high", "parameter": "f"},
    {"url": "http://t.example.com/log.php", "type": "RCE Shell", "severity": "Critical",
     "confidence": "medium", "parameter": "c"},
    {"url": "http://t.example.com/list.php", "type": "SQL Injection", "severity": "Critical",
     "confidence": "high", "parameter": "id"},
]

REPORT = {
    "target": "http://t.example.com",
    "alive_assets": ["http://t.example.com"],
    "subdomains": ["sub.t.example.com"],
    "vulnerabilities": VULNS,
}


def make_graph():
    return AttackGraph().build_from_report(REPORT)


class TestConfidenceAndSeverity:
    def test_confidence_prob(self):
        assert _confidence_prob("high") == 0.95
        assert _confidence_prob("medium") == 0.7
        assert _confidence_prob("low") == 0.35
        assert _confidence_prob(100) == 0.95
        assert _confidence_prob(60) == 0.7
        assert _confidence_prob(None) == 0.5

    def test_severity_weight(self):
        assert _severity_weight("Critical") == 25
        assert _severity_weight("HIGH") == 18
        assert _severity_weight("medium") == 12
        assert _severity_weight("low") == 6

    def test_target_keyword(self):
        assert _is_target_vuln("Remote Code Execution") is True
        assert _is_target_vuln("SQL Injection") is True
        assert _is_target_vuln("XSS") is False


class TestModel:
    def test_build_from_report(self):
        g = make_graph()
        assert g.graph.number_of_nodes() == 6  # 2 资产 + 3 漏洞 + ... 见上
        assert g.graph.number_of_nodes() >= 5
        kinds = {d.get("kind") for _, d in g.graph.nodes(data=True)}
        assert {"asset", "vuln"} <= kinds
        # asset -> vuln expose 边
        expose = [d for _, _, d in g.graph.edges(data=True) if d.get("label") == "expose"]
        assert len(expose) == 3

    def test_cascade_edges(self):
        g = make_graph()
        cascades = [d for _, _, d in g.graph.edges(data=True) if d.get("label") == "cascade"]
        assert len(cascades) >= 1

    def test_vuln_node_meta(self):
        g = make_graph()
        vulns = [d for _, d in g.graph.nodes(data=True) if d.get("kind") == "vuln"]
        assert all("url" in d and "type" in d and "severity" in d for d in vulns)


class TestAttackPaths:
    def test_top_paths_returns(self):
        g = make_graph()
        paths = g.top_attack_paths(top_k=3)
        assert len(paths) >= 1
        for p in paths:
            assert p["path"][0].endswith("t.example.com")
            assert p["total_weight"] > 0
            assert 0 < p["probability"] <= 1

    def test_sink_only_target_vulns(self):
        g = make_graph()
        ends = {p["end_type"] for p in g.top_attack_paths(top_k=10)}
        assert ends <= {"SQL Injection", "RCE Shell"}

    def test_min_prob_filter(self):
        g = make_graph()
        strict = g.top_attack_paths(top_k=10, min_prob=0.9)
        loose = g.top_attack_paths(top_k=10)
        assert all(p["probability"] >= 0.9 for p in strict)
        assert len(strict) <= len(loose)

    def test_empty_report(self):
        g = AttackGraph().build_from_report({})
        assert g.top_attack_paths() == []


class TestExport:
    def test_json_export(self):
        data = make_graph().to_json()
        assert data["stats"]["vulns"] >= 3
        assert data["stats"]["assets"] >= 1
        assert data["nodes"] and data["edges"]

    def test_json_roundtrip(self):
        data = make_graph().to_json()
        s = json.dumps(data, ensure_ascii=False)
        assert json.loads(s)["stats"]["nodes"] == data["stats"]["nodes"]

    def test_graphml_export(self):
        xml = make_graph().to_graphml()
        assert "<graphml" in xml
        assert "<graph" in xml


class TestExploitChainBridge:
    def test_from_chains(self):
        chains = [{
            "finding_id": "f1", "strategy": "sqlmap", "success": True,
            "url": "http://t.example.com/x.php",
            "chain": [{"node": "f1", "strategy": "sqlmap"},
                      {"node": "gate:admin", "strategy": ""}],
        }]
        g = AttackGraph.from_chains(chains, target="http://t.example.com")
        kinds = {d.get("kind") for _, d in g.graph.nodes(data=True)}
        assert "gate" in kinds
        assert g.graph.number_of_edges() == 2  # cascade + expose

class TestReportEmbed:
    """"E1.3: 报告 HTML 嵌入攻击图段（D3 + TOP 路径 + 离线降级）。"""

    def test_render_html_contains_attack_graph(self):
        from vulnclaw.core.report_generator import render_html

        report = {
            "target": "http://t.example.com",
            "scan_time": "2026-09-04 12:00:00",
            "vulnerabilities": VULNS,
        }
        g = AttackGraph().build_from_report(report)
        report["attack_graph"] = g.to_json()
        report["attack_paths"] = g.top_attack_paths(top_k=5)
        html = render_html(report)
        assert "attackGraphBox" in html
        assert "window.__AG_DATA__" in html
        assert "attackGraphFallback" in html
        assert "TOP" in html and "Path 1" in html

    def test_render_html_empty_graph_degrades(self):
        from vulnclaw.core.report_generator import render_html

        report = {"target": "http://t.example.com", "vulnerabilities": []}
        html = render_html(report)
        # 无攻击图数据时不注入 D3 数据脚本，仍生成完整报告
        assert "window.__AG_DATA__" not in html
        assert html.strip().endswith("</html>")
