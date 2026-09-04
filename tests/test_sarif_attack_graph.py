# -*- coding: utf-8 -*-
"""SP4 SARIF 内嵌 E1 攻击图：run.graphs + graphTraversals。"""
import json

from vulnclaw.core.attack_graph import AttackGraph
from vulnclaw.core.report_generator import generate_sarif

VULNS = [
    {"url": "http://t.example.com/a.php", "type": "LFI", "severity": "High",
     "confidence": "high", "parameter": "f"},
    {"url": "http://t.example.com/list.php", "type": "SQL Injection", "severity": "Critical",
     "confidence": "high", "parameter": "id"},
]

REPORT = {
    "target": "http://t.example.com",
    "scan_time": "2026-09-04 12:00:00",
    "vulnerabilities": VULNS,
}


def _report_with_graph():
    rep = dict(REPORT)
    g = AttackGraph().build_from_report(rep)
    rep["attack_graph"] = g.to_json()
    rep["attack_paths"] = g.top_attack_paths(top_k=5)
    return rep


class TestSarifGraphs:
    def test_graphs_embedded(self):
        sarif = generate_sarif(_report_with_graph())
        run0 = sarif["runs"][0]
        assert "graphs" in run0
        graphs = run0["graphs"]
        assert len(graphs) == 1
        g0 = graphs[0]
        assert g0["nodes"] and g0["edges"]
        ids = {n["id"] for n in g0["nodes"]}
        for e in g0["edges"]:
            assert e["sourceNodeId"] in ids
            assert e["targetNodeId"] in ids

    def test_top_path_traversals(self):
        sarif = generate_sarif(_report_with_graph())
        run0 = sarif["runs"][0]
        assert "graphTraversals" in run0
        t0 = run0["graphTraversals"][0]
        assert t0["graphIndex"] == 0
        assert t0["edgeTraversals"]
        edge_ids = {e["id"] for e in run0["graphs"][0]["edges"]}
        for tv in t0["edgeTraversals"]:
            assert tv["edgeId"] in edge_ids

    def test_json_roundtrip(self):
        sarif = generate_sarif(_report_with_graph())
        s = json.dumps(sarif, ensure_ascii=False)
        assert json.loads(s)["version"] == "2.1.0"

    def test_no_graph_when_missing(self):
        sarif = generate_sarif({"target": "http://t.example.com", "vulnerabilities": VULNS})
        assert "graphs" not in sarif["runs"][0]
        # 主流程不破坏
        assert sarif["runs"][0]["results"]