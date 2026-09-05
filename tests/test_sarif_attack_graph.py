# -*- coding: utf-8 -*-
"""SP4 SARIF 内嵌 E1 攻击图：run.graphs + graphTraversals。"""
import json

from vulnclaw.core.attack_graph import AttackGraph
from vulnclaw.core.report_generator import (
    generate_html_report,
    generate_markdown_report,
    generate_poc_artifacts,
    generate_sarif,
)

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


# ============================================================
# C1.4: PoC 产物落盘 + 报告挂接
# ============================================================
class TestPocArtifacts:
    def _report(self, vulns):
        return {"target": "http://t.example.com", "vulnerabilities": vulns}

    def test_artifacts_written_and_annotated(self, tmp_path):
        rep = self._report([{
            "url": "http://t.example.com/a.php?id=1", "type": "SQL注入-报错注入",
            "severity": "Critical", "parameter": "id", "payload": "'",
        }])
        arts = generate_poc_artifacts(rep, str(tmp_path))
        assert len(arts) == 1
        a = arts[0]
        assert a["file"].startswith("poc/poc_") and a["file"].endswith(".py")
        assert (tmp_path / "poc" / a["file"].split("/", 1)[1]).exists()
        # finding 被标注（normalize_vulns 返回原引用）
        v = rep["vulnerabilities"][0]
        assert v["poc_file"] == a["file"]
        assert v["poc_origin"].startswith("template:")
        assert rep["poc_artifacts"] == arts

    def test_cve_poc_reused_first(self, tmp_path):
        rep = self._report([{
            "url": "http://t.example.com/x", "type": "未知新类型", "severity": "High",
            "cve_poc": {"cve_id": "CVE-2026-1234", "poc_script": "print('poc-body')"},
        }])
        arts = generate_poc_artifacts(rep, str(tmp_path))
        assert arts[0]["origin"] == "cve_index"
        body = (tmp_path / "poc" / arts[0]["file"].split("/", 1)[1]).read_text(encoding="utf-8")
        assert "poc-body" in body

    def test_b5_fallback_for_unmapped_type(self, tmp_path):
        rep = self._report([{
            "url": "http://t.example.com/y?uid=1", "type": "越权-IDOR",
            "severity": "Medium", "parameter": "uid",
        }])
        arts = generate_poc_artifacts(rep, str(tmp_path))
        assert arts[0]["origin"] == "b5_skeleton"
        body = (tmp_path / "poc" / arts[0]["file"].split("/", 1)[1]).read_text(encoding="utf-8")
        assert "urllib" in body

    def test_severity_priority_and_cap(self, tmp_path):
        vulns = [{"url": f"http://t.example.com/{i}", "type": "信息泄露",
                  "severity": "Info", "parameter": ""} for i in range(30)]
        vulns.insert(0, {"url": "http://t.example.com/crit", "type": "命令注入-RCE",
                         "severity": "Critical", "parameter": "cmd", "payload": "id"})
        rep = self._report(vulns)
        arts = generate_poc_artifacts(rep, str(tmp_path), max_artifacts=20)
        assert len(arts) == 20
        assert arts[0]["severity"] == "Critical"

    def test_empty_vulns_no_dir(self, tmp_path):
        rep = self._report([])
        assert generate_poc_artifacts(rep, str(tmp_path)) == []
        assert not (tmp_path / "poc").exists()

    def test_html_report_integration(self, tmp_path):
        rep = self._report([{
            "url": "http://t.example.com/a.php?id=1", "type": "SQL注入-报错注入",
            "severity": "High", "parameter": "id", "payload": "'",
        }])
        html_file = tmp_path / "report.html"
        assert generate_html_report(rep, str(html_file)) is True
        html = html_file.read_text(encoding="utf-8")
        assert "PoC 产物（C1.4" in html
        assert "poc/poc_" in html
        assert any((tmp_path / "poc").glob("*.py"))

    def test_markdown_artifacts_section(self, tmp_path):
        rep = self._report([{
            "url": "http://t.example.com/a.php?id=1", "type": "SQL注入-报错注入",
            "severity": "High", "parameter": "id", "payload": "'",
        }])
        generate_poc_artifacts(rep, str(tmp_path))
        md = tmp_path / "report.md"
        generate_markdown_report(rep, str(md))
        text = md.read_text(encoding="utf-8")
        assert "可运行 PoC 产物" in text and "poc/poc_" in text