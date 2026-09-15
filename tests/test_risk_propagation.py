# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
"""风险传播模型（core/risk_propagation.py）离线验收。

口径说明（写测试前先明确，避免误判实现）：
  * 每个 **vuln 节点自身有种子分** = severity 权重 × confidence 概率；
  * 节点最终分 = max(自身种子分, 从上游传来的"最强路径"分)——
    因此要**单独验证传播链**，必须用无种子的 ``gate`` 节点（它只能靠传播得分）。

覆盖：
  A 确定性：同一图多次调用结果逐字段一致
  B 边界：空图 / 无漏洞 → 空结果 + note（不编造分数）
  C 种子分：severity 权重 × confidence 概率
  D 传播：无种子 gate 节点得分 = 上游分 × 边概率 × decay；decay 单调；父链可回溯
  E 种子占优语义：自身种子分高于传播值时取种子分
  F 资产聚合：资产分 = Σ(后继 vuln 分)，上限 100
  G confirmed_only：严格只取已确认；无可确认 → 空 + note，绝不用可疑项顶替
  H 便捷入口 propagate_from_report 与 AttackGraph 路径等价
"""
import pytest

from vulnclaw.core.attack_graph import AttackGraph
from vulnclaw.core.risk_propagation import propagate_from_report, propagate_risk


def _vuln_finding(url: str, vtype: str, severity: str, confidence="高",
                  verdict="suspicious", **extra) -> dict:
    finding = {
        "url": url,
        "type": vtype,
        "severity": severity,
        "confidence": confidence,
        "verdict": verdict,
        "parameter": "q",
    }
    finding.update(extra)
    return finding


def _two_vuln_graph() -> tuple:
    """a.test：sqli(critical/高) → cascade(prob=0.8) → file read(high/高)。

    两者**自身都有种子分**（9.5 与 7.6），因此本图只用于种子/聚合/占优语义。
    """
    g = AttackGraph()
    va = g.add_vuln(_vuln_finding("http://a.test/x?q=1", "sql injection", "critical"))
    vb = g.add_vuln(_vuln_finding("http://a.test/y?q=1", "file read", "high"))
    g.add_edge(va, vb, label="cascade", prob=0.8)
    return g, va, vb


def _graph_with_gate(prob: float = 0.8) -> tuple:
    """sqli(critical/高) → gate（无种子，只能靠传播得分）。"""
    g = AttackGraph()
    va = g.add_vuln(_vuln_finding("http://a.test/x?q=1", "sql injection", "critical"))
    g.add_node("gate:rce", kind="gate", label="RCE 前置")
    g.add_edge(va, "gate:rce", label="cascade", prob=prob)
    return g, va


# ============================================================
# A. 确定性
# ============================================================
def test_propagation_is_deterministic():
    g, _, _ = _two_vuln_graph()
    assert propagate_risk(g) == propagate_risk(g)


# ============================================================
# B. 边界：空图 / 无漏洞
# ============================================================
def test_empty_graph_returns_empty_with_note():
    out = propagate_risk(AttackGraph())
    assert out["sources"] == []
    assert out["asset_scores"] == {}
    assert out["top_assets"] == []
    assert out["note"], "空图必须给出 note，而不是伪造分数"


# ============================================================
# C. 种子分 = severity × confidence 概率
# ============================================================
def test_seed_score_is_severity_times_confidence():
    g, va, vb = _two_vuln_graph()
    out = propagate_risk(g)
    assert out["node_scores"][va] == pytest.approx(9.5, abs=1e-6)   # critical 10 × 0.95
    assert out["node_scores"][vb] == pytest.approx(7.6, abs=1e-6)   # high 8 × 0.95


# ============================================================
# D. 传播（gate 无种子，纯传播链）
# ============================================================
def test_gate_node_receives_decayed_propagation():
    g, _ = _graph_with_gate(prob=0.8)
    out = propagate_risk(g, decay=0.6)
    # 9.5 × 0.8 × 0.6 = 4.56
    assert out["node_scores"]["gate:rce"] == pytest.approx(4.56, abs=1e-6)


def test_decay_is_monotonic():
    low = propagate_risk(_graph_with_gate()[0], decay=0.3)["node_scores"]["gate:rce"]
    high = propagate_risk(_graph_with_gate()[0], decay=0.9)["node_scores"]["gate:rce"]
    assert low < high < 9.5
    assert low == pytest.approx(9.5 * 0.8 * 0.3, abs=1e-6)
    assert high == pytest.approx(9.5 * 0.8 * 0.9, abs=1e-6)


def test_path_traces_back_to_seed():
    g, va = _graph_with_gate()
    out = propagate_risk(g)
    top = out["top_assets"][0]
    assert top["asset"] == "a.test"
    assert top["path"], "top 资产必须带可回溯路径"
    assert top["path"][0] == va, f"路径应始于种子漏洞: {top['path']}"


# ============================================================
# E. 种子占优语义（自身种子分 > 传播分时取种子）
# ============================================================
def test_seed_score_dominates_weaker_propagation():
    g, _, vb = _two_vuln_graph()
    out = propagate_risk(g, decay=0.6)
    # 传播值 9.5×0.8×0.6=4.56 < 自身种子 7.6 → 取 7.6
    assert out["node_scores"][vb] == pytest.approx(7.6, abs=1e-6)


# ============================================================
# F. 资产聚合
# ============================================================
def test_asset_score_is_sum_of_vuln_scores():
    g, _, _ = _two_vuln_graph()
    out = propagate_risk(g, decay=0.6)
    assert out["asset_scores"]["a.test"] == pytest.approx(9.5 + 7.6, abs=1e-6)


def test_asset_score_capped_at_100():
    g = AttackGraph()
    for i in range(15):
        g.add_vuln(_vuln_finding(f"http://b.test/{i}?q=1", f"sqli {i}", "critical"))
    out = propagate_risk(g)
    assert out["asset_scores"]["b.test"] == pytest.approx(100.0)


# ============================================================
# G. confirmed_only：严格口径
# ============================================================
def test_confirmed_only_ignores_suspicious():
    g, _, _ = _two_vuln_graph()  # 两条 verdict 都是 suspicious
    out = propagate_risk(g, confirmed_only=True)
    assert out["sources"] == [], "无可确认漏洞时绝不能拿 suspicious 顶替"
    assert out["note"], "严格模式下必须给出 note 说明原因"


def test_confirmed_only_keeps_verified():
    g = AttackGraph()
    v_ok = g.add_vuln(_vuln_finding("http://c.test/x?q=1", "rce", "critical", verdict="verified"))
    v_sus = g.add_vuln(_vuln_finding("http://c.test/y?q=1", "xss", "high", verdict="suspicious"))
    out = propagate_risk(g, confirmed_only=True)
    assert v_ok in out["node_scores"]
    assert v_sus not in out["node_scores"]


# ============================================================
# H. 便捷入口：report → 图 → 传播
# ============================================================
def test_propagate_from_report_matches_graph_path():
    report = {
        "alive_assets": ["http://a.test"],
        "vulnerabilities": [
            _vuln_finding("http://a.test/x?q=1", "sql injection", "critical"),
            _vuln_finding("http://a.test/y?q=1", "file read", "high"),
        ],
    }
    direct = propagate_risk(AttackGraph().build_from_report(report))
    via_report = propagate_from_report(report)
    assert via_report["node_scores"] == direct["node_scores"]
    assert via_report["top_assets"] == direct["top_assets"]


# ============================================================
# I. 报告链路接线（report_generator.ensure_attack_graph → risk_propagation）
# ============================================================
def test_report_pipeline_populates_risk_propagation():
    """兜底构建分支：非 AI 路径报告缺图时构建后必须补 risk_propagation。"""
    from vulnclaw.core.report_generator import ensure_attack_graph

    report = {
        "alive_assets": ["http://a.test"],
        "vulnerabilities": [_vuln_finding("http://a.test/x?q=1", "sql injection", "critical")],
    }
    ensure_attack_graph(report)
    rp = report.get("risk_propagation")
    assert rp, "报告链路必须注入 risk_propagation 块"
    assert rp["top_assets"], "top_assets 不应为空"
    assert rp["top_assets"][0]["asset"] == "a.test"


def test_report_pipeline_existing_graph_branch_also_populates():
    """已有攻击图（AI 路径）分支同样必须补风险传播（ensure_attack_graph 的早退出口）。"""
    from vulnclaw.core.attack_graph import AttackGraph
    from vulnclaw.core.report_generator import ensure_attack_graph

    g = AttackGraph()
    g.add_vuln(_vuln_finding("http://d.test/x?q=1", "rce", "critical"))
    report = {"attack_graph": g.to_json()}
    ensure_attack_graph(report)
    assert report.get("risk_propagation"), "已有攻击图分支也必须补风险传播"


def test_report_pipeline_is_idempotent():
    from vulnclaw.core.report_generator import ensure_risk_propagation

    sentinel = {"params": {"decay": 0.6}, "sources": [], "top_assets": []}
    report = {"risk_propagation": sentinel}
    ensure_risk_propagation(report)
    assert report["risk_propagation"] is sentinel, "已有 risk_propagation 不得被覆盖"


def test_report_pipeline_no_graph_no_injection():
    from vulnclaw.core.report_generator import ensure_risk_propagation

    report = {}
    ensure_risk_propagation(report)
    assert "risk_propagation" not in report, "无攻击图时不得注入空块"


# ============================================================
# J. HTML 报告渲染（report_generator._build_risk_block）
# ============================================================
def test_html_report_renders_risk_section():
    from vulnclaw.core.report_generator import render_html

    report = {
        "target": "http://a.test",
        "alive_assets": ["http://a.test"],
        "vulnerabilities": [_vuln_finding("http://a.test/x?q=1", "sql injection", "critical")],
    }
    html = render_html(report, detail="summary")
    assert "风险传播 TOP 资产" in html, "HTML 报告必须渲染风险传播段（否则数据注入了也看不到）"
    assert "a.test" in html


def test_html_report_no_risk_section_without_vulns():
    from vulnclaw.core.report_generator import render_html

    html = render_html({"target": "http://empty.test"}, detail="summary")
    assert "风险传播 TOP 资产" not in html, "无漏洞时不得注入空风险表"
