# -*- coding: utf-8 -*-
"""P3 长线三项单元测试（2026-09-15）：

- P3-④ Merkle 证据链（core.evidence_merkle）
- P3-② 图上 MCTS 攻击路径（core.attack_graph）
- P3-⑤ RL bandit 可迁移键 + 跨扫描状态持久化（ai.v100.bandit）
"""
from vulnclaw.ai.v100.bandit import ContextualBandit, bandit_key_v2, key_from_task
from vulnclaw.core.attack_graph import AttackGraph
from vulnclaw.core.evidence_merkle import (
    build_evidence_chain,
    build_merkle,
    leaf_hash,
    merkle_proof,
    verify_evidence_chain,
    verify_proof,
)


class TestEvidenceMerkle:
    def test_leaf_hash_stable_and_sensitive(self):
        v1 = {"url": "http://x/", "type": "sqli", "parameter": "id", "evidence": "e"}
        assert leaf_hash(v1) == leaf_hash(dict(v1))
        assert leaf_hash(v1) != leaf_hash(dict(v1, evidence="tampered"))

    def test_build_merkle_even_and_odd(self):
        assert build_merkle(["a", "b"])["count"] == 2
        t3 = build_merkle(["a", "b", "c"])
        assert t3["count"] == 3 and t3["root"]

    def test_empty_tree(self):
        assert build_merkle([])["root"] == ""

    def test_proof_roundtrip(self):
        leaves = [leaf_hash({"url": f"u{i}", "evidence": str(i)}) for i in range(5)]
        tree = build_merkle(leaves)
        for i in range(5):
            assert verify_proof(leaves[i], i, merkle_proof(tree["levels"], i), tree["root"])

    def test_tampered_leaf_fails(self):
        leaves = [leaf_hash({"url": "a"}), leaf_hash({"url": "b"})]
        tree = build_merkle(leaves)
        assert not verify_proof(
            leaf_hash({"url": "tampered"}), 0, merkle_proof(tree["levels"], 0), tree["root"])

    def test_report_chain_verify_and_tamper_detection(self):
        report = {"vulnerabilities": [
            {"url": "http://x/", "type": "sqli", "evidence": "e1", "poc_sha256": "abc"},
            {"url": "http://y/", "type": "xss", "evidence": "e2"},
        ]}
        report["evidence_root"] = build_evidence_chain(report)["root"]
        ok, msg = verify_evidence_chain(report)
        assert ok, msg
        report["vulnerabilities"][0]["evidence"] = "TAMPERED"
        ok2, _msg2 = verify_evidence_chain(report)
        assert not ok2  # 改一条证据 → 根不匹配

    def test_legacy_report_is_uncertified(self):
        ok, msg = verify_evidence_chain({"vulnerabilities": []})
        assert ok is False and "未出证" in msg


def _ring_graph() -> AttackGraph:
    """asset → sqli → rce，另含 lfi 支路 + 一条回边（故意造环）。"""
    g = AttackGraph()
    g.add_node("asset:host", kind="asset", url="http://host/")
    g.add_node("v:sqli", kind="vuln", type="SQL Injection", severity="High", url="http://host/a")
    g.add_node("v:lfi", kind="vuln", type="Local File Inclusion", severity="Medium", url="http://host/c")
    g.add_node("v:rce", kind="vuln", type="RCE", severity="Critical", url="http://host/b")
    g.add_edge("asset:host", "v:sqli", prob=0.8, weight=3)
    g.add_edge("asset:host", "v:lfi", prob=0.6, weight=3)
    g.add_edge("v:sqli", "v:rce", label="cascade", prob=0.7, weight=5)
    g.add_edge("v:lfi", "v:rce", label="cascade", prob=0.5, weight=5)
    g.add_edge("v:rce", "v:sqli", label="cascade", prob=0.1, weight=5)  # 环
    return g


class TestMCTSPaths:
    def test_mcts_direct(self):
        g = _ring_graph()
        out = g._mcts_paths(["asset:host"], ["v:rce"], max_depth=4, simulations=200)
        assert out
        assert all(o["source"] == "mcts" for o in out)
        assert all(o["end_type"] == "RCE" for o in out)
        # 环防护：路径无重复节点
        assert all(len(set(o["path"])) == len(o["path"]) for o in out)

    def test_mcts_strategy_merges(self):
        g = _ring_graph()
        paths = g.top_attack_paths(top_k=5, strategy="mcts")
        assert paths
        # 终点集合含 sqli/lfi/rce（三者都是"目标类漏洞"，既有 dijkstra 行为如此），
        # 且至少有一条到达 RCE —— 保证合并后仍按同一排序键竞争
        assert all(p["path"][-1] in ("v:rce", "v:sqli", "v:lfi") for p in paths)
        assert any(p["path"][-1] == "v:rce" for p in paths)
        assert all(len(set(p["path"])) == len(p["path"]) for p in paths)

    def test_default_strategy_unchanged(self):
        """默认 dijkstra：结果不含 mcts 候选（零行为变化）"""
        g = _ring_graph()
        paths = g.top_attack_paths(top_k=3)
        assert paths
        assert all(p.get("source") is None for p in paths)

    def test_empty_graph(self):
        assert AttackGraph().top_attack_paths(strategy="mcts") == []


class TestBanditV2AndPersistence:
    def test_v2_key_is_target_free(self):
        k = bandit_key_v2(tech="php", param="id", engine="sqli", family="union")
        assert k.startswith("v2|") and "php" in k
        k2 = key_from_task({"target": "http://a/", "tech": "php", "param": "id",
                            "engine": "sqli"}, v2=True)
        assert "http://a/" not in k2  # 关键：经验可跨目标迁移

    def test_v1_default_unchanged(self):
        assert key_from_task(
            {"target": "http://a/", "param": "id", "engine": "sqli"}
        ).startswith("http://a/|")

    def test_state_persistence(self, tmp_path):
        p = tmp_path / "bandit_state.json"
        b1 = ContextualBandit(state_path=str(p))
        key = bandit_key_v2(tech="php", param="id", engine="sqli")
        for _ in range(3):
            b1.record(key, hit=True)
        b2 = ContextualBandit(state_path=str(p))  # 新实例 = 下一次扫描
        assert b2.has_sample(key)
        assert b2.stats()[key]["hits"] == 3

    def test_no_state_path_is_in_memory_only(self):
        b = ContextualBandit()
        b.record("k", hit=True)
        assert ContextualBandit().stats() == {}


class TestCounterfactualImpact:
    """P3-③ 反事实分析：移除节点后攻击面变化。"""

    def test_bridge_node_removal_breaks_its_chains(self):
        g = _ring_graph()
        impact = g.counterfactual_impact("v:sqli")
        assert impact["found"] is True
        assert impact["before_chains"] >= 2
        assert impact["after_chains"] < impact["before_chains"]
        assert impact["removed_chains"]
        assert impact["risk_reduction"] > 0
        # 被断掉的链必然包含被移除节点
        assert all("v:sqli" in c["path"] for c in impact["removed_chains"])

    def test_terminal_node_removal(self):
        g = _ring_graph()
        impact = g.counterfactual_impact("v:rce")
        assert impact["found"] is True
        # 注意：sqli/lfi 也属"目标类漏洞"（termini 定义），移除 rce 后仍有
        # 直连 sqli/lfi 的链 —— 只断言"经过 rce 的链被断、风险下降"
        assert impact["after_chains"] < impact["before_chains"]
        assert impact["risk_reduction"] > 0
        assert impact["removed_chains"]
        assert all("v:rce" in c["path"] for c in impact["removed_chains"])

    def test_missing_node_not_found(self):
        g = _ring_graph()
        assert g.counterfactual_impact("no-such-node")["found"] is False

    def test_original_graph_unchanged(self):
        """反事实分析必须用副本，不改原图"""
        g = _ring_graph()
        before = len(g.top_attack_paths(top_k=10))
        g.counterfactual_impact("v:rce")
        assert len(g.top_attack_paths(top_k=10)) == before


class TestMCTSLlmFusion:
    """P3-② LLM 启发式融合与回退。"""

    def test_use_llm_without_client_falls_back(self, monkeypatch):
        """无 LLM 客户端 → 回退纯 UCB1，结果有效且不抛异常"""
        import vulnclaw.ai.core as ai_core
        monkeypatch.setattr(ai_core, "get_llm_client", lambda *a, **k: None)
        g = _ring_graph()
        out = g.top_attack_paths(top_k=5, strategy="mcts", use_llm=True)
        assert out
        assert all(len(set(p["path"])) == len(p["path"]) for p in out)

    def test_llm_heuristic_is_consumed(self, monkeypatch):
        """mock LLM 返回分数 → 融合路径被消费（调用发生且结果有效）"""
        import vulnclaw.ai.core as ai_core
        calls = []

        class _FakeClient:
            def ask(self, prompt, **kw):
                calls.append(prompt)
                return '{"v:sqli": 0.1, "v:lfi": 0.9}'

        monkeypatch.setattr(ai_core, "get_llm_client", lambda *a, **k: _FakeClient())
        g = _ring_graph()
        out = g.top_attack_paths(top_k=5, strategy="mcts", use_llm=True)
        assert out
        assert calls, "LLM 启发式应被调用（融合路径生效）"

    def test_budget_exhaustion_returns_none(self):
        g = _ring_graph()
        assert g._llm_edge_scores("asset:host", ["v:sqli"], {"used": 99, "max": 3}) is None
