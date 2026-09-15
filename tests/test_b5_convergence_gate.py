# -*- coding: utf-8 -*-
"""B5 收敛门（orchestrator 终稿收敛：verify 背书 + pending_review 降级）专项测试。

钉住红线（project_memory 口径）：
  * verify 背书（ai_verdict 含"真实漏洞"，含单源"真实漏洞（本地规则确认）"）不降级；
  * 硬证据（cross_confirmed / burp_verified / exploited / oob_confirmed）不降级；
  * AI 未背书且无实锤 -> severity 降 Info + verdict=pending_review + 入 _pending_review 桶
    （保留 original_severity / type / evidence 可追溯）；
  * E3：cross_tool_pending（业务逻辑单点且无差分证据）强制复核降级；
  * 幂等：已是 pending_review 的 finding 不重降、不重复入桶。
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vulnclaw.ai.v100.orchestrator import V100Orchestrator as Orchestrator  # noqa: E402
# H 组拆分后 _apply_final_review_gate 迁至 phases/phases_verify.py（经 bind_phase_methods 绑定到实例），
# 空壳测试直接调用实现函数，语义与旧 `V100_apply_final_review_gate(o)`（unbound）一致。
from vulnclaw.ai.v100.phases.phases_verify import _apply_final_review_gate  # noqa: E402


def _mk(**kw):
    base = {"url": "http://t/a?b=1", "type": "x", "ai_verdict": "", "confidence": "中"}
    base.update(kw)
    return base


# ---------------------------------------------------------------- 三档分级
def test_classify_hard_proof_confirm():
    for k in ("exploited", "burp_verified", "cross_confirmed", "oob_confirmed", "collaborator_callback"):
        assert Orchestrator._classify_finding_verdict({k: True}) == "confirm", k


def test_classify_real_high_confirm():
    assert Orchestrator._classify_finding_verdict(_mk(ai_verdict="真实漏洞", confidence="高")) == "confirm"
    assert Orchestrator._classify_finding_verdict(_mk(ai_verdict="真实漏洞", confidence=90)) == "confirm"
    # 本地规则单源背书仍算背书（+1 档，但不升 confirm 除非高置信）
    assert Orchestrator._classify_finding_verdict(
        _mk(ai_verdict="真实漏洞（本地规则确认）", confidence="高")) == "confirm"


def test_classify_real_medium_likely():
    assert Orchestrator._classify_finding_verdict(_mk(ai_verdict="真实漏洞", confidence="中")) == "likely"


def test_classify_unendorsed_suspicious():
    assert Orchestrator._classify_finding_verdict(_mk()) == "suspicious"
    assert Orchestrator._classify_finding_verdict(_mk(ai_verdict="待人工复核")) == "suspicious"
    assert Orchestrator._classify_finding_verdict(_mk(ai_verdict="预算已满")) == "suspicious"
    assert Orchestrator._classify_finding_verdict(_mk(ai_verdict="非漏洞", confidence="高")) == "suspicious"


def test_classify_verbose_confidence_real():
    assert Orchestrator._classify_finding_verdict(
        _mk(ai_verdict="真实漏洞", confidence="高（已人工复核）")) == "confirm"


# ---------------------------------------------------------------- 终稿收敛门
def _gate_apply(findings, settings=None):
    """最小空壳：只接 _apply_final_review_gate 用到的属性。"""
    o = Orchestrator.__new__(Orchestrator)
    o.findings = findings
    o._pending_review = []
    return o


def test_gate_endorsed_not_downgraded():
    f = _mk(ai_verdict="真实漏洞", confidence="高", severity="Medium")
    o = _gate_apply([f])
    _apply_final_review_gate(o)
    assert f.get("verdict") != "pending_review"
    assert f.get("severity") == "Medium"


def test_gate_local_rule_endorsed_not_downgraded():
    # sigma：'真实漏洞（本地规则确认）' 属背书，不因"非纯实锤"误降
    f = _mk(ai_verdict="真实漏洞（本地规则确认）", verdict="suspicious", severity="Medium")
    o = _gate_apply([f])
    _apply_final_review_gate(o)
    assert f.get("verdict") != "pending_review"


def test_gate_hard_proof_not_downgraded():
    for k in ("cross_confirmed", "burp_verified", "exploited", "oob_confirmed"):
        f = _mk(ai_verdict="待人工复核", **{k: True}, severity="High")
        o = _gate_apply([f])
        _apply_final_review_gate(o)
        assert o.findings[0].get("verdict") == "confirm" or o.findings[0].get("verdict") != "pending_review", k


def test_gate_unendorsed_without_proof_downgraded():
    f = _mk(ai_verdict="待人工复核", severity="High", type="业务逻辑不变量违反（剧本差分证实）")
    o = _gate_apply([f])
    _apply_final_review_gate(o)
    assert o.findings[0]["severity"] == "Info"
    assert o.findings[0]["verdict"] == "pending_review"
    assert o.findings[0]["original_severity"] == "High"
    assert o.findings[0]["type"] == "业务逻辑不变量违反（剧本差分证实）"
    assert len(o._pending_review) == 1
    assert o._pending_review[0]["url"] == f["url"]


def test_gate_staged_suspicious_blank_verdict_downgraded():
    # 引擎裸模板：先被 _classify 拗成 suspicious 且非"真实漏洞" -> 收敛降级
    f = _mk(ai_verdict="", verdict="suspicious", severity="Medium")
    o = _gate_apply([f])
    _apply_final_review_gate(o)
    assert o.findings[0]["verdict"] == "pending_review"
    assert o.findings[0]["severity"] == "Info"


def test_gate_llm_degraded_verdict_downgraded():
    f = _mk(ai_verdict="LLM 降级，未背书", verdict="suspicious", severity="High")
    o = _gate_apply([f])
    _apply_final_review_gate(o)
    assert o.findings[0]["verdict"] == "pending_review"


def test_gate_e3_cross_tool_pending_forced():
    # E3：业务逻辑单点且 cross_tool_pending -> 即使 AI 背书也强制复核
    f = _mk(ai_verdict="真实漏洞", confidence="高", cross_tool_pending=True, severity="High")
    o = _gate_apply([f])
    _apply_final_review_gate(o)
    assert o.findings[0]["verdict"] == "pending_review"


def test_gate_idempotent_already_pending():
    f = _mk(ai_verdict="待人工复核", verdict="pending_review", severity="Medium")
    f["original_severity"] = "High"
    o = _gate_apply([f])
    _apply_final_review_gate(o)
    assert o.findings[0]["severity"] == "Medium"  # 不再重降
    assert o._pending_review == []  # 不重复入桶


def test_gate_empty_findings_noop():
    o = _gate_apply([])
    _apply_final_review_gate(o)
    assert o._pending_review == []


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--capture=no"]))