# -*- coding: utf-8 -*-
"""C4-C10 三档分级单测：verdict = confirm / likely / suspicious。"""
import pytest

from vulnclaw.ai.v100.orchestrator import V100Orchestrator


def grad(finding):
    return V100Orchestrator._classify_finding_verdict(finding)


class TestVerdictGrading:
    def test_confirm_hard_evidence(self):
        assert grad({"exploited": True, "ai_verdict": "真实漏洞"}) == "confirm"
        assert grad({"burp_verified": True}) == "confirm"
        assert grad({"cross_confirmed": True}) == "confirm"
        assert grad({"collaborator_callback": {"interaction_id": "x"}}) == "confirm"
        assert grad({"oob_confirmed": True}) == "confirm"

    def test_confirm_high_conf_real(self):
        assert grad({"confidence": "高", "ai_verdict": "真实漏洞"}) == "confirm"
        assert grad({"confidence": 100, "ai_verdict": "真实漏洞"}) == "confirm"
        assert grad({"confidence": "high", "ai_verdict": "真实漏洞"}) == "confirm"

    def test_likely_medium_conf_real(self):
        assert grad({"confidence": "medium", "ai_verdict": "真实漏洞"}) == "likely"
        assert grad({"confidence": "中", "ai_verdict": "真实漏洞"}) == "likely"
        assert grad({"confidence": "中（引擎证据，待人工复核）", "ai_verdict": "真实漏洞"}) == "likely"

    def test_suspicious_pending_review(self):
        assert grad({"ai_verdict": "待人工复核（无回显/无响应证据）", "confidence": "中"}) == "suspicious"
        assert grad({"ai_verdict": "低优先级，已跳过验证", "confidence": "low"}) == "suspicious"
        assert grad({"ai_verdict": "待人工复核（AI验证预算已满）"}) == "suspicious"

    def test_suspicious_defaults(self):
        assert grad({}) == "suspicious"
        assert grad({"confidence": "low"}) == "suspicious"
        assert grad({"ai_verdict": "非漏洞"}) == "suspicious"
        assert grad({"confidence": "高", "ai_verdict": "非漏洞"}) == "suspicious"