# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""AI Agent 决策审计链路 单元测试。

背景（2026-09-11 核验）：`_runtime_cache/agent_decisions/` 目录存在但 0 文件，
被质疑"aiagent 树是空壳"。核验结论：

  - **不是开关没开**：`enable_react_dive` 默认 True（config/settings.py），
    模型池 4 个模型（_ai_enabled=True）、danger_guard 对 react_dive_probe 放行，
    深挖阶段由 orchestrator 主流程调用（_run_react_gated_deep_dive）。
  - **审计落盘机制本身是真实可用的**（本文件锁定，防止以后被改坏）。
  - 空目录只说明"深挖没产生可深挖的候选参数"：_collect_react_candidates 只收
    「无高/中危 finding 且 bundle 结果全 low/info」的参数；靶场漏洞特征明显、
    引擎直接判高危时，该集合为空 → ReActAgent 从不实例化 → 无审计文件。

本文件锁定两件事：审计落盘真实可用；候选门槛按设计过滤。
"""
import json

from vulnclaw.ai.dispatcher import ReActAgent
from vulnclaw.ai.v100.phases import phases_executor as pe


class _Stub:
    """最小 self 替身（避开 orchestrator 完整构造）。"""


def _bare_agent():
    """构造裸 ReActAgent：跳过 __init__ 的 LLM/黑板初始化副作用。"""
    agent = ReActAgent.__new__(ReActAgent)
    agent.target = "http://t/"
    agent.role = "analysis"
    agent.stage = "execute"
    return agent


def test_audit_decision_writes_jsonl(tmp_path):
    """决策审计确实落盘：think/decide 每轮一条 JSONL，字段齐全。"""
    agent = _bare_agent()
    agent._audit_path = str(tmp_path / "decisions.jsonl")

    agent._audit_decision("decide", {"thought": "试注入", "action": {"tool": "sqli"}})
    agent._audit_decision("think", {"observation": "无差异"})

    lines = [ln for ln in (tmp_path / "decisions.jsonl").read_text(
        encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 2, "审计未逐条落盘"

    rec = json.loads(lines[0])
    assert rec["kind"] == "decide"
    assert rec["target"] == "http://t/"
    assert rec["role"] == "analysis"
    assert rec["thought"] == "试注入"
    assert rec["action"] == {"tool": "sqli"}
    assert json.loads(lines[1])["kind"] == "think"


def test_audit_decision_fails_silent_when_disabled(tmp_path):
    """审计是增强项：路径为空/不可写时必须静默降级，绝不影响主流程。"""
    agent = _bare_agent()
    agent._audit_path = ""                      # 未初始化审计路径
    agent._audit_decision("decide", {"thought": "x"})   # 不得抛异常

    agent._audit_path = str(tmp_path / "no" / "such" / "dir" / "a.jsonl")  # 不可写
    agent._audit_decision("decide", {"thought": "x"})   # 不得抛异常


def test_collect_react_candidates_only_keeps_ambiguous_params():
    """深挖门槛：已有高/中危 finding 的参数必须排除，只留判定模糊的。"""
    s = _Stub()
    s._bundle_results = {
        "weak_param": [{"severity": "info"}, {"severity": "low"}],
        "empty_param": [],
        "strong_param": [{"severity": "high"}],
    }
    s.findings = [{"parameter": "strong_param", "severity": "High"}]

    out = pe._collect_react_candidates(s)
    assert set(out) == {"weak_param", "empty_param"}
    assert "strong_param" not in out, "已有高危结论的参数不应再交给深挖"


def test_collect_react_candidates_force_bypasses_threshold(monkeypatch):
    """REACT_DIVE_FORCE=true 时跳过门槛，把所有已执行参数交深挖（验收 agent 链路用）。"""
    s = _Stub()
    s._bundle_results = {"strong_param": [{"severity": "high"}], "weak_param": []}
    s.findings = [{"parameter": "strong_param", "severity": "High"}]

    monkeypatch.setattr(pe.settings, "react_dive_force", True, raising=False)
    out = pe._collect_react_candidates(s)
    assert set(out) == {"strong_param", "weak_param"}, "强制模式应连高危参数一起深挖"


def test_collect_react_candidates_empty_without_bundle_results():
    """bundle 结果为空（未执行/被截断）→ 无候选 → ReActAgent 不会实例化。

    这正是 agent_decisions 目录为空的可能路径之一：深挖启动了但零候选。
    """
    s = _Stub()
    s._bundle_results = {}
    s.findings = []
    assert pe._collect_react_candidates(s) == []
