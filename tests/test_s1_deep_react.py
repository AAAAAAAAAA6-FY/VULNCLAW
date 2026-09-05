# -*- coding: utf-8 -*-
"""线2：Agent 能力深化 —— S1 ReAct 深挖阶段接入 V100 主链路的验收测试。

覆盖：
- S1.1：deep 开启时输出 "[S1] 深度挖掘" 阶段节点日志，并下钻 ReActAgent 深挖入口。
- S1.2：danger_guard 未放行（默认 deny / 放行配置缺失 / 异常）→ 降级本地确定性兜底，
        跳过 LLM 深挖但绝不中断扫描。
- S1.3：模糊参数回落收集 + 深挖 finding 回写并标记 source=react_agent，与引擎来源区分。
- 零回归：deep=False（默认）时走原 _run_react_deep_dive 路径，不出现 S1 阶段节点。
"""
import json
import logging

import pytest

from vulnclaw.ai import dispatcher as disp
from vulnclaw.ai.v100 import orchestrator as v100
from vulnclaw.ai.v100.phases import phases_executor as pex


def _bare_orchestrator():
    """绕过重量级 __init__（引擎/记忆/检查点）构造轻量实例，直测门卫方法。"""
    return object.__new__(v100.V100Orchestrator)


@pytest.fixture
def enable_deep(monkeypatch):
    monkeypatch.setattr(v100.settings, "enable_react_dive", True)


# ---------------------------------------------------------------------------
# S1.1 插桩"深度挖掘"阶段：deep 开启输出阶段节点日志
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_s1_1_deep_logs_node_and_runs_agent(caplog, monkeypatch, enable_deep):
    caplog.set_level(logging.DEBUG, logger="pentest_agent")
    inst = _bare_orchestrator()
    calls = []

    async def _fake_dive():
        calls.append("deep_dive")
        return None

    monkeypatch.setattr(inst, "_run_react_deep_dive", _fake_dive, raising=False)
    monkeypatch.setattr(v100.V100Orchestrator, "_deep_dive_danger_allowed", lambda self: True)

    await inst._run_react_gated_deep_dive()

    assert calls == ["deep_dive"]            # 放行后下钻深挖入口
    assert "[S1] 深度挖掘" in caplog.text     # 阶段节点日志


# ---------------------------------------------------------------------------
# S1.2 回落触发：danger_guard 未放行 → 降级本地兜底，绝不中断
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_s1_2_danger_deny_degrades_local_and_continues(caplog, monkeypatch, enable_deep):
    caplog.set_level(logging.DEBUG, logger="pentest_agent")
    inst = _bare_orchestrator()
    calls = []

    async def _fake_dive():
        calls.append("deep_dive")
        return None

    monkeypatch.setattr(inst, "_run_react_deep_dive", _fake_dive, raising=False)
    monkeypatch.setattr(v100.V100Orchestrator, "_deep_dive_danger_allowed", lambda self: False)

    await inst._run_react_gated_deep_dive()   # 不抛异常 → 扫描继续

    assert calls == []                        # LLM 深挖被跳过
    assert "降级为本地确定性兜底" in caplog.text


@pytest.mark.asyncio
async def test_s1_2_danger_deny_never_raises(monkeypatch, enable_deep):
    inst = _bare_orchestrator()
    monkeypatch.setattr(
        inst, "_run_react_deep_dive",
        lambda self: (_ for _ in ()).throw(AssertionError("不应被调用")),
        raising=False,
    )
    monkeypatch.setattr(v100.V100Orchestrator, "_deep_dive_danger_allowed", lambda self: False)
    # deny 路径在调用深挖前即返回，永不触达会抛错的 fake，也不会异常外抛
    assert await inst._run_react_gated_deep_dive() is None


def test_s1_2_danger_guard_allow_and_deny(monkeypatch):
    import vulnclaw.core.danger_guard as dg

    inst = _bare_orchestrator()
    monkeypatch.setattr(dg.guard, "require_approval", lambda *a, **k: True)
    assert inst._deep_dive_danger_allowed() is True
    monkeypatch.setattr(dg.guard, "require_approval", lambda *a, **k: False)
    assert inst._deep_dive_danger_allowed() is False


def test_s1_2_danger_guard_missing_or_error_falls_back(monkeypatch):
    """danger 放行配置缺失/异常 → 一律按 deny，返回 False 降级兜底。"""
    import vulnclaw.core.danger_guard as dg

    inst = _bare_orchestrator()
    monkeypatch.setattr(
        dg.guard, "require_approval",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("guard unavailable")),
    )
    assert inst._deep_dive_danger_allowed() is False


# ---------------------------------------------------------------------------
# S1.3 定位固化：模糊参数回落 + 深挖 finding 标记 source 区分来源
# ---------------------------------------------------------------------------
def test_s1_3_collect_react_candidates_low_info_and_strong_skip():
    class H:
        _bundle_results = {
            "id": [{"severity": "low"}, {"severity": "info"}],
            "strong": [{"severity": "info"}],
        }
        findings = [{"parameter": "strong", "severity": "High"}]

    cands = pex._collect_react_candidates(H())
    assert "id" in cands          # 全部 low/info → 模糊参数入选
    assert "strong" not in cands  # 已有高/中危 finding → 跳过


def test_s1_3_merge_marks_react_source_and_preserves_structure():
    class H:
        target = "http://t.example.com"

        def __init__(self):
            self.added = []

        def _add_finding(self, f):
            self.added.append(f)

    h = H()
    report = {"vulnerabilities": [{"type": "sqli"}]}
    n = pex._merge_react_findings(h, report, "id")

    assert n == 1
    f = h.added[0]
    assert f["source"] == "react_agent"          # 新增可选字段标识来源
    assert f["parameter"] == "id"
    assert f["url"] == "http://t.example.com"
    assert f["severity"] == "Medium"             # 无 severity 时默认，不破坏结构
    assert f["type"] == "sqli"                   # 既有字段保留


# ---------------------------------------------------------------------------
# 零回归：deep=False（默认）与现状完全一致
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_deep_false_preserves_original_path(caplog, monkeypatch):
    caplog.set_level(logging.DEBUG, logger="pentest_agent")
    inst = _bare_orchestrator()   # 默认 enable_react_dive=False（未开 deep）
    calls = []

    async def _fake_dive():
        calls.append("deep_dive")
        return None

    monkeypatch.setattr(inst, "_run_react_deep_dive", _fake_dive, raising=False)

    await inst._run_react_gated_deep_dive()

    assert calls == ["deep_dive"]                    # 原入口被调用
    assert "[S1] 深度挖掘" not in caplog.text          # 不出现 S1 阶段节点
    assert "降级为本地确定性兜底" not in caplog.text    # 没有 danger 降级逻辑旁路


# ---------------------------------------------------------------------------
# 线2 深化：A1.2 Plan-then-Act / A1.3 反思循环 / A1.4 目标函数
# ---------------------------------------------------------------------------
def _bare_react_agent():
    """绕过重量级 __init__（引擎/记忆/LLM），构造轻量 ReActAgent 直测 A1 逻辑。

    参照 tests/test_budget_wiring.py 的 object.__new__ 模式。
    """
    return object.__new__(disp.ReActAgent)


def test_a1_2_plan_parse_structured_and_filters():
    agent = _bare_react_agent()
    agent.tools = {"sqli": object(), "xss": object()}
    plan = agent._parse_plan([
        {"phase": "recon", "tool": "sqli", "reason": "r", "expected_observation": "o"},
        "xss",
        {"tool": "unknown_tool"},                 # 不可识工具过滤
        {"phase": "exploit", "tool": "xss", "reason": "r2"},
    ])
    assert [s["tool"] for s in plan] == ["sqli", "xss", "xss"]
    assert plan[0]["phase"] == "recon"
    assert plan[0]["expected_observation"] == "o"
    assert plan[2]["reason"] == "r2"


@pytest.mark.asyncio
async def test_a1_2_generate_plan_structured_from_llm():
    class _FakeLLM:
        async def ask(self, *a, **kw):
            return json.dumps([
                {"phase": "recon", "tool": "sqli", "reason": "r", "expected_observation": "o"},
                {"phase": "exploit", "tool": "xss", "reason": "r2", "expected_observation": "o2"},
            ])

    agent = _bare_react_agent()
    agent.llm = _FakeLLM()
    agent._recon_observation = {}
    agent.tools = {"sqli": object(), "xss": object()}
    agent.plan_step = 0
    agent.current_plan = []
    await agent._generate_plan()
    assert len(agent.current_plan) == 2
    assert agent.current_plan[0]["tool"] == "sqli"
    assert agent.current_plan[0]["expected_observation"] == "o"


@pytest.mark.asyncio
async def test_a1_2_generate_plan_fallback_when_no_llm():
    agent = _bare_react_agent()
    agent.llm = None
    agent.tools = {"sqli": object(), "xss": object()}
    agent.tool_success_rates = {}
    agent.tool_stats = {}
    agent._tool_recent = []
    agent.plan_step = 0
    agent.current_plan = []
    agent._ensure_shared_knowledge = lambda: {"tool_stats": {}}
    await agent._generate_plan()
    assert len(agent.current_plan) == 2
    assert all(isinstance(s, dict) and "tool" in s for s in agent.current_plan)


@pytest.mark.asyncio
async def test_a1_3_reflection_switches_after_two_failures():
    agent = _bare_react_agent()
    agent.llm = None                              # 走本地启发式：连续失败>=2 -> switch
    agent._consecutive_failures = 1
    agent._strategy_switched = 0
    agent._force_strategy_switch = False
    agent._strategy_note = ""
    agent.current_plan = [{"phase": "attack", "tool": "sqli", "reason": "", "expected_observation": ""}]
    await agent._post_step_reflection("t", {"tool": "sqli"}, {"error": "x"}, {"type": "error"}, False)
    assert agent._strategy_switched == 1
    assert agent._force_strategy_switch is True
    assert agent.current_plan == []               # 触发换策略即清空原计划


@pytest.mark.asyncio
async def test_a1_3_decide_action_avoids_repeat_on_switch():
    agent = _bare_react_agent()
    agent.current_plan = [
        {"phase": "attack", "tool": "sqli", "reason": "r", "expected_observation": "e"},
        {"phase": "attack", "tool": "xss", "reason": "r", "expected_observation": "e"},
    ]
    agent.plan_step = 0
    agent.plan_fail_count = 0
    agent._recon_observation = {"params": [{"param": "id"}]}
    agent.tools = {"sqli": object(), "xss": object()}
    agent.tool_success_rates = {}
    agent.tool_stats = {}
    agent._tool_recent = []
    agent._force_strategy_switch = True
    agent._last_action_tool = "sqli"
    agent.llm = None
    agent.target = "http://t.example.com"
    agent.role = "general"
    agent.blackboard = None
    agent.findings = []
    agent.history = []
    agent.max_iterations = 10
    agent.iteration = 0
    agent._failed_params = set()
    agent._ensure_shared_knowledge = lambda: {"tool_stats": {}}

    action = await agent._decide_action("thought")
    assert action["tool"] == "xss"               # 强制换策略：避开最近重复工具 sqli
    assert agent._last_action_tool == "xss"
    assert agent.plan_step == 2


def test_a1_4_objective_scores_success_times_info_gain():
    agent = _bare_react_agent()
    agent.tools = {"sqli": object(), "xss": object()}
    agent.tool_success_rates = {"sqli": 0.9, "xss": 0.5}
    agent.tool_stats = {}
    agent._tool_recent = []
    agent._ensure_shared_knowledge = lambda: {"tool_stats": {}}

    assert abs(agent._objective_score("sqli") - 0.9) < 1e-6
    assert abs(agent._objective_score("xss") - 0.5) < 1e-6
    # 未尝试工具信息增益满
    assert abs(agent._expected_info_gain("sqli") - 1.0) < 1e-6
    # 多次调用后信息增益衰减
    agent.tool_stats = {"sqli": {"success": 0, "failure": 5}}
    agent._tool_recent = ["sqli"]
    assert agent._expected_info_gain("sqli") < 1.0
    # 目标函数更高者优先排序
    agent.tool_stats = {"xss": {"success": 0, "failure": 5}}
    agent._tool_recent = ["xss"]
    assert agent._rank_tools(["sqli", "xss"])[0] == "sqli"


# ---------------------------------------------------------------------------
# A1.5 失败原因结构化沉淀：memory 条目带 failure_class + 下轮 prompt 必带
# ---------------------------------------------------------------------------
def test_a1_5_build_failure_class_structured():
    agent = _bare_react_agent()
    action = {"tool": "sqli", "params": {"url": "http://t", "param": "id"}}
    result = {"error": "无回显", "evidence": "baseline 200", "status": 500}
    fc = agent._build_failure_class("sqli", action, result, {"type": "error"})
    assert fc is not None
    assert fc["param"] == "id"
    assert fc["tool"] == "sqli"
    assert fc["vuln_type"] == "sqli"                 # 从工具名启发式推断
    assert fc["response_features"]["status"] == 500
    assert fc["response_features"]["error"] == "无回显"
    # 成功发现路径不沉淀失败
    ok = agent._build_failure_class("sqli", action, {"type": "SQL注入"}, {"type": "finding"})
    assert ok is None


def test_a1_5_record_tool_outcome_carries_failure_class():
    agent = _bare_react_agent()
    agent.short_term_memory = []
    agent.short_term_memory_limit = 25
    agent._failure_classes = []
    agent._failure_classes_limit = 10
    agent.target = "http://t.example.com"
    agent.tool_stats = {"sqli": {"success": 0, "failure": 0}}
    agent.tool_success_rates = {}
    agent._ensure_shared_knowledge = lambda: {"tool_stats": {}}
    agent._record_tool_outcome(
        "sqli", False, payload="p", detail="d",
        failure_class={"param": "id", "tool": "sqli", "vuln_type": "sqli", "response_features": {}},
    )
    assert "failure_class" in agent.short_term_memory[-1]   # memory 文件出现 failure_class 字段
    assert agent.short_term_memory[-1]["failure_class"]["param"] == "id"
    assert len(agent._failure_classes) == 1


@pytest.mark.asyncio
async def test_a1_5_failure_lessons_injected_into_think_prompt():
    agent = _bare_react_agent()
    agent.target = "http://t.example.com"
    agent.role = "general"
    agent.role_system = ""
    agent.blackboard = None
    agent._scene_cache = {}
    agent.findings = []
    agent._failed_params = set()
    agent.tools = {}
    agent._failure_classes = [{
        "param": "id", "tool": "sqli", "vuln_type": "sqli",
        "response_features": {"status": 500, "error": "无回显"},
    }]
    # 桩掉重依赖，聚焦 A1.5 注入
    agent._global_context = lambda: ""
    agent._target_context = lambda: ""
    agent._format_tools = lambda: ""
    agent._skills_context = lambda *a, **k: ""

    captured = {}

    class _FakeLLM:
        async def ask(self, prompt, **kw):
            captured["prompt"] = prompt
            return "继续探索。"

    agent.llm = _FakeLLM()
    await agent._think({"params": [], "tech_stack": [], "status": "200"})
    assert "历史失败教训" in captured["prompt"]
    assert "参数[id]" in captured["prompt"]            # 失败教训必带进下轮 prompt