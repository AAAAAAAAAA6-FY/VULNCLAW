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
from vulnclaw.ai import tools as aitools
from vulnclaw.ai.core import _MemoryFallback
from vulnclaw.ai.v100 import orchestrator as v100
from vulnclaw.ai.v100.phases import phases_executor as pex
from vulnclaw.dashboard import server as srv


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
# 零回归：deep=False（显式关闭）与旧路径完全一致
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_deep_false_preserves_original_path(caplog, monkeypatch):
    caplog.set_level(logging.DEBUG, logger="pentest_agent")
    monkeypatch.setattr(v100.settings, "enable_react_dive", False)  # SP22 起默认 True，显式关闭验证旧路径
    inst = _bare_orchestrator()
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


def test_s1_2_probe_default_allowed_without_danger_mode():
    """SP22：默认 deny 模式下，本地探测级深挖仍放行（react_dive_probe 非危险键恒放行）。"""
    inst = _bare_orchestrator()
    assert inst._deep_dive_danger_allowed() is True


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

# ---------------------------------------------------------------------------
# PGEN-SUPERVISE 监督三件套（对齐 PentAGI）：RepeatingDetector /
# ExecutionMonitorDetector 深度反思 / HardLimit 优雅终止 / 未知工具忽略
# ---------------------------------------------------------------------------
def _monitor_agent(**over):
    agent = _bare_react_agent()
    agent.tools = {"sqli": object(), "xss": object()}
    agent._total_tool_calls = 0
    agent._same_tool_streak = 0
    agent._last_monitor_tool = None
    agent._force_strategy_switch = False
    agent._repeat_block_limit = 3
    agent._monitor_same_tool_limit = 5
    agent._monitor_total_tool_limit = 100
    agent._reflection_calls = []

    async def _fake_reflect(*_a, **_k):
        agent._reflection_calls.append(_k.get("thought") if _k else None)

    agent._post_step_reflection = _fake_reflect
    for k, v in over.items():
        setattr(agent, k, v)
    return agent


@pytest.mark.asyncio
async def test_monitor_repeating_detector_forces_strategy_switch(caplog):
    """RepeatingDetector：连续同工具达阈值 → 强制换策略 + 列车计数正确。"""
    caplog.set_level(logging.DEBUG, logger="pentest_agent")
    agent = _monitor_agent()
    for _ in range(3):
        assert await agent._monitor_tool_usage(
            "sqli", thought="t", action={"tool": "sqli"},
            result={}, observation={}, is_valid=True,
        ) is False
    assert agent._force_strategy_switch is True      # 达阈值即触发换策略
    assert agent._same_tool_streak == 3
    assert agent._total_tool_calls == 3
    assert "触发强制换策略" in caplog.text
    # 换策略触发后同工具继续调用不再重复置位（不幂等破坏），但仍计数
    assert await agent._monitor_tool_usage(
        "sqli", thought="t", action={"tool": "sqli"}, result={}, observation={}, is_valid=True,
    ) is False
    assert agent._total_tool_calls == 4


@pytest.mark.asyncio
async def test_monitor_execution_detector_triggers_reflection(caplog):
    """ExecutionMonitorDetector：连续同工具达更高阈值 → 深度反思被调用。"""
    caplog.set_level(logging.DEBUG, logger="pentest_agent")
    agent = _monitor_agent()
    for _ in range(5):
        await agent._monitor_tool_usage(
            "sqli", thought="t", action={"tool": "sqli"},
            result={}, observation={"message": "o"}, is_valid=False,
        )
    assert len(agent._reflection_calls) >= 1          # 深度反思触发
    assert agent._force_strategy_switch is True       # 先经 RepeatingDetector 置位
    assert "建议深度反思策略" in caplog.text


@pytest.mark.asyncio
async def test_monitor_hardlimit_graceful_termination(caplog):
    """HardLimit：总工具调用达硬上限 → 返回 True（优雅终止信号，防 runaway）。"""
    caplog.set_level(logging.DEBUG, logger="pentest_agent")
    agent = _monitor_agent(_monitor_total_tool_limit=3)
    for i in range(3):
        terminated = await agent._monitor_tool_usage(
            "sqli" if i % 2 == 0 else "xss", thought="t",
            action={}, result={}, observation={}, is_valid=True,
        )
    assert terminated is True                          # 第 3 次调用达上限
    assert agent._total_tool_calls == 3
    assert "优雅终止 Agent" in caplog.text


@pytest.mark.asyncio
async def test_monitor_ignores_unknown_tool():
    """未知工具/无工具名：不计数、不终止（不产生副作用）。"""
    agent = _monitor_agent()
    assert await agent._monitor_tool_usage(
        "unknown_tool", thought="t", action={}, result={}, observation={}, is_valid=True,
    ) is False
    assert await agent._monitor_tool_usage(
        None, thought="t", action={}, result={}, observation={}, is_valid=True,
    ) is False
    assert agent._total_tool_calls == 0
    assert agent._same_tool_streak == 0

# ---------------------------------------------------------------------------
# PGEN 能力落地专项断言（对面交付 39858e3/e807342 引入，补齐无测试锁定缺口）
# ToolCallFixer / 记忆分层 doc_type / Planner 验证点 success_criteria / 状态总线 no-op
# ---------------------------------------------------------------------------
class _SchemaTool:
    """带 parameters schema 的假工具：缺 url 即 TypeError（模拟 LLM 漏参）。"""
    parameters = [{"name": "url"}, {"name": "timeout"}]

    async def execute(self, **kwargs):
        if "url" not in kwargs:
            raise TypeError("execute() missing required argument: 'url'")
        return {"ok": True, "url": kwargs["url"]}


class _AlwaysFailTool:
    parameters = [{"name": "url"}]

    async def execute(self, **kwargs):
        raise TypeError("boom")


@pytest.mark.asyncio
async def test_tool_call_fixer_repairs_missing_arg(monkeypatch):
    """PGEN-TCF：缺失必填参数 → 按 schema 补空串重试成功；未知参数被剔除。"""
    monkeypatch.setitem(aitools.TOOL_REGISTRY, "__fake_schema_tool__", _SchemaTool())
    res = await aitools.execute_tool("__fake_schema_tool__", bogus=1)
    assert res == {"ok": True, "url": ""}   # bogus 剔除 + url 补空串


@pytest.mark.asyncio
async def test_tool_call_fixer_retries_only_once(monkeypatch, caplog):
    """PGEN-TCF：修复后仍失败 → 返回错误且不二次重试（只修一次）。"""
    caplog.set_level(logging.DEBUG, logger="pentest_agent")
    monkeypatch.setitem(aitools.TOOL_REGISTRY, "__always_fail_tool__", _AlwaysFailTool())
    res = await aitools.execute_tool("__always_fail_tool__", unknown=1)
    assert res == {"error": "boom"}
    assert "修复后仍失败" in caplog.text


@pytest.mark.asyncio
@pytest.mark.asyncio
async def test_memory_layering_doc_type_in_fallback():
    """PGEN-MEM：降级记忆 doc_type 落库，recall_reusable 复用 recall 不抛错。"""
    mf = _MemoryFallback(max_entries=10)
    await mf.add_experience("http://t1", "sqli", "payload1", True, "ev1", doc_type="reusable")
    assert mf._data[0]["doc_type"] == "reusable"        # 分层字段落库
    assert mf._data[0]["target"] == "http://t1"         # 明文目标仅限降级内存模式
    hits = await mf.recall_reusable("sqli", n_results=3)
    assert hits and "sqli" in hits[0]


def test_plan_step_carries_success_criteria():
    """PGEN-PLAN：Planner 验证点——success_criteria 经 _parse_plan 透传保留。"""
    agent = _bare_react_agent()
    agent.tools = {"sqli": object()}
    data = [{
        "phase": "verify", "tool": "sqli", "reason": "确认注入点",
        "expected_observation": "行数差异", "success_criteria": "HTTP 200 且 2 rows vs 0 rows",
    }]
    steps = agent._parse_plan(data)
    assert steps and steps[0]["success_criteria"] == "HTTP 200 且 2 rows vs 0 rows"
    assert steps[0]["expected_observation"] == "行数差异"


@pytest.mark.asyncio
async def test_emit_event_noop_without_bus(monkeypatch):
    """PGEN-EVENT：未注入 bus 时 emit_event 静默不抛（绝不阻塞扫描）。"""
    monkeypatch.setattr(srv, "_bus", None)
    await srv.emit_event(srv.ScanEvent.AGENT_LOG, {"tool": "sqli"})   # 不抛即过
    assert srv._bus is None
