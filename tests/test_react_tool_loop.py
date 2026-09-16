# -*- coding: utf-8 -*-
"""T09: 通用 ReAct 工具循环 MVP 的单元测试。

覆盖：
- T09.1 正例：多步工具调用（think→act→observe）后收敛到 finish 结论。
- T09.2 max_steps 硬上限触发：LLM 一直返回 call → 优雅终止于 max_steps。
- T09.3 工具失败/治理拦截：act 返回 error → observe 把失败注入上下文，循环继续重试直至收敛。
- T09.4 上下文长度保护：超长 observation 被裁剪、总上下文超限丢弃最旧步骤（防爆 token）。
- T09.5 开关关闭：settings.react_tool_loop=False → run() 原样返回，不走循环（零行为变更）。
- T09.0 工具调用必须经治理：act 默认走 execute_tool（CLITool→tool_registry.run_tool 治理链路）。
"""
import json

import pytest

from vulnclaw.ai.tools import ReactToolLoop, TOOL_REGISTRY


class _QueueLLM:
    """按序返回预设 JSON 动作的假 LLM（模拟 think 决策）。"""

    def __init__(self, actions):
        self.actions = list(actions)
        self.calls = []

    async def ask(self, prompt, **kw):
        self.calls.append(prompt)
        if self.actions:
            return self.actions.pop(0)
        return json.dumps({"action": "finish", "conclusion": "默认结论"})


@pytest.fixture
def loop_on(monkeypatch):
    from vulnclaw.ai import tools as aitools

    monkeypatch.setattr(aitools.settings, "react_tool_loop", True)
    monkeypatch.setattr(aitools.settings, "react_tool_loop_max_steps", 6)


@pytest.fixture
def loop_off(monkeypatch):
    from vulnclaw.ai import tools as aitools

    monkeypatch.setattr(aitools.settings, "react_tool_loop", False)


# ---------------------------------------------------------------------------
# T09.1 正例：多步工具调用收敛到结论
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_t09_1_multi_step_converges_to_conclusion(loop_on, monkeypatch):
    from vulnclaw.ai import tools as aitools

    loop = ReactToolLoop(
        llm=_QueueLLM([
            {"action": "call", "tool": "httpx", "extra_args": ""},
            {"action": "call", "tool": "nuclei", "extra_args": "-t cve.yaml"},
            {"action": "finish", "conclusion": "发现 CVE-2021-41773 痕迹"},
        ]),
        max_steps=6,
    )

    acted = []

    async def _fake_act(tool, target, extra_args="", **kw):
        acted.append((tool, extra_args, target))
        return {"success": True, "summary": f"{tool} 返回命中: 2 obs"}

    monkeypatch.setattr(loop, "act", _fake_act)

    out = await loop.run(["httpx", "nuclei"], target="http://t.example.com")

    assert out["enabled"] is True
    assert out["stopped_reason"] == "concluded"
    assert out["conclusion"] == "发现 CVE-2021-41773 痕迹"
    assert [a[0] for a in acted] == ["httpx", "nuclei"]       # 两次成功工具调用
    assert out["tool_calls"] == 2                             # tool_calls=已执行工具数
    assert [s["tool"] for s in out["steps"]] == ["httpx", "nuclei"]
    assert all(s["success"] is True for s in out["steps"])
    assert "httpx 返回命中" in out["steps"][0]["observation"]


# ---------------------------------------------------------------------------
# T09.2 max_steps 触发：LLM 一直返回 call，优雅终止于上限，不无限循环
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_t09_2_max_steps_hard_limit(loop_on, monkeypatch):
    max_steps = 3
    loop = ReactToolLoop(
        llm=_QueueLLM([{"action": "call", "tool": "httpx", "extra_args": ""}] * 10),
        max_steps=max_steps,
    )
    acted = []

    async def _fake_act(tool, target, extra_args="", **kw):
        acted.append(tool)
        return {"success": True, "summary": "ok"}

    monkeypatch.setattr(loop, "act", _fake_act)

    out = await loop.run(["httpx"], target="http://t.example.com")

    assert out["stopped_reason"] == "max_steps"
    assert out["tool_calls"] == max_steps
    assert len(acted) == max_steps       # 恰好烧满上限步数，不再增长 → 防 runaway
    assert len(out["steps"]) == max_steps


# ---------------------------------------------------------------------------
# T09.3 工具失败/治理拦截 → observe 记录失败，循环继续重试直至收敛
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_t09_3_tool_failure_intercepted_then_retry(loop_on, monkeypatch):
    loop = ReactToolLoop(
        llm=_QueueLLM([
            {"action": "call", "tool": "ffuf", "extra_args": ""},
            {"action": "finish", "conclusion": "目录枚举失败后改用方案得到结论"},
        ]),
        max_steps=6,
    )
    results = [
        # 第一次被治理/工具拦截：返回错误（如 DangerGuard deny 或未注册）
        {"success": False, "error": "[DangerGuard] 参数被拒绝（危险参数黑名单）"},
    ]

    async def _fake_act(tool, target, extra_args="", **kw):
        r = results.pop(0)
        return dict(r, tool=tool)

    monkeypatch.setattr(loop, "act", _fake_act)

    out = await loop.run(["ffuf"], target="http://t.example.com")

    assert out["stopped_reason"] == "concluded"
    # 失败被 observe 注入上下文，且循环未被异常打断 → 从观察到重试语义成立
    step = out["steps"][0]
    assert step["success"] is False
    assert "DangerGuard" in step["error"] or "DangerGuard" in step["observation"]
    assert step["tool"] == "ffuf"
    assert out["conclusion"] == "目录枚举失败后改用方案得到结论"


# ---------------------------------------------------------------------------
# T09.4 上下文长度保护：裁剪超长 + 丢弃最旧超限步骤（防爆 token）
# ---------------------------------------------------------------------------
def test_t09_4_context_length_guard_clips_and_evicts():
    loop = ReactToolLoop(max_steps=3, max_context_chars=100)
    # 单个 observation 超长 → 被裁剪到 per-step 上限
    ctx = []
    loop.observe(ctx, "t", "httpx", {"success": True, "summary": "x" * 5000})
    assert len(ctx[0]["observation"]) < 500   # 已被 _clip 裁剪（步上限 = 100//3 ≈ 33）

    # 多步骤总上下文超限 → 丢弃最旧（先进先出）
    ctx = []
    for i in range(6):
        loop.observe(ctx, f"t{i}", f"tool{i}", {"success": True, "summary": "y" * 40})
    total = sum(len(str(s["observation"])) for s in ctx)
    assert total <= loop.max_context_chars      # 总上下文始终受上限约束
    assert len(ctx) < 6                          # 最旧若干条已被逐出（FIFO 逐出确实发生）
    assert ctx[0]["tool"] == "tool4"            # 裁剪含截断后缀 → 每步 ≈33+13=46；6 步累计超限 → 逐出最旧到剩 tool4..


# ---------------------------------------------------------------------------
# T09.5 开关关闭：run() 原样返回，不走循环（零行为变更）
# ---------------------------------------------------------------------------
def test_t09_5_disabled_returns_without_loop(loop_off, monkeypatch):
    llm = _QueueLLM([])  # 若进入循环会消费/抛错
    loop = ReactToolLoop(llm=llm, max_steps=3)

    async def _fake_act(tool, target, extra_args="", **kw):
        raise AssertionError("开关关闭时不应执行任何工具")

    monkeypatch.setattr(loop, "act", _fake_act)

    import asyncio

    out = asyncio.run(loop.run(["httpx"], target="http://t.example.com"))

    assert out == {"enabled": False, "conclusion": "", "steps": [], "tool_calls": 0}
    assert llm.calls == []      # think 未被调用 → 循环确实被短路


# ---------------------------------------------------------------------------
# T09.0 act 必须经治理：未过治理注册的工具被拒绝；过注册的走 execute_tool 治理入口
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_t09_0_act_rejects_unregistered_tool(loop_on):
    loop = ReactToolLoop(max_steps=3)
    result = await loop.act("__not_registered_tool__", "http://t.example.com")
    assert result["success"] is False
    assert "未注册" in result["error"] or "未知工具" in result["error"]


# 说明：真实 act 走 execute_tool → TOOL_REGISTRY → CLITool.execute → run_tool 治理链路，
# 该链路已由 existing CLITool 单测覆盖；此处以 rejected 分支锁定"不过治理不可执行"的兜底。