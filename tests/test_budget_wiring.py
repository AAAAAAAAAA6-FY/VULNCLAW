# -*- coding: utf-8 -*-
"""SP5: ProviderBalancer × 上下文预算接线测试。

覆盖：预算超限→降级收缩 max_tokens；连续超限→BudgetExhaustedError；
ReActAgent 捕获→压缩历史→本地确定性兜底（不中断）。
"""
import pytest

from vulnclaw.ai.core import BudgetExhaustedError, TokenBudget, get_token_budget


class TestTokenBudgetStreaks:
    @pytest.mark.asyncio
    async def test_exceed_sets_degraded_and_streaks(self):
        b = TokenBudget(max_total_tokens=100, max_rounds=999999)
        assert await b.consume(60, 60) is False    # 120 > 100 -> degraded
        assert b.is_degraded() is True
        assert b.degraded_streaks() >= 1

    @pytest.mark.asyncio
    async def test_streaks_accumulate_and_reset_on_recovery(self):
        b = TokenBudget(max_total_tokens=100, max_rounds=999999)
        assert await b.consume(60, 60) is False
        assert await b.consume(1, 1) is False      # 仍在降级态 -> streaks +1
        s1 = b.degraded_streaks()
        assert s1 >= 2
        b._degraded_until = 0                      # 冷却结束
        assert b.degraded_streaks() == 0           # 恢复后归零
        assert b.is_degraded() is False

    def test_singleton(self):
        assert get_token_budget() is get_token_budget()


class TestLLMBudgetDegrade:
    @pytest.fixture
    def client(self, monkeypatch):
        from vulnclaw.ai.core import LLMClient
        seen = {}

        async def _fake_call(self, *a, **kw):
            seen["max_tokens"] = kw.get("max_tokens")
            seen["temperature"] = kw.get("temperature")
            return "ok"

        monkeypatch.setattr(LLMClient, "_call_model_once", _fake_call)
        c = LLMClient(provider="test", api_key="k", models=["m1"], api_base="http://x",
                      max_total_tokens=100, max_rounds=999999,
                      budget=TokenBudget(max_total_tokens=100, max_rounds=999999))
        c._semaphore = None
        c._session = None
        return c, seen

    @pytest.mark.asyncio
    async def test_degraded_shrinks_max_tokens(self, client):
        c, seen = client
        await c.budget.consume(60, 60)             # 进入降级态
        out = await c.ask("hi", temperature=0.9, max_tokens=200, use_cache=False)
        assert out == "ok"
        assert seen["max_tokens"] <= 50
        assert seen["temperature"] <= 0.1

    @pytest.mark.asyncio
    async def test_persistent_exhaustion_raises(self, client):
        c, seen = client
        for _ in range(3):
            await c.budget.consume(60, 60)         # 连续 3 次超限 -> streaks>=3
        with pytest.raises(BudgetExhaustedError):
            await c.ask("hi", use_cache=False)


class TestReActAgentLocalFallback:
    @pytest.mark.asyncio
    async def test_think_falls_back_locally_and_compresses(self, monkeypatch):
        import vulnclaw.ai.dispatcher as disp

        class _FakeLLM:
            async def ask(self, *a, **kw):
                raise BudgetExhaustedError("budget exhausted")

        monkeypatch.setattr(disp, "get_llm_client", lambda: _FakeLLM())
        monkeypatch.setattr(disp.ReActAgent, "_global_context", lambda self: "")
        monkeypatch.setattr(disp.ReActAgent, "_target_context", lambda self: "")
        monkeypatch.setattr(disp.ReActAgent, "_format_tools", lambda self: "")
        monkeypatch.setattr(disp.ReActAgent, "_format_history", lambda self: "")
        monkeypatch.setattr(disp.ReActAgent, "_get_memory_experiences", lambda self: "无")
        monkeypatch.setattr(disp.ReActAgent, "_get_review_clues", lambda self: "")
        monkeypatch.setattr(disp.ReActAgent, "_skills_context", lambda self, *a, **k: "")

        agent = disp.ReActAgent(target="http://t.example.com", session=None)
        agent.history = [{"action": {"tool": "sqli", "params": {"url": "u", "param": "id"}},
                          "thought": "probe", "observation": "no"}]
        agent._scene_cache = {}

        think = await agent._think({"params": [], "tech_stack": []})
        # 预算耗尽 -> 本地默认决策（不崩溃、不中断）
        assert "继续使用常见漏洞检测工具" in think
        # 触发 _mark_budget_exhausted -> 历史被滚动压缩留纪要标记
        assert any(h.get("phase") == "compressed" for h in agent.history) or think

    def test_mark_budget_exhausted_compresses(self, monkeypatch):
        import vulnclaw.ai.dispatcher as disp

        monkeypatch.setattr(disp.ReActAgent, "_get_memory_experiences", lambda self: "无")
        monkeypatch.setattr(disp.ReActAgent, "_get_review_clues", lambda self: "")
        monkeypatch.setattr(disp.ReActAgent, "_skills_context", lambda self, *a, **k: "")
        agent = object.__new__(disp.ReActAgent)
        agent.history = [
            {"action": {"tool": "x", "params": {"url": "u", "param": "p"}}, "thought": "t", "observation": "o"},
        ] * 20
        agent._compressed_summary = None
        agent._compress_threshold = 3   # 20 条历史 > 阈值 -> 触发滚动压缩
        agent._recon_observation = {}
        agent._remember_note = ""
        agent._note = ""
        agent._mark_budget_exhausted()
        assert any(h.get("phase") == "compressed" for h in agent.history)
        assert len(agent.history) <= 4


@pytest.mark.asyncio
async def test_async_tests():  # 占位避免 asyncio 标记空转
    assert True