# -*- coding: utf-8 -*-
"""SP8: AI 成本/用量台账测试（UsageLedger + ask() 透传埋点）。"""
import pytest

from vulnclaw.core_modules.metrics import UsageLedger
from vulnclaw.ai.core import LLMClient, TokenBudget


@pytest.fixture(autouse=True)
def _isolate_provider_failover(monkeypatch):
    """隔离全局 ProviderFailover 熔断状态与模型黑名单，保证台账链路用例不被跨用例状态污染。"""
    from vulnclaw.ai.provider_failover import ProviderFailover

    monkeypatch.setattr(
        "vulnclaw.ai.provider_failover._failover",
        ProviderFailover(priority=["__test__"]),
    )
    monkeypatch.setattr(LLMClient, "_blocked_models", set())


class TestUsageLedger:
    def test_record_and_breakdown(self, tmp_path, monkeypatch):
        monkeypatch.setattr(UsageLedger, "path", lambda: tmp_path / "usage.jsonl")
        UsageLedger.reset()
        UsageLedger.record("p1", "m1", 100, 50, 10.2, ok=True, site="react")
        UsageLedger.record("p1", "m1", 200, 100, 20.5, ok=True, site="react")
        UsageLedger.record("p2", "m2", 10, 5, 1.0, ok=True, site="verify")
        agg = UsageLedger.breakdown()
        assert agg[("p1", "m1")]["calls"] == 2
        assert agg[("p1", "m1")]["completion_tokens"] == 150
        assert agg[("p2", "m2")]["calls"] == 1
        tbl = UsageLedger.table(by=("provider", "model"))
        assert "p1" in tbl and "| 2 |" in tbl

    def test_record_ok_flag(self, tmp_path, monkeypatch):
        monkeypatch.setattr(UsageLedger, "path", lambda: tmp_path / "usage.jsonl")
        UsageLedger.reset()
        UsageLedger.record("p", "m", 1, 1, 1.0, ok=False, site="x")
        rows = UsageLedger.rows()
        assert rows and rows[0]["ok"] is False
        agg = UsageLedger.breakdown(by=("provider",))
        assert agg[("p",)]["ok"] == 0

    def test_by_site_dimension(self, tmp_path, monkeypatch):
        monkeypatch.setattr(UsageLedger, "path", lambda: tmp_path / "usage.jsonl")
        UsageLedger.reset()
        UsageLedger.record("p1", "m1", 1, 1, 1.0, ok=True, site="react:exploit")
        UsageLedger.record("p1", "m1", 1, 1, 1.0, ok=True, site="verify:cross")
        agg = UsageLedger.breakdown(by=("site",))
        assert set(agg.keys()) == {("react:exploit",), ("verify:cross",)}

    def test_breakdown_skips_bad_rows(self, tmp_path, monkeypatch):
        p = tmp_path / "usage.jsonl"
        monkeypatch.setattr(UsageLedger, "path", lambda: p)
        p.write_text("not-json\n{\"valid\":1}\n", encoding="utf-8")
        rows = UsageLedger.rows()
        assert rows and rows[0].get("valid") == 1
        assert UsageLedger.breakdown()[("", "")]["calls"] == 1


@pytest.mark.asyncio
async def test_ask_passes_usage_site_to_ledger(tmp_path, monkeypatch):
    """ask() -> _call_model_once 透传 usage_site，台账行 site 正确。"""
    monkeypatch.setattr(UsageLedger, "path", lambda: tmp_path / "usage.jsonl")
    UsageLedger.reset()

    async def _fake_call(self, model, prompt, system, temperature, max_tokens,
                         usage_site=None):
        UsageLedger.record(provider=self.provider, model=model, prompt_tokens=100,
                           completion_tokens=50, ms=3.2, ok=True, site=usage_site)
        return "ok-response"

    monkeypatch.setattr(LLMClient, "_call_model_once", _fake_call)
    c = LLMClient(provider="test", api_key="k", models=["m1"], api_base="http://x",
                  budget=TokenBudget(max_total_tokens=1_000_000, max_rounds=999999))
    c._semaphore = None
    c._session = None
    out = await c.ask("hi", use_cache=False, usage_site="react:general")
    assert out == "ok-response"
    rows = UsageLedger.rows()
    assert len(rows) >= 1
    r = rows[-1]
    assert r["provider"] == "test"
    assert r["model"] == "m1"
    assert r["site"] == "react:general"
    assert r["ok"] is True


@pytest.mark.asyncio
async def test_ask_default_site_is_empty(tmp_path, monkeypatch):
    """未传 usage_site 时台账行 site 为空串（不写 None）。"""
    monkeypatch.setattr(UsageLedger, "path", lambda: tmp_path / "usage.jsonl")
    UsageLedger.reset()

    async def _fake_call(self, model, prompt, system, temperature, max_tokens,
                         usage_site=None):
        UsageLedger.record(provider=self.provider, model=model, prompt_tokens=1,
                           completion_tokens=1, ms=1.0, ok=True, site=usage_site)
        return "resp"

    monkeypatch.setattr(LLMClient, "_call_model_once", _fake_call)
    c = LLMClient(provider="test", api_key="k", models=["m1"], api_base="http://x",
                  budget=TokenBudget(max_total_tokens=1_000_000, max_rounds=999999))
    c._semaphore = None
    c._session = None
    await c.ask("hi", use_cache=False)
    assert UsageLedger.rows()[-1]["site"] == ""


@pytest.mark.asyncio
async def test_ask_breaker_skipped_raises_actionable_error(tmp_path, monkeypatch):
    """全部模型被熔断跳过（而非调用失败）时：报错必须可操作（含被跳过模型与处置建议），
    不再出现笼统的 "所有模型调用均失败: None"。"""
    import time as _time

    from vulnclaw.ai.provider_failover import ProviderFailover

    async def _should_not_be_called(self, model, prompt, system, temperature,
                                    max_tokens, usage_site=None):
        raise AssertionError("熔断跳过场景不应真正发起模型调用")

    monkeypatch.setattr(LLMClient, "_call_model_once", _should_not_be_called)
    fo = ProviderFailover(priority=["zhipu"])
    fo._breakers["zhipu"]._state = "OPEN"
    # 未来时间戳保持 OPEN 不自动转 HALF_OPEN（模拟熔断期内）
    fo._breakers["zhipu"]._last_fail_time = _time.time() + 9999
    c = LLMClient(provider="zhipu", api_key="k", models=["m1"], api_base="http://x",
                  budget=TokenBudget(max_total_tokens=1_000_000, max_rounds=999999))
    c._failover = fo
    c._semaphore = None
    c._session = None
    with pytest.raises(RuntimeError) as ei:
        await c.ask("hi", use_cache=False)
    msg = str(ei.value)
    assert "熔断" in msg
    assert "均失败: None" not in msg
