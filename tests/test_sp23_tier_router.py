# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""SP23 A4.4: 任务分层模型路由 单元测试。

覆盖：开关关闭回退全量池（与 get_client 等价）/ 开关开启 cheap/expensive 落位对应
      模型码子集 / 档位子集内故障路由仍生效 / 未配置 tier 字段零报错回退 /
      cost_router 粗筛接线（开关关闭走原路径、开启走 cheap 档、异常回退）。
零外网依赖：直接构造 ProviderBalancer 并注入 fake client，不真调 API。
"""
import pytest

from vulnclaw.ai.cost_router import PRESCREEN_SITE, pre_screen_candidates
from vulnclaw.ai.v100.provider_balancer import ProviderBalancer, get_tier_client
from vulnclaw.core.settings import settings


class _FakeClient:
    """最小 client 替身：只承载 model 属性，不触网。"""

    def __init__(self, model: str):
        self.model = model


def _make_balancer() -> ProviderBalancer:
    b = ProviderBalancer()
    b._initialized = True
    for cfg in b.providers.values():
        cfg["client"] = _FakeClient(cfg["model"])
        cfg["available"] = True
    return b


def _canonical_aliases(b):
    """与 balancer 硬编码 provider 模型一致的别名表（保证测试与运行环境解耦）。"""
    return {
        "1": b.providers["zhipu"]["model"],
        "2": b.providers["aliyun"]["model"],
        "4": b.providers["siliconflow"]["model"],
        "5": "glm-4.7",
    }


def _enable_tier(monkeypatch, b):
    monkeypatch.setattr(settings, "model_tier_routing", True)
    monkeypatch.setattr(settings, "ai_model_aliases", _canonical_aliases(b))
    return b


@pytest.mark.asyncio
async def test_off_switch_returns_same_pool_as_get_client(monkeypatch):
    monkeypatch.setattr(settings, "model_tier_routing", False)
    b = _make_balancer()
    _c, provider, _m = await b.get_client_for_tier("cheap")
    assert provider in b.get_all_providers()
    # 开关关闭时与 get_client 等价：即使 cheap 子集全挂，仍可命中 expensive-only 供应商
    for _ in range(3):
        await b.record_result("zhipu", False)
        await b.record_result("aliyun", False)
    _c, provider, _m = await b.get_client_for_tier("cheap")
    assert provider == "siliconflow"


@pytest.mark.asyncio
async def test_on_switch_lands_on_model_code_subsets(monkeypatch):
    b = _enable_tier(monkeypatch, _make_balancer())
    _c, p1, m1 = await b.get_client_for_tier("cheap")
    assert p1 in ("zhipu", "aliyun")
    assert m1 in ("glm-4-flash", "qwen-plus-2025-07-28")
    _c, p2, m2 = await b.get_client_for_tier("expensive")
    assert p2 in ("siliconflow",)
    assert m2 == "deepseek-ai/DeepSeek-V3.1-Terminus"


@pytest.mark.asyncio
async def test_failover_within_tier_subset(monkeypatch):
    b = _enable_tier(monkeypatch, _make_balancer())
    # cheap 子集内：zhipu 连续失败 3 次进入冷却 → 自动切到同子集 aliyun
    for _ in range(3):
        await b.record_result("zhipu", False)
    _c, p, _m = await b.get_client_for_tier("cheap")
    assert p == "aliyun"
    assert b.providers["zhipu"]["available"] is False
    # expensive 子集不受 cheap 故障影响
    _c, p2, _m = await b.get_client_for_tier("expensive")
    assert p2 == "siliconflow"


@pytest.mark.asyncio
async def test_unconfigured_tier_fields_default_fallback(monkeypatch):
    monkeypatch.delattr(settings, "model_tier_routing", raising=False)
    monkeypatch.delattr(settings, "tier_cheap_codes", raising=False)
    monkeypatch.delattr(settings, "tier_expensive_codes", raising=False)
    b = _make_balancer()
    _c, p, _m = await b.get_client_for_tier("cheap")
    assert p in b.get_all_providers()
    _c, p2, _m = await b.get_client_for_tier("expensive")
    assert p2 in b.get_all_providers()


@pytest.mark.asyncio
async def test_empty_tier_subset_falls_back_to_full_pool(monkeypatch):
    b = _enable_tier(monkeypatch, _make_balancer())
    monkeypatch.setattr(settings, "tier_cheap_codes", ["99", "98"])
    _c, p, _m = await b.get_client_for_tier("cheap")
    assert p in b.get_all_providers()  # 无匹配 → 回退全量池，不报错


@pytest.mark.asyncio
async def test_unknown_tier_falls_back(monkeypatch):
    b = _enable_tier(monkeypatch, _make_balancer())
    _c, p, _m = await b.get_client_for_tier("ultra")
    assert p in b.get_all_providers()


@pytest.mark.asyncio
async def test_get_tier_client_module_helper(monkeypatch):
    import vulnclaw.ai.v100.provider_balancer as pb

    b = _enable_tier(monkeypatch, _make_balancer())
    monkeypatch.setattr(pb, "_balancer", b)
    _c, p, _m = await get_tier_client("cheap")
    assert p in ("zhipu", "aliyun")
    _c, p2, _m = await get_tier_client("expensive")
    assert p2 == "siliconflow"


@pytest.mark.asyncio
async def test_prescreen_off_switch_uses_original_path(monkeypatch):
    monkeypatch.setattr(settings, "model_tier_routing", False)
    seen = {}

    class _FakeOrch:
        async def _ask_ai(self, prompt, system="", temperature=0.1, max_tokens=2048,
                          compress=False, use_cache=False, task_type="default", usage_site=""):
            seen["task_type"] = task_type
            seen["usage_site"] = usage_site
            return '{"false_positives": []}'

    cands = [{"type": "sqli", "url": "http://t/p", "parameter": "q", "evidence": "e"}]
    fp_ids, calls = await pre_screen_candidates(_FakeOrch(), cands, batch_size=10)
    assert calls == 1
    assert seen.get("task_type") == "filter"
    assert seen.get("usage_site") == PRESCREEN_SITE
    assert fp_ids == set()


@pytest.mark.asyncio
async def test_prescreen_uses_cheap_tier_when_enabled(monkeypatch):
    import vulnclaw.ai.v100.provider_balancer as pb

    monkeypatch.setattr(settings, "model_tier_routing", True)
    captured = {}
    called = {"client_ask": 0, "orch": 0}

    class _FakeClient:
        async def ask(self, prompt, **kwargs):
            called["client_ask"] += 1
            return '{"false_positives": [0]}'

    fake_client = _FakeClient()

    async def _tier_client(tier):
        captured["tier"] = tier
        return fake_client, "zhipu", "glm-4-flash"

    monkeypatch.setattr(pb, "get_tier_client", _tier_client)

    class _FakeOrch:
        async def _ask_ai(self, *args, **kwargs):
            called["orch"] += 1
            return '{"false_positives": []}'

    cands = [{"type": "sqli", "url": "http://t/p", "parameter": "q", "evidence": "e"}]
    fp_ids, calls = await pre_screen_candidates(_FakeOrch(), cands, batch_size=10)
    assert calls == 1
    assert captured["tier"] == "cheap"
    assert called["client_ask"] == 1
    assert called["orch"] == 0  # 档位直调成功，未走 orch._ask_ai
    assert fp_ids == {id(cands[0])}


@pytest.mark.asyncio
async def test_prescreen_tier_failure_falls_back_to_orch(monkeypatch):
    import vulnclaw.ai.v100.provider_balancer as pb

    monkeypatch.setattr(settings, "model_tier_routing", True)

    async def _boom(tier):
        raise RuntimeError("tier client down")

    monkeypatch.setattr(pb, "get_tier_client", _boom)
    seen = {}

    class _FakeOrch:
        async def _ask_ai(self, prompt, system="", temperature=0.1, max_tokens=2048,
                          compress=False, use_cache=False, task_type="default", usage_site=""):
            seen["task_type"] = task_type
            seen["usage_site"] = usage_site
            return '{"false_positives": []}'

    cands = [{"type": "sqli", "url": "http://t/p", "parameter": "q", "evidence": "e"}]
    fp_ids, calls = await pre_screen_candidates(_FakeOrch(), cands, batch_size=10)
    assert calls == 1
    assert seen.get("task_type") == "filter"
    assert seen.get("usage_site") == PRESCREEN_SITE
    assert fp_ids == set()
