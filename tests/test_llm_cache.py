# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""A4.5: 语义缓存（P1-2）单元测试。

覆盖：同 prompt 二次调用命中（hit +1，模型仅真实调用一次）；
      不同 prompt / 不同模型不命中；空白归一化（语义等价命中）；
      TTL 过期后重新计算（含恰好 TTL 边界）；512 上限的过期清理与裁剪；
      get_cache_stats() 的 hits/misses/hit_rate/size 正确性。

零外网：monkeypatch _call_model_once 为假应答，不真调 LLM。
"""
import hashlib
import time

import pytest

from vulnclaw.ai.core import LLMClient, TokenBudget

_MODEL = "test-cache-model"


@pytest.fixture
def client(monkeypatch):
    """干净的 LLMClient：类级缓存状态重置 + _call_model_once 假应答。"""
    # 类级缓存是全局共享的，逐用例重置，避免用例间互相污染
    monkeypatch.setattr(LLMClient, "_semantic_cache", {})
    monkeypatch.setattr(LLMClient, "_cache_hits", 0)
    monkeypatch.setattr(LLMClient, "_cache_misses", 0)

    calls = []

    async def _fake_call(model, prompt, system, temperature, max_tokens, usage_site=None, **kw):
        calls.append((model, prompt))
        return f"answer-{len(calls)}"

    c = LLMClient(models=[_MODEL], budget=TokenBudget())
    c.api_key = "test-key"
    monkeypatch.setattr(c, "_call_model_once", _fake_call)
    c._fake_calls = calls
    return c


async def _ask(client, prompt, system=None, models=None, **kw):
    return await client.ask(
        prompt=prompt,
        system=system,
        models=models or [_MODEL],
        use_cache=kw.pop("use_cache", True),
        **kw,
    )


@pytest.mark.asyncio
async def test_cache_hit_second_call(client):
    """同 prompt 二次调用：命中缓存，模型只被真实调用一次。"""
    r1 = await _ask(client, "判断该输入是否存在注入风险", system="你是安全分析专家")
    r2 = await _ask(client, "判断该输入是否存在注入风险", system="你是安全分析专家")
    assert r1 == r2
    assert len(client._fake_calls) == 1  # 第二次走缓存，不再调模型
    stats = LLMClient.get_cache_stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 1
    assert stats["hit_rate"] == 0.5


@pytest.mark.asyncio
async def test_cache_miss_on_different_prompt(client):
    """不同 prompt：均未命中，各自真实调用一次。"""
    await _ask(client, "prompt-A")
    await _ask(client, "prompt-B")
    stats = LLMClient.get_cache_stats()
    assert stats["hits"] == 0
    assert stats["misses"] == 2
    assert len(client._fake_calls) == 2


@pytest.mark.asyncio
async def test_cache_key_normalizes_whitespace(client):
    """缓存 key 按空白归一化：仅空白差异的 prompt 视为同一请求。"""
    await _ask(client, "  a    b  c ")
    await _ask(client, " a b c")
    stats = LLMClient.get_cache_stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 1


@pytest.mark.asyncio
async def test_cache_key_includes_model(client):
    """缓存 key 含模型名：同 prompt 不同模型 → 不命中。"""
    await _ask(client, "same prompt", models=["model-a"])
    await _ask(client, "same prompt", models=["model-b"])
    stats = LLMClient.get_cache_stats()
    assert stats["hits"] == 0
    assert stats["misses"] == 2


@pytest.mark.asyncio
async def test_cache_ttl_exact_boundary_hits(client, monkeypatch):
    """TTL 边界：elapsed 恰好等于 TTL（<= 判定）→ 仍命中。"""
    clock = [2000.0]
    monkeypatch.setattr("vulnclaw.ai.core.time.time", lambda: clock[0])
    await _ask(client, "boundary prompt")
    clock[0] = 2000.0 + LLMClient._semantic_cache_ttl
    await _ask(client, "boundary prompt")
    stats = LLMClient.get_cache_stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 1


@pytest.mark.asyncio
async def test_cache_ttl_expiry_recomputes(client, monkeypatch):
    """TTL 过期：条目作废并重新计算，新条目随后可命中。"""
    clock = [1000.0]
    monkeypatch.setattr("vulnclaw.ai.core.time.time", lambda: clock[0])
    await _ask(client, "ttl prompt")  # miss → 写入（@1000）
    assert LLMClient.get_cache_stats()["misses"] == 1

    clock[0] = 1000.0 + LLMClient._semantic_cache_ttl + 0.1
    await _ask(client, "ttl prompt")  # 过期 → 重新计算（miss）
    stats = LLMClient.get_cache_stats()
    assert stats["misses"] == 2
    assert stats["hits"] == 0
    assert stats["size"] == 1  # 旧条目已被弹出

    await _ask(client, "ttl prompt")  # 新条目在有效期内 → hit
    assert LLMClient.get_cache_stats()["hits"] == 1


@pytest.mark.asyncio
async def test_cache_max_512_trims(client):
    """超过 512 上限：先清过期，仍超限则裁剪到 max//2。"""
    now = time.time()
    LLMClient._semantic_cache.update(
        {f"seed-{i}": (now, f"x{i}") for i in range(LLMClient._semantic_cache_max + 1)}
    )
    assert len(LLMClient._semantic_cache) == 513

    await _ask(client, "overflow prompt")  # miss → 写入 → 触发裁剪

    stats = LLMClient.get_cache_stats()
    assert stats["size"] == LLMClient._semantic_cache_max // 2  # 512 → 256
    assert stats["misses"] == 1
    # 新写入的 key 必须保留（裁剪保留最后插入的条目）
    norm = " ".join("overflow prompt".split())
    norm_sys = " ".join("".split())
    new_key = hashlib.sha256(f"{_MODEL}||{norm_sys}||{norm}".encode("utf-8")).hexdigest()
    assert new_key in LLMClient._semantic_cache
    # 最早插入的种子条目应被裁剪掉
    assert "seed-0" not in LLMClient._semantic_cache


@pytest.mark.asyncio
async def test_cache_trim_removes_expired_first(client):
    """超上限时先清理过期条目；清理后未超限则不再裁剪。"""
    now = time.time()
    fresh = {f"f-{i}": (now, "x") for i in range(300)}
    stale = {f"s-{i}": (now - LLMClient._semantic_cache_ttl - 10, "x") for i in range(213)}
    LLMClient._semantic_cache.update(fresh)
    LLMClient._semantic_cache.update(stale)
    assert len(LLMClient._semantic_cache) == 513

    await _ask(client, "expired-trim prompt")

    stats = LLMClient.get_cache_stats()
    # 213 条过期全部清除，300 fresh + 1 新条目 = 301，无需二次裁剪
    assert stats["size"] == 301


@pytest.mark.asyncio
async def test_no_cache_side_effect_when_disabled(client):
    """use_cache=False：不读不写缓存，统计与模型调用均不受影响。"""
    await _ask(client, "nocache", use_cache=False)
    await _ask(client, "nocache", use_cache=False)
    stats = LLMClient.get_cache_stats()
    assert stats["hits"] == 0
    assert stats["misses"] == 0
    assert stats["size"] == 0
    assert len(client._fake_calls) == 2  # 每次都真实调用


@pytest.mark.asyncio
async def test_cache_stats_zero_before_calls(client):
    """无任何调用：hit_rate 兜底为 0，不除零。"""
    stats = LLMClient.get_cache_stats()
    assert stats["hits"] == 0
    assert stats["misses"] == 0
    assert stats["hit_rate"] == 0.0
    assert stats["size"] == 0
    assert stats["ttl_seconds"] == LLMClient._semantic_cache_ttl


@pytest.mark.asyncio
async def test_cache_stats_hit_rate(client):
    """hit_rate = hits / (hits + misses) 四舍五入到 4 位。"""
    await _ask(client, "p1")
    await _ask(client, "p1")  # hit
    await _ask(client, "p2")  # miss
    stats = LLMClient.get_cache_stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 2
    assert stats["hit_rate"] == round(1 / 3, 4)
    assert stats["size"] == 2  # p1 / p2 两条均存活
