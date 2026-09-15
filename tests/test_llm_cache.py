# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# 验收：P1-2 LLM Prompt 压缩 + 语义缓存（OPTIMIZATION_ROADMAP.md）
#
# 覆盖：
#   1) 语义缓存命中：相同 (model,system,prompt) 第二次请求直接命中，不再打 Provider
#   2) 语义缓存未命中：不同 prompt 触发新 Provider 调用
#   3) 默认关闭：use_cache=False（默认）时即便相同 prompt 也每次都打 Provider
#   4) TTL 过期：缓存条目超时被视作 miss，重新打 Provider 并刷新
#   5) Prompt 压缩：超长 prompt 被压成含关键三元组行的精简版；短 prompt 原样返回
#
# 全部离线：通过 monkeypatch LLMClient._call_model_once 避免真实 API 调用。
# 语义缓存是 LLMClient 类级共享结构，每个用例前清理以保证隔离。

import asyncio
import time

import pytest
from unittest.mock import AsyncMock

from vulnclaw.ai.core import LLMClient


@pytest.fixture(autouse=True)
def _reset_cache():
    """每个用例前清空类级语义缓存与命中计数，保证隔离。"""
    LLMClient._semantic_cache.clear()
    LLMClient._cache_hits = 0
    LLMClient._cache_misses = 0
    yield
    LLMClient._semantic_cache.clear()
    LLMClient._cache_hits = 0
    LLMClient._cache_misses = 0


def _make_client():
    # api_key 用占位值（ask 仅校验非空，不会真正发起请求——_call_model_once 被 mock）
    client = LLMClient(
        provider="zhipu",
        api_key="dummy-key-for-test",
        models=["test-model"],
        timeout=5,
    )
    client._call_model_once = AsyncMock(return_value="CACHED_RESULT")
    return client


def test_semantic_cache_hit_avoids_provider_call():
    """相同 prompt 第二次命中缓存：Provider 只被打一次，cache_hits==1。"""
    client = _make_client()

    r1 = asyncio.run(
        client.ask("相同的探测 prompt", system="sys", use_cache=True, models=["test-model"])
    )
    r2 = asyncio.run(
        client.ask("相同的探测 prompt", system="sys", use_cache=True, models=["test-model"])
    )

    assert r1 == "CACHED_RESULT"
    assert r2 == "CACHED_RESULT"
    # 第二次应直接命中，Provider 仅被调用一次
    assert client._call_model_once.call_count == 1
    stats = LLMClient.get_cache_stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 1  # 第一次是 miss


def test_semantic_cache_miss_on_different_prompt():
    """不同 prompt 视为不同键：两次都 miss，Provider 被打两次。"""
    client = _make_client()

    asyncio.run(client.ask("prompt-A", system="sys", use_cache=True, models=["test-model"]))
    asyncio.run(client.ask("prompt-B", system="sys", use_cache=True, models=["test-model"]))

    assert client._call_model_once.call_count == 2
    assert LLMClient.get_cache_stats()["hits"] == 0
    assert LLMClient.get_cache_stats()["misses"] == 2


def test_semantic_cache_disabled_by_default():
    """use_cache 默认 False：相同 prompt 也每次打 Provider，不产生命中。"""
    client = _make_client()

    asyncio.run(client.ask("重复 prompt", system="sys", models=["test-model"]))
    asyncio.run(client.ask("重复 prompt", system="sys", models=["test-model"]))

    assert client._call_model_once.call_count == 2
    assert LLMClient.get_cache_stats()["hits"] == 0


def test_semantic_cache_ttl_expiry():
    """缓存条目超时被视作 miss：过期后重新打 Provider 并刷新。"""
    client = _make_client()

    # 第一次：miss + 写入（now）
    asyncio.run(client.ask("ttl-prompt", system="sys", use_cache=True, models=["test-model"]))
    assert client._call_model_once.call_count == 1

    # 手动把已存条目时间戳改成过期
    key = next(iter(LLMClient._semantic_cache))
    LLMClient._semantic_cache[key] = (time.time() - 9999, "stale")

    # 第二次：条目过期 → 视为 miss → 重新打 Provider，返回新结果而非 stale
    r2 = asyncio.run(
        client.ask("ttl-prompt", system="sys", use_cache=True, models=["test-model"])
    )
    assert r2 == "CACHED_RESULT"
    assert client._call_model_once.call_count == 2


# ---- H 组: 统一缓存 key（解析后模型集合 + temperature 分档） ----
def test_cache_key_split_by_temperature():
    """temperature 参与 key：同 prompt 不同采样档位不得互相串味。"""
    client = _make_client()

    asyncio.run(client.ask("temp-key", system="sys", use_cache=True,
                           models=["test-model"], temperature=0.0))
    asyncio.run(client.ask("temp-key", system="sys", use_cache=True,
                           models=["test-model"], temperature=0.9))

    assert client._call_model_once.call_count == 2
    assert LLMClient.get_cache_stats()["hits"] == 0


def test_cache_key_model_order_invariant():
    """key 取解析后模型集合：models 传参顺序无关（sorted 归一），同档位命中。"""
    client = _make_client()

    asyncio.run(client.ask("order-key", system="sys", use_cache=True,
                           models=["test-model-a", "test-model-b"]))
    r2 = asyncio.run(client.ask("order-key", system="sys", use_cache=True,
                                models=["test-model-b", "test-model-a"]))

    assert r2 == "CACHED_RESULT"
    assert client._call_model_once.call_count == 1  # 顺序无关 → 第二次命中
    assert LLMClient.get_cache_stats()["hits"] == 1


def test_cache_key_respects_task_type_route():
    """按 task_type 路由时 key 用解析后的模型档位而非 'default'。"""
    client = _make_client()

    asyncio.run(client.ask("task-key", system="sys", use_cache=True, task_type="filter"))
    stats = LLMClient.get_cache_stats()
    assert stats["misses"] == 1
    assert stats["hits"] == 0


def test_compress_prompt_short_passthrough():
    """短 prompt 不触发压缩，原样返回。"""
    from vulnclaw.ai.v100.orchestrator import compress_prompt

    short = "请判断 http://x/?id=1 是否存在 SQL 注入"
    assert compress_prompt(short, max_len=16000) == short


def test_compress_prompt_long_keeps_key_lines():
    """超长 prompt 被压缩：长度下降、保留含 url/param/engine 的关键行。"""
    from vulnclaw.ai.v100.orchestrator import compress_prompt

    filler = "\n".join(f"无关填充行 {i}" for i in range(2000))  # 远超 16000 字符
    key_block = "url=http://x/a\nparam=id\nengine=nuclei\n"
    long_prompt = key_block + filler

    compressed = compress_prompt(long_prompt, max_len=16000)

    assert len(compressed) < len(long_prompt)
    assert "压缩后" in compressed
    assert "url=http://x/a" in compressed
    assert "param=id" in compressed
    assert "engine=nuclei" in compressed
    # 无关填充行不应被逐行保留
    assert "无关填充行 1999" not in compressed
