# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 20：RedisContext（redis_backend.py）专项单元测试。

覆盖 Redis 后端上下文的完整行为，全程 mock Redis 客户端（不真连 Redis）：

  1. 降级路径：from_url 抛异常 -> 自动进入内存 fallback 模式，set/get/update/
     get_and_clear/get_all/clear/has 全部走 _fallback_data，行为与 DAGContext 一致；
  2. Redis 路径：from_url 返回 fake client，验证 set 按类型序列化
     （str 直接存 / int-float-bool 与 dict-list 走 JSON / 复杂对象走 pickle+base64）、
     get 读回反序列化正确、key 命名 {prefix}:ctx:{key}；
  3. 降级后不重连：首次连接失败后 _fallback_mode 锁定内存模式，from_url 不再被调用；
  4. 序列化边界：None / bool / list / dict 嵌套 / float / 复杂对象 round-trip 正确；
  5. update 在 key 不存在时的行为（直接 set 新值），list 扩展 / dict 合并 / 其他覆盖。

说明：项目 pytest 为 asyncio_mode=strict，异步方法统一用 asyncio.run 驱动，
不依赖 pytest-asyncio。全文件无 emoji（Windows 控制台硬约束）。
"""
import asyncio
import base64
import fnmatch
import json
import os
import pickle
from unittest.mock import AsyncMock, patch

import pytest

from vulnclaw.distributed.redis_backend import RedisContext

REDIS_URL = "redis://127.0.0.1:6379/0"
PREFIX = "vulnclaw"


class _ComplexValue:
    """用于 pickle 序列化路径的自定义类型（模块级保证可 pickle）。"""

    def __init__(self, name, tags):
        self.name = name
        self.tags = tags

    def __eq__(self, other):
        return (
            isinstance(other, _ComplexValue)
            and self.name == other.name
            and self.tags == other.tags
        )


class _FakeRedis:
    """带内存存储的假 Redis 客户端（async 方法签名与 redis.asyncio.Redis 一致）。"""

    def __init__(self, store=None):
        self.store = store if store is not None else {}
        self.ping_count = 0

    async def ping(self):
        self.ping_count += 1
        return True

    async def set(self, key, value):
        self.store[key] = value
        return True

    async def get(self, key):
        return self.store.get(key)

    async def delete(self, *keys):
        removed = 0
        for k in keys:
            if k in self.store:
                del self.store[k]
                removed += 1
        return removed

    async def keys(self, pattern):
        self.keys_calls = getattr(self, "keys_calls", 0) + 1
        return [k for k in self.store if fnmatch.fnmatchcase(k, pattern)]

    async def scan(self, cursor=0, match=None, count=100):
        """P1-12：SCAN 增量迭代（单次返回，游标回 0 结束）。"""
        self.scan_calls = getattr(self, "scan_calls", 0) + 1
        keys = [k for k in self.store if fnmatch.fnmatchcase(k, match or "*")]
        return 0, keys[: int(count or 100)]

    async def mget(self, keys):
        self.mget_calls = getattr(self, "mget_calls", 0) + 1
        return [self.store.get(k) for k in keys]

    async def setnx(self, key, value):
        if key in self.store:
            return False
        self.store[key] = value
        return True

    async def exists(self, key):
        return 1 if key in self.store else 0


def _make_ctx() -> RedisContext:
    return RedisContext(redis_url=REDIS_URL, prefix=PREFIX)


async def _run_fallback(scenario) -> RedisContext:
    """在 from_url 抛异常的降级环境下运行 scenario，返回 ctx 供断言。"""
    ctx = _make_ctx()
    with patch("redis.asyncio.from_url", side_effect=ConnectionError("no redis server")):
        await scenario(ctx)
    return ctx


# ============================================================
# P0-8 / P1-12：降级可观测 + fail-stop + SCAN/MGET 替代 KEYS
# ============================================================
class TestDegradedObservability:
    def test_fallback_reports_degraded_state(self):
        """P0-8：降级必须可观测（不许再静默当成功）。"""
        async def scenario(ctx):
            await ctx.set("k", 1)
        ctx = asyncio.run(_run_fallback(scenario))
        assert ctx.degraded() is True
        info = ctx.degraded_info()
        assert info["degraded"] is True
        assert "connect" in (info["reason"] or ""), info

    def test_fail_stop_raises_instead_of_silent_fallback(self):
        """P0-8：fail-stop 开启 → 抛错，不用节点本地内存冒充分布式状态。"""
        ctx = _make_ctx()
        ctx._fail_stop = True
        with patch("redis.asyncio.from_url", side_effect=ConnectionError("down")):
            try:
                asyncio.run(ctx.set("k", 1))
            except RuntimeError as exc:
                assert "fail-stop" in str(exc)
            else:
                raise AssertionError("fail-stop 开启时未抛错（仍会静默降级！）")

    def test_default_is_not_fail_stop(self):
        """默认关闭，保证无 Redis 单机场景可用性不回归。"""
        ctx = _make_ctx()
        assert ctx._fail_stop is False


class TestScanInsteadOfKeys:
    @staticmethod
    def _ctx_with_fake(store=None):
        fake = _FakeRedis(store or {})
        ctx = _make_ctx()
        ctx._redis = fake
        return ctx, fake

    def test_get_all_uses_scan_and_mget(self):
        """P1-12：get_all 走 SCAN+MGET，不再 KEYS + 逐 key GET。"""
        async def scenario():
            ctx, fake = self._ctx_with_fake({
                "vulnclaw:ctx:a": b"s:1", "vulnclaw:ctx:b": b"j:2"})
            got = await ctx.get_all()
            assert got == {"a": "1", "b": 2}
            assert getattr(fake, "scan_calls", 0) >= 1
            assert getattr(fake, "mget_calls", 0) >= 1
            assert getattr(fake, "keys_calls", 0) == 0
        asyncio.run(scenario())

    def test_clear_uses_scan(self):
        async def scenario():
            ctx, fake = self._ctx_with_fake({
                "vulnclaw:ctx:a": b"s:1", "vulnclaw:ctx:b": b"s:2"})
            await ctx.clear()
            assert fake.store == {}
            assert getattr(fake, "scan_calls", 0) >= 1
            assert getattr(fake, "keys_calls", 0) == 0
        asyncio.run(scenario())

    def test_falls_back_to_keys_when_scan_unavailable(self):
        class _NoScan(_FakeRedis):
            async def scan(self, *a, **k):
                raise AttributeError("no scan")

        async def scenario():
            ctx = _make_ctx()
            ctx._redis = _NoScan({"vulnclaw:ctx:z": b"s:9"})
            assert await ctx.get_all() == {"z": "9"}
        asyncio.run(scenario())


# ============================================================
# 1. 降级路径：Redis 不可用 -> 内存 fallback
# ============================================================
class TestFallbackMode:
    def test_set_get_roundtrip(self):
        async def scenario(ctx):
            await ctx.set("k", "value")
            assert await ctx.get("k") == "value"
            assert ctx._fallback_mode is True

        asyncio.run(_run_fallback(scenario))

    def test_get_missing_returns_none(self):
        async def scenario(ctx):
            assert await ctx.get("missing") is None

        asyncio.run(_run_fallback(scenario))

    def test_get_missing_returns_default(self):
        async def scenario(ctx):
            assert await ctx.get("missing", "dflt") == "dflt"

        asyncio.run(_run_fallback(scenario))

    def test_update_list_extend(self):
        async def scenario(ctx):
            await ctx.set("k", [1])
            await ctx.update("k", [2, 3])
            assert await ctx.get("k") == [1, 2, 3]

        asyncio.run(_run_fallback(scenario))

    def test_update_dict_merge(self):
        async def scenario(ctx):
            await ctx.set("k", {"a": 1})
            await ctx.update("k", {"b": 2})
            assert await ctx.get("k") == {"a": 1, "b": 2}

        asyncio.run(_run_fallback(scenario))

    def test_update_missing_key_sets_value(self):
        async def scenario(ctx):
            await ctx.update("k", "new")
            assert await ctx.get("k") == "new"

        asyncio.run(_run_fallback(scenario))

    def test_update_other_type_overwrites(self):
        async def scenario(ctx):
            await ctx.set("k", 1)
            await ctx.update("k", "x")
            assert await ctx.get("k") == "x"

        asyncio.run(_run_fallback(scenario))

    def test_get_and_clear(self):
        async def scenario(ctx):
            await ctx.set("k", {"a": 1})
            assert await ctx.get_and_clear("k") == {"a": 1}
            assert await ctx.get("k") is None
            assert await ctx.has("k") is False

        asyncio.run(_run_fallback(scenario))

    def test_clear(self):
        async def scenario(ctx):
            await ctx.set("a", 1)
            await ctx.set("b", 2)
            await ctx.clear()
            assert await ctx.get("a") is None
            assert await ctx.get_all() == {}

        asyncio.run(_run_fallback(scenario))

    def test_has(self):
        async def scenario(ctx):
            assert await ctx.has("k") is False
            await ctx.set("k", 1)
            assert await ctx.has("k") is True

        asyncio.run(_run_fallback(scenario))

    def test_get_all_returns_copy(self):
        async def scenario(ctx):
            await ctx.set("a", 1)
            await ctx.set("b", 2)
            result = await ctx.get_all()
            assert result == {"a": 1, "b": 2}
            result["a"] = 999
            # 返回值是副本，不影响内部数据
            assert await ctx.get("a") == 1

        asyncio.run(_run_fallback(scenario))


# ============================================================
# 2. 降级后不重连：首次失败锁定内存模式
# ============================================================
class TestFallbackNoReconnect:
    def test_connect_attempted_once_and_stays_in_memory(self):
        calls = []

        def _flaky(*args, **kwargs):
            calls.append(1)
            raise ConnectionError("no redis server")

        async def scenario():
            ctx = _make_ctx()
            fake = _FakeRedis()
            with patch("redis.asyncio.from_url", side_effect=_flaky):
                await ctx.set("a", 1)
                await ctx.set("b", 2)
                assert await ctx.get("a") == 1
            # 即使 Redis 已恢复可用，也不再重连（fallback_mode 已锁定）
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.set("c", 3)
                assert await ctx.get("b") == 2
            assert len(calls) == 1
            assert ctx._fallback_mode is True
            assert ctx._redis is None
            assert fake.store == {}
            assert fake.ping_count == 0
            assert ctx._fallback_data == {"a": 1, "b": 2, "c": 3}

        asyncio.run(scenario())


# ============================================================
# 3. Redis 路径：fake client 正常
# ============================================================
class TestRedisPath:
    def test_connect_once_and_cached(self):
        fake = _FakeRedis()
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake) as m:
                await ctx.set("a", 1)
                await ctx.set("b", 2)
                await ctx.get("a")
                assert m.call_count == 1
                assert ctx._redis is fake
                assert fake.ping_count == 1

        asyncio.run(scenario())

    def test_set_str_stored_direct(self):
        fake = _FakeRedis()
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.set("s", "hello")
                assert fake.store["vulnclaw:ctx:s"] == b"s:hello"

        asyncio.run(scenario())

    def test_set_int_float_bool_json(self):
        fake = _FakeRedis()
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.set("i", 42)
                await ctx.set("f", 1.5)
                await ctx.set("b", True)
                assert fake.store["vulnclaw:ctx:i"] == b"j:42"
                assert fake.store["vulnclaw:ctx:f"] == b"j:1.5"
                assert fake.store["vulnclaw:ctx:b"] == b"j:true"

        asyncio.run(scenario())

    def test_set_dict_list_json(self):
        fake = _FakeRedis()
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.set("d", {"a": 1})
                await ctx.set("l", [1, 2])
                assert fake.store["vulnclaw:ctx:d"] == b'j:{"a": 1}'
                assert fake.store["vulnclaw:ctx:l"] == b"j:[1, 2]"

        asyncio.run(scenario())

    def test_set_complex_object_pickle_base64(self):
        from collections import deque
        fake = _FakeRedis()
        ctx = _make_ctx()
        obj = deque(["svc", "t1", "t2"])  # 非 JSON 类型 -> p: pickle 分支

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.set("c", obj)
                stored = fake.store["vulnclaw:ctx:c"]
                assert stored.startswith(b"p:")
                from vulnclaw.core.safe_pickle import safe_pickle_loads
                restored = safe_pickle_loads(base64.b64decode(stored[2:]))
                assert restored == deque(["svc", "t1", "t2"])

        asyncio.run(scenario())

    def test_get_roundtrip(self):
        from collections import deque
        fake = _FakeRedis()
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.set("d", {"a": 1, "b": [1, 2]})
                await ctx.set("s", "text")
                await ctx.set("c", deque(["x", "y"]))
                assert await ctx.get("d") == {"a": 1, "b": [1, 2]}
                assert await ctx.get("s") == "text"
                assert await ctx.get("c") == deque(["x", "y"])

        asyncio.run(scenario())

    def test_get_missing_returns_default(self):
        fake = _FakeRedis()
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                assert await ctx.get("missing") is None
                assert await ctx.get("missing", "dflt") == "dflt"

        asyncio.run(scenario())

    def test_has(self):
        fake = _FakeRedis()
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                assert await ctx.has("k") is False
                await ctx.set("k", 1)
                assert await ctx.has("k") is True

        asyncio.run(scenario())

    def test_get_and_clear(self):
        fake = _FakeRedis()
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.set("k", [1, 2])
                assert await ctx.get_and_clear("k") == [1, 2]
                assert "vulnclaw:ctx:k" not in fake.store
                assert await ctx.get_and_clear("missing") is None

        asyncio.run(scenario())

    def test_get_all(self):
        fake = _FakeRedis()
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.set("a", 1)
                await ctx.set("b", {"x": "y"})
                assert await ctx.get_all() == {"a": 1, "b": {"x": "y"}}

        asyncio.run(scenario())

    def test_clear(self):
        fake = _FakeRedis()
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.set("a", 1)
                await ctx.set("b", 2)
                await ctx.clear()
                assert fake.store == {}
                assert await ctx.get_all() == {}

        asyncio.run(scenario())

    def test_prefix_key_naming(self):
        fake = _FakeRedis()
        ctx = RedisContext(redis_url=REDIS_URL, prefix="target42")

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.set("k", 1)
                assert "target42:ctx:k" in fake.store
                assert await ctx.has("k") is True

        asyncio.run(scenario())


# ============================================================
# 4. Redis 路径：update 语义（key 不存在 / 合并 / 覆盖）
# ============================================================
class TestRedisUpdate:
    def test_missing_key_sets_value(self):
        fake = _FakeRedis()
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.update("u", [1])
                assert fake.store["vulnclaw:ctx:u"] == b"j:[1]"

        asyncio.run(scenario())

    def test_list_extend(self):
        fake = _FakeRedis()
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.set("u", [1])
                await ctx.update("u", [2, 3])
                assert fake.store["vulnclaw:ctx:u"] == b"j:[1, 2, 3]"

        asyncio.run(scenario())

    def test_dict_merge(self):
        fake = _FakeRedis()
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.set("u", {"a": 1})
                await ctx.update("u", {"b": 2})
                assert fake.store["vulnclaw:ctx:u"] == b'j:{"a": 1, "b": 2}'

        asyncio.run(scenario())

    def test_other_type_overwrites(self):
        fake = _FakeRedis()
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.set("u", 1)
                await ctx.update("u", "x")
                assert fake.store["vulnclaw:ctx:u"] == b"s:x"

        asyncio.run(scenario())


# ============================================================
# 5. Redis 路径：单次操作失败降级到内存
# ============================================================
class TestRedisOpFailureFallback:
    def test_set_failure_writes_to_fallback(self):
        fake = _FakeRedis()
        fake.set = AsyncMock(side_effect=OSError("redis down"))
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.set("k", "v")
                assert ctx._fallback_data == {"k": "v"}

        asyncio.run(scenario())

    def test_get_failure_returns_default(self):
        fake = _FakeRedis()
        fake.get = AsyncMock(side_effect=OSError("redis down"))
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                assert await ctx.get("k", "dflt") == "dflt"
                assert await ctx.get("k") is None

        asyncio.run(scenario())

    def test_update_failure_falls_back_to_memory(self):
        fake = _FakeRedis()
        fake.get = AsyncMock(side_effect=OSError("redis down"))
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.update("k", "v")
                assert ctx._fallback_data == {"k": "v"}

        asyncio.run(scenario())


# ============================================================
# 6. 序列化边界：各类型 round-trip
# ============================================================
class TestSerializationRoundtrip:
    def test_none(self):
        ctx = _make_ctx()
        data = ctx._serialize(None)
        assert ctx._deserialize(data) is None

    def test_bool(self):
        ctx = _make_ctx()
        for value in (True, False):
            data = ctx._serialize(value)
            assert ctx._deserialize(data) is value

    def test_nested_dict_unicode(self):
        ctx = _make_ctx()
        value = {"k": {"sub": "中文内容"}, "n": [1, {"x": None}]}
        data = ctx._serialize(value)
        assert ctx._deserialize(data) == value

    def test_list(self):
        ctx = _make_ctx()
        value = [1, "two", 3.0, [4], {"five": 5}]
        data = ctx._serialize(value)
        assert ctx._deserialize(data) == value

    def test_float(self):
        ctx = _make_ctx()
        value = 3.14159
        data = ctx._serialize(value)
        assert ctx._deserialize(data) == value

    def test_complex_object(self):
        from collections import deque
        ctx = _make_ctx()
        value = deque(["db", "prod", "backup"])
        data = ctx._serialize(value)
        assert ctx._deserialize(data) == value

    def test_unknown_class_rejected(self):
        # 信任边界收窄：白名单外的自定义类反序列化必须拒绝（防 RCE）
        ctx = _make_ctx()
        value = _ComplexValue("db", ["prod", "backup"])
        data = ctx._serialize(value)
        assert data.startswith(b"p:")
        assert ctx._deserialize(data) is None

    def test_redis_path_none_and_bool_roundtrip(self):
        fake = _FakeRedis()
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx.set("n", None)
                await ctx.set("t", True)
                await ctx.set("f", False)
                assert await ctx.get("n") is None
                assert await ctx.get("t") is True
                assert await ctx.get("f") is False

        asyncio.run(scenario())

    def test_redis_path_legacy_plain_json_deserialize(self):
        # 兼容无前缀的旧数据：直接 json.loads
        fake = _FakeRedis(store={"vulnclaw:ctx:old": b'{"a": 1}'})
        ctx = _make_ctx()

        async def scenario():
            with patch("redis.asyncio.from_url", return_value=fake):
                assert await ctx.get("old") == {"a": 1}

        asyncio.run(scenario())


@pytest.fixture(autouse=True)
def _isolate_wal(tmp_path, monkeypatch):
    """把 WAL 重定向到 tmp，避免测试之间通过 WAL 文件互相污染。

    WAL 默认开启后会真实落盘。若不隔离，前一个"降级测试"写入的 WAL
    会被后一个"Redis 路径测试"在首次连接时自动回放，把陈旧键值灌进
    fake store —— test_get_all 这类全量断言会莫名失败（且极难定位）。
    """
    from vulnclaw.config.settings import settings
    monkeypatch.setattr(settings, "redis_wal_path", str(tmp_path / "wal.jsonl"))
    monkeypatch.setattr(settings, "redis_wal_enabled", True)


# ============================================================
# 7. P0-8 补：降级期 WAL（落盘 + 恢复后回放）
# ============================================================
class TestDegradedWAL:
    """降级期写入此前只活在本进程内存：进程一退就丢，且从不回灌 Redis。

    WAL 保证这些写入落盘，Redis 恢复（或进程重启）后按序回放。
    """

    @staticmethod
    def _ctx_with_wal(tmp_path, name="wal.jsonl"):
        """构造一个 WAL 指向 tmp_path 的 ctx（绕过 settings，路径可控）。"""
        ctx = RedisContext(redis_url=REDIS_URL, prefix=PREFIX)
        ctx._wal_path = str(tmp_path / name)
        ctx._wal_enabled = True
        return ctx

    @staticmethod
    def _read_wal(path):
        with open(path, encoding="utf-8") as fh:
            return [l for l in fh.read().splitlines() if l.strip()]

    def test_degraded_writes_land_in_wal(self, tmp_path):
        """降级期 set 必须落 WAL（否则恢复后无从回放）。"""
        async def scenario(ctx):
            await ctx.set("a", 1)
            await ctx.set("b", {"x": "y"})

        ctx = self._ctx_with_wal(tmp_path)
        with patch("redis.asyncio.from_url", side_effect=ConnectionError("down")):
            asyncio.run(scenario(ctx))

        assert os.path.exists(ctx._wal_path), "降级写入未落 WAL"
        lines = self._read_wal(ctx._wal_path)
        assert len(lines) == 2
        assert json.loads(lines[0])["key"] == "a"

    def test_replay_refills_redis_after_recovery(self, tmp_path):
        """Redis 恢复后首次连接自动回放：降级期写入真的进 Redis（不再永久丢失）。"""
        async def scenario(ctx):
            await ctx.set("a", 42)
            await ctx.set("b", "hello")

        ctx = self._ctx_with_wal(tmp_path)
        with patch("redis.asyncio.from_url", side_effect=ConnectionError("down")):
            asyncio.run(scenario(ctx))

        # 新 ctx 复用同一 WAL（模拟进程重启后 Redis 已恢复）
        ctx2 = self._ctx_with_wal(tmp_path)
        fake = _FakeRedis()

        async def recover():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx2.set("c", "after")  # 首次连接即触发自动回放

        asyncio.run(recover())

        assert ctx2._deserialize(fake.store["vulnclaw:ctx:a"]) == 42
        assert ctx2._deserialize(fake.store["vulnclaw:ctx:b"]) == "hello"
        assert ctx2._deserialize(fake.store["vulnclaw:ctx:c"]) == "after"
        # 回放成功后 WAL 必须清空（否则下次重复回灌）
        assert self._read_wal(ctx2._wal_path) == []

    def test_delete_and_merge_semantics_replayed(self, tmp_path):
        """delete（get_and_clear）与 update 合并值都能被正确回放。"""
        async def scenario(ctx):
            await ctx.set("gone", "x")
            await ctx.get_and_clear("gone")   # -> WAL delete
            await ctx.set("lst", [1])
            await ctx.update("lst", [2, 3])   # -> WAL 记合并后的 [1, 2, 3]

        ctx = self._ctx_with_wal(tmp_path)
        with patch("redis.asyncio.from_url", side_effect=ConnectionError("down")):
            asyncio.run(scenario(ctx))

        ctx2 = self._ctx_with_wal(tmp_path)
        fake = _FakeRedis({"vulnclaw:ctx:gone": b"s:stale"})  # 回放前已存在的陈旧值

        async def recover():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx2.set("k", 0)

        asyncio.run(recover())
        assert "vulnclaw:ctx:gone" not in fake.store, "delete 未被回放"
        assert ctx2._deserialize(fake.store["vulnclaw:ctx:lst"]) == [1, 2, 3]

    def test_replay_is_idempotent(self, tmp_path):
        """重复 replay 不报错且返回 0（WAL 已空），不会重复回灌。"""
        async def scenario(ctx):
            await ctx.set("a", 1)

        ctx = self._ctx_with_wal(tmp_path)
        with patch("redis.asyncio.from_url", side_effect=ConnectionError("down")):
            asyncio.run(scenario(ctx))

        ctx2 = self._ctx_with_wal(tmp_path)
        fake = _FakeRedis()

        async def recover():
            with patch("redis.asyncio.from_url", return_value=fake):
                await ctx2.set("z", 9)          # 触发自动回放（第 1 次）
                return await ctx2.replay_wal()  # 第 2 次：应为 no-op

        assert asyncio.run(recover()) == 0
        assert ctx2._deserialize(fake.store["vulnclaw:ctx:a"]) == 1

    def test_wal_disabled_writes_nothing(self, tmp_path):
        """开关关闭时不产生任何 WAL 文件（保持旧行为）。"""
        ctx = self._ctx_with_wal(tmp_path)
        ctx._wal_enabled = False

        async def scenario():
            with patch("redis.asyncio.from_url", side_effect=ConnectionError("down")):
                await ctx.set("a", 1)

        asyncio.run(scenario())
        assert not os.path.exists(ctx._wal_path)

    def test_corrupt_wal_line_is_skipped(self, tmp_path):
        """WAL 尾部半行（断电残留）不得让回放整体炸掉。"""
        ctx = self._ctx_with_wal(tmp_path)
        with open(ctx._wal_path, "w", encoding="utf-8") as fh:
            fh.write('{"op":"set","key":"ok","value":')  # 被截断的半行
            fh.write("\n")

        fake = _FakeRedis()
        ctx._redis = fake
        # 坏行跳过 -> 不计入 applied；整体不抛异常
        assert asyncio.run(ctx.replay_wal()) == 0

    def test_replay_noop_when_wal_absent(self, tmp_path):
        """无 WAL 文件时 replay 是安全的 no-op。"""
        ctx = self._ctx_with_wal(tmp_path, "missing.jsonl")
        ctx._redis = _FakeRedis()
        assert asyncio.run(ctx.replay_wal()) == 0
