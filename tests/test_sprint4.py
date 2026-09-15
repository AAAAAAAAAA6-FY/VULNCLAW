#!/usr/bin/env python3
"""
Sprint 4 验收测试骨架。
覆盖分布式部署全模块。

运行: pytest tests/test_sprint4.py -v --tb=short
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# RedisContext 测试
# ============================================================

class TestRedisContext:
    """Redis 后端上下文测试。"""

    def test_init(self):
        """TC-RC-01: 初始化参数。"""
        from vulnclaw.distributed.redis_backend import RedisContext

        ctx = RedisContext(redis_url="redis://localhost:6379/1", prefix="test")
        assert ctx._redis_url == "redis://localhost:6379/1"
        assert ctx._prefix == "test:ctx"

    def test_make_key(self):
        """TC-RC-02: Key 构建。"""
        from vulnclaw.distributed.redis_backend import RedisContext

        ctx = RedisContext(prefix="vulnclaw")
        assert ctx._make_key("findings") == "vulnclaw:ctx:findings"

    def test_serialize_string(self):
        """TC-RC-03: 字符串序列化。"""
        from vulnclaw.distributed.redis_backend import RedisContext

        ctx = RedisContext()
        data = ctx._serialize("hello")
        assert ctx._deserialize(data) == "hello"

    def test_serialize_dict(self):
        """TC-RC-04: 字典序列化。"""
        from vulnclaw.distributed.redis_backend import RedisContext

        ctx = RedisContext()
        original = {"key": "value", "num": 42}
        data = ctx._serialize(original)
        result = ctx._deserialize(data)
        assert result == original

    def test_serialize_list(self):
        """TC-RC-05: 列表序列化。"""
        from vulnclaw.distributed.redis_backend import RedisContext

        ctx = RedisContext()
        original = [1, "two", {"three": 3}]
        data = ctx._serialize(original)
        result = ctx._deserialize(data)
        assert result == original

    def test_serialize_int(self):
        """TC-RC-06: 整数序列化。"""
        from vulnclaw.distributed.redis_backend import RedisContext

        ctx = RedisContext()
        data = ctx._serialize(42)
        assert ctx._deserialize(data) == 42

    @pytest.mark.asyncio
    async def test_fallback_mode(self):
        """TC-RC-07: Redis 不可用时降级到内存模式。"""
        from vulnclaw.distributed.redis_backend import RedisContext

        ctx = RedisContext(redis_url="redis://localhost:9999/0")  # 不存在的 Redis
        await ctx._connect()
        # 应该降级到内存模式
        assert ctx._fallback_mode is True

        # 测试内存模式下的基本操作
        await ctx.set("test_key", "test_value")
        value = await ctx.get("test_key")
        assert value == "test_value"

    @pytest.mark.asyncio
    async def test_interface_compatibility(self):
        """TC-RC-08: 接口与 DAGContext 兼容（set/get/update/clear/has）。"""
        from vulnclaw.distributed.redis_backend import RedisContext

        ctx = RedisContext(redis_url="redis://localhost:9999/0")
        await ctx._connect()  # 降级到内存模式

        # set / get
        await ctx.set("key1", "value1")
        assert await ctx.get("key1") == "value1"

        # update (list extend)
        await ctx.set("list1", ["a", "b"])
        await ctx.update("list1", ["c", "d"])
        assert await ctx.get("list1") == ["a", "b", "c", "d"]

        # update (dict merge)
        await ctx.set("dict1", {"a": 1})
        await ctx.update("dict1", {"b": 2})
        assert await ctx.get("dict1") == {"a": 1, "b": 2}

        # has
        assert await ctx.has("key1") is True
        assert await ctx.has("nonexistent") is False

        # get_and_clear
        val = await ctx.get_and_clear("key1")
        assert val == "value1"
        assert await ctx.has("key1") is False

        # clear
        await ctx.set("temp", "temp")
        await ctx.clear()
        assert await ctx.has("temp") is False


# ============================================================
# DistributedMaster 测试
# ============================================================

class TestDistributedMaster:
    """Master 节点测试。"""

    def test_init(self):
        """TC-DM-01: 初始化。"""
        from vulnclaw.distributed.master import DistributedMaster

        master = DistributedMaster(redis_url="redis://localhost:6379/0", prefix="test")
        assert master._redis_url == "redis://localhost:6379/0"
        assert master._prefix == "test"
        assert master.HEARTBEAT_TIMEOUT == 30

    def test_heartbeat_timeout(self):
        """TC-DM-02: 心跳超时 30s。"""
        from vulnclaw.distributed.master import DistributedMaster

        master = DistributedMaster()
        assert master.HEARTBEAT_TIMEOUT == 30

    def test_task_timeout(self):
        """TC-DM-03: 任务超时 600s。"""
        from vulnclaw.distributed.master import DistributedMaster

        master = DistributedMaster()
        assert master.TASK_TIMEOUT == 600


# ============================================================
# P0-9 / P0-10 / P1-13：Master 状态持久化、结果幂等、故障转移 SCAN
# ============================================================
class _FakeMasterRedis:
    """最小假 Redis：hash(taskstatus) + result 槽 + SCAN。"""

    def __init__(self):
        self.hashes = {}
        self.store = {}
        self.deleted = []

    async def hset(self, name, key=None, value=None, mapping=None):
        self.hashes.setdefault(name, {})
        if mapping:
            self.hashes[name].update(mapping)
        else:
            self.hashes[name][key] = value
        return 1

    async def hget(self, name, key):
        return (self.hashes.get(name) or {}).get(key)

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value):
        self.store[key] = value
        return True

    async def setnx(self, key, value):
        if key in self.store:
            return False
        self.store[key] = value
        return True

    async def rpush(self, key, *values):
        self.store.setdefault(key, [])
        if isinstance(self.store[key], list):
            self.store[key].extend(values)
        return len(self.store[key])

    async def delete(self, *keys):
        for k in keys:
            self.store.pop(k, None)
            self.deleted.append(k)
        return len(keys)

    async def keys(self, pattern):
        import fnmatch
        return [k for k in self.store if fnmatch.fnmatchcase(k, pattern)]

    async def scan(self, cursor=0, match=None, count=100):
        import fnmatch
        keys = [k for k in self.store if fnmatch.fnmatchcase(k, match or "*")]
        return 0, keys[: int(count or 100)]

    async def xadd(self, *a, **k):
        return "1-0"

    async def xgroup_create(self, *a, **k):
        return True


class TestMasterStateAndIdempotency:
    @staticmethod
    def _master():
        from vulnclaw.distributed.master import DistributedMaster
        m = DistributedMaster(prefix="t")
        m._redis = _FakeMasterRedis()
        return m

    def test_submitted_task_status_persisted(self):
        """P0-9：提交即落 Redis（重启可恢复），不是只在进程内 dict。"""
        import asyncio
        m = self._master()
        tid = asyncio.run(m.submit_task({"type": "recon", "params": {}}))
        assert tid
        raw = m._redis.hashes.get("t:taskstatus", {}).get(tid)
        assert raw, "任务状态未持久化到 Redis（Master 重启即丢）"

    def test_result_readable_after_master_restart(self):
        """P0-9：本地 dict 清空（模拟重启）后，仍能从 Redis 读回状态/结果。"""
        import asyncio, json
        m = self._master()
        tid = asyncio.run(m.submit_task({"type": "recon"}))
        m._redis.store[f"t:result:{tid}"] = json.dumps({"ok": True})
        m._task_status.clear()  # 模拟 Master 重启
        got = asyncio.run(m.get_result(tid, timeout=2))
        assert got == {"ok": True}

    def test_worker_result_commit_is_idempotent(self):
        """P0-10：重复投递时第二次提交不得覆盖已有结果。"""
        import asyncio
        from vulnclaw.distributed.worker import DistributedWorker
        w = DistributedWorker(prefix="t")
        w._redis = _FakeMasterRedis()
        asyncio.run(w.report_result("task1", {"finding": "A"}))
        asyncio.run(w.report_result("task1", {"finding": "B"}))  # 重复投递
        import json
        assert json.loads(w._redis.store["t:result:task1"])["finding"] == "A"

    def test_dead_worker_failover_uses_scan_not_keys(self):
        """P1-13：故障转移走 SCAN，不阻塞 Redis。"""
        import asyncio, json
        m = self._master()
        m._redis.store["t:assigned:w1:task9"] = json.dumps({"task_id": "task9"})
        m._redis.xpending_range = _async_none
        m._redis.xack = _async_none
        m._redis.xrange = _async_list
        m._redis.srem = _async_none
        n = asyncio.run(m.handle_dead_worker("w1"))
        assert n >= 1
        assert m._redis.store.get("t:assigned:w1:task9") is None


async def _async_none(*a, **k):
    return None


async def _async_list(*a, **k):
    return []


# ============================================================
# DistributedWorker 测试
# ============================================================

class TestDistributedWorker:
    """Worker 节点测试。"""

    def test_init(self):
        """TC-DW-01: 初始化。"""
        from vulnclaw.distributed.worker import DistributedWorker

        worker = DistributedWorker(
            redis_url="redis://localhost:6379/0",
            prefix="test",
            capabilities=["recon", "attack"],
        )
        assert worker._prefix == "test"
        assert "recon" in worker._capabilities
        assert worker._worker_id.startswith("worker_")

    def test_heartbeat_interval(self):
        """TC-DW-02: 心跳间隔 < 30s。"""
        from vulnclaw.distributed.worker import DistributedWorker

        worker = DistributedWorker()
        assert worker.HEARTBEAT_INTERVAL < 30

    def test_get_stats(self):
        """TC-DW-03: 统计信息。"""
        from vulnclaw.distributed.worker import DistributedWorker

        worker = DistributedWorker()
        stats = worker.get_stats()
        assert "worker_id" in stats
        assert "capabilities" in stats
        assert "completed" in stats
        assert "failed" in stats


# ============================================================
# DashboardServer 测试
# ============================================================

class TestDashboardServer:
    """Dashboard 服务器测试。"""

    def test_init(self):
        """TC-DB-01: 初始化（回环绑定无 token 允许）。"""
        from vulnclaw.dashboard.server import DashboardServer

        server = DashboardServer(host="127.0.0.1", port=9090)
        assert server.host == "127.0.0.1"
        assert server.port == 9090

    def test_init_fail_closed_non_loopback(self):
        """TC-DB-01b: 非回环绑定且无 token → fail-closed 拒绝（防无鉴权对外暴露）。"""
        import pytest

        from vulnclaw.dashboard.server import DashboardServer

        with pytest.raises(RuntimeError):
            DashboardServer(host="0.0.0.0", port=9090)

    def test_create_app(self):
        """TC-DB-02: FastAPI 应用创建。"""
        from vulnclaw.dashboard.server import DashboardServer

        server = DashboardServer()
        app = server.create_app()
        assert app is not None
        assert app.title == "VULNCLAW Dashboard"

    def test_broadcast_drops_when_client_queue_full(self):
        """P1-14：慢客户端队列满 → 丢弃事件并摘除客户端，广播不阻塞。"""
        import asyncio

        from vulnclaw.dashboard.server import DashboardServer

        server = DashboardServer(host="127.0.0.1", port=9090)
        server._ws_queue_size = 2

        async def _go():
            client = object()
            server._ws_clients.add(client)
            server._ws_queues[client] = asyncio.Queue(maxsize=2)
            for _ in range(5):  # 无消费者 → 第 3 条起溢出
                await server.broadcast_update({"i": 1})
            return client

        client = asyncio.run(_go())
        assert server._dropped_events >= 1
        # 溢出客户端被摘除（不再接收后续广播，避免无限堆积）
        assert client not in server._ws_clients

    def test_broadcast_delivers_via_pump(self):
        """P1-14：正常客户端由后台泵投递，广播调用本身不直接 send。"""
        import asyncio

        from vulnclaw.dashboard.server import DashboardServer

        server = DashboardServer(host="127.0.0.1", port=9090)

        class _Client:
            def __init__(self):
                self.sent = []

            async def send_text(self, message):
                self.sent.append(message)

        async def _go():
            client = _Client()
            queue = asyncio.Queue(maxsize=8)
            server._ws_clients.add(client)
            server._ws_queues[client] = queue
            server._ws_pumps[client] = asyncio.create_task(
                server._ws_pump(client, queue))
            await server.broadcast_update({"hello": "world"})
            await asyncio.sleep(0.05)  # 让泵跑一轮
            server._unregister_ws(client)
            return client

        client = asyncio.run(_go())
        assert len(client.sent) == 1
        assert "hello" in client.sent[0]


# ============================================================
# TutorialGenerator 测试
# ============================================================

class TestTutorialGenerator:
    """教程生成器测试。"""

    def test_parse_log_extract_target(self):
        """TC-TG-01: 从日志提取目标 URL。"""
        from scripts.tutorial_generator import TutorialGenerator

        gen = TutorialGenerator()
        log = "目标: http://testphp.vulnweb.com\n开始扫描..."
        parsed = gen._parse_log(log)
        assert parsed["target"] == "http://testphp.vulnweb.com"

    def test_parse_log_extract_elapsed(self):
        """TC-TG-02: 从日志提取耗时。"""
        from scripts.tutorial_generator import TutorialGenerator

        gen = TutorialGenerator()
        log = "扫描完成，耗时: 123.45s"
        parsed = gen._parse_log(log)
        assert "123.45" in parsed["elapsed"]

    def test_render_builtin(self):
        """TC-TG-03: 内置模板渲染。"""
        from scripts.tutorial_generator import TutorialGenerator

        gen = TutorialGenerator()
        data = {
            "target": "http://test.com",
            "elapsed": "60s",
            "findings": [{"type": "SQLi", "url": "http://test.com/page", "severity": "High"}],
            "recon": {"subdomains": ["a.test.com"], "ports": [80, 443]},
            "verify": {"total": 5, "verified": 3, "false_positives": 2},
            "exploit": {"chains": ["SQLi → data extraction"]},
        }
        md = gen._render_builtin(data)
        assert "http://test.com" in md
        assert "SQLi" in md
        assert "60s" in md

    @pytest.mark.asyncio
    async def test_generate_basic(self):
        """TC-TG-04: 完整生成流程。"""
        from scripts.tutorial_generator import TutorialGenerator

        gen = TutorialGenerator()
        log = "目标: http://test.com\n耗时: 30s\n漏洞: SQL注入\n漏洞: XSS"
        md = await gen.generate(log)
        assert "http://test.com" in md
        assert "渗透测试教程" in md


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
