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
        """TC-DB-01: 初始化。"""
        from vulnclaw.dashboard.server import DashboardServer

        server = DashboardServer(host="0.0.0.0", port=9090)
        assert server.host == "0.0.0.0"
        assert server.port == 9090

    def test_create_app(self):
        """TC-DB-02: FastAPI 应用创建。"""
        from vulnclaw.dashboard.server import DashboardServer

        server = DashboardServer()
        app = server.create_app()
        assert app is not None
        assert app.title == "VULNCLAW Dashboard"


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
