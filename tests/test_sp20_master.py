# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""SP20 分布式模块 B 线：DistributedMaster（src/vulnclaw/distributed/master.py）专项测试。

全部用例用 unittest.mock 构造 fake Redis 客户端并注入 master._redis，
不建立任何真实 Redis 连接，无 Redis 服务环境下同样全绿。

覆盖方法：
  - _connect / _ensure_stream
  - submit_task / submit_batch
  - get_result
  - register_worker / update_heartbeat / check_workers
  - handle_dead_worker
  - start_monitor / stop
  - get_cluster_status

说明：项目 pytest 为 asyncio_mode=strict，本文件统一用 asyncio.run 驱动异步场景，
不依赖 pytest-asyncio 事件循环。全文件无 emoji。
"""
import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest

from vulnclaw.distributed.master import DistributedMaster


class FakeRedis:
    """最小 Redis 客户端替身：每个方法都是 AsyncMock，按需覆盖返回值。"""

    def __init__(self):
        self.ping = AsyncMock(return_value=True)
        self.xgroup_create = AsyncMock()
        self.xadd = AsyncMock()
        self.get = AsyncMock(return_value=None)
        self.hset = AsyncMock()
        self.sadd = AsyncMock()
        self.setex = AsyncMock()
        self.smembers = AsyncMock(return_value=set())
        self.exists = AsyncMock(return_value=1)
        self.keys = AsyncMock(return_value=[])
        self.delete = AsyncMock(return_value=1)
        self.xpending_range = AsyncMock(return_value=[])
        self.xrange = AsyncMock(return_value=[])
        self.xack = AsyncMock()
        self.srem = AsyncMock()
        self.xlen = AsyncMock(return_value=0)
        self.llen = AsyncMock(return_value=0)
        self.close = AsyncMock()


def _make_master(fake=None):
    """构造 master 并直接注入 fake Redis，方法内的 _connect 会短路返回。"""
    fake = fake or FakeRedis()
    master = DistributedMaster(redis_url="redis://fake:6379/0", prefix="vulnclaw")
    master._redis = fake
    return master, fake


def _xadd_payload(fake, index=0):
    """取出第 index 次 xadd 调用中被序列化的任务 dict。"""
    call = fake.xadd.await_args_list[index]
    fields = call.args[1]
    return json.loads(fields["task"])


class TestConnect:
    def test_connect_patches_from_url_and_pings(self):
        fake = FakeRedis()

        async def _go():
            with patch("redis.asyncio.from_url", return_value=fake) as mocked:
                master = DistributedMaster(redis_url="redis://fake:6379/0")
                handle = await master._connect()
                return master, handle, mocked

        master, handle, mocked = asyncio.run(_go())
        mocked.assert_called_once_with(
            "redis://fake:6379/0", decode_responses=True, socket_timeout=5
        )
        fake.ping.assert_awaited_once()
        assert handle is fake
        assert master._redis is fake

    def test_connect_is_idempotent(self):
        fake = FakeRedis()

        async def _go():
            with patch("redis.asyncio.from_url", return_value=fake) as mocked:
                master = DistributedMaster(redis_url="redis://fake:6379/0")
                await master._connect()
                await master._connect()
                return mocked

        mocked = asyncio.run(_go())
        assert mocked.call_count == 1
        assert fake.ping.await_count == 1

    def test_connect_failure_propagates(self):
        async def _go():
            with patch("redis.asyncio.from_url", side_effect=ConnectionError("no redis")):
                master = DistributedMaster(redis_url="redis://fake:6379/0")
                await master._connect()

        with pytest.raises(ConnectionError):
            asyncio.run(_go())


class TestSubmitTask:
    def test_submit_returns_id_and_queues_serialized_task(self):
        master, fake = _make_master()
        task = {"task_id": "t-1", "type": "portscan", "params": {"host": "10.0.0.1"}}

        async def _go():
            return await master.submit_task(task)

        task_id = asyncio.run(_go())
        assert task_id == "t-1"

        fake.xgroup_create.assert_awaited_once_with(
            "vulnclaw:tasks", "vulnclaw:workers", id="0", mkstream=True
        )
        fake.xadd.assert_awaited_once()
        stream_key, fields = fake.xadd.await_args.args
        assert stream_key == "vulnclaw:tasks"
        payload = json.loads(fields["task"])
        assert payload["task_id"] == "t-1"
        assert payload["type"] == "portscan"
        assert payload["status"] == "pending"
        assert payload["ttl"] == DistributedMaster.TASK_TIMEOUT + 60
        assert "submitted_at" in payload
        # 内存任务状态登记
        assert master._task_status["t-1"]["status"] == "pending"
        assert master._task_status["t-1"]["assigned_to"] is None
        assert master._task_status["t-1"]["result"] is None

    def test_submit_generates_task_id_when_missing(self):
        master, _fake = _make_master()
        task = {"type": "scan"}

        async def _go():
            return await master.submit_task(task)

        task_id = asyncio.run(_go())
        assert isinstance(task_id, str) and task_id.startswith("task_")
        assert task["task_id"] == task_id

    def test_submit_keeps_existing_ttl(self):
        master, fake = _make_master()
        task = {"task_id": "t-ttl", "ttl": 42}

        async def _go():
            return await master.submit_task(task)

        asyncio.run(_go())
        assert _xadd_payload(fake)["ttl"] == 42

    def test_submit_survives_existing_stream_group(self):
        master, fake = _make_master()
        fake.xgroup_create.side_effect = Exception(
            "BUSYGROUP Consumer Group Name already exists"
        )
        task = {"task_id": "t-dup"}

        async def _go():
            return await master.submit_task(task)

        assert asyncio.run(_go()) == "t-dup"


class TestSubmitBatch:
    def test_batch_returns_same_number_of_ids(self):
        master, fake = _make_master()
        tasks = [
            {"task_id": "b-1", "type": "a"},
            {"task_id": "b-2", "type": "b"},
            {"task_id": "b-3", "type": "c"},
        ]

        async def _go():
            return await master.submit_batch(tasks)

        task_ids = asyncio.run(_go())
        assert task_ids == ["b-1", "b-2", "b-3"]
        assert fake.xadd.await_count == 3


class TestWorkerLifecycle:
    def test_register_worker_hsets_and_sadds(self):
        master, fake = _make_master()

        async def _go():
            return await master.register_worker("w1", ["portscan", "http"])

        assert asyncio.run(_go()) is True
        hset_key = fake.hset.await_args.args[0]
        mapping = fake.hset.await_args.kwargs["mapping"]
        assert hset_key == "vulnclaw:worker:w1"
        assert json.loads(mapping["capabilities"]) == ["portscan", "http"]
        assert json.loads(mapping["status"]) == "idle"
        fake.sadd.assert_awaited_once_with("vulnclaw:workers", "w1")
        assert master._workers["w1"]["capabilities"] == ["portscan", "http"]

    def test_update_heartbeat_setex_and_status(self):
        master, fake = _make_master()

        async def _go():
            await master.register_worker("w1", ["portscan"])
            await master.update_heartbeat("w1", status="busy")
            return master._workers["w1"]["status"]

        assert asyncio.run(_go()) == "busy"
        hb_key, ttl, stamp = fake.setex.await_args.args
        assert hb_key == "vulnclaw:heartbeat:w1"
        assert ttl == DistributedMaster.HEARTBEAT_TIMEOUT
        float(stamp)  # 心跳时间戳可解析

    def test_check_workers_splits_alive_and_dead(self):
        master, fake = _make_master()
        fake.smembers.return_value = {"w1", "w2"}
        fake.exists.side_effect = lambda key: 1 if "w1" in key else 0

        async def _go():
            return await master.check_workers()

        result = asyncio.run(_go())
        assert set(result["alive"]) == {"w1"}
        assert set(result["dead"]) == {"w2"}
        fake.smembers.assert_awaited_once_with("vulnclaw:workers")

    def test_registered_worker_visible_in_check_workers(self):
        master, fake = _make_master()
        fake.smembers.return_value = {"w9"}

        async def _go():
            await master.register_worker("w9", ["http"])
            await master.update_heartbeat("w9")
            return await master.check_workers()

        result = asyncio.run(_go())
        assert result == {"alive": ["w9"], "dead": []}
        assert master._workers["w9"]["capabilities"] == ["http"]
        assert master._workers["w9"]["status"] == "idle"


class TestGetResult:
    def test_timeout_returns_none(self):
        master, fake = _make_master()
        fake.get.return_value = None

        async def _go():
            with patch(
                "vulnclaw.distributed.master.asyncio.sleep", new=AsyncMock()
            ) as mocked_sleep:
                result = await master.get_result("t-missing", timeout=0.05)
                return result, mocked_sleep

        result, mocked_sleep = asyncio.run(_go())
        assert result is None
        assert mocked_sleep.await_count >= 1
        fake.get.assert_awaited()

    def test_returns_result_when_present_in_redis(self):
        master, fake = _make_master()
        result_payload = {"status": "done", "output": "ok"}

        async def _go():
            await master.submit_task({"task_id": "t-1", "type": "scan"})
            fake.get.return_value = json.dumps(result_payload)
            return await master.get_result("t-1", timeout=1)

        result = asyncio.run(_go())
        assert result == result_payload
        assert master._task_status["t-1"]["status"] == "completed"
        fake.get.assert_awaited_once_with("vulnclaw:result:t-1")

    def test_failed_status_returns_error_dict(self):
        master, fake = _make_master()

        async def _go():
            await master.submit_task({"task_id": "t-1", "type": "scan"})
            master._task_status["t-1"]["status"] = "failed"
            master._task_status["t-1"]["error"] = "boom"
            return await master.get_result("t-1", timeout=1)

        result = asyncio.run(_go())
        assert result == {"error": "boom"}
        assert fake.get.await_count == 0


class TestHandleDeadWorker:
    def test_requeues_assigned_tasks(self):
        master, fake = _make_master()
        assigned = {
            "task_id": "t-1",
            "type": "scan",
            "status": "assigned",
            "assigned_to": "w1",
        }
        fake.keys.return_value = ["vulnclaw:assigned:w1:t-1"]
        fake.get.return_value = json.dumps(assigned)
        fake.xpending_range.side_effect = Exception("no group")

        async def _go():
            return await master.handle_dead_worker("w1")

        requeued = asyncio.run(_go())
        assert requeued == 1
        fake.keys.assert_awaited_once_with("vulnclaw:assigned:w1:*")
        fake.delete.assert_awaited_once_with("vulnclaw:assigned:w1:t-1")
        fake.srem.assert_awaited_once_with("vulnclaw:workers", "w1")
        payload = _xadd_payload(fake)
        assert payload["task_id"] == "t-1"
        assert payload["status"] == "pending"
        assert payload["requeued_from"] == "w1"
        assert "requeued_at" in payload

    def test_redelivers_pending_consumer_messages(self):
        master, fake = _make_master()
        fake.keys.return_value = []
        fake.xpending_range.return_value = [
            {"message_id": "1-1", "consumer": "w1"},
            {"message_id": "1-2", "consumer": "w1"},
        ]
        fake.xrange.side_effect = (
            lambda stream, **kw: [("1-1", {"task": "{}"})] if kw.get("min") == "1-1" else []
        )

        async def _go():
            return await master.handle_dead_worker("w1")

        requeued = asyncio.run(_go())
        assert requeued == 1
        fake.xpending_range.assert_awaited_once_with(
            "vulnclaw:tasks", "vulnclaw:workers", "-", "+", 50, "w1"
        )
        assert fake.xack.await_count == 2
        assert fake.xadd.await_count == 1
        fake.srem.assert_awaited_once_with("vulnclaw:workers", "w1")

    def test_no_tasks_returns_zero(self):
        master, fake = _make_master()

        async def _go():
            return await master.handle_dead_worker("w1")

        assert asyncio.run(_go()) == 0
        fake.srem.assert_awaited_once()


class TestMonitorAndStatus:
    def test_start_monitor_detects_dead_worker_then_stop(self):
        master, fake = _make_master()
        fake.smembers.return_value = {"w1"}
        fake.exists.return_value = 0  # w1 心跳过期 -> dead
        fake.keys.return_value = []
        fake.xpending_range.return_value = []

        async def _go():
            async def _break_loop(*args, **kwargs):
                master._running = False

            with patch(
                "vulnclaw.distributed.master.asyncio.sleep",
                new=AsyncMock(side_effect=_break_loop),
            ):
                await master.start_monitor()
            await master.stop()
            return master

        master = asyncio.run(_go())
        assert master._running is False
        fake.srem.assert_awaited_once_with("vulnclaw:workers", "w1")
        fake.close.assert_awaited_once()

    def test_get_cluster_status_structure(self):
        master, fake = _make_master()
        fake.smembers.return_value = {"w1"}
        fake.exists.return_value = 1
        fake.xlen.return_value = 5
        fake.llen.return_value = 3

        async def _go():
            return await master.get_cluster_status()

        status = asyncio.run(_go())
        assert status["workers"] == {"alive": 1, "dead": 0, "ids": ["w1"]}
        assert status["tasks"] == {"pending": 5, "completed": 3}
        assert status["queue_prefix"] == "vulnclaw"
        fake.xlen.assert_awaited_once_with("vulnclaw:tasks")
        fake.llen.assert_awaited_once_with("vulnclaw:results")

    def test_get_cluster_status_handles_missing_stream(self):
        master, fake = _make_master()
        fake.smembers.return_value = set()
        fake.xlen.side_effect = Exception("no stream")
        fake.llen.return_value = 0

        async def _go():
            return await master.get_cluster_status()

        status = asyncio.run(_go())
        assert status["workers"] == {"alive": 0, "dead": 0, "ids": []}
        assert status["tasks"]["pending"] == 0
