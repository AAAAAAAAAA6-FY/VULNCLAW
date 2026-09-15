# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""SP20 分布式模块测试：DistributedWorker 专项测试（A 线，全 mock Redis）。

覆盖（全部离线，不连真实 Redis，patch redis.asyncio.from_url 返回 fake client）：
- a) pull_task：XREADGROUP 拉到任务 -> 返回 task、assigned key 被 set、
     任务被打上 assigned_to / assigned_at / status=running；
- b) pull_task：TTL 过期任务被丢弃（返回 None）且 xack 被调用；
- c) pull_task：空队列返回 None；
- d) execute_task：真实执行 NODE_EXECUTORS 中纯逻辑的 SUBGRAPH 执行器
     （RECON 执行器需联网扫描 + LLM，离线单测不可用，改用同为真实执行器的
     execute_subgraph_node，覆盖 NodeType 解析 -> 执行器查找 -> DAGNode 构造 -> 执行）；
- e) execute_task：未知 type -> status=failed 且不抛错；
- f) report_result：写 result key、删 assigned、XACK stream、RPUSH results 队列；
- g) get_stats：基础字段齐全。
"""
import json
import time
from unittest.mock import AsyncMock

import pytest

from vulnclaw.distributed.worker import DistributedWorker

_PREFIX = "vulnclaw"
_STREAM_KEY = f"{_PREFIX}:tasks"
_GROUP_NAME = f"{_PREFIX}:workers"


class _FakeRedis:
    """纯 mock Redis 客户端：全部方法为 AsyncMock，不连接真实 Redis。"""

    def __init__(self):
        self.ping = AsyncMock(return_value=True)
        self.set = AsyncMock()
        # P0-10：结果上报改为 SETNX 抢占（幂等），claim 成功 = True
        self.setnx = AsyncMock(return_value=True)
        self.get = AsyncMock()
        self.hset = AsyncMock()
        self.setex = AsyncMock()
        self.xgroup_create = AsyncMock()
        self.xreadgroup = AsyncMock()
        self.xack = AsyncMock()
        self.delete = AsyncMock()
        self.rpush = AsyncMock()
        self.close = AsyncMock()


@pytest.fixture
def fake_redis(monkeypatch):
    """patch redis.asyncio.from_url，返回 fake client（worker._connect 内部 ping 走 fake）。"""
    fake = _FakeRedis()
    monkeypatch.setattr("redis.asyncio.from_url", lambda *a, **k: fake)
    return fake


async def _connected_worker(fake):
    """构造 DistributedWorker 并完成 _connect，断言 ping 确实走了 fake。"""
    w = DistributedWorker(redis_url="redis://localhost:6379/0", prefix=_PREFIX)
    await w._connect()
    assert fake.ping.await_count == 1
    return w


# ---------------------------------------------------------------------------
# a) pull_task：正常拉到任务并标记分配
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_a_pull_task_assigns_and_marks_running(fake_redis):
    w = await _connected_worker(fake_redis)
    payload = {"task_id": "t-001", "type": "subgraph", "target": "", "params": {}}
    fake_redis.xreadgroup.return_value = [
        [_STREAM_KEY, [("msg-1", {"task": json.dumps(payload)})]]
    ]

    task = await w.pull_task(timeout=0)

    assert task is not None
    assert task["task_id"] == "t-001"
    assert task["assigned_to"] == w._worker_id
    assert "assigned_at" in task
    assert task["status"] == "running"
    assert w._current_msg_id == "msg-1"
    assert w._current_task == task
    fake_redis.set.assert_awaited_once()
    assert fake_redis.set.await_args.args[0] == f"{_PREFIX}:assigned:{w._worker_id}:t-001"


# ---------------------------------------------------------------------------
# b) pull_task：TTL 过期任务丢弃并 ACK
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_b_pull_task_drops_expired_ttl(fake_redis):
    w = await _connected_worker(fake_redis)
    expired = {"task_id": "t-002", "type": "subgraph", "ttl": 30, "submitted_at": time.time() - 100}
    fake_redis.xreadgroup.return_value = [
        [_STREAM_KEY, [("msg-2", {"task": json.dumps(expired)})]]
    ]

    task = await w.pull_task(timeout=0)

    assert task is None
    fake_redis.xack.assert_awaited_once_with(_STREAM_KEY, _GROUP_NAME, "msg-2")
    fake_redis.set.assert_not_awaited()


# ---------------------------------------------------------------------------
# c) pull_task：空队列返回 None
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_c_pull_task_empty_queue_returns_none(fake_redis):
    w = await _connected_worker(fake_redis)
    fake_redis.xreadgroup.return_value = []

    task = await w.pull_task(timeout=0)

    assert task is None
    fake_redis.xack.assert_not_awaited()
    fake_redis.set.assert_not_awaited()


# ---------------------------------------------------------------------------
# d) execute_task：真实执行（SUBGRAPH 纯逻辑执行器，全链路）
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_d_execute_task_real_executor_success(fake_redis):
    """真实执行 NODE_EXECUTORS。

    RECON 执行器（execute_recon_node）会启动 V100Orchestrator 做真实扫描
    （联网 + LLM），离线单测不可用；SUBGRAPH（execute_subgraph_node）为
    NODE_EXECUTORS 中的纯逻辑真实执行器，完整覆盖 _execute_node 的
    NodeType 解析 -> 执行器查找 -> DAGNode 构造 -> 执行 链路。
    """
    w = await _connected_worker(fake_redis)
    task = {"task_id": "t-003", "type": "subgraph", "target": "", "params": {}}

    result = await w.execute_task(task)

    assert result["task_id"] == "t-003"
    assert result["status"] == "success"
    assert result["worker_id"] == w._worker_id
    assert result["subgraph_id"] == "t-003"
    assert result["completed_at"] > 0
    assert w._tasks_completed == 1
    assert w._tasks_failed == 0


# ---------------------------------------------------------------------------
# e) execute_task：未知 type -> failed 且不抛错
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_e_execute_task_unknown_type_fails_gracefully(fake_redis):
    w = await _connected_worker(fake_redis)
    task = {"task_id": "t-004", "type": "no_such_type"}

    result = await w.execute_task(task)

    assert result["task_id"] == "t-004"
    assert result["status"] == "failed"
    assert "error" in result
    assert result["worker_id"] == w._worker_id
    assert w._tasks_failed == 1
    assert w._tasks_completed == 0


# ---------------------------------------------------------------------------
# f) report_result：ACK + 结果 key + results 队列
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_f_report_result_acks_and_queues(fake_redis):
    w = await _connected_worker(fake_redis)
    w._current_msg_id = "msg-1"
    result = {"status": "success", "task_id": "t-005"}

    await w.report_result("t-005", result)

    fake_redis.xack.assert_awaited_once_with(_STREAM_KEY, _GROUP_NAME, "msg-1")
    assert w._current_msg_id is None
    fake_redis.setnx.assert_awaited_once_with(f"{_PREFIX}:result:t-005", json.dumps(result, default=str))
    fake_redis.delete.assert_awaited_once_with(f"{_PREFIX}:assigned:{w._worker_id}:t-005")
    fake_redis.rpush.assert_awaited_once()
    queued = json.loads(fake_redis.rpush.await_args.args[1])
    assert queued["task_id"] == "t-005"
    assert queued["worker_id"] == w._worker_id
    assert queued["result"]["status"] == "success"


# ---------------------------------------------------------------------------
# g) get_stats：基础字段
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_g_get_stats_basic_fields(fake_redis):
    w = await _connected_worker(fake_redis)
    w._tasks_completed = 3
    w._tasks_failed = 1
    w._current_task = {"task_id": "t-006"}

    stats = w.get_stats()

    assert stats["worker_id"] == w._worker_id
    assert stats["capabilities"] == w._capabilities
    assert stats["completed"] == 3
    assert stats["failed"] == 1
    assert stats["running"] is False
    assert stats["current_task"] == "t-006"

    w._current_task = None
    assert w.get_stats()["current_task"] is None
