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

    def test_assigned_and_pending_same_task_requeued_once(self):
        """P0-10：同一任务同时在 assigned 记录与 PEL 中 → 只重投递一次。"""
        master, fake = _make_master()
        assigned = {"task_id": "t-dup", "status": "running", "assigned_to": "w1"}
        fake.keys.return_value = ["vulnclaw:assigned:w1:t-dup"]
        fake.get.return_value = json.dumps(assigned)
        # PEL 里是同一任务（worker 写了 assigned 但没来得及 XACK 就崩了）
        fake.xpending_range.return_value = [{"message_id": "1-9", "consumer": "w1"}]
        fake.xrange.side_effect = (
            lambda stream, **kw: [("1-9", {"task": json.dumps(assigned)})]
        )

        async def _go():
            return await master.handle_dead_worker("w1")

        assert asyncio.run(_go()) == 1
        # 分配记录路径投 1 次；PEL 路径只 ACK 不投递
        assert fake.xadd.await_count == 1
        assert fake.xack.await_count == 1

    def test_duplicate_assigned_records_requeued_once(self):
        """P0-10：同一 task_id 的多条分配记录 → 只重投递一次，多余记录清理。"""
        master, fake = _make_master()
        task = {"task_id": "t-dup2", "status": "running"}
        fake.keys.return_value = [
            "vulnclaw:assigned:w1:t-dup2",
            "vulnclaw:assigned:w1:t-dup2#retry",
        ]
        fake.get.return_value = json.dumps(task)
        fake.xpending_range.side_effect = Exception("no group")

        async def _go():
            return await master.handle_dead_worker("w1")

        assert asyncio.run(_go()) == 1
        assert fake.xadd.await_count == 1
        assert fake.delete.await_count == 2


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


from vulnclaw.distributed import (  # noqa: E402
    PROTOCOL_VERSION,
    is_terminal,
    validate_envelope,
)


# ============================================================
# P2-19 编排端口协议：信封 schema 契约（Master/Worker 共享）
# ============================================================
class TestEnvelopeProtocol:
    """此前 Master/Worker 之间只有隐式约定（字段散落在两侧实现里），
    任一侧改字段都只能靠"跑一遍集群才发现问题"。协议把口头约定变成可断言的契约。
    """

    def test_valid_task_envelope(self):
        ok, errs = validate_envelope("task", {"task_id": "t1", "type": "scan"})
        assert ok is True and errs == []

    def test_missing_required_field_is_error(self):
        """缺必填 -> 判错（不许静默放行）。"""
        ok, errs = validate_envelope("task", {"task_id": "t1"})
        assert ok is False
        assert "missing:type" in errs

    def test_unknown_field_only_warns(self):
        """未知字段 -> 只告警不判错（前向兼容：新版加字段，老节点不该炸）。"""
        ok, errs = validate_envelope(
            "task", {"task_id": "t1", "type": "scan", "future_field": 1})
        assert ok is True
        assert any(e.startswith("unknown:") for e in errs)

    def test_version_mismatch_is_error(self):
        ok, errs = validate_envelope(
            "task", {"task_id": "t1", "type": "scan"}, version="0.9")
        assert ok is False
        assert "version_mismatch" in errs[0]

    def test_heartbeat_and_result_envelopes(self):
        assert validate_envelope("heartbeat", {"worker_id": "w1"})[0] is True
        assert validate_envelope("heartbeat", {})[0] is False
        assert validate_envelope(
            "result", {"task_id": "t1", "status": "completed"})[0] is True
        assert validate_envelope("result", {"task_id": "t1"})[0] is False

    def test_unknown_kind_and_non_dict_rejected(self):
        ok, errs = validate_envelope("bogus", {})
        assert ok is False and "unknown_envelope_kind" in errs[0]
        assert validate_envelope("task", ["not", "a", "dict"])[0] is False

    def test_terminal_statuses(self):
        """终态判定：故障转移时用于决定值不值得重投递。"""
        assert is_terminal("completed") and is_terminal("failed")
        assert not is_terminal("running") and not is_terminal("pending")

    def test_submit_task_accepts_compliant_envelope(self):
        """合规信封正常投递，不产生告警。"""
        master, fake = _make_master()
        with patch("vulnclaw.distributed.master.logger.warning") as warn:
            tid = asyncio.run(master.submit_task({"type": "scan"}))  # task_id 由 master 补
        assert tid
        warn.assert_not_called()
        fake.xadd.assert_awaited_once()

    def test_submit_task_warns_but_still_delivers(self):
        """不合规信封：只告警不阻断（老 Master 不得直接拒收新节点任务）。"""
        master, fake = _make_master()
        with patch("vulnclaw.distributed.master.logger.warning") as warn:
            tid = asyncio.run(master.submit_task({"task_id": "t1"}))  # 缺 type
        assert tid == "t1"
        assert warn.call_count >= 1
        assert "missing:type" in str(warn.call_args)
        fake.xadd.assert_awaited_once()  # 仍然投递

    def test_protocol_version_is_declared(self):
        assert PROTOCOL_VERSION == "1.0"


# ============================================================
# T14 分布式压测：内存状态机 Redis（支持真实消费组语义）
# ============================================================
class MemRedis:
    """内存版 Redis：只实现分布式链路用到的命令，但**有真实状态**。

    为什么不用 AsyncMock 桩：T14 要压的是"分发 / ACK / PEL 重投递 / 去重"
    的**状态机正确性** —— 桩没有状态就压不出来（它只会返回预设值，任何
    "重复投递/丢任务"的 bug 都会被桩掩盖）。

    覆盖：stream(xadd/xreadgroup/xack/xlen/xpending_range/xrange)、
    kv(set/setex/get/exists/delete/scan/keys)、hash(hset/hget)、
    set(sadd/smembers/srem)、llen/close。
    """

    def __init__(self):
        self._seq = 0
        self.kv = {}
        self.hashes = {}
        self.sets = {}
        self.streams = {}   # key -> [(mid, fields)]
        self.groups = {}    # (stream, group) -> {"last_id": str}
        self.pel = {}       # (stream, group) -> {mid: consumer}
        self.xadd_log = []  # 便于断言重投递次数
        self.deleted = []

    async def ping(self):
        return True

    async def close(self):
        return None

    # --- stream ---
    def _next_id(self):
        self._seq += 1
        return f"{self._seq}-0"

    @staticmethod
    def _gt(a, b):
        def parse(s):
            p = str(s).split("-")
            return (int(p[0]) if p and p[0].isdigit() else 0,
                    int(p[1]) if len(p) > 1 and p[1].isdigit() else 0)
        return parse(a) > parse(b)

    async def xgroup_create(self, stream, group, id="0", mkstream=False):
        self.streams.setdefault(stream, [])
        self.groups.setdefault((stream, group), {"last_id": id})
        return True

    async def xadd(self, stream, fields):
        mid = self._next_id()
        self.streams.setdefault(stream, []).append((mid, dict(fields)))
        self.xadd_log.append((stream, mid))
        return mid

    async def xreadgroup(self, groupname, consumername, streams, count=1, block=None):
        (stream, start), = list(streams.items())
        g = self.groups.get((stream, groupname))
        if g is None:
            return []
        out = []
        for mid, fields in self.streams.get(stream, []):
            # ">" 语义 = 只看"从未投递过"的消息（即 id > last_id）。
            # 早期写法 `start == ">" or ...` 条件恒真 → 每次都重发第一条
            # （T14 压测一跑就抓到：同一条 t00 把 20 个任务全顶掉）。
            if self._gt(mid, g["last_id"]):
                out.append((mid, fields))
                g["last_id"] = mid
                self.pel.setdefault((stream, groupname), {})[mid] = consumername
                if len(out) >= int(count or 1):
                    break
        return [(stream, out)] if out else []

    async def xack(self, stream, group, *mids):
        pel = self.pel.get((stream, group), {})
        n = 0
        for m in mids:
            if pel.pop(m, None) is not None:
                n += 1
        return n

    async def xlen(self, stream):
        return len(self.streams.get(stream, []))

    async def xpending_range(self, stream, group, start, end, count, consumer=None):
        pel = self.pel.get((stream, group), {})
        rows = [{"message_id": m, "consumer": c}
                for m, c in pel.items() if consumer is None or c == consumer]
        return rows[:int(count or 50)]

    async def xrange(self, stream, min=None, max=None):
        return [(m, f) for m, f in self.streams.get(stream, []) if m == min]

    # --- kv / hash / set ---
    async def set(self, key, value):
        self.kv[key] = value
        return True

    async def setex(self, key, ttl, value):
        self.kv[key] = value
        return True

    async def get(self, key):
        return self.kv.get(key)

    async def delete(self, *keys):
        n = 0
        for k in keys:
            self.deleted.append(k)
            if self.kv.pop(k, None) is not None:
                n += 1
            self.hashes.pop(k, None)
        return n

    async def exists(self, key):
        return 1 if key in self.kv else 0

    async def keys(self, pattern):
        import fnmatch
        return [k for k in self.kv if fnmatch.fnmatchcase(k, pattern)]

    async def scan(self, cursor=0, match=None, count=100):
        import fnmatch
        ks = [k for k in self.kv if fnmatch.fnmatchcase(k, match or "*")]
        return 0, ks[:int(count or 100)]

    async def hset(self, key, field=None, value=None, mapping=None):
        h = self.hashes.setdefault(key, {})
        if mapping:
            h.update({k: v for k, v in mapping.items()})
        if field is not None:
            h[field] = value
        return 1

    async def hget(self, key, field):
        return self.hashes.get(key, {}).get(field)

    async def sadd(self, key, *members):
        s = self.sets.setdefault(key, set())
        before = len(s)
        s.update(members)
        return len(s) - before

    async def smembers(self, key):
        return set(self.sets.get(key, set()))

    async def srem(self, key, *members):
        s = self.sets.get(key, set())
        n = 0
        for m in members:
            if m in s:
                s.discard(m)
                n += 1
        return n

    async def llen(self, key):
        return 0


class TestDistributedStressT14:
    """T14：10 worker 协议级压测 + 故障转移 + 续扫恢复正确性。

    本机无 Redis 服务（6379 CLOSED）→ 用**内存状态机**驱动协议逻辑：
    压的是"分发 / ACK / PEL 重投递 / 去重 / 重启恢复"的**正确性**；
    真实网络吞吐需要真 Redis，不在本测范围（报告 note 已注明）。
    """

    PREFIX = "vulnclaw"

    @staticmethod
    def _mk_master(fake):
        m = DistributedMaster(redis_url="redis://mem:6379/0", prefix="vulnclaw")
        m._redis = fake
        return m

    @staticmethod
    def _mk_worker(fake, wid):
        from vulnclaw.distributed.worker import DistributedWorker
        w = DistributedWorker(redis_url="redis://mem:6379/0", prefix="vulnclaw")
        w._redis = fake
        w._worker_id = wid
        return w

    def test_10_workers_no_loss_no_duplication(self):
        """20 任务 × 10 worker：每个任务恰好被处理一次（无丢、无重）。"""
        async def scenario():
            fake = MemRedis()
            master = self._mk_master(fake)
            for i in range(20):
                await master.submit_task({"task_id": f"t{i:02d}", "type": "scan"})

            workers = [self._mk_worker(fake, f"w{i}") for i in range(10)]
            processed = []
            for _ in range(5):  # 20 任务 / 10 worker 应在 2 轮内取完，留余量
                for wk in workers:
                    t = await wk.pull_task(timeout=0)
                    if not t:
                        continue
                    processed.append(t["task_id"])
                    await fake.xack(f"{self.PREFIX}:tasks", f"{self.PREFIX}:workers",
                                    wk._current_msg_id)

            assert sorted(processed) == [f"t{i:02d}" for i in range(20)], \
                f"任务丢失或多余: {processed}"
            assert len(processed) == len(set(processed)), "同一任务被分发多次"

            # 压测报告（T14 验收物）
            try:
                import os as _os
                _os.makedirs("_runtime_cache", exist_ok=True)
                with open("_runtime_cache/t14_distributed_stress.json",
                          "w", encoding="utf-8") as fh:
                    json.dump({
                        "kind": "t14_distributed_stress",
                        "mode": "protocol_level_memredis",
                        "workers": 10, "tasks": 20,
                        "processed": len(processed),
                        "duplicated": len(processed) - len(set(processed)),
                        "lost": 20 - len(set(processed)),
                        "note": "本机无 Redis 服务，压的是协议正确性；网络吞吐需真 Redis",
                    }, fh, ensure_ascii=False, indent=2)
            except Exception:  # noqa: BLE001 - 报告落盘失败不影响断言结论
                pass
        asyncio.run(scenario())

    def test_dead_worker_requeue_is_deduplicated(self):
        """worker 崩溃（拉到任务但不 ACK）→ 重投递且**只投一次**，新 worker 只取一次。

        这是"断点续扫"的故障侧证明：assigned 记录与消费组 PEL 会同时持有
        同一任务，若两条路径各自重投递就会重复执行。
        """
        async def scenario():
            fake = MemRedis()
            master = self._mk_master(fake)
            await master.submit_task({"task_id": "tX", "type": "scan"})

            dead = self._mk_worker(fake, "w_dead")
            pulled = await dead.pull_task(timeout=0)
            assert pulled and pulled["task_id"] == "tX"

            # w_dead 此后不再心跳（模拟崩溃）；assigned 记录与 PEL 都仍在
            requeued = await master.handle_dead_worker("w_dead")
            assert requeued == 1, f"重投递次数异常（应为 1，去重后）: {requeued}"

            alive = self._mk_worker(fake, "w_alive")
            again = await alive.pull_task(timeout=0)
            assert again and again["task_id"] == "tX", "重投递后应能重新取到"
            assert await alive.pull_task(timeout=0) is None, "同一任务被重复投递"
        asyncio.run(scenario())

    def test_resume_after_master_restart(self):
        """master 重启（进程内 dict 清空）→ 任务状态/结果可从 Redis 读回（续扫恢复）。"""
        async def scenario():
            fake = MemRedis()
            master = self._mk_master(fake)
            await master.submit_task({"task_id": "tR", "type": "scan"})

            # 重启：新实例、本地 dict 为空，但 Redis 侧状态仍在
            master2 = self._mk_master(fake)
            assert master2._task_status == {}, "前置：本地状态确为空"

            await fake.set(f"{self.PREFIX}:result:tR", json.dumps({"ok": True}))
            res = await master2.get_result("tR", timeout=3)
            assert res == {"ok": True}, "重启后未能从 Redis 恢复结果（续扫断链）"

            # 已提交任务的状态也能从 Redis 读回（不是只剩结果）
            st = await master2._load_task_status("tR")
            assert st and st.get("submitted_at"), "任务元状态未持久化"
        asyncio.run(scenario())
