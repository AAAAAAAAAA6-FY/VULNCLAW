# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""调度/队列层审计契约测试（A/B/C/D）。

A. sentinel guard 故障自愈：is_drained 连续抛错 → 有界失败后 finally 兜底广播，
   所有消费者拿到 sentinel 正常退出，杜绝 attack 阶段永久挂起。
B. 依赖 FAILED → 下游显式 SKIPPED + 结果补齐 + 死信，不再滞留 PENDING 静默漏执行。
C. 重试退避期使用 RETRYING 态 + run_loop 提交去重：同一节点并发峰值恒为 1，
   retry_count 与实际调用次数一致。
D. 队列满且新任务优先级不占优 → 丢弃但必须打警告（不再静默丢失）。
"""
import asyncio
import time

from vulnclaw.ai.v100.smart_queue import SmartTaskQueue
from vulnclaw.dag.graph import DAG, DAGNode, NodeStatus, NodeType
from vulnclaw.dag.scheduler import DAGScheduler


def _t(engine="xss", param=None, source=None):
    td = {"type": "engine_bundle", "engines": [engine], "target": "http://t/x", "priority": 8}
    if source:
        td["source"] = source
    if param:
        td["param"] = param
        td["target"] = "http://t/x?q=1"
    return td


class TestSentinelGuardResilience:
    """A: guard 有界失败 + finally 兜底广播，worker 不会永久空转。"""

    def test_guard_bounded_fail_then_broadcast_workers_exit(self):
        async def _main():
            q = SmartTaskQueue()
            for i in range(2):
                await q.add_task(_t(engine=f"e{i}"), priority=8)
            exited = []

            async def consumer(cid):
                while True:
                    full = await q.get_next_full()
                    if full is None:
                        await asyncio.sleep(0.01)
                        continue
                    _, td = full
                    if isinstance(td, dict) and td.get("__done_sentinel__") is True:
                        exited.append(cid)
                        return

            consumers = [asyncio.create_task(consumer(i)) for i in range(2)]
            guard_done = asyncio.Event()

            async def guard():
                # 与 phases_executor._sentinel_guard 的修复同构：有界失败 + finally 兜底
                try:
                    fail = 0
                    while True:
                        try:
                            await q.is_drained()
                            fail = 0
                        except Exception:
                            fail += 1
                            if fail >= 5:
                                break
                            await asyncio.sleep(0.02)
                            continue
                        break
                finally:
                    await q.mark_production_done(num_consumers=2)
                    guard_done.set()

            calls = {"n": 0}

            async def broken_is_drained():
                calls["n"] += 1
                raise RuntimeError("queue down")

            q.is_drained = broken_is_drained
            g = asyncio.create_task(guard())
            await asyncio.wait_for(guard_done.wait(), timeout=5)
            await g
            await asyncio.wait_for(asyncio.gather(*consumers), timeout=5)
            assert calls["n"] == 5  # 有界失败：不会无限重试空转
            assert sorted(exited) == [0, 1]  # 兜底广播后消费者均正常退出

        asyncio.run(_main())


class TestDepFailedDownstream:
    """B: 依赖失败 → 下游显式 SKIPPED，不再静默滞留 PENDING。"""

    def test_downstream_skipped_when_dep_failed(self):
        async def _main():
            dag = DAG()
            dag.add_node(DAGNode("recon", NodeType.RECON, name="recon", target="http://t"))
            dag.add_node(DAGNode("attack", NodeType.ATTACK, name="attack", target="http://t"))
            dag.add_edge("recon", "attack")
            dag.nodes["recon"].max_retries = 0
            s = DAGScheduler(dag, max_concurrent=2, scan_id="t_scan_b")

            async def fail_exec(_node, _ctx):
                raise RuntimeError("boom")

            async def ok_exec(_node, _ctx):
                return {"ok": 1}

            s.register_executor(NodeType.RECON, fail_exec)
            s.register_executor(NodeType.ATTACK, ok_exec)

            results = await s.run()

            assert dag.nodes["recon"].status == NodeStatus.FAILED
            assert dag.nodes["attack"].status == NodeStatus.SKIPPED
            assert dag.nodes["attack"].error and "失败" in dag.nodes["attack"].error
            assert not [n for n in dag.nodes.values() if n.status == NodeStatus.PENDING]
            assert "recon" in results and "attack" in results  # 结果不再静默缺键

        asyncio.run(_main())


class TestRetryNoDoubleSubmit:
    """C: RETRYING 态 + 提交去重，同一节点并发峰值恒为 1。"""

    def test_retry_succeeds_with_single_execution_stream(self):
        async def _main():
            dag = DAG()
            n = DAGNode("task", NodeType.ATTACK, name="t", target="http://t")
            n.max_retries = 1
            dag.add_node(n)
            s = DAGScheduler(dag, max_concurrent=3, scan_id="t_scan_c1")
            st = {"calls": 0, "concurrent": 0, "max_seen": 0, "lock": asyncio.Lock()}

            async def flaky(_node, _ctx):
                async with st["lock"]:
                    st["concurrent"] += 1
                    st["max_seen"] = max(st["max_seen"], st["concurrent"])
                await asyncio.sleep(0.15)
                try:
                    st["calls"] += 1
                    if st["calls"] <= 1:
                        raise RuntimeError("retry me")
                    return {"ok": True}
                finally:
                    await asyncio.sleep(0.05)
                    async with st["lock"]:
                        st["concurrent"] -= 1

            s.register_executor(NodeType.ATTACK, flaky)
            await s.run()

            assert dag.nodes["task"].status == NodeStatus.SUCCEEDED
            assert dag.nodes["task"].retry_count == 1
            assert st["calls"] == 2
            assert st["max_seen"] == 1  # 旧实现双提交会让并发 >= 2

        asyncio.run(_main())

    def test_retry_exhaustion_no_phantom_pending(self):
        async def _main():
            dag = DAG()
            n = DAGNode("task", NodeType.ATTACK, name="t", target="http://t")
            n.max_retries = 2
            dag.add_node(n)
            s = DAGScheduler(dag, max_concurrent=3, scan_id="t_scan_c2")
            st = {"calls": 0, "concurrent": 0, "max_seen": 0, "lock": asyncio.Lock()}

            async def always_fail(_node, _ctx):
                async with st["lock"]:
                    st["concurrent"] += 1
                    st["max_seen"] = max(st["max_seen"], st["concurrent"])
                await asyncio.sleep(0.05)
                try:
                    st["calls"] += 1
                    raise RuntimeError("always fail")
                finally:
                    async with st["lock"]:
                        st["concurrent"] -= 1

            s.register_executor(NodeType.ATTACK, always_fail)
            await s.run()

            assert dag.nodes["task"].status == NodeStatus.FAILED
            assert dag.nodes["task"].retry_count == 2
            assert st["calls"] == 3
            assert st["max_seen"] == 1

        asyncio.run(_main())


class TestQueueFullDropLogged:
    """D: 队列满丢弃必须打警告，不再静默丢失。"""

    def test_low_priority_drop_logs_warning(self, monkeypatch):
        import vulnclaw.ai.v100.smart_queue as sq

        captured = []
        monkeypatch.setattr(
            sq.logger, "warning",
            lambda msg, *a, **k: captured.append(str(msg)),
        )

        async def _main():
            q = SmartTaskQueue(max_size=2)
            await q.add_task(_t(engine="a"), priority=5)
            await q.add_task(_t(engine="b"), priority=5)
            tid = await q.add_task(_t(engine="zzz", param="p"), priority=1)
            assert tid  # API 语义不变：仍返回 task_id
            assert q.get_pending_count() == 2  # 新任务确实被拒
            assert q._stats["total_added"] == 2

        asyncio.run(_main())
        assert any("丢弃" in m for m in captured)


class TestQueueFullEviction:
    """F: 队列满淘汰走 O(log n) 局部堆修复，语义与旧实现一致。"""

    def test_evicts_lowest_and_admits_higher(self):
        async def _main():
            q = SmartTaskQueue(max_size=3)
            await q.add_task(_t(engine="a"), priority=5)
            await q.add_task(_t(engine="b"), priority=5)
            await q.add_task(_t(engine="c"), priority=8)
            await q.add_task(_t(engine="d"), priority=10)
            assert q.get_pending_count() == 3
            assert q._stats["total_added"] == 3  # 淘汰+插入净增 0
            engines = {t.task_data.get("engines", [""])[0] for t in q._pending_tasks.values()}
            assert "d" in engines
            assert "c" in engines
            assert not ({"a", "b"} <= engines)  # 最低优先级的 a/b 至少其一被淘汰

        asyncio.run(_main())

    def test_full_drop_still_counts(self):
        async def _main():
            q = SmartTaskQueue(max_size=1)
            await q.add_task(_t(engine="a"), priority=5)
            await q.add_task(_t(engine="b"), priority=1)  # ≤ 最低 → 拒绝入队
            assert q.get_pending_count() == 1
            assert q._stats["total_added"] == 1

        asyncio.run(_main())


class TestGraceConsumerExecutesProtected:
    """E: 宽限窗口主动消费执行受保护补测任务（队列原语镜像 E2 机制）。"""

    def test_grace_window_runs_protected_not_waits(self):
        async def _main():
            q = SmartTaskQueue()
            await q.add_task(_t(engine="ord"), priority=5)
            await q.add_task(_t(engine="dyn", param="q", source="param_mining"), priority=8)
            n = await q.fail_all_pending(reason="deadline", protect=True)
            assert n == 1  # 仅普通任务判败
            executed = []
            _until = time.time() + 0.6
            while time.time() < _until:
                full = await q.get_next_full()
                if full is None:
                    await asyncio.sleep(0.05)
                    continue
                _tid, _td = full
                if isinstance(_td, dict) and _td.get("__done_sentinel__") is True:
                    continue
                executed.append(_tid)
                await q.complete_task(_tid, success=True)
            n2 = await q.fail_all_pending(reason="grace end", protect=False)
            assert len(executed) == 1  # 宽限窗口内真正执行，而非干等后判败
            assert n2 == 0

        asyncio.run(_main())


class TestCompletedTasksBounded:
    """G: 审计集合有界裁剪，长驻复用防无限膨胀。"""

    def test_completed_set_trimmed_at_cap(self):
        async def _main():
            q = SmartTaskQueue()
            q._completed_cap = 5
            q._completed_keep = 2
            ids = []
            for i in range(6):
                ids.append(await q.add_task(_t(engine=f"e{i}"), priority=8))
            for i in range(6):
                await q.complete_task(ids[i], success=True)
            assert len(q._completed_tasks) <= 2

        asyncio.run(_main())


class TestTotalAddedCountsEviction:
    """I1: 队列满覆盖入队统计口径守恒——被淘汰任务扣回、新任务入账。"""

    def test_eviction_net_zero_and_new_task_counted(self):
        async def _main():
            q = SmartTaskQueue(max_size=2)
            await q.add_task(_t(engine="a"), priority=5)
            await q.add_task(_t(engine="b"), priority=5)
            c = await q.add_task(_t(engine="c"), priority=9)  # 覆盖最低优先级槽位
            d = await q.add_task(_t(engine="d"), priority=1)  # ≤ 最低 → 拒绝
            st = q.get_stats()
            assert st["total_added"] == 2          # 覆盖净0 + 拒绝不计
            assert c in q._pending_tasks           # 新任务成功入队
            assert d not in q._pending_tasks       # 拒绝任务不占位
            assert len(q._pending_tasks) == 2

        asyncio.run(_main())


class TestBanditFailSafe:
    """J1: bandit 挂件抛异常时，add_task/complete_task 必须正常走完。"""

    class _BrokenBandit:
        def has_sample(self, *_a, **_k):
            raise RuntimeError("sampling backend crashed")

        def adjust(self, *_a, **_k):
            raise RuntimeError("adjust crashed")

        def record(self, *_a, **_k):
            raise RuntimeError("record crashed")

    def test_add_ok_when_bandit_breaks(self):
        async def _main():
            q = SmartTaskQueue(bandit=self._BrokenBandit())
            tid = await q.add_task(_t(engine="a"), priority=8)
            assert tid in q._pending_tasks      # 入队仍成功
            assert q.get_stats()["total_added"] == 1

        asyncio.run(_main())

    def test_complete_ok_when_bandit_breaks(self):
        async def _main():
            q = SmartTaskQueue(bandit=self._BrokenBandit())
            tid = await q.add_task(_t(engine="a"), priority=8)
            await q.complete_task(tid, success=False)   # 不应抛异常
            st = q.get_stats()
            assert st["total_processed"] == 0           # 未消费不计数
            assert st["total_failed"] == 1              # 失败记账正常

        asyncio.run(_main())


class TestCompletedTrimKeepsRecent:
    """I2: 保序裁剪——只裁最早完成者，最近完成的必须保留（set 无序切片会误裁）。"""

    def test_recent_kept_old_dropped(self):
        async def _main():
            q = SmartTaskQueue()
            q._completed_cap = 3
            q._completed_keep = 2
            ids = []
            for i in range(4):
                ids.append(await q.add_task(_t(engine=f"e{i}"), priority=8))
            for i in range(4):
                await q.complete_task(ids[i], success=True)
            assert len(q._completed_tasks) == 2
            assert ids[0] not in q._completed_tasks  # 最早完成两个被裁
            assert ids[1] not in q._completed_tasks
            assert ids[2] in q._completed_tasks       # 最近完成两个保留
            assert ids[3] in q._completed_tasks

        asyncio.run(_main())


class TestParamMapIndexedGc:
    """I5: 完成/淘汰任务的参数关联索引同步清理，防长驻映射膨胀。"""

    def test_complete_clears_param_index(self):
        async def _main():
            q = SmartTaskQueue()
            tid1 = await q.add_task(_t(engine="x", param="p"), priority=8)
            tid2 = await q.add_task(_t(engine="y", param="p"), priority=8)
            await q.complete_task(tid1, success=True)
            left = q._param_task_map.get("p", [])
            assert tid1 not in left and tid2 in left
            await q.complete_task(tid2, success=True)
            assert "p" not in q._param_task_map  # 空键也回收

        asyncio.run(_main())

    def test_eviction_clears_param_index(self):
        async def _main():
            q = SmartTaskQueue(max_size=2)
            a = await q.add_task(_t(engine="a", param="p"), priority=1)
            b = await q.add_task(_t(engine="b", param="q"), priority=5)
            c = await q.add_task(_t(engine="c", param="r"), priority=9)  # 淘汰 a
            assert a not in q._pending_tasks
            for k in ("p", "q", "r"):
                for tid in q._param_task_map.get(k, []):
                    assert tid in q._pending_tasks  # 索引中不得残留已淘汰 id

        asyncio.run(_main())
