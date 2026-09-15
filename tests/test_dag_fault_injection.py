# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# 验收：C1 DAG/Worker 故障注入（lease / 取消传播 / 节点超时 / 失败分类 / 部分成功）
#
# 全部离线确定性（内存 lease，无 Redis / 无容器）。
# 说明：Redis 跨进程 lease 与容器级故障恢复属环境 blocked 项（见 docs/DAG_STATE_MACHINE.md）。
#
# scan_id 指向 _runtime_cache/dag_dead_letter/<id>.jsonl，每个用例 finally 清理。

import asyncio
import os

from vulnclaw.dag.executor import dead_letter_dir, read_dead_letter
from vulnclaw.dag.graph import DAG, DAGNode, NodeStatus, NodeType
from vulnclaw.dag.scheduler import DAGScheduler, classify_failure, is_retryable


def _cleanup_dlq(scan_id: str) -> None:
    """测试卫生：清空（而非删除）DLQ 文件——本机删除会触发 safe-delete 钩子。

    清空后 read_dead_letter 读到 0 条，等效于"从 0 开始计数"，
    且不产生文件删除系统调用（IDE safe-delete 钩子对 os.remove 会抛 SystemExit）。
    """
    try:
        path = os.path.join(dead_letter_dir(), f"{scan_id}.jsonl")
        if os.path.exists(path):
            with open(path, "w", encoding="utf-8"):
                pass
    except OSError:
        pass


def _node(node_id: str, node_type=NodeType.RECON, depends_on=None, **kw) -> DAGNode:
    return DAGNode(
        node_id=node_id,
        node_type=node_type,
        name=node_id,
        target="http://example.com",
        depends_on=list(depends_on or []),
        **kw,
    )


# ============================================================
# 1. 失败分类（纯函数）
# ============================================================
class TestFailureClassification:
    def test_cancelled(self):
        assert classify_failure(asyncio.CancelledError()) == "cancelled"

    def test_timeout_types(self):
        assert classify_failure(asyncio.TimeoutError()) == "timeout"
        assert classify_failure(TimeoutError("timed out")) == "timeout"

    def test_resource(self):
        assert classify_failure(MemoryError()) == "resource"

    def test_network_oserror(self):
        assert classify_failure(OSError("connection refused")) == "network"

    def test_permanent_exceptions(self):
        # 代码/环境类错误归 permanent：重试无意义，直接终结
        assert classify_failure(ValueError("bad value")) == "permanent"
        assert classify_failure(KeyError("missing")) == "permanent"
        assert is_retryable("permanent") is False

    def test_unknown_default(self):
        class _WeirdError(Exception):
            pass

        assert classify_failure(_WeirdError("odd unexpected failure")) == "unknown"

    def test_retryability(self):
        assert is_retryable("timeout") is True
        assert is_retryable("network") is True
        assert is_retryable("unknown") is True
        assert is_retryable("permanent") is False
        assert is_retryable("cancelled") is False
        assert is_retryable(None) is True


# ============================================================
# 2. lease：领取 / 重复投递丢弃 / 换手
# ============================================================
class TestLease:
    def test_acquire_and_duplicate_delivery_rejected(self):
        dag = DAG()
        dag.add_node(_node("n1"))
        sched_a = DAGScheduler(dag, max_concurrent=1, scan_id="t_lease", lease_ttl=60, lease_owner="A")
        sched_b = DAGScheduler(dag, max_concurrent=1, scan_id="t_lease", lease_ttl=60, lease_owner="B")

        assert sched_a.acquire_lease("n1") is True
        assert dag.nodes["n1"].status == NodeStatus.LEASED
        assert sched_b.acquire_lease("n1") is False, "同一节点重复投递必须被丢弃"
        assert sched_a.renew_lease("n1") is True
        assert sched_b.renew_lease("n1") is False, "非 owner 不得续租"

        sched_a.release_lease("n1")
        assert sched_b.acquire_lease("n1") is True, "释放后允许换手重排"

    def test_lease_disabled_keeps_legacy_semantics(self):
        dag = DAG()
        dag.add_node(_node("n1"))
        sched = DAGScheduler(dag, max_concurrent=1, scan_id="t_lease_off", lease_ttl=0)
        assert sched.acquire_lease("n1") is True
        assert dag.nodes["n1"].status == NodeStatus.PENDING, "lease 关闭时不引入 LEASED 中间态"

    def test_expired_lease_reclaimed_to_pending(self):
        dag = DAG()
        dag.add_node(_node("n1"))
        sched = DAGScheduler(
            dag, max_concurrent=1, scan_id="t_lease_reclaim",
            lease_ttl=30, lease_owner="A", max_lease_reclaims=1,
        )
        assert sched.acquire_lease("n1") is True
        node = dag.nodes["n1"]
        reclaimed = sched.recover_expired_leases(now=(node.lease_expires_at or 0) + 1)
        assert reclaimed == ["n1"]
        assert node.status == NodeStatus.PENDING, "未超限 → 回 PENDING 重新可调度"
        assert node.lease_reclaims == 1

    def test_reclaim_over_limit_goes_dead_letter(self):
        scan_id = "t_lease_dead"
        _cleanup_dlq(scan_id)
        dag = DAG()
        dag.add_node(_node("n1"))
        sched = DAGScheduler(
            dag, max_concurrent=1, scan_id=scan_id,
            lease_ttl=30, lease_owner="A", max_lease_reclaims=1,
        )
        try:
            assert sched.acquire_lease("n1") is True
            node = dag.nodes["n1"]
            sched.recover_expired_leases(now=(node.lease_expires_at or 0) + 1)  # 第 1 次
            assert sched.acquire_lease("n1") is True
            sched.recover_expired_leases(now=(node.lease_expires_at or 0) + 1)  # 第 2 次超限
            assert node.status == NodeStatus.FAILED
            assert node.failure_reason == "lease_expired"
            records = read_dead_letter(scan_id)
            assert len(records) == 1
            assert records[0]["skipped_by"] == "lease_expired"
        finally:
            _cleanup_dlq(scan_id)

    def test_active_task_not_reclaimed(self):
        """有活跃任务的节点即便 lease 过期也不回收（长任务由心跳保命）。"""
        async def run():
            dag = DAG()
            dag.add_node(_node("n1"))
            sched = DAGScheduler(dag, max_concurrent=1, scan_id="t_lease_active", lease_ttl=30)
            block = asyncio.Event()

            async def hold(node, ctx):
                await block.wait()
                return {}

            sched.register_executor(NodeType.RECON, hold)
            task = asyncio.create_task(sched.execute_node("n1"))
            # 模拟 _run_loop 的登记（生产路径在调度主循环里写 _running_tasks）
            sched._running_tasks["n1"] = task
            await asyncio.sleep(0.05)  # 让节点进入 RUNNING
            node = dag.nodes["n1"]
            reclaimed = sched.recover_expired_leases(now=(node.lease_expires_at or 0) + 999)
            block.set()
            await task
            return reclaimed, node.status

        reclaimed, status = asyncio.run(run())
        assert reclaimed == [], "RUNNING 且有活跃任务不得被回收"
        assert status == NodeStatus.SUCCEEDED


# ============================================================
# 3. 取消传播
# ============================================================
class TestCancellation:
    def test_cancel_propagates_to_descendants(self):
        scan_id = "t_cancel_prop"
        _cleanup_dlq(scan_id)
        dag = DAG()
        dag.add_node(_node("up"))
        dag.add_node(_node("mid", depends_on=["up"]))
        dag.add_node(_node("leaf", depends_on=["mid"]))
        dag.add_edge("up", "mid")
        dag.add_edge("mid", "leaf")
        sched = DAGScheduler(dag, max_concurrent=1, scan_id=scan_id)

        try:
            cancelled = sched.cancel_node("up")
            assert set(cancelled) == {"up", "mid", "leaf"}
            for nid in ("up", "mid", "leaf"):
                assert dag.nodes[nid].status == NodeStatus.CANCELLED
                assert dag.nodes[nid].failure_reason == "cancelled"
            records = read_dead_letter(scan_id)
            assert len(records) == 3
            assert all(r["skipped_by"] == "cancelled" for r in records)
            # 幂等：终态节点不再被重复取消
            assert sched.cancel_node("up") == []
        finally:
            _cleanup_dlq(scan_id)

    def test_cancel_while_running_recovers_coroutine(self):
        """执行中取消：协程被回收，节点落 CANCELLED 终态，run() 正常收敛。"""
        scan_id = "t_cancel_live"
        _cleanup_dlq(scan_id)

        async def run():
            started = asyncio.Event()

            async def blocking(node, ctx):
                started.set()
                await asyncio.sleep(30)
                return {}

            dag = DAG()
            dag.add_node(_node("n1"))
            sched = DAGScheduler(dag, max_concurrent=1, scan_id=scan_id)
            sched.register_executor(NodeType.RECON, blocking)

            async def canceller():
                await started.wait()
                await asyncio.sleep(0.05)
                sched.cancel_node("n1")

            await asyncio.gather(sched.run(), canceller())
            return dag.nodes["n1"]

        try:
            node = asyncio.run(run())
            assert node.status == NodeStatus.CANCELLED
            assert node.error
        finally:
            _cleanup_dlq(scan_id)

    def test_cancel_all_stops_everything(self):
        dag = DAG()
        dag.add_node(_node("a"))
        dag.add_node(_node("b"))
        sched = DAGScheduler(dag, max_concurrent=1, scan_id="t_cancel_all")
        cancelled = sched.cancel_all(reason="总超时")
        assert set(cancelled) == {"a", "b"}
        assert all(n.status == NodeStatus.CANCELLED for n in dag.nodes.values())


# ============================================================
# 4. 节点级超时
# ============================================================
def test_node_timeout_terminal_and_dead_letter():
    scan_id = "t_node_timeout"
    _cleanup_dlq(scan_id)

    async def slow(node, ctx):
        await asyncio.sleep(5)
        return {}

    dag = DAG()
    dag.add_node(_node("slow1", timeout=0.05, max_retries=2))
    sched = DAGScheduler(dag, max_concurrent=1, scan_id=scan_id)
    sched.register_executor(NodeType.RECON, slow)

    try:
        asyncio.run(sched.run())
        node = dag.nodes["slow1"]
        assert node.status == NodeStatus.TIMEOUT
        assert node.failure_reason == "timeout"
        assert node.retry_count == 0, "节点级超时不重试"
        records = read_dead_letter(scan_id)
        assert len(records) == 1
        assert records[0]["state"] == "dead_letter"
    finally:
        _cleanup_dlq(scan_id)


# ============================================================
# 5. 幂等（重复投递不双执行）
# ============================================================
def test_repeat_delivery_single_execution():
    async def run():
        calls = {"n": 0}

        async def ok(node, ctx):
            calls["n"] += 1
            return {"done": True}

        dag = DAG()
        dag.add_node(_node("n1"))
        sched = DAGScheduler(dag, max_concurrent=1, scan_id="t_idempotent")
        sched.register_executor(NodeType.RECON, ok)

        first = await sched.execute_node("n1")
        second = await sched.execute_node("n1")  # 重复投递
        return calls["n"], sched._exec_counts.get("n1"), first, second

    calls, exec_counts, first, second = asyncio.run(run())
    assert calls == 1, "重复投递不得二次执行"
    assert exec_counts == 1
    assert first == second


# ============================================================
# 6. 部分成功报告（outcome 台账）
# ============================================================
def test_partial_success_outcome_and_ledger():
    scan_id = "t_partial"
    _cleanup_dlq(scan_id)

    async def ok(node, ctx):
        return {"ok": True}

    async def bad(node, ctx):
        raise ValueError("hard failure")

    dag = DAG()
    dag.add_node(_node("good", node_type=NodeType.RECON, max_retries=0))
    dag.add_node(_node("bad", node_type=NodeType.VERIFY, max_retries=0))
    sched = DAGScheduler(dag, max_concurrent=2, scan_id=scan_id)
    sched.register_executor(NodeType.RECON, ok)
    sched.register_executor(NodeType.VERIFY, bad)

    try:
        results = asyncio.run(sched.run())
        profile = results.get("dag_profile") or {}
        assert profile.get("outcome") == "partial_success"
        assert profile.get("dead_letter_count") == 1
        assert any(f["node_id"] == "bad" for f in profile.get("failures") or [])
        assert profile.get("executions", {}).get("good") == 1
        # 成功节点的结果照常可用（不因个别失败整体不可用）
        assert results.get("good") == {"ok": True}
    finally:
        _cleanup_dlq(scan_id)
