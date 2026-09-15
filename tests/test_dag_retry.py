# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# 验收：P1-3 DAG 失败重试 + 死信队列（OPTIMIZATION_ROADMAP.md）
#
# 覆盖：
#   1) 节点首次失败后重试并最终成功（retry_count 累加、不卡在 RETRYING）
#   2) 重试次数耗尽后标记 FAILED，并把节点写入死信队列（DLQ 可读回）
#   3) 上游 FAILED 时下游依赖节点被显式 SKIPPED（不再静默滞留）
#   4) 重试次数经 DAGContext.record_node_retry 可观测
#
# 说明：调度器内的指数退避为 1s / 2s（max_retries=2），测试因此约 3s，
# 属确定性区间，非 flaky。scan_id 指向 _runtime_cache/dag_dead_letter/<id>.jsonl，
# 每个用例 finally 清理。

import asyncio
import os

from vulnclaw.dag.context import DAGContext
from vulnclaw.dag.executor import dead_letter_dir, read_dead_letter
from vulnclaw.dag.graph import DAG, DAGNode, NodeStatus, NodeType
from vulnclaw.dag.scheduler import DAGScheduler


def _cleanup_dlq(scan_id: str) -> None:
    """清空（而非删除）DLQ 文件——文件变多后 os.remove 会触发本机
    safe-delete 钩子的 bulk guard（WinError 50 → SystemExit）。
    清空后 read_dead_letter 读到 0 条，等效于"从 0 开始计数"。"""
    try:
        path = os.path.join(dead_letter_dir(), f"{scan_id}.jsonl")
        if os.path.exists(path):
            with open(path, "w", encoding="utf-8"):
                pass
    except OSError:
        pass


def _single_node(max_retries: int, node_type: NodeType = NodeType.RECON):
    dag = DAG()
    dag.add_node(
        DAGNode(
            node_id="n1",
            node_type=node_type,
            name="n1",
            target="http://example.com",
            max_retries=max_retries,
        )
    )
    return dag


def test_retry_then_success():
    """首次失败、第二次成功：最终 SUCCEEDED，retry_count==1，且不卡在 RETRYING。"""
    calls = {"n": 0}

    async def exec_fn(node, ctx):
        calls["n"] += 1
        if calls["n"] < 2:
            raise RuntimeError("transient failure")
        return {"ok": True}

    dag = _single_node(max_retries=2)
    sched = DAGScheduler(dag, max_concurrent=1, scan_id="test_retry_ok")
    sched.register_executor(NodeType.RECON, exec_fn)

    asyncio.run(sched.run())

    node = dag.nodes["n1"]
    assert node.status == NodeStatus.SUCCEEDED
    assert node.retry_count == 1
    assert calls["n"] == 2
    assert node.status != NodeStatus.RETRYING


def test_retry_exhausted_writes_dead_letter():
    """始终失败、重试耗尽：FAILED + retry_count==2，且死信队列有 1 条可读记录。"""
    scan_id = "test_retry_dlq"
    calls = {"n": 0}

    async def exec_fn(node, ctx):
        calls["n"] += 1
        raise RuntimeError("always fail")

    # 测试卫生：清理上次异常中断遗留的 DLQ 记录，保证从 0 开始计数
    _cleanup_dlq(scan_id)

    dag = _single_node(max_retries=2)
    sched = DAGScheduler(dag, max_concurrent=1, scan_id=scan_id)
    sched.register_executor(NodeType.RECON, exec_fn)

    try:
        asyncio.run(sched.run())

        node = dag.nodes["n1"]
        assert node.status == NodeStatus.FAILED
        assert node.retry_count == 2
        # 初始 1 次 + 2 次重试
        assert calls["n"] == 3

        records = read_dead_letter(scan_id)
        assert len(records) == 1
        rec = records[0]
        assert rec["node_id"] == "n1"
        assert rec["retries"] == 2
        assert "always fail" in rec["error"]
        assert rec.get("ts") is not None
    finally:
        _cleanup_dlq(scan_id)


def test_dependent_skipped_on_upstream_failure():
    """上游 FAILED 时，下游依赖节点应被显式 SKIPPED，而非静默滞留 PENDING。"""
    scan_id = "test_dep_skip"

    async def upstream_fail(node, ctx):
        raise RuntimeError("upstream fail")

    async def downstream_should_not_run(node, ctx):
        raise AssertionError("下游不应被执行")

    _cleanup_dlq(scan_id)  # 测试卫生：清理上次异常中断遗留记录

    dag = DAG()
    dag.add_node(
        DAGNode(
            node_id="up",
            node_type=NodeType.RECON,
            name="up",
            target="http://example.com",
            max_retries=0,
        )
    )
    dag.add_node(
        DAGNode(
            node_id="down",
            node_type=NodeType.VERIFY,
            name="down",
            target="http://example.com",
            depends_on=["up"],
        )
    )
    sched = DAGScheduler(dag, max_concurrent=1, scan_id=scan_id)
    sched.register_executor(NodeType.RECON, upstream_fail)
    sched.register_executor(NodeType.VERIFY, downstream_should_not_run)

    try:
        asyncio.run(sched.run())
        assert dag.nodes["up"].status == NodeStatus.FAILED
        assert dag.nodes["down"].status == NodeStatus.SKIPPED
    finally:
        _cleanup_dlq(scan_id)


def test_retry_count_recorded_in_context():
    """重试次数经 DAGContext.record_node_retry 落账，可观测（用于报告/审计）。"""

    async def run():
        calls = {"n": 0}

        async def exec_fn(node, ctx):
            calls["n"] += 1
            if calls["n"] < 2:
                raise RuntimeError("boom")
            return {}

        ctx = DAGContext()
        dag = _single_node(max_retries=2)
        sched = DAGScheduler(dag, max_concurrent=1, context=ctx, scan_id="test_ctx")
        sched.register_executor(NodeType.RECON, exec_fn)
        await sched.run()
        return await ctx.get_node_retries("n1")

    assert asyncio.run(run()) == 1
