# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# dag/scheduler.py
import asyncio
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional
from vulnclaw.core.logger import logger
from .graph import DAG, DAGNode, NodeStatus, NodeType
from .resources import ResourceGovernor


class AgentPool:
    """多 Agent 池 - 控制并发执行数量"""

    def __init__(self, max_agents: int = 5):
        self.max_agents = max_agents
        self._semaphore = asyncio.Semaphore(max_agents)
        self._active_agents = 0
        self.max_active_seen = 0
        self.total_submitted = 0
        self._lock = asyncio.Lock()

    @property
    def active(self) -> int:
        return self._active_agents

    async def submit(self, coro: Awaitable) -> Any:
        async with self._semaphore:
            async with self._lock:
                self._active_agents += 1
                self.total_submitted += 1
                if self._active_agents > self.max_active_seen:
                    self.max_active_seen = self._active_agents
            try:
                return await coro
            finally:
                async with self._lock:
                    self._active_agents -= 1


class DAGScheduler:
    def __init__(self, dag: DAG, max_concurrent: int = 5, context=None,
                 context_backend: str = "memory", redis_url: str = None, prefix: str = "",
                 scan_id: str = ""):
        self.dag = dag
        self.max_concurrent = max_concurrent
        self.scan_id = scan_id  # P1-3: 死信队列归属（resume 用）
        self._agent_pool = AgentPool(max_agents=max_concurrent)
        self._results: Dict[str, Any] = {}
        self._status_lock = asyncio.Lock()
        self._running_tasks: Dict[str, asyncio.Task] = {}
        self._node_executors: Dict[NodeType, Callable] = {}
        # Sprint 1: 支持 Redis 后端的多目标上下文
        if context is not None:
            self._context = context
        elif context_backend == "redis":
            from vulnclaw.dag.multi_target_context import MultiTargetContext
            self._context = MultiTargetContext(redis_url=redis_url, prefix=prefix)
        else:
            self._context = None
        self._governor = ResourceGovernor()
        self._run_start: Optional[float] = None
        self._run_end: Optional[float] = None
        self._dashboard_task: Optional[asyncio.Task] = None

    def register_executor(self, node_type: NodeType, executor: Callable) -> None:
        self._node_executors[node_type] = executor

    async def run(self) -> Dict[str, Any]:
        cycle = self.dag.detect_cycle()
        if cycle:
            raise ValueError(f"Cycle detected in DAG: {' -> '.join(cycle)}")

        self._run_start = time.time()
        self._results = {}

        self._dashboard_task = asyncio.create_task(self._metrics_dashboard_task())

        try:
            return await self._run_loop()
        finally:
            self._run_end = time.time()
            if self._dashboard_task and not self._dashboard_task.done():
                self._dashboard_task.cancel()
                try:
                    await self._dashboard_task
                except asyncio.CancelledError:
                    pass

    async def _run_loop(self) -> Dict[str, Any]:
        pending: Dict[str, asyncio.Task] = {}

        while True:
            ready_nodes = self.get_ready_nodes()
            if not ready_nodes and not pending:
                break

            for node_id in ready_nodes:
                task = asyncio.create_task(
                    self._agent_pool.submit(self.execute_node(node_id))
                )
                pending[node_id] = task

            if not pending:
                await asyncio.sleep(0.01)
                continue

            done, _ = await asyncio.wait(
                pending.values(),
                return_when=asyncio.FIRST_COMPLETED
            )

            for task in done:
                for node_id, t in list(pending.items()):
                    if t is task:
                        del pending[node_id]
                        try:
                            task.result()
                        except Exception:
                            pass
                        break

            await asyncio.sleep(0.01)

        return self._build_results()

    def _build_results(self) -> Dict[str, Any]:
        results = dict(self._results)
        results["dag_profile"] = self._build_profile()
        return results

    def _build_profile(self) -> Dict[str, Any]:
        elapsed = (self._run_end or time.time()) - (self._run_start or time.time())
        node_stats = {}
        for node_id, node in self.dag.nodes.items():
            node_stats[node_id] = {
                "type": node.node_type.value,
                "status": node.status.value,
                "retries": node.retry_count,
                "duration_ms": round((node.completed_at - node.started_at) * 1000) if node.started_at and node.completed_at else None,
            }
        status_counts = {}
        for node in self.dag.nodes.values():
            s = node.status.value
            status_counts[s] = status_counts.get(s, 0) + 1
        return {
            "total_nodes": len(self.dag.nodes),
            "status_counts": status_counts,
            "elapsed_seconds": round(elapsed, 2),
            "agent_peak_concurrency": self._agent_pool.max_active_seen,
            "agent_total_submitted": self._agent_pool.total_submitted,
            "resource_limits": self._governor._limits,
            "nodes": node_stats,
        }

    async def _metrics_dashboard_task(self) -> None:
        try:
            while True:
                await asyncio.sleep(5)
                self._print_dashboard()
        except asyncio.CancelledError:
            self._print_dashboard(final=True)

    def _print_dashboard(self, final: bool = False) -> None:
        tag = "FINAL" if final else "TICK"
        elapsed = time.time() - self._run_start if self._run_start else 0
        running = [nid for nid, n in self.dag.nodes.items() if n.status == NodeStatus.RUNNING]
        pending = [nid for nid, n in self.dag.nodes.items() if n.status == NodeStatus.PENDING]
        succeeded = sum(1 for n in self.dag.nodes.values() if n.status == NodeStatus.SUCCEEDED)
        failed = sum(1 for n in self.dag.nodes.values() if n.status == NodeStatus.FAILED)
        total = len(self.dag.nodes)
        res_status = self._governor.status()

        logger.info(
            f"[DAG Dashboard] [{tag}] "
            f"elapsed={elapsed:.1f}s | "
            f"nodes={total} ✅{succeeded} 🔄{len(running)} ⏳{len(pending)} ❌{failed} | "
            f"agents_active={self._agent_pool.active}/{self.max_concurrent} "
            f"peak={self._agent_pool.max_active_seen} | "
            f"resources={res_status}"
        )
        if running:
            logger.info(f"[DAG Dashboard]   RUNNING: {', '.join(running)}")

    def get_ready_nodes(self) -> List[str]:
        ready = []
        for node_id, node in self.dag.nodes.items():
            if node.status != NodeStatus.PENDING:
                continue
            deps_completed = all(
                self.dag.nodes.get(dep_id, None) is not None and
                self.dag.nodes[dep_id].status in (NodeStatus.SUCCEEDED, NodeStatus.SKIPPED)
                for dep_id in node.depends_on
            )
            if deps_completed:
                ready.append(node_id)
        return ready

    async def execute_node(self, node_id: str) -> Any:
        node = self.dag.nodes.get(node_id)
        if not node:
            return None

        async with self._status_lock:
            node.status = NodeStatus.RUNNING
            node.started_at = time.time()

        logger.info(f"🚀 [Agent-{node_id}] 开始执行: {node.name} ({node.node_type.value})")

        try:
            executor = self._node_executors.get(node.node_type)
            if executor:
                result = await self._governor.run_with_acquire(
                    node.node_type,
                    executor(node, self._context)
                )
            else:
                result = await self._default_executor(node)

            async with self._status_lock:
                node.status = NodeStatus.SUCCEEDED
                node.result = result
                node.completed_at = time.time()

            self._results[node_id] = result
            logger.info(f"✅ [Agent-{node_id}] 完成: {node.name}")
            return result

        except Exception as e:
            async with self._status_lock:
                if node.retry_count < node.max_retries:
                    node.retry_count += 1
                    node.status = NodeStatus.PENDING
                    node.error = str(e)
                    logger.warning(f"⚠️ [Agent-{node_id}] 重试 ({node.retry_count}/{node.max_retries}): {e}")
                    retry_delay = 2 ** (node.retry_count - 1)  # P1-3: 指数退避 2s、4s
                else:
                    node.status = NodeStatus.FAILED
                    node.error = str(e)
                    node.completed_at = time.time()
                    logger.error(f"❌ [Agent-{node_id}] 失败: {e}")

            if node.status == NodeStatus.PENDING:
                # P1-3: 指数退避后重新入队，并记录重试计数
                await asyncio.sleep(retry_delay)
                if self._context is not None:
                    try:
                        await self._context.record_node_retry(node_id)
                    except Exception:
                        pass
            if node.status == NodeStatus.FAILED:
                self._results[node_id] = None
                # P1-3: 超限节点写入死信队列 _runtime_cache/dag_dead_letter/{scan_id}.jsonl
                try:
                    from .executor import write_dead_letter
                    write_dead_letter(self.scan_id, {
                        "scan_id": self.scan_id,
                        "node_id": node_id,
                        "node_type": node.node_type.value,
                        "name": node.name,
                        "target": node.target,
                        "params": node.params,
                        "error": str(e),
                        "retries": node.retry_count,
                        "ts": time.time(),
                    })
                except Exception as _dlq_err:
                    logger.warning(f"💀 [DLQ] 写入死信失败: {_dlq_err}")
            return None

    async def _default_executor(self, node: DAGNode) -> Any:
        await asyncio.sleep(0.1)
        return {"node_id": node.node_id, "status": "executed"}

    def get_node_status(self, node_id: str) -> Optional[NodeStatus]:
        node = self.dag.nodes.get(node_id)
        return node.status if node else None

    def get_failed_nodes(self) -> List[str]:
        return [
            node_id for node_id, node in self.dag.nodes.items()
            if node.status == NodeStatus.FAILED
        ]

    def get_completed_nodes(self) -> List[str]:
        return [
            node_id for node_id, node in self.dag.nodes.items()
            if node.status == NodeStatus.SUCCEEDED
        ]