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
from .graph import (
    DAG,
    DAGNode,
    FAILURE_STATUSES,
    NodeStatus,
    NodeType,
    TERMINAL_STATUSES,
)
from .resources import ResourceGovernor


# C1: 失败原因分类。分类只决定"是否值得重试"，不改变节点最终是否失败：
# permanent（参数/逻辑/环境错）与 cancelled 重试无意义 → 直接终结，不再空烧退避窗口。
_PERMANENT_EXC = (
    ValueError, TypeError, KeyError, AttributeError, IndexError,
    NotImplementedError, AssertionError, ImportError,
    FileNotFoundError, PermissionError, IsADirectoryError, NotADirectoryError,
)
_RESOURCE_HINTS = (
    "too many open files", "no space left", "cannot allocate memory",
    "out of memory", "resource temporarily unavailable", "memoryerror",
)
_NETWORK_HINTS = (
    "connection", "unreachable", "refused", "reset by peer", "broken pipe",
    "name resolution", "nodename nor servname", "temporary failure",
    "network is down", "ssl", "certificate", "proxy error", "bad gateway",
)


def classify_failure(exc: BaseException) -> str:
    """C1: 把异常归入 timeout / network / resource / permanent / cancelled / unknown。"""
    if isinstance(exc, asyncio.CancelledError):
        return "cancelled"
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "timeout"
    if isinstance(exc, MemoryError):
        return "resource"
    msg = str(exc).lower()
    if any(h in msg for h in _RESOURCE_HINTS):
        return "resource"
    if isinstance(exc, _PERMANENT_EXC):
        return "permanent"
    if "timed out" in msg or "timeout" in msg:
        return "timeout"
    if isinstance(exc, OSError) or any(h in msg for h in _NETWORK_HINTS):
        return "network"
    return "unknown"


def is_retryable(reason: Optional[str]) -> bool:
    """C1: permanent / cancelled 不重试；timeout/network/resource/unknown 可重试。"""
    return reason not in ("permanent", "cancelled")


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
                 scan_id: str = "", lease_ttl: float = 0.0, lease_owner: str = "",
                 max_lease_reclaims: int = 2):
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
        # C1: 节点级 lease（内存实现；跨进程 / Redis lease 属 blocked 项，
        # 见 docs/DAG_STATE_MACHINE.md）。lease_ttl<=0 = 关闭 lease 语义，
        # 投递行为与 P1-3 之前完全一致（默认值，避免内存模式的无谓开销）。
        self._lease_ttl = float(lease_ttl or 0.0)
        self._lease_owner = lease_owner or f"sched-{id(self):x}"
        self._max_lease_reclaims = max(0, int(max_lease_reclaims))
        self._lease_reclaims: Dict[str, int] = {}
        # C1: 每节点实际执行次数（幂等/重复投递的机器可证事实）
        self._exec_counts: Dict[str, int] = {}
        # C1: 本调度器写入的死信条数（部分成功报告的账本口径）
        self._dlq_written = 0

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
                    logger.debug("suppressed exception (core audit)")

    async def _run_loop(self) -> Dict[str, Any]:
        pending: Dict[str, asyncio.Task] = {}

        while True:
            # C1: 先回收 lease 过期且无活跃任务的节点（无 lease 时为空操作），
            # 让"上一个调度器领取后崩溃"的节点自动回到 PENDING 重新可调度。
            self.recover_expired_leases()
            ready_nodes = self.get_ready_nodes()
            if not ready_nodes and not pending:
                break

            for node_id in ready_nodes:
                if node_id in pending:  # 调度审计C: 已在跑/退避中的节点不再重复提交
                    continue
                if not self.acquire_lease(node_id):
                    # C1: lease 未过期且非本调度器持有 → 重复投递，必须丢弃
                    continue
                task = asyncio.create_task(
                    self._agent_pool.submit(self.execute_node(node_id))
                )
                pending[node_id] = task
                self._running_tasks[node_id] = task

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
                        self._running_tasks.pop(node_id, None)
                        try:
                            task.result()
                        except asyncio.CancelledError:
                            logger.debug("node task cancelled (C1)")
                        except Exception:
                            logger.debug("suppressed exception (core audit)")
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
        # C1: 部分成功语义——失败/取消的节点单列台账，成功节点的结果照常可用，
        # 不因个别节点失败而把整份报告判为不可用（也不静默丢失失败事实）。
        failures = [
            {
                "node_id": node_id,
                "type": node.node_type.value,
                "status": node.status.value,
                "failure_reason": node.failure_reason,
                "error": node.error,
                "retries": node.retry_count,
            }
            for node_id, node in self.dag.nodes.items()
            if node.status in FAILURE_STATUSES or node.status == NodeStatus.CANCELLED
        ]
        return {
            "total_nodes": len(self.dag.nodes),
            "status_counts": status_counts,
            "outcome": self._outcome(status_counts),
            "failures": failures,
            "lease_reclaims": dict(self._lease_reclaims),
            "executions": dict(self._exec_counts),
            "dead_letter_count": self._dlq_written,
            "elapsed_seconds": round(elapsed, 2),
            "agent_peak_concurrency": self._agent_pool.max_active_seen,
            "agent_total_submitted": self._agent_pool.total_submitted,
            "resource_limits": self._governor._limits,
            "nodes": node_stats,
        }

    @staticmethod
    def _outcome(status_counts: Dict[str, int]) -> str:
        """C1: 整体判定。success=全绿；partial_success=有成功也有失败/取消；
        failed=无任何成功且存在失败；cancelled=仅取消无失败。"""
        succeeded = status_counts.get(NodeStatus.SUCCEEDED.value, 0)
        failed = sum(status_counts.get(s.value, 0) for s in FAILURE_STATUSES)
        cancelled = status_counts.get(NodeStatus.CANCELLED.value, 0)
        if not failed and not cancelled:
            return "success"
        if succeeded:
            return "partial_success"
        if cancelled and not failed:
            return "cancelled"
        return "failed"

    async def _metrics_dashboard_task(self) -> None:
        try:
            while True:
                await asyncio.sleep(5)
                # C1: 心跳续租，长任务不会因为 lease 过期被误判为"已死"而回收
                self._renew_active_leases()
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
        """就绪节点集合。

        调度审计B: 依赖 FAILED 的下游不再无限滞留 PENDING——显式转 SKIPPED
        并写死信/告警，避免主循环在 `not ready and not pending` 时直接 break
        造成整段扫描阶段静默漏执行（如 recon 挂则 attack/verify 无声无息不跑）。
        """
        ready = []
        for node_id, node in self.dag.nodes.items():
            if node.status != NodeStatus.PENDING:
                continue
            blocked = [
                dep_id for dep_id in node.depends_on
                if dep_id in self.dag.nodes
                and self.dag.nodes[dep_id].status in FAILURE_STATUSES
            ]
            if blocked:
                node.status = NodeStatus.SKIPPED
                node.completed_at = time.time()
                node.error = ("依赖 %s 失败，本节点跳过") % ",".join(blocked)
                self._results[node_id] = None
                logger.error(
                    "⏭ [Agent-%s] 依赖失败被跳过: %s -> %s (%s)",
                    node_id, ",".join(blocked), node.name, node.node_type.value,
                )
                self._write_dlq(node, skipped_by="dep_failed")
                continue
            cancelled_deps = [
                dep_id for dep_id in node.depends_on
                if dep_id in self.dag.nodes
                and self.dag.nodes[dep_id].status == NodeStatus.CANCELLED
            ]
            if cancelled_deps:
                # C1: 上游被取消 → 下游一并取消（取消传播的兜底：即便节点是在
                # 取消之后才加入 DAG 的，也不会静默滞留 PENDING）
                node.status = NodeStatus.CANCELLED
                node.completed_at = time.time()
                node.failure_reason = "cancelled"
                node.error = ("依赖 %s 已取消，本节点取消") % ",".join(cancelled_deps)
                self._results[node_id] = None
                logger.warning(
                    "🚫 [Agent-%s] 上游取消被连带取消: %s -> %s (%s)",
                    node_id, ",".join(cancelled_deps), node.name, node.node_type.value,
                )
                self._write_dlq(node, skipped_by="dep_cancelled")
                continue
            deps_completed = all(
                self.dag.nodes.get(dep_id, None) is not None and
                self.dag.nodes[dep_id].status in (NodeStatus.SUCCEEDED, NodeStatus.SKIPPED)
                for dep_id in node.depends_on
            )
            if deps_completed:
                ready.append(node_id)
        return ready

    # ========== C1: lease（领取 / 续租 / 回收） ==========
    def acquire_lease(self, node_id: str) -> bool:
        """尝试取得节点执行权（投递权）。

        lease_ttl<=0 时退化为恒成功（保持 P1-3 之前的直投递语义）。
        返回 False 表示 lease 由**其它**调度器持有且尚未过期 → 本次是重复投递，
        调用方必须丢弃，不得重复执行节点。
        """
        node = self.dag.nodes.get(node_id)
        if node is None:
            return False
        if self._lease_ttl <= 0:
            return True
        now = time.time()
        if (node.lease_owner and node.lease_owner != self._lease_owner
                and node.lease_expires_at and node.lease_expires_at > now):
            logger.warning(
                "♻️ [Agent-%s] 重复投递被丢弃: lease 由 %s 持有至 %.0f",
                node_id, node.lease_owner, node.lease_expires_at,
            )
            return False
        node.lease_owner = self._lease_owner
        node.lease_expires_at = now + self._lease_ttl
        if node.status == NodeStatus.PENDING:
            node.status = NodeStatus.LEASED
        return True

    def renew_lease(self, node_id: str) -> bool:
        """心跳续租（仅对本调度器持有的 lease 生效）。"""
        node = self.dag.nodes.get(node_id)
        if node is None or self._lease_ttl <= 0 or node.lease_owner != self._lease_owner:
            return False
        node.lease_expires_at = time.time() + self._lease_ttl
        return True

    def release_lease(self, node_id: str) -> None:
        node = self.dag.nodes.get(node_id)
        if node is not None:
            node.lease_owner = None
            node.lease_expires_at = None

    def _renew_active_leases(self) -> None:
        for node_id, node in self.dag.nodes.items():
            if node.status == NodeStatus.RUNNING:
                self.renew_lease(node_id)

    def recover_expired_leases(self, now: Optional[float] = None) -> List[str]:
        """C1: 回收 lease 已过期且没有活跃任务的节点。

        - 未超回收上限 → 节点回到 PENDING 重新可调度（至少一次语义）；
        - 超过 max_lease_reclaims → 判定为无法恢复的失败，写死信
          （state=dead_letter, skipped_by=lease_expired）；
        - 正在执行（有活跃 asyncio.Task）的节点不回收——长任务由心跳续租保命。
        """
        if self._lease_ttl <= 0:
            return []
        now = time.time() if now is None else now
        reclaimed: List[str] = []
        for node_id, node in self.dag.nodes.items():
            if node.status not in (NodeStatus.LEASED, NodeStatus.RUNNING):
                continue
            if not node.lease_expires_at or node.lease_expires_at > now:
                continue
            task = self._running_tasks.get(node_id)
            if task is not None and not task.done():
                continue
            node.lease_reclaims += 1
            self._lease_reclaims[node_id] = node.lease_reclaims
            reclaimed.append(node_id)
            self.release_lease(node_id)
            if node.lease_reclaims > self._max_lease_reclaims:
                node.status = NodeStatus.FAILED
                node.failure_reason = "lease_expired"
                node.error = f"lease 过期回收 {node.lease_reclaims} 次，放弃重排"
                node.completed_at = now
                self._results[node_id] = None
                logger.error("💀 [Agent-%s] lease 回收超限，判定失败并入死信", node_id)
                self._write_dlq(node, skipped_by="lease_expired")
            else:
                node.status = NodeStatus.PENDING
                node.failure_reason = "lease_expired"
                node.started_at = None
                logger.warning(
                    "♻️ [Agent-%s] lease 过期回收（第 %d 次），节点重新入队",
                    node_id, node.lease_reclaims,
                )
        return reclaimed

    # ========== C1: 取消传播 ==========
    def _descendants(self, node_id: str) -> List[str]:
        """返回依赖该节点的所有下游节点（传递闭包，按发现顺序去重）。"""
        out: List[str] = []
        seen = {node_id}
        queue = [node_id]
        while queue:
            cur = queue.pop(0)
            for from_id, to_id in self.dag.edges:
                if from_id == cur and to_id not in seen:
                    seen.add(to_id)
                    out.append(to_id)
                    queue.append(to_id)
        return out

    def cancel_node(self, node_id: str, reason: str = "cancelled",
                    propagate: bool = True) -> List[str]:
        """C1: 取消节点。父取消 → 下游节点与正在跑的协程一并回收。

        已在终态的节点不动（取消是幂等的）。返回实际被取消的节点列表。
        """
        targets = [node_id] + (self._descendants(node_id) if propagate else [])
        cancelled: List[str] = []
        for nid in targets:
            node = self.dag.nodes.get(nid)
            if node is None or node.status in TERMINAL_STATUSES:
                continue
            node.status = NodeStatus.CANCELLED
            node.failure_reason = "cancelled"
            node.error = f"已取消: {reason}"
            node.completed_at = time.time()
            self.release_lease(nid)
            self._results[nid] = None
            task = self._running_tasks.get(nid)
            if task is not None and not task.done():
                task.cancel()  # 协程回收：CancelledError 由 execute_node 收敛为终态
            cancelled.append(nid)
            logger.warning("🚫 [Agent-%s] 已取消（%s）", nid, reason)
            self._write_dlq(node, skipped_by="cancelled")
        return cancelled

    def cancel_all(self, reason: str = "cancelled") -> List[str]:
        """取消所有未进入终态的节点（上层中止扫描 / 总超时闸门用）。"""
        cancelled: List[str] = []
        for nid, node in list(self.dag.nodes.items()):
            if node.status in TERMINAL_STATUSES:
                continue
            cancelled.extend(self.cancel_node(nid, reason, propagate=False))
        return cancelled

    # ========== C1: 死信落账 / 统一失败路径 ==========
    def _write_dlq(self, node: DAGNode, skipped_by: Optional[str] = None) -> None:
        """C1: 统一死信落账。

        state=dead_letter：重试耗尽 / 节点超时 / lease 回收超限（真·死信）；
        state=skipped + skipped_by：依赖失败、上游取消、显式取消（跳过而非死信）。
        """
        try:
            from .executor import write_dead_letter
            record = {
                "scan_id": self.scan_id,
                "node_id": node.node_id,
                "node_type": node.node_type.value,
                "name": node.name,
                "target": node.target,
                "params": node.params,
                "error": node.error,
                "failure_reason": node.failure_reason,
                "retries": node.retry_count,
                "state": (NodeStatus.SKIPPED.value if skipped_by
                          else NodeStatus.DEAD_LETTER.value),
                "ts": time.time(),
            }
            if skipped_by:
                record["skipped_by"] = skipped_by
            write_dead_letter(self.scan_id, record)
            self._dlq_written += 1
        except Exception as _dlq_err:
            logger.warning(f"💀 [DLQ] 写入死信失败: {_dlq_err}")

    async def _handle_failure(self, node: DAGNode, node_id: str,
                              exc: BaseException, reason: str) -> None:
        """C1: 统一失败路径——按分类决定"退避重试"还是"终结入死信"。"""
        async with self._status_lock:
            node.failure_reason = reason
            if node.retry_count < node.max_retries and is_retryable(reason):
                node.retry_count += 1
                node.status = NodeStatus.RETRYING  # 调度审计C: 退避期间挂起，杜绝被重复提交
                node.error = str(exc)
                logger.warning(
                    f"⚠️ [Agent-{node_id}] 重试 ({node.retry_count}/{node.max_retries})"
                    f"[{reason}]: {exc}"
                )
                retry_delay = 2 ** (node.retry_count - 1)  # P1-3: 指数退避 2s、4s
            else:
                node.status = NodeStatus.FAILED
                node.error = str(exc)
                node.completed_at = time.time()
                retry_delay = 0.0

        if node.status == NodeStatus.RETRYING:
            # 退避期间让渡 lease（本任务仍在，不会被误回收；但允许换手重排）
            self.release_lease(node_id)
            # 调度审计C: 指数退避后回到 PENDING 重新可调度（期间不占 pending 额外槽位）
            await asyncio.sleep(retry_delay)
            async with self._status_lock:
                node.status = NodeStatus.PENDING
            if self._context is not None:
                try:
                    await self._context.record_node_retry(node_id)
                except Exception:
                    logger.debug("suppressed exception (core audit)")
            return

        if not is_retryable(reason):
            logger.error(f"❌ [Agent-{node_id}] 不可重试失败[{reason}]: {exc}")
        else:
            logger.error(f"❌ [Agent-{node_id}] 失败: {exc}")
        self._results[node_id] = None
        self.release_lease(node_id)
        # P1-3: 超限节点写入死信队列 _runtime_cache/dag_dead_letter/{scan_id}.jsonl
        self._write_dlq(node)

    async def execute_node(self, node_id: str) -> Any:
        node = self.dag.nodes.get(node_id)
        if not node:
            return None

        # C1: 幂等闸门（同一把锁内判定 + 置位，杜绝并发双执行）
        async with self._status_lock:
            if node.status in TERMINAL_STATUSES:
                logger.debug("⏭ [Agent-%s] 已是终态(%s)，重复投递忽略",
                             node_id, node.status.value)
                return self._results.get(node_id)
            if node.status == NodeStatus.RUNNING:
                logger.warning("♻️ [Agent-%s] 重复投递被丢弃：节点正在执行", node_id)
                return self._results.get(node_id)
            if (self._lease_ttl > 0 and node.lease_owner
                    and node.lease_owner != self._lease_owner
                    and node.lease_expires_at and node.lease_expires_at > time.time()):
                logger.warning("♻️ [Agent-%s] 重复投递被丢弃：lease 由 %s 持有",
                               node_id, node.lease_owner)
                return None
            self.acquire_lease(node_id)
            node.status = NodeStatus.RUNNING
            node.started_at = time.time()
            self._exec_counts[node_id] = self._exec_counts.get(node_id, 0) + 1

        self.renew_lease(node_id)
        logger.info(f"🚀 [Agent-{node_id}] 开始执行: {node.name} ({node.node_type.value})")

        node_timeout = float(node.timeout) if node.timeout and float(node.timeout) > 0 else 0.0
        timed_out = False
        try:
            executor = self._node_executors.get(node.node_type)
            if executor:
                coro = self._governor.run_with_acquire(
                    node.node_type,
                    executor(node, self._context)
                )
            else:
                coro = self._default_executor(node)
            if node_timeout:
                try:
                    result = await asyncio.wait_for(coro, timeout=node_timeout)
                except asyncio.TimeoutError:
                    timed_out = True
                    raise
            else:
                result = await coro

            async with self._status_lock:
                node.status = NodeStatus.SUCCEEDED
                node.result = result
                node.completed_at = time.time()
                node.failure_reason = None

            self._results[node_id] = result
            self.release_lease(node_id)
            logger.info(f"✅ [Agent-{node_id}] 完成: {node.name}")
            return result

        except asyncio.CancelledError:
            # C1: 节点被显式取消（或上游取消传播）。终态 CANCELLED，不重试；
            # 不再上抛——调度主循环把取消当作一次状态迁移，避免整轮 run() 被中断。
            async with self._status_lock:
                node.status = NodeStatus.CANCELLED
                node.failure_reason = "cancelled"
                node.error = node.error or "执行中被取消"
                node.completed_at = time.time()
            self._results[node_id] = None
            self.release_lease(node_id)
            logger.warning("🚫 [Agent-%s] 执行中被取消，协程已回收", node_id)
            return None

        except asyncio.TimeoutError as e:
            if timed_out:
                # C1: 节点级超时 → TIMEOUT 终态，不重试（重试只会再烧一个超时窗口）
                async with self._status_lock:
                    node.status = NodeStatus.TIMEOUT
                    node.failure_reason = "timeout"
                    node.error = f"节点超时（>{node_timeout:g}s）"
                    node.completed_at = time.time()
                self._results[node_id] = None
                self.release_lease(node_id)
                logger.error("⏱ [Agent-%s] 节点超时 %ss，已强制回收", node_id, node_timeout)
                self._write_dlq(node)
                return None
            # 执行器自身抛出的超时（非节点级超时）：按可重试失败处理
            await self._handle_failure(node, node_id, e, "timeout")
            return None

        except Exception as e:
            await self._handle_failure(node, node_id, e, classify_failure(e))
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