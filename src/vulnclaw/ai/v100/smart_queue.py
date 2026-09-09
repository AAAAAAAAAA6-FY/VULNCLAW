# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/v100/smart_queue.py
"""
智能任务队列 - 按价值排序，优先处理高价值任务
修复：异步锁改用 async with
"""

import asyncio
import heapq
import time
from dataclasses import dataclass, field

from vulnclaw.ai.v100.bandit import ContextualBandit, key_from_task  # SP16.1
from vulnclaw.core.logger import logger
from typing import Dict, List, Optional, Tuple


# ============================================================
# 瓶颈3（任务分发阶段）：多协程并发消费者模型需要"统一退出信号"。
# DONE_SENTINEL 为"队列已封闭，所有消费者请退出"的占位对象；
# 当 orchestrator 确认生产阶段已完成（所有计划任务入队）且不再产生重试新入队后，
# 会调用 mark_production_done() 向消费者广播 N 份 sentinel。
# ============================================================
DONE_SENTINEL_TASK_ID = "__SMART_TASK_QUEUE_DONE__"

# SP21.2 动态补测任务保护：param_mining 回灌 / live_intake 实时任务在 attack
# 预算耗尽时不随普通任务一起被误杀，给宽限窗口执行完（真扫观察项收口）。
_PROTECTED_SOURCE_PREFIXES = ("param_mining", "live:")


def is_protected_task(task_data) -> bool:
    """动态补测/实时任务识别：source 命中受保护前缀。"""
    if not isinstance(task_data, dict):
        return False
    src = task_data.get("source") or ""
    return any(str(src).startswith(p) for p in _PROTECTED_SOURCE_PREFIXES)


def _is_sentinel(task_data) -> bool:
    return isinstance(task_data, dict) and task_data.get("__done_sentinel__") is True


@dataclass
class PrioritizedTask:
    """带优先级的任务

    priority: 1-10，数值越大优先级越高、越先被弹出执行。
    注意：heapq 是最小堆（默认数值小者先出队），与"10 最高"语义相反，
    曾导致 priority=6 的全局任务先于 priority=8-10 的 crawl 端点任务执行，
    高价值 XSS/SQLi 端点任务在 attack 预算内未被执行而漏检。
    修复：自定义 __lt__ 反转比较，使堆按 priority 降序出队。
    """
    priority: int
    created_at: float = field(compare=False)
    task_id: str = field(compare=False)
    task_data: Dict = field(compare=False)
    retry_count: int = field(compare=False, default=0)
    max_retries: int = field(compare=False, default=3)

    def __lt__(self, other: "PrioritizedTask") -> bool:
        # heapq 弹出的"最小"对象 → priority 数值大者判为更小 → 先出队
        return self.priority > other.priority


class SmartTaskQueue:
    """
    智能任务队列
    - 按优先级排序
    - 动态调整优先级
    - 支持任务重试
    - 支持限流感知
    """

    def __init__(self, max_size: int = 10000, bandit: ContextualBandit | None = None):
        # SP16.1 RL 决策层：可选注入上下文老虎机（默认 None，零行为回归）
        self._bandit = bandit
        self._queue: List[PrioritizedTask] = []
        self._max_size = max_size
        self._lock = asyncio.Lock()
        self._task_counter = 0
        self._pending_tasks: Dict[str, PrioritizedTask] = {}
        # 审计I2: 保序 dict（插入序=c完成序）——set 无序切片裁剪会裁掉任意元素，
        # 导致"刚完成的任务 id 被裁、重试漏拦重复执行"；dict 成员测试仍 O(1)。
        self._completed_tasks: Dict[str, float] = {}
        self._failed_tasks: Dict[str, int] = {}
        self._drained = False
        self._reopened = False
        self._production_done = False  # 瓶颈3：多消费者模型标记"生产端已封板"

        self._stats = {
            "total_added": 0,
            "total_processed": 0,
            "total_success": 0,
            "total_failed": 0,
            "total_retried": 0
        }
        # 审计G: 长驻复用的审计集合/映射有界上限，超限裁剪防无限膨胀
        self._completed_cap = 200_000
        self._completed_keep = 100_000

        # 参数-任务关联（用于提升相关任务优先级）
        self._param_task_map: Dict[str, List[str]] = {}

        logger.info("📋 智能任务队列已创建")

    @staticmethod
    def _heap_wrap(queue, pos: int) -> None:
        """就地修复堆上被覆盖的 pos 位置（删除处留下空位再放入新元素后调用）。

        heapq 是"最小元素在堆顶"（__lt__ 反转后即最高优先级），
        覆盖后按父节点/子节点比较做上下浮，维持堆不变量，O(log n)。
        """
        item = queue[pos]
        n = len(queue)
        if pos > 0:
            parent_pos = (pos - 1) >> 1
            if item < queue[parent_pos]:
                while pos > 0:
                    parent_pos = (pos - 1) >> 1
                    parent = queue[parent_pos]
                    if item < parent:
                        queue[pos] = parent
                        pos = parent_pos
                    else:
                        break
                queue[pos] = item
                return
        while True:
            child_pos = 2 * pos + 1
            if child_pos >= n:
                queue[pos] = item
                return
            right_pos = child_pos + 1
            if right_pos < n and queue[right_pos] < queue[child_pos]:
                child_pos = right_pos
            if queue[child_pos] < item:
                queue[pos] = queue[child_pos]
                pos = child_pos
            else:
                queue[pos] = item
                return

    async def add_task(self, task_data: Dict, priority: int = 5) -> str:
        """
        添加任务
        priority: 1-10, 10最高
        返回: task_id
        """
        self._task_counter += 1
        task_id = f"task_{self._task_counter}_{int(time.time())}"

        async with self._lock:
            _final_priority = priority
            # 审计J1: bandit 是可选 RL 挂件，采样/调权异常绝不可阻断任务入队
            #（否则 taskgen 批量 add_task 一处抛异常 → 当期全部任务丢失=部分漏检）
            if self._bandit is not None:
                try:
                    _bk = key_from_task(task_data)
                    if _bk and self._bandit.has_sample(_bk):
                        _final_priority = self._bandit.adjust(priority, _bk)
                except Exception as _be:  # noqa: BLE001
                    logger.debug(f"[bandit] 调权失败，按原始优先级入队: {_be}")

            # 检查队列大小
            if len(self._queue) >= self._max_size:
                # 移除最低优先级的任务（priority 数值最小者）
                lowest_pos, lowest = min(
                    enumerate(self._queue), key=lambda it: it[1].priority
                )
                if _final_priority <= lowest.priority:
                    # 调度审计D: 队列满且新任务优先级不占优 → 拒绝添加，
                    # 必须打警告，避免静默丢弃导致漏检误判为已入队
                    logger.warning(
                        "⚠️ [queue] 队列已满(%s)，新任务优先级 %s <= 最低 %s，丢弃: %s",
                        len(self._queue), _final_priority, lowest.priority,
                        task_data.get("param") or task_data.get("engine") or task_data.get("type"),
                    )
                    return task_id
                # 审计F: 覆盖最低优先级槽位 + 局部堆修复（O(log n)），
                # 替代原 remove+heapify 的 O(n) 淘汰，队列满时显著降 CPU
                self._pending_tasks.pop(lowest.task_id, None)
                # 审计I1: 覆盖入队统计守恒——被淘汰任务扣回(-1)，新任务入账(+1)，
                # 口径与常规入队一致（净入队数 = processed + 在队 + 待执行）
                self._stats["total_added"] -= 1
                self._stats["total_added"] += 1
                # 审计I5: 被淘汰任务的参数关联索引同步清理
                try:
                    _p0 = str(lowest.task_data.get("param", ""))
                    if _p0 and lowest.task_id in self._param_task_map.get(_p0, []):
                        self._param_task_map[_p0] = [
                            t for t in self._param_task_map[_p0] if t != lowest.task_id
                        ]
                        if not self._param_task_map[_p0]:
                            self._param_task_map.pop(_p0, None)
                except Exception:  # noqa: BLE001
                    logger.debug("suppressed exception (core audit)")
                task = PrioritizedTask(
                    _final_priority, time.time(), task_id, task_data, 0, 3
                )
                self._queue[lowest_pos] = task
                self._heap_wrap(self._queue, lowest_pos)
                self._pending_tasks[task_id] = task

                # 记录参数关联
                param = task_data.get("param", "")
                if param:
                    if param not in self._param_task_map:
                        self._param_task_map[param] = []
                    self._param_task_map[param].append(task_id)

                return task_id

            task = PrioritizedTask(_final_priority, time.time(), task_id, task_data, 0, 3)
            heapq.heappush(self._queue, task)
            self._pending_tasks[task_id] = task
            self._stats["total_added"] += 1

            # 记录参数关联
            param = task_data.get("param", "")
            if param:
                if param not in self._param_task_map:
                    self._param_task_map[param] = []
                self._param_task_map[param].append(task_id)

            return task_id

    async def get_next(self) -> Optional[Dict]:
        """获取下一个最高优先级任务

        旧接口返回 task_data dict / None；保留以兼容调用方。
        注意：多消费者模式下，若队列空且 production 未结束时会返回 None，
        调用方必须配合 is_drained() / mark_production_done() + 等待重试耗尽来判断是否真正结束。
        """
        full = await self.get_next_full()
        if full is None:
            return None
        _, task_data = full
        return task_data

    def pending_count(self) -> int:
        """待执行任务数（队列中尚未被消费者取走的任务）。用于 attack 阶段预算自适应。"""
        return len(self._queue)

    async def get_next_full(self) -> Optional[Tuple[str, Dict]]:
        """获取下一个 (task_id, task_data)。瓶颈3多消费者需要真实 task_id：
        旧版 orchestrator 在调用 get_next 后用 getattr(task, 'task_id') 或
        time.time() 造一个假 id → 与 retry_task / complete_task 键不一致，
        导致重试/统计都对不上真实 pending 记录。
        """
        async with self._lock:
            while self._queue:
                task = heapq.heappop(self._queue)

                # 多消费者退出信号
                if task.task_id == DONE_SENTINEL_TASK_ID:
                    # 返回 sentinel：调用方识别后 worker 退出
                    return DONE_SENTINEL_TASK_ID, {"__done_sentinel__": True}

                # 检查是否已被完成
                if task.task_id in self._completed_tasks:
                    continue

                # 检查是否达到最大重试次数
                if task.retry_count >= task.max_retries:
                    self._stats["total_failed"] += 1
                    self._failed_tasks[task.task_id] = task.retry_count
                    # 修复死锁：超限任务必须同步从 pending 移除，否则
                    # is_drained() 永远为 False → sentinel 永不广播 →
                    # worker 空转轮询 → attack 节点无限挂起
                    self._pending_tasks.pop(task.task_id, None)
                    continue

                # 返回任务
                self._stats["total_processed"] += 1
                return task.task_id, task.task_data

            return None

    async def mark_production_done(self, num_consumers: int = 1) -> None:
        """瓶颈3：通知 num_consumers 个并发消费者"生产端封板"。

        具体做法：向堆内以 priority=0 塞入 N 个 sentinel（调用方守护者
        已确认队列 drained，sentinel 会立即被弹出），消费者各收到一个
        → 全部退出 while 循环。
        num_consumers 必须和实际 worker 数一致，否则会"剩一个 worker 一直等"或
        "sentinel 多塞了被 get_next 当成 None 丢"。
        """
        async with self._lock:
            self._production_done = True
            for _ in range(max(1, int(num_consumers))):
                sentinel = PrioritizedTask(
                    priority=0,
                    created_at=time.time(),
                    task_id=DONE_SENTINEL_TASK_ID,
                    task_data={"__done_sentinel__": True},
                    retry_count=0,
                    max_retries=0,
                )
                heapq.heappush(self._queue, sentinel)

    async def is_drained(self) -> bool:
        """瓶颈3：判断是否"真正已结束（无队列+无pending）"，供 orchestrator 的
        "生产端封板 → 等待所有重试被消费完毕 → 再发 sentinel" 逻辑使用。
        """
        async with self._lock:
            if len(self._queue) > 0:
                return False
            # pending 中有非 sentinel 记录 → 仍有任务在执行/重试
            return len([tid for tid in self._pending_tasks.keys() if tid != DONE_SENTINEL_TASK_ID]) == 0

    async def complete_task(self, task_id: str, success: bool = True):
        """标记任务完成"""
        async with self._lock:
            task = self._pending_tasks.get(task_id)
            self._completed_tasks[task_id] = time.time()
            # 审计I2: 保序裁剪——逐出最早完成者（插入序=完成序），保留最近 keep 个；
            # set 无序切片会误裁"刚完成的任务"，重试漏拦导致重复执行。
            if len(self._completed_tasks) > self._completed_cap:
                _n_drop = len(self._completed_tasks) - self._completed_keep
                for _ in range(_n_drop):
                    self._completed_tasks.pop(next(iter(self._completed_tasks)), None)
            if len(self._failed_tasks) > self._completed_cap:
                self._failed_tasks = dict(tuple(self._failed_tasks.items())[-self._completed_keep:])
            self._pending_tasks.pop(task_id, None)
            # 审计I5: 同步清理该任务的参数关联索引，防长驻复用下映射膨胀
            if task is not None:
                try:
                    _p = str(task.task_data.get("param", ""))
                    if _p and task_id in self._param_task_map.get(_p, []):
                        self._param_task_map[_p] = [
                            t for t in self._param_task_map[_p] if t != task_id
                        ]
                        if not self._param_task_map[_p]:
                            self._param_task_map.pop(_p, None)
                except Exception:  # noqa: BLE001
                    logger.debug("suppressed exception (core audit)")
            if success:
                self._stats["total_success"] += 1
            else:
                self._stats["total_failed"] += 1
            # SP16.1 回注：执行失败 → bandit 负样本
            # 保守策略：成功但无产出不降权（避免误伤慢热组合），仅失败落地
            # 审计J1: 回注失败不得阻塞 complete_task（否则 worker 收尾路径中断）
            if self._bandit is not None and not success and task is not None:
                try:
                    _bk = key_from_task(task.task_data)
                    if _bk:
                        self._bandit.record(_bk, hit=False)
                except Exception as _br:  # noqa: BLE001
                    logger.debug(f"[bandit] 负样本回注失败（忽略）: {_br}")

    async def fail_all_pending(self, reason: str = "deadline", protect: bool = False) -> int:
        """attack 预算截止：把所有未完成任务直接判失败并清空队列。

        使 is_drained() 能尽快变 True → sentinel 正常广播，worker 有序退出。
        仅清未执行任务；worker 正在执行的任务由调用方的生命周期超时兜底。
        protect=True（SP21.2）：保留动态补测任务（param_mining / live:*），
        由调用方宽限窗口内续跑或再清，避免固定墙钟误杀阶段中后期入队的补测任务；
        无受保护任务时行为与旧版完全一致（零回归）。
        """
        async with self._lock:
            n = 0
            kept: List[PrioritizedTask] = []
            for tid in list(self._pending_tasks.keys()):
                if tid == DONE_SENTINEL_TASK_ID:
                    continue
                task = self._pending_tasks[tid]
                if protect and is_protected_task(task.task_data):
                    kept.append(task)
                    continue
                self._failed_tasks[tid] = -1
                self._pending_tasks.pop(tid, None)
                self._stats["total_failed"] += 1
                n += 1
            self._queue = [t for t in self._queue if t.task_id == DONE_SENTINEL_TASK_ID]
            self._queue.extend(kept)
            heapq.heapify(self._queue)
            if n:
                logger.warning(f"📋 [{reason}]: {n} 个未执行任务判失败出队")
            return n

    async def protected_pending_count(self) -> int:
        """统计 pending 中受保护动态补测任务数（SP21.2 宽限窗口判定用）。"""
        async with self._lock:
            return sum(
                1
                for tid, task in self._pending_tasks.items()
                if tid != DONE_SENTINEL_TASK_ID and is_protected_task(task.task_data)
            )

    async def retry_task(self, task_id: str) -> bool:
        """重试任务"""
        async with self._lock:
            if task_id not in self._pending_tasks:
                return False

            task = self._pending_tasks[task_id]
            if task.retry_count >= task.max_retries:
                return False

            # 增加重试次数
            task.retry_count += 1
            task.priority = max(1, task.priority - 1)  # 降低优先级
            self._stats["total_retried"] += 1

            # 重新入队
            heapq.heappush(self._queue, task)
            return True

    async def update_priority(self, param: str, new_priority: int):
        """
        更新参数关联任务的优先级
        用于: 发现相关漏洞后提升关联任务优先级
        """
        async with self._lock:
            if param not in self._param_task_map:
                return

            updated = 0
            for task_id in self._param_task_map[param]:
                if task_id in self._pending_tasks:
                    task = self._pending_tasks[task_id]
                    if task.priority < new_priority:
                        task.priority = new_priority
                        updated += 1

            # 重新堆化
            heapq.heapify(self._queue)

            if updated > 0:
                logger.debug(f"📈 提升优先级: {param} 相关 {updated} 个任务")

    def get_stats(self) -> Dict:
        """获取统计信息"""
        return {
            "queue_size": len(self._queue),
            "pending": len(self._pending_tasks),
            **self._stats,
            "success_rate": f"{self._stats['total_success'] / max(1, self._stats['total_processed']) * 100:.1f}%"
        }

    def get_pending_count(self) -> int:
        return len(self._pending_tasks)

    def is_empty(self) -> bool:
        return len(self._queue) == 0 and len(self._pending_tasks) == 0

    def reopen_for_dynamic(self) -> None:
        """允许在 drain 后继续添加任务（用于动态子图展开）"""
        self._drained = False
        self._reopened = True

    def finalize(self) -> None:
        """标记任务生产完成（与 reopen_for_dynamic 配对使用）。

        注意：这是同步"快速写入"版本，只适合在外部已经拿到锁/不需要并发
        安全的调用方。orchestrator 的 workers 路径统一使用 async 的
        mark_production_done / is_drained 版本，不要走这里。
        """
        self._drained = True
        self._production_done = True
        sentinel = PrioritizedTask(
            priority=0,
            created_at=time.time(),
            task_id=DONE_SENTINEL_TASK_ID,
            task_data={"__done_sentinel__": True},
            retry_count=0,
            max_retries=0,
        )
        heapq.heappush(self._queue, sentinel)


__all__ = ['DONE_SENTINEL_TASK_ID', 'SmartTaskQueue', '_is_sentinel', 'is_protected_task']