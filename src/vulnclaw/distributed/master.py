# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 4 模块 3：分布式 Master 节点。

职责：
1. 管理任务队列（Redis List）
2. 监控 Worker 心跳（30s 超时判定离线）
3. 故障转移：离线 Worker 的任务重新入队
4. 结果收集和汇总

协议：
- 任务队列: {prefix}:tasks (Redis List)
- 结果队列: {prefix}:results (Redis List)
- 心跳: {prefix}:heartbeat:{worker_id} (Redis String, TTL=30s)
- Worker 注册: {prefix}:workers (Redis Set)
"""
import asyncio
import json
import time
from typing import Dict, List, Optional

from vulnclaw.core.logger import logger


class DistributedMaster:
    """分布式 Master 节点。

    管理任务分发、Worker 监控和故障转移。
    """

    HEARTBEAT_TIMEOUT = 30  # 秒
    HEARTBEAT_CHECK_INTERVAL = 10  # 检查间隔
    TASK_TIMEOUT = 600  # 单任务超时 10 分钟

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        prefix: str = "vulnclaw",
    ):
        """初始化 Master 节点。

        Args:
            redis_url: Redis 连接 URL。
            prefix: Key 前缀。
        """
        self._redis_url = redis_url
        self._prefix = prefix
        self._redis = None
        self._running = False
        self._workers: Dict[str, Dict] = {}  # worker_id → info
        self._task_status: Dict[str, Dict] = {}  # task_id → status

        logger.info(f"👑 [Master] 初始化: redis={redis_url} prefix={prefix}")

    async def _connect(self):
        """连接 Redis。"""
        if self._redis is not None:
            return self._redis

        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_timeout=5,
            )
            await self._redis.ping()
            logger.info("✅ [Master] Redis 连接成功")
        except Exception as exc:
            logger.error(f"❌ [Master] Redis 连接失败: {exc}")
            raise

        return self._redis

    # --- 任务管理 ---

    async def _ensure_stream(self) -> None:
        """P3-3: 确保任务 Stream 与消费组存在（Redis Stream 队列）。"""
        stream_key = f"{self._prefix}:tasks"
        group_name = f"{self._prefix}:workers"
        try:
            await self._redis.xgroup_create(
                stream_key, group_name, id="0", mkstream=True
            )
        except Exception:  # noqa: BLE001 - 消费组已存在
            logger.debug("suppressed exception (core audit)")

    async def submit_task(self, task: Dict) -> str:
        """P3-3: 提交任务到 Redis Stream 队列。

        Args:
            task: 任务字典，包含 task_id / type / params / context / ttl 等。

        Returns:
            task_id: 任务 ID。
        """
        await self._connect()

        task_id = task.get("task_id", f"task_{int(time.time() * 1000)}")
        task["task_id"] = task_id
        task["submitted_at"] = time.time()
        task["status"] = "pending"
        # P3-3: 任务 TTL（默认 单任务超时 + 60s 余量）
        if "ttl" not in task:
            task["ttl"] = self.TASK_TIMEOUT + 60

        # 存入任务状态
        self._task_status[task_id] = {
            "status": "pending",
            "submitted_at": task["submitted_at"],
            "assigned_to": None,
            "completed_at": None,
            "result": None,
        }

        # 推入 Stream 队列（多 worker 消费组公平分发）
        await self._ensure_stream()
        await self._redis.xadd(
            f"{self._prefix}:tasks",
            {"task": json.dumps(task, default=str)},
        )

        logger.info(f"📋 [Master] 任务提交: {task_id} type={task.get('type', '?')}")
        return task_id

    async def submit_batch(self, tasks: List[Dict]) -> List[str]:
        """批量提交任务。"""
        task_ids = []
        for task in tasks:
            task_id = await self.submit_task(task)
            task_ids.append(task_id)
        logger.info(f"📋 [Master] 批量提交 {len(task_ids)} 个任务")
        return task_ids

    async def get_result(self, task_id: str, timeout: float = 600) -> Optional[Dict]:
        """等待并获取任务结果。

        Args:
            task_id: 任务 ID。
            timeout: 等待超时（秒）。

        Returns:
            任务结果字典，或 None（超时）。
        """
        await self._connect()

        start = time.time()
        while time.time() - start < timeout:
            status = self._task_status.get(task_id, {})
            if status.get("status") == "completed":
                return status.get("result")
            if status.get("status") == "failed":
                return {"error": status.get("error", "unknown")}

            # 从结果队列检查
            result_key = f"{self._prefix}:result:{task_id}"
            result_data = await self._redis.get(result_key)
            if result_data:
                result = json.loads(result_data)
                self._task_status[task_id]["status"] = "completed"
                self._task_status[task_id]["result"] = result
                self._task_status[task_id]["completed_at"] = time.time()
                return result

            await asyncio.sleep(1)

        logger.warning(f"⚠️ [Master] 任务 {task_id} 等待超时 ({timeout}s)")
        return None

    # --- Worker 管理 ---

    async def register_worker(self, worker_id: str, capabilities: List[str]) -> bool:
        """注册 Worker。

        Args:
            worker_id: Worker 唯一标识。
            capabilities: Worker 支持的节点类型列表。

        Returns:
            True 表示注册成功。
        """
        await self._connect()

        worker_info = {
            "worker_id": worker_id,
            "capabilities": capabilities,
            "registered_at": time.time(),
            "last_heartbeat": time.time(),
            "status": "idle",
            "tasks_completed": 0,
            "tasks_failed": 0,
        }

        await self._redis.hset(
            f"{self._prefix}:worker:{worker_id}",
            mapping={k: json.dumps(v) for k, v in worker_info.items()},
        )
        await self._redis.sadd(f"{self._prefix}:workers", worker_id)

        self._workers[worker_id] = worker_info
        logger.info(f"👷 [Master] Worker 注册: {worker_id} caps={capabilities}")
        return True

    async def update_heartbeat(self, worker_id: str, status: str = "idle") -> None:
        """更新 Worker 心跳。

        Args:
            worker_id: Worker ID。
            status: 当前状态（idle / busy）。
        """
        await self._connect()

        now = time.time()
        heartbeat_key = f"{self._prefix}:heartbeat:{worker_id}"

        # 设置心跳，TTL = HEARTBEAT_TIMEOUT
        await self._redis.setex(heartbeat_key, self.HEARTBEAT_TIMEOUT, str(now))

        # 更新 worker 信息
        await self._redis.hset(
            f"{self._prefix}:worker:{worker_id}",
            mapping={
                "last_heartbeat": str(now),
                "status": status,
            },
        )

        if worker_id in self._workers:
            self._workers[worker_id]["last_heartbeat"] = now
            self._workers[worker_id]["status"] = status

    async def check_workers(self) -> Dict[str, List[str]]:
        """检查 Worker 健康状态。

        Returns:
            {"alive": [...], "dead": [...]}
        """
        await self._connect()

        worker_ids = await self._redis.smembers(f"{self._prefix}:workers")
        alive, dead = [], []

        for worker_id in worker_ids:
            heartbeat_key = f"{self._prefix}:heartbeat:{worker_id}"
            exists = await self._redis.exists(heartbeat_key)
            if exists:
                alive.append(worker_id)
            else:
                dead.append(worker_id)

        return {"alive": alive, "dead": dead}

    async def handle_dead_worker(self, worker_id: str) -> int:
        """处理离线 Worker 的故障转移。

        将该 Worker 正在执行的任务重新入队。

        Args:
            worker_id: 离线的 Worker ID。

        Returns:
            重新入队的任务数量。
        """
        await self._connect()

        # 查找该 worker 正在执行的任务
        pattern = f"{self._prefix}:assigned:{worker_id}:*"
        keys = await self._redis.keys(pattern)

        requeued = 0
        for key in keys:
            task_data = await self._redis.get(key)
            if task_data:
                task = json.loads(task_data)
                task["status"] = "pending"
                task["requeued_from"] = worker_id
                task["requeued_at"] = time.time()

                # 重新入队
                await self._redis.xadd(
                    f"{self._prefix}:tasks",
                    {"task": json.dumps(task, default=str)},
                )
                # 删除原分配记录
                await self._redis.delete(key)
                requeued += 1

        # P3-3: 消费组 pending 重分配（worker 崩溃未 XACK 的消息）
        stream_key = f"{self._prefix}:tasks"
        group_name = f"{self._prefix}:workers"
        try:
            pending = await self._redis.xpending_range(
                stream_key, group_name, "-", "+", 50, worker_id
            )
        except Exception:  # noqa: BLE001 - 组/流不存在或语法不支持
            pending = []
        for entry in pending or []:
            msg_id = entry.get("message_id") if isinstance(entry, dict) else entry[0]
            if not msg_id:
                continue
            try:
                data = await self._redis.xrange(stream_key, min=msg_id, max=msg_id)
            except Exception:  # noqa: BLE001
                data = []
            # 取回后 ACK 再从队尾重新投递，避免消息卡死在死 worker 名下
            await self._redis.xack(stream_key, group_name, msg_id)
            if data:
                fields = data[0][1]
                await self._redis.xadd(stream_key, fields)
                requeued += 1

        # 从 workers 集合移除
        await self._redis.srem(f"{self._prefix}:workers", worker_id)

        logger.warning(f"⚠️ [Master] Worker {worker_id} 离线，重新入队 {requeued} 个任务")
        return requeued

    # --- 监控循环 ---

    async def start_monitor(self) -> None:
        """启动 Worker 监控循环。"""
        self._running = True
        logger.info("👁️ [Master] 启动 Worker 监控")

        while self._running:
            try:
                health = await self.check_workers()
                for dead_worker in health["dead"]:
                    await self.handle_dead_worker(dead_worker)
            except Exception as exc:
                logger.warning(f"⚠️ [Master] 监控异常: {exc}")

            await asyncio.sleep(self.HEARTBEAT_CHECK_INTERVAL)

    async def stop(self) -> None:
        """停止 Master。"""
        self._running = False
        if self._redis:
            await self._redis.close()
        logger.info("🛑 [Master] 已停止")

    # --- 状态查询 ---

    async def get_cluster_status(self) -> Dict:
        """获取集群状态。"""
        await self._connect()

        health = await self.check_workers()
        try:
            task_queue_len = await self._redis.xlen(f"{self._prefix}:tasks")
        except Exception:  # noqa: BLE001 - Stream 不存在时视为空队列
            task_queue_len = 0
        result_queue_len = await self._redis.llen(f"{self._prefix}:results")

        return {
            "workers": {
                "alive": len(health["alive"]),
                "dead": len(health["dead"]),
                "ids": health["alive"],
            },
            "tasks": {
                "pending": task_queue_len,
                "completed": result_queue_len,
            },
            "queue_prefix": self._prefix,
        }
