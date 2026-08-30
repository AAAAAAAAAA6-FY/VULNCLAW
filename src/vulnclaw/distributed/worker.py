# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 4 模块 4：分布式 Worker 节点。

职责：
1. 向 Master 注册能力
2. 从任务队列拉取任务
3. 执行 DAG 节点
4. 上报结果 + 心跳

工作循环：
  register → (pull_task → execute → report_result → heartbeat) loop → shutdown
"""
import asyncio
import json
import time
import uuid
from typing import Dict, List, Optional

from vulnclaw.core.logger import logger


class DistributedWorker:
    """分布式 Worker 节点。

    从 Redis 任务队列拉取任务，执行 DAG 节点，上报结果。
    """

    HEARTBEAT_INTERVAL = 15  # 心跳间隔（秒），需 < Master.HEARTBEAT_TIMEOUT
    TASK_POLL_INTERVAL = 2   # 任务轮询间隔
    TASK_TIMEOUT = 600       # 单任务超时

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        prefix: str = "vulnclaw",
        capabilities: List[str] = None,
    ):
        """初始化 Worker。

        Args:
            redis_url: Redis 连接 URL。
            prefix: Key 前缀（与 Master 一致）。
            capabilities: 支持的节点类型列表（如 ["recon", "attack", "verify"]）。
        """
        self._redis_url = redis_url
        self._prefix = prefix
        self._capabilities = capabilities or ["recon", "attack", "verify", "report", "deserialization"]
        self._worker_id = f"worker_{uuid.uuid4().hex[:8]}"
        self._redis = None
        self._running = False
        self._current_task: Optional[Dict] = None
        self._current_msg_id = None  # P3-3: 当前 Stream 消息 ID（完成后 ACK）
        self._tasks_completed = 0
        self._tasks_failed = 0

        logger.info(
            f"👷 [Worker] 初始化: id={self._worker_id} "
            f"caps={self._capabilities}"
        )

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
            logger.info(f"✅ [Worker:{self._worker_id}] Redis 连接成功")
        except Exception as exc:
            logger.error(f"❌ [Worker:{self._worker_id}] Redis 连接失败: {exc}")
            raise

        return self._redis

    async def register(self) -> bool:
        """向 Master 注册。"""
        await self._connect()

        from vulnclaw.distributed.master import DistributedMaster

        master = DistributedMaster(redis_url=self._redis_url, prefix=self._prefix)
        await master.register_worker(self._worker_id, self._capabilities)

        # 初始心跳
        await self._send_heartbeat("idle")

        logger.info(f"✅ [Worker:{self._worker_id}] 注册成功")
        return True

    async def _send_heartbeat(self, status: str = "idle") -> None:
        """发送心跳。"""
        await self._connect()

        now = time.time()
        heartbeat_key = f"{self._prefix}:heartbeat:{self._worker_id}"

        await self._redis.setex(heartbeat_key, 30, str(now))
        await self._redis.hset(
            f"{self._prefix}:worker:{self._worker_id}",
            mapping={"last_heartbeat": str(now), "status": status},
        )

    STREAM_KEY_PREFIX = "tasks"      # Stream key: {prefix}:tasks
    GROUP_NAME_PREFIX = "workers"    # 消费组: {prefix}:workers

    async def _ensure_group(self) -> None:
        """P3-3: 确保任务 Stream 消费组存在（多 worker 共享同一组）。"""
        stream_key = f"{self._prefix}:{self.STREAM_KEY_PREFIX}"
        group_name = f"{self._prefix}:{self.GROUP_NAME_PREFIX}"
        try:
            await self._redis.xgroup_create(
                stream_key, group_name, id="0", mkstream=True
            )
        except Exception:  # noqa: BLE001 - 组已存在
            pass

    async def pull_task(self, timeout: int = 5) -> Optional[Dict]:
        """P3-3: 从 Redis Stream 消费组拉取任务。

        多 worker 同时 XREADGROUP ">" 同一队列，Redis 消费组自动公平分发；
        worker 崩溃未 ACK 的消息进入 PENDING，由 Master 重分配。

        Args:
            timeout: 阻塞等待超时（秒），0 表示非阻塞。

        Returns:
            任务字典，或 None（队列为空）。
        """
        await self._connect()
        await self._ensure_group()

        stream_key = f"{self._prefix}:{self.STREAM_KEY_PREFIX}"
        group_name = f"{self._prefix}:{self.GROUP_NAME_PREFIX}"

        try:
            entries = await self._redis.xreadgroup(
                groupname=group_name,
                consumername=self._worker_id,
                streams={stream_key: ">"},
                count=1,
                block=(timeout * 1000) if timeout and timeout > 0 else 1,
            )
        except Exception as exc:
            logger.warning(f"⚠️ [Worker:{self._worker_id}] 拉取任务失败: {exc}")
            return None

        if not entries:
            return None
        messages = entries[0][1] if len(entries[0]) > 1 else []
        if not messages:
            return None

        msg_id, fields = messages[0]
        task_data = fields.get("task", "") if isinstance(fields, dict) else ""
        if not task_data:
            await self._redis.xack(stream_key, group_name, msg_id)
            return None
        task = json.loads(task_data)

        # P3-3: 任务 TTL 检查（过期直接丢弃并 ACK）
        ttl = task.get("ttl") or 0
        submitted_at = task.get("submitted_at") or time.time()
        if ttl and time.time() - submitted_at > ttl:
            await self._redis.xack(stream_key, group_name, msg_id)
            logger.info(
                f"⏰ [Worker:{self._worker_id}] 丢弃过期任务: {task.get('task_id')}"
            )
            return None

        # 记录任务分配
        task["assigned_to"] = self._worker_id
        task["assigned_at"] = time.time()
        task["status"] = "running"
        self._current_msg_id = msg_id

        assigned_key = f"{self._prefix}:assigned:{self._worker_id}:{task['task_id']}"
        await self._redis.set(assigned_key, json.dumps(task, default=str))

        self._current_task = task
        logger.info(f"📋 [Worker:{self._worker_id}] 拉取任务: {task['task_id']} type={task.get('type', '?')}")
        return task

    async def execute_task(self, task: Dict) -> Dict:
        """执行单个任务。

        根据 task.type 调用对应的 DAG 节点执行器。

        Args:
            task: 任务字典。

        Returns:
            执行结果字典。
        """
        task_type = task.get("type", "")
        task.get("params", {})

        logger.info(f"🔧 [Worker:{self._worker_id}] 执行: {task_type}")

        try:
            # 动态导入执行器

            # 创建节点对象
            # TODO: 根据 task 构造 DAGNode
            # node = DAGNode(node_id=task["task_id"], node_type=task_type, ...)
            # context = DAGContext() 或 RedisContext

            # 模拟执行
            result = await asyncio.wait_for(
                self._execute_node(task),
                timeout=self.TASK_TIMEOUT,
            )

            result["task_id"] = task["task_id"]
            result["worker_id"] = self._worker_id
            result["status"] = "success"
            result["completed_at"] = time.time()

            self._tasks_completed += 1
            return result

        except asyncio.TimeoutError:
            logger.error(f"❌ [Worker:{self._worker_id}] 任务超时: {task_type}")
            self._tasks_failed += 1
            return {
                "task_id": task["task_id"],
                "status": "timeout",
                "error": f"Task timeout ({self.TASK_TIMEOUT}s)",
                "worker_id": self._worker_id,
            }
        except Exception as exc:
            logger.error(f"❌ [Worker:{self._worker_id}] 任务失败: {exc}")
            self._tasks_failed += 1
            return {
                "task_id": task["task_id"],
                "status": "failed",
                "error": str(exc),
                "worker_id": self._worker_id,
            }

    async def _execute_node(self, task: Dict) -> Dict:
        """执行 DAG 节点（由 execute_task 调用）。

        根据 task.type 查找 dag.executor.NODE_EXECUTORS 并调用：
        1. 解析 NodeType：优先匹配枚举值（如 "recon_sub"），其次匹配枚举名（如 "RECON_SUB"）；
        2. 按 NODE_EXECUTORS 取执行器，构造 DAGNode + 本地 DAGContext 后执行。
        """
        from vulnclaw.dag.executor import NODE_EXECUTORS
        from vulnclaw.dag.graph import DAGNode, NodeType
        from vulnclaw.dag.context import DAGContext

        task_type = task.get("type", "")

        # 1. 解析 NodeType（P3-3: 先查任务别名表，再枚举值/名匹配）
        _NODE_TYPE_ALIASES = {
            "recon_sub": NodeType.RECON_SUB,
            "recon_alive": NodeType.RECON_ALIVE,
            "alive": NodeType.RECON_ALIVE,
            "attack_engine": NodeType.ATTACK,
            "attack": NodeType.ATTACK,
            "verify": NodeType.VERIFY,
            "exploit": NodeType.EXPLOIT,
            "report": NodeType.REPORT,
            "recon": NodeType.RECON,
            "deserialization": NodeType.DESERIALIZATION,
        }
        node_type = _NODE_TYPE_ALIASES.get(str(task_type).lower())
        if node_type is None:
            try:
                node_type = NodeType(task_type)
            except ValueError:
                for _nt in NodeType:
                    if _nt.name.lower() == str(task_type).lower() or _nt.value == str(task_type).lower():
                        node_type = _nt
                        break
        if node_type is None:
            raise ValueError(f"未知节点类型: {task_type}")

        # 2. 查找执行器
        executor = NODE_EXECUTORS.get(node_type)
        if executor is None:
            raise ValueError(f"节点类型 {task_type} 无对应执行器")

        # 3. 构造 DAGNode 并执行
        node = DAGNode(
            node_id=task.get("task_id", f"task_{task_type}"),
            node_type=node_type,
            name=task.get("name", task_type),
            target=task.get("target", ""),
            params=task.get("params", {}),
        )
        context = DAGContext()
        # P3-3: 携带提交端共享数据（如 recon_sub 的子域名 → recon_alive 使用）
        seed = task.get("context") or {}
        if isinstance(seed, dict):
            for _k, _v in seed.items():
                try:
                    await context.set(_k, _v)
                except Exception:  # noqa: BLE001
                    pass
        result = await executor(node, context)

        if not isinstance(result, dict):
            return {"result": result}
        return result

    async def report_result(self, task_id: str, result: Dict) -> None:
        """上报任务结果。"""
        await self._connect()

        result_key = f"{self._prefix}:result:{task_id}"
        await self._redis.set(result_key, json.dumps(result, default=str))

        # 删除任务分配记录
        assigned_key = f"{self._prefix}:assigned:{self._worker_id}:{task_id}"
        await self._redis.delete(assigned_key)

        # P3-3: ACK Stream 消息（任务完成，从消费组移除，避免重复投递）
        stream_key = f"{self._prefix}:{self.STREAM_KEY_PREFIX}"
        group_name = f"{self._prefix}:{self.GROUP_NAME_PREFIX}"
        msg_id = getattr(self, "_current_msg_id", None)
        if msg_id:
            try:
                await self._redis.xack(stream_key, group_name, msg_id)
            except Exception:  # noqa: BLE001
                pass
            self._current_msg_id = None

        # 推入结果队列
        await self._redis.rpush(f"{self._prefix}:results", json.dumps({
            "task_id": task_id,
            "worker_id": self._worker_id,
            "result": result,
            "reported_at": time.time(),
        }))

        self._current_task = None
        logger.info(f"📤 [Worker:{self._worker_id}] 结果上报: {task_id} status={result.get('status', '?')}")

    async def _heartbeat_loop(self) -> None:
        """心跳循环。"""
        while self._running:
            status = "busy" if self._current_task else "idle"
            await self._send_heartbeat(status)
            await asyncio.sleep(self.HEARTBEAT_INTERVAL)

    async def _task_loop(self) -> None:
        """任务拉取+执行循环。"""
        while self._running:
            try:
                task = await self.pull_task(timeout=5)
                if task is None:
                    continue

                # 发送忙碌心跳
                await self._send_heartbeat("busy")

                # 执行任务
                result = await self.execute_task(task)

                # 上报结果
                await self.report_result(task["task_id"], result)

                # 恢复空闲心跳
                await self._send_heartbeat("idle")

            except Exception as exc:
                logger.error(f"❌ [Worker:{self._worker_id}] 任务循环异常: {exc}")
                await asyncio.sleep(self.TASK_POLL_INTERVAL)

    async def start(self) -> None:
        """启动 Worker。"""
        await self.register()
        self._running = True

        # 并行运行心跳和任务循环
        heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        task_task = asyncio.create_task(self._task_loop())

        logger.info(f"🚀 [Worker:{self._worker_id}] 启动完成")

        try:
            await asyncio.gather(heartbeat_task, task_task)
        except asyncio.CancelledError:
            pass

    async def stop(self) -> None:
        """停止 Worker。"""
        self._running = False
        if self._redis:
            await self._redis.close()
        logger.info(
            f"🛑 [Worker:{self._worker_id}] 已停止 "
            f"(completed={self._tasks_completed}, failed={self._tasks_failed})"
        )

    def get_stats(self) -> Dict:
        """返回 Worker 统计。"""
        return {
            "worker_id": self._worker_id,
            "capabilities": self._capabilities,
            "completed": self._tasks_completed,
            "failed": self._tasks_failed,
            "running": self._running,
            "current_task": self._current_task.get("task_id") if self._current_task else None,
        }
