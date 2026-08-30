# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 1 模块 3：多目标上下文 —— Redis 后端 DAGContext。

为 DAGContext 提供 Redis 后端支持，每个 target 使用独立前缀隔离数据。
redis_url 为空时降级为内存模式（与原 DAGContext 行为一致）。

集成点：dag/scheduler.py __init__ 增加 context_backend 参数。
"""
import asyncio
import pickle
from typing import Any, Dict, List, Optional

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.dag.context import DAGContext


class MultiTargetContext(DAGContext):
    """支持 Redis 后端 + 前缀隔离的 DAGContext。

    - redis_url 非空时使用 Redis（支持多节点共享任务队列）
    - redis_url 为空时降级为内存模式（单机场景，无报错）
    - prefix 用于区分不同目标，如 "target_abc123_"
    """

    def __init__(self, redis_url: Optional[str] = None, prefix: str = ""):
        self._redis_url = redis_url or getattr(settings, "REDIS_URL", None)
        self._prefix = prefix
        self._redis = None
        self._memory: Dict[str, Any] = {}  # 降级内存存储
        self._lock = asyncio.Lock()

        if self._redis_url:
            self._init_redis()

    def _init_redis(self) -> None:
        """初始化 Redis 连接池。"""
        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(
                self._redis_url, decode_responses=False
            )
            logger.info(f"🔗 MultiTargetContext 连接 Redis: {self._redis_url} prefix={self._prefix}")
        except ImportError:
            logger.warning("⚠️ redis 库未安装，MultiTargetContext 降级为内存模式")
            self._redis = None
        except Exception as exc:
            logger.warning(f"⚠️ Redis 连接失败({exc})，降级为内存模式")
            self._redis = None

    def _full_key(self, key: str) -> str:
        """拼接带前缀的完整 key。"""
        return f"{self._prefix}:{key}" if self._prefix else key

    # --- DAGContext 接口实现 ---

    async def set(self, key: str, value: Any) -> None:
        full_key = self._full_key(key)
        if self._redis:
            serialized = pickle.dumps(value)
            await self._redis.set(full_key, serialized)
        else:
            async with self._lock:
                self._memory[full_key] = value

    async def get(self, key: str) -> Any:
        full_key = self._full_key(key)
        if self._redis:
            raw = await self._redis.get(full_key)
            if raw is None:
                return None
            return pickle.loads(raw)
        else:
            async with self._lock:
                return self._memory.get(full_key)

    async def update(self, key: str, value: Any) -> None:
        """合并更新（dict 类型追加，列表类型追加，其他覆盖）。"""
        self._full_key(key)
        existing = await self.get(key)
        if existing is None:
            await self.set(key, value)
        elif isinstance(existing, dict) and isinstance(value, dict):
            existing.update(value)
            await self.set(key, existing)
        elif isinstance(existing, list) and isinstance(value, list):
            existing.extend(value)
            await self.set(key, existing)
        else:
            await self.set(key, value)

    async def get_and_clear(self, key: str) -> Any:
        """读取并清空指定 key。"""
        value = await self.get(key)
        await self.delete(key)
        return value

    async def get_all(self, prefix: Optional[str] = None) -> Dict[str, Any]:
        """扫描所有 {prefix}:* 键，返回字典。"""
        scan_prefix = prefix or self._prefix
        result: Dict[str, Any] = {}
        if self._redis:
            pattern = f"{scan_prefix}:*" if scan_prefix else "*"
            async for key in self._redis.scan_iter(match=pattern):
                key_str = key.decode() if isinstance(key, bytes) else key
                short_key = key_str.split(":", 1)[-1] if ":" in key_str else key_str
                result[short_key] = await self.get(short_key)
        else:
            async with self._lock:
                for k, v in self._memory.items():
                    if scan_prefix and not k.startswith(scan_prefix):
                        continue
                    short_key = k.split(":", 1)[-1] if ":" in k else k
                    result[short_key] = v
        return result

    async def delete(self, key: str) -> None:
        full_key = self._full_key(key)
        if self._redis:
            await self._redis.delete(full_key)
        else:
            async with self._lock:
                self._memory.pop(full_key, None)

    async def clear(self, prefix: Optional[str] = None) -> None:
        """删除所有 {prefix}:* 键。"""
        scan_prefix = prefix or self._prefix
        if self._redis:
            pattern = f"{scan_prefix}:*" if scan_prefix else "*"
            keys: List[bytes] = []
            async for key in self._redis.scan_iter(match=pattern):
                keys.append(key)
            if keys:
                await self._redis.delete(*keys)
        else:
            async with self._lock:
                to_remove = [
                    k for k in self._memory
                    if not scan_prefix or k.startswith(scan_prefix)
                ]
                for k in to_remove:
                    self._memory.pop(k, None)

    async def has(self, key: str) -> bool:
        full_key = self._full_key(key)
        if self._redis:
            return await self._redis.exists(full_key) > 0
        else:
            async with self._lock:
                return full_key in self._memory

    @property
    def is_redis_mode(self) -> bool:
        """当前是否运行在 Redis 模式。"""
        return self._redis is not None

    async def close(self) -> None:
        """关闭 Redis 连接。"""
        if self._redis:
            await self._redis.close()
