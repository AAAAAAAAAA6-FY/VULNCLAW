# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 4 模块 2：Redis 后端上下文。

替代内存版 DAGContext，支持多节点共享状态。
接口与 DAGContext 完全兼容：set / get / update / get_and_clear / get_all / clear / has。

序列化策略：
- str/int/float/bool: 直接存储
- dict/list: JSON 序列化
- 其他类型: pickle 序列化（base64 编码）

Key 命名：{prefix}:ctx:{key}
"""
import asyncio
import base64
import json
import pickle
from typing import Any, Dict

from vulnclaw.core.logger import logger


class RedisContext:
    """Redis 后端共享上下文（与 DAGContext 接口完全兼容）。

    所有方法均为 async，与 DAGContext 签名一致。
    当 Redis 不可用时，自动降级到内存模式。
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        prefix: str = "vulnclaw",
    ):
        """初始化 Redis 上下文。

        Args:
            redis_url: Redis 连接 URL。
            prefix: Key 前缀（用于多目标隔离）。
        """
        self._redis_url = redis_url
        self._prefix = f"{prefix}:ctx"
        self._redis = None
        self._fallback_data: Dict[str, Any] = {}  # Redis 不可用时降级
        self._fallback_mode = False
        self._lock = asyncio.Lock()

        logger.info(f"📦 [RedisContext] 初始化: url={redis_url} prefix={prefix}")

    async def _connect(self):
        """延迟连接 Redis。"""
        if self._redis is not None:
            return self._redis

        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(
                self._redis_url,
                decode_responses=False,
                socket_timeout=5,
                socket_connect_timeout=3,
            )
            # 测试连接
            await self._redis.ping()
            logger.info("✅ [RedisContext] Redis 连接成功")
        except Exception as exc:
            logger.warning(f"⚠️ [RedisContext] Redis 不可用，降级到内存模式: {exc}")
            self._fallback_mode = True
            self._redis = None

        return self._redis

    def _make_key(self, key: str) -> str:
        """构建 Redis Key。"""
        return f"{self._prefix}:{key}"

    def _serialize(self, value: Any) -> bytes:
        """序列化值。

        策略：
        - str → 直接编码
        - int/float/bool → JSON
        - dict/list → JSON
        - 其他 → pickle + base64
        """
        if isinstance(value, str):
            return f"s:{value}".encode("utf-8")
        elif isinstance(value, (int, float, bool)):
            return f"j:{json.dumps(value)}".encode("utf-8")
        elif isinstance(value, (dict, list)):
            return f"j:{json.dumps(value, ensure_ascii=False)}".encode("utf-8")
        else:
            try:
                # JSON 优先：绝大多数上下文值可 JSON 化，避免产生 pickle
                return f"j:{json.dumps(value, ensure_ascii=False)}".encode("utf-8")
            except Exception:  # noqa: BLE001 - 不可 JSON 化的类型才走 pickle
                pass
            pickled = pickle.dumps(value)
            b64 = base64.b64encode(pickled)
            return b"p:" + b64

    def _deserialize(self, data: bytes) -> Any:
        """反序列化值。"""
        if data is None:
            return None

        if isinstance(data, str):
            data = data.encode("utf-8")

        prefix = data[:2]
        payload = data[2:]

        if prefix == b"s:":
            return payload.decode("utf-8")
        elif prefix == b"j:":
            return json.loads(payload.decode("utf-8"))
        elif prefix == b"p:":
            from vulnclaw.core.safe_pickle import safe_pickle_loads
            return safe_pickle_loads(base64.b64decode(payload))
        else:
            # 兼容无前缀的旧数据
            try:
                return json.loads(data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return data.decode("utf-8", errors="replace")

    # --- DAGContext 兼容接口 ---

    async def set(self, key: str, value: Any) -> None:
        """设置键值。"""
        async with self._lock:
            if self._fallback_mode:
                self._fallback_data[key] = value
                return

            await self._connect()
            if self._redis is None:
                self._fallback_data[key] = value
                return

            try:
                serialized = self._serialize(value)
                await self._redis.set(self._make_key(key), serialized)
            except Exception as exc:
                logger.warning(f"⚠️ [RedisContext] set 失败，降级: {exc}")
                self._fallback_data[key] = value

    async def get(self, key: str, default: Any = None) -> Any:
        """获取键值。"""
        async with self._lock:
            if self._fallback_mode:
                return self._fallback_data.get(key, default)

            await self._connect()
            if self._redis is None:
                return self._fallback_data.get(key, default)

            try:
                data = await self._redis.get(self._make_key(key))
                if data is None:
                    return default
                return self._deserialize(data)
            except Exception as exc:
                logger.warning(f"⚠️ [RedisContext] get 失败，降级: {exc}")
                return self._fallback_data.get(key, default)

    async def update(self, key: str, value: Any) -> None:
        """更新键值（与 DAGContext.update 语义一致）。

        - list + list → extend
        - dict + dict → merge
        - 其他 → 覆盖
        """
        async with self._lock:
            if self._fallback_mode:
                self._update_in_memory(key, value)
                return

            await self._connect()
            if self._redis is None:
                self._update_in_memory(key, value)
                return

            # 注意：_lock 不可重入，直接操作 Redis，避免嵌套调用 get/set 造成死锁
            try:
                raw = await self._redis.get(self._make_key(key))
                current = self._deserialize(raw) if raw is not None else None
                if current is None:
                    await self._redis.set(self._make_key(key), self._serialize(value))
                elif isinstance(current, list) and isinstance(value, list):
                    current.extend(value)
                    await self._redis.set(self._make_key(key), self._serialize(current))
                elif isinstance(current, dict) and isinstance(value, dict):
                    current.update(value)
                    await self._redis.set(self._make_key(key), self._serialize(current))
                else:
                    await self._redis.set(self._make_key(key), self._serialize(value))
            except Exception as exc:
                logger.warning(f"⚠️ [RedisContext] update 失败，降级: {exc}")
                self._update_in_memory(key, value)

    def _update_in_memory(self, key: str, value: Any) -> None:
        """内存模式下的 update 逻辑。"""
        if key in self._fallback_data:
            current = self._fallback_data[key]
            if isinstance(current, list) and isinstance(value, list):
                current.extend(value)
            elif isinstance(current, dict) and isinstance(value, dict):
                current.update(value)
            else:
                self._fallback_data[key] = value
        else:
            self._fallback_data[key] = value

    async def get_and_clear(self, key: str) -> Any:
        """获取并删除键值。"""
        async with self._lock:
            if self._fallback_mode:
                return self._fallback_data.pop(key, None)

            await self._connect()
            if self._redis is None:
                return self._fallback_data.pop(key, None)

            try:
                raw = await self._redis.get(self._make_key(key))
                await self._redis.delete(self._make_key(key))
                return self._deserialize(raw)
            except Exception as exc:
                logger.warning(f"⚠️ [RedisContext] get_and_clear 失败: {exc}")
                return self._fallback_data.pop(key, None)

    async def get_all(self) -> Dict[str, Any]:
        """获取所有键值对。"""
        async with self._lock:
            if self._fallback_mode:
                return dict(self._fallback_data)

            await self._connect()
            if self._redis is None:
                return dict(self._fallback_data)

            try:
                pattern = f"{self._prefix}:*"
                keys = await self._redis.keys(pattern)
                result = {}
                for raw_key in keys:
                    key_str = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else raw_key
                    # 去掉 prefix 前缀
                    short_key = key_str[len(self._prefix) + 1:]
                    result[short_key] = self._deserialize(
                        await self._redis.get(self._make_key(short_key))
                    )
                return result
            except Exception as exc:
                logger.warning(f"⚠️ [RedisContext] get_all 失败: {exc}")
                return dict(self._fallback_data)

    async def clear(self) -> None:
        """清空所有键值。"""
        async with self._lock:
            if self._fallback_mode:
                self._fallback_data.clear()
                return

            await self._connect()
            if self._redis is None:
                self._fallback_data.clear()
                return

            try:
                pattern = f"{self._prefix}:*"
                keys = await self._redis.keys(pattern)
                if keys:
                    await self._redis.delete(*keys)
                logger.info(f"🧹 [RedisContext] 清空 {len(keys)} 个键")
            except Exception as exc:
                logger.warning(f"⚠️ [RedisContext] clear 失败: {exc}")
                self._fallback_data.clear()

    async def has(self, key: str) -> bool:
        """检查键是否存在。"""
        async with self._lock:
            if self._fallback_mode:
                return key in self._fallback_data

            await self._connect()
            if self._redis is None:
                return key in self._fallback_data

            try:
                return await self._redis.exists(self._make_key(key)) > 0
            except Exception:
                return key in self._fallback_data
