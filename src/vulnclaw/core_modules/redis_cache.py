# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Redis 缓存后端（CACHE_BACKEND=redis 时由 core_modules/cache.get_cache() 使用）。

设计要点：
- **懒加载**：import 时绝不导入 redis 包，只在实例化时尝试；包缺失抛 ImportError，
  由 get_cache() 捕获并回退 memory —— 缓存层永远不能成为扫描的硬依赖。
- 值统一 JSON 序列化（与 SQLiteCache 口径一致），TTL 交给 Redis 原生 EX。
- 连接参数来自 settings.REDIS_URL（.env 已有 redis://localhost:6379/0）。
- **定位澄清**：跨运行复用（recon 事实型中间结果）用 sqlite 就够了；
  redis 的真正价值在多进程/分布式共享同一份缓存。单机用户请优先 CACHE_BACKEND=sqlite。
"""
import json
from typing import Any, Optional

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings


class RedisCache:
    """CacheBackend 协议的 Redis 实现（get/set/delete）。"""

    def __init__(self, url: Optional[str] = None, default_ttl: int = 7200):
        try:
            import redis  # 懒加载：缺失时抛 ImportError → get_cache 回退 memory
        except ImportError as e:
            raise ImportError(
                "redis 包未安装（pip install redis）；或改用 CACHE_BACKEND=sqlite"
            ) from e
        self._default_ttl = default_ttl
        _url = url or getattr(settings, "redis_url", None) or "redis://localhost:6379/0"
        # decode_responses=True：统一拿 str，省去逐处 decode
        self._client = redis.Redis.from_url(_url, decode_responses=True)
        # 立即探活：连不上就在这里抛错，让 get_cache 回退，而不是扫描中途炸
        self._client.ping()
        logger.info(f"[Cache] Redis 后端已连接: {_url}")

    def get(self, key: str) -> Optional[Any]:
        try:
            raw = self._client.get(key)
            return json.loads(raw) if raw is not None else None
        except Exception as e:  # noqa: BLE001 — 缓存读失败按 miss 处理
            logger.warning(f"[Cache] redis get 失败: {e}")
            return None

    def set(self, key: str, value: Any, ttl: int = 7200):
        try:
            self._client.set(key, json.dumps(value, ensure_ascii=False), ex=ttl or self._default_ttl)
        except Exception as e:  # noqa: BLE001 — 缓存写失败不影响主流程
            logger.warning(f"[Cache] redis set 失败: {e}")

    def delete(self, key: str):
        try:
            self._client.delete(key)
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[Cache] redis delete 失败: {e}")


__all__ = ["RedisCache"]
