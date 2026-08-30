# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/v100/provider_balancer.py
"""
三供应商负载均衡器 - 修复版 v2.0
修复：
1. #17: 增加 get_last_provider 方法
2. #11: 故障恢复机制 - 失败3次后进入冷却期，冷却后自动恢复
3. 🆕 修复异步锁错误：record_result 改为 async 方法，使用 async with
4. 🆕 修复 get_client 改为 async 方法，使用 async with
5. 🆕 修复 get_client_by_provider 改为 async 方法，使用 async with
6. 🆕 修复所有调用 get_client_by_provider 的地方加 await
"""

import asyncio
import time
from collections import deque

from vulnclaw.core.logger import logger
from vulnclaw.ai.core import get_llm_client, LLMClient
from typing import Dict, List, Optional, Tuple


class ProviderBalancer:
    """
    三供应商负载均衡器
    - 轮询 + 加权分配
    - 自动故障转移
    - QPS自适应
    - 每个供应商独立限流
    - 故障冷却后自动恢复
    """

    def __init__(self):
        self.providers = {
            "zhipu": {
                "name": "智谱",
                "model": "glm-4-flash",
                "weight": 10,
                "qps_limit": 5,
                "available": True,
                "fail_count": 0,
                "success_count": 0,
                "last_fail": 0,
                "client": None,
                "current_qps": 0,
                "cooldown_until": 0,
                "consecutive_failures": 0,
            },
            "aliyun": {
                "name": "阿里云",
                "model": "qwen-plus-2025-07-28",
                "weight": 8,
                "qps_limit": 5,
                "available": True,
                "fail_count": 0,
                "success_count": 0,
                "last_fail": 0,
                "client": None,
                "current_qps": 0,
                "cooldown_until": 0,
                "consecutive_failures": 0,
            },
            "siliconflow": {
                "name": "硅基流动",
                "model": "deepseek-ai/DeepSeek-V3.1-Terminus",
                "weight": 7,
                "qps_limit": 3,
                "available": True,
                "fail_count": 0,
                "success_count": 0,
                "last_fail": 0,
                "client": None,
                "current_qps": 0,
                "cooldown_until": 0,
                "consecutive_failures": 0,
            }
        }

        self._history = {p: deque(maxlen=60) for p in self.providers}
        self._lock = asyncio.Lock()
        self._initialized = False
        self.rate_limiter = None
        self._last_provider: Optional[str] = None

        self._cooldown_seconds = 60
        self._recovery_success_threshold = 2

        logger.info("🔄 三供应商负载均衡器初始化 (含故障恢复)")

    def init_clients(self, rate_limiter=None):
        if self._initialized:
            return

        self.rate_limiter = rate_limiter

        for key, config in self.providers.items():
            try:
                client = get_llm_client(
                    force_new=True,
                    models=[config["model"]]
                )
                config["client"] = client
                config["available"] = True
                logger.info(f"   ✅ {config['name']} 客户端就绪")
            except Exception as e:
                logger.warning(f"   ❌ {config['name']} 初始化失败: {e}")
                config["available"] = False

        self._initialized = True

    # ============================================================
    # 修复：get_client 异步方法
    # ============================================================
    async def get_client(self) -> Tuple[LLMClient, str, str]:
        """获取最优供应商的客户端（负载均衡）- 异步版"""
        if not self._initialized:
            self.init_clients()

        now = time.time()
        for key, config in self.providers.items():
            if not config["available"] and config.get("cooldown_until", 0) > 0:
                if now > config["cooldown_until"]:
                    config["available"] = True
                    config["consecutive_failures"] = 0
                    logger.info(f"♻️ {config['name']} 冷却结束，已自动恢复")

        available = []
        for key, config in self.providers.items():
            if config["available"] and config["client"] is not None:
                available.append((key, config))

        if not available:
            for key, config in self.providers.items():
                if config["client"] is not None:
                    config["available"] = True
                    config["consecutive_failures"] = 0
                    available.append((key, config))
            logger.warning("⚠️ 所有供应商不可用，强制恢复")

        if not available:
            raise RuntimeError("所有供应商均不可用")

        async with self._lock:
            for key, config in available:
                recent = [t for t in self._history.get(key, []) if t > now - 1]
                config["current_qps"] = len(recent)

            best_key, best_config = min(
                available,
                key=lambda item: item[1]["current_qps"] / max(0.1, item[1]["weight"])
            )

            self._history[best_key].append(now)
            self._last_provider = best_key

        return best_config["client"], best_key, best_config["model"]

    def get_last_provider(self) -> Optional[str]:
        """获取最后一次使用的 provider key"""
        return self._last_provider

    # ============================================================
    # 🆕 修复：get_client_by_provider 改为异步方法
    # ============================================================
    async def get_client_by_provider(self, provider_key: str) -> Tuple[LLMClient, str, str]:
        """根据 provider_key 获取客户端 - 异步版"""
        if not self._initialized:
            self.init_clients()

        if provider_key not in self.providers:
            raise ValueError(f"未知供应商: {provider_key}")

        now = time.time()
        config = self.providers[provider_key]

        # 冷却检查
        if not config["available"] and config.get("cooldown_until", 0) > 0:
            if now > config["cooldown_until"]:
                config["available"] = True
                config["consecutive_failures"] = 0
                logger.info(f"♻️ {config['name']} 冷却结束，已自动恢复")

        if not config["available"] or config["client"] is None:
            raise RuntimeError(f"供应商 {provider_key} 不可用")

        # ============================================================
        # 🆕 修复：使用 async with
        # ============================================================
        async with self._lock:
            self._history[provider_key].append(now)
            self._last_provider = provider_key

        return config["client"], provider_key, config["model"]

    def get_all_providers(self) -> List[str]:
        return list(self.providers.keys())

    # ============================================================
    # record_result 异步方法
    # ============================================================
    async def record_result(self, provider_key: str, success: bool, status_code: int = 0):
        """记录结果，用于动态调整权重 - 异步版本"""
        async with self._lock:
            if provider_key not in self.providers:
                return

            config = self.providers[provider_key]
            now = time.time()

            if success:
                config["success_count"] += 1
                config["fail_count"] = max(0, config["fail_count"] - 1)
                config["weight"] = min(10, config["weight"] + 0.3)

                config["consecutive_failures"] = 0
                if not config["available"] and config.get("cooldown_until", 0) > 0:
                    if now > config["cooldown_until"]:
                        config["available"] = True
                        logger.info(f"♻️ {config['name']} 冷却结束，已自动恢复")
            else:
                config["fail_count"] += 1
                config["consecutive_failures"] += 1
                config["weight"] = max(1, config["weight"] - 0.5)
                config["last_fail"] = now

                if config["consecutive_failures"] >= 3:
                    config["available"] = False
                    config["cooldown_until"] = now + self._cooldown_seconds
                    logger.warning(
                        f"⚠️ {config['name']} 连续失败 {config['consecutive_failures']} 次，"
                        f"进入冷却 {self._cooldown_seconds}s，将在 {time.strftime('%H:%M:%S', time.localtime(config['cooldown_until']))} 恢复"
                    )

                if status_code == 429:
                    config["weight"] = max(1, config["weight"] - 2)
                    logger.warning(f"⏳ {config['name']} 触发限流，降低权重")

            if config["available"] and config["weight"] < 5:
                config["weight"] = min(10, config["weight"] + 0.05)

    def get_stats(self) -> Dict:
        """获取统计信息"""
        stats = {}
        now = time.time()
        for key, config in self.providers.items():
            stats[key] = {
                "name": config["name"],
                "model": config["model"],
                "available": config["available"],
                "weight": config["weight"],
                "success": config["success_count"],
                "fail": config["fail_count"],
                "current_qps": config.get("current_qps", 0),
                "qps_limit": config.get("qps_limit", 5),
                "consecutive_failures": config.get("consecutive_failures", 0),
                "cooldown_remaining": max(0, config.get("cooldown_until", 0) - now) if not config["available"] else 0,
            }
        return stats


# 全局单例
_balancer = None


def get_balancer() -> ProviderBalancer:
    global _balancer
    if _balancer is None:
        _balancer = ProviderBalancer()
    return _balancer


__all__ = ['ProviderBalancer', 'get_balancer']
