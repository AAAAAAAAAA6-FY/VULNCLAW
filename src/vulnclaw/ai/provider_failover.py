# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 1 模块 1：Provider 故障转移 + 熔断器。

在 ProviderBalancer 之上增加一层故障转移逻辑：当主 Provider 连续失败时
自动切换到备用 Provider，并支持熔断恢复（CLOSED → OPEN → HALF_OPEN）。

集成点：ai/core.py 的 LLMClient.ask() 需集成 ProviderFailover（约 30 行）。
配置项：core/settings.py 增加 PROVIDER_PRIORITY。
"""
import asyncio
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings


class CircuitBreakerOpenError(RuntimeError):
    """熔断器处于 OPEN 状态，请求被直接拒绝。"""


class AllProvidersFailedError(RuntimeError):
    """所有 Provider 均失败。"""


class CircuitBreaker:
    """单 Provider 熔断器。

    状态机：CLOSED（正常）→ OPEN（熔断）→ HALF_OPEN（试探）→ CLOSED/OPEN。
    - CLOSED：连续失败达 failure_threshold → 切换 OPEN
    - OPEN：直接拒绝请求；timeout_seconds 后 → HALF_OPEN
    - HALF_OPEN：允许一次试探调用，成功 → CLOSED，失败 → OPEN
    """

    def __init__(self, failure_threshold: int = 3, timeout_seconds: int = 60):
        self.failure_threshold = failure_threshold
        self.timeout_seconds = timeout_seconds
        self._state = "CLOSED"
        self._failures = 0
        self._last_fail_time: Optional[float] = None
        self._lock = asyncio.Lock()

    @property
    def state(self) -> str:
        """当前熔断状态（含 OPEN→HALF_OPEN 自动转换判定）。"""
        if self._state == "OPEN" and self._last_fail_time is not None:
            if time.time() - self._last_fail_time >= self.timeout_seconds:
                self._state = "HALF_OPEN"
                logger.info("   [CircuitBreaker] OPEN → HALF_OPEN（试探）")
        return self._state

    @property
    def failures(self) -> int:
        return self._failures

    @property
    def last_fail(self) -> Optional[float]:
        return self._last_fail_time

    async def on_success(self) -> None:
        async with self._lock:
            self._failures = 0
            self._state = "CLOSED"

    async def on_failure(self) -> None:
        async with self._lock:
            self._failures += 1
            self._last_fail_time = time.time()
            if self._failures >= self.failure_threshold:
                self._state = "OPEN"
                logger.warning(
                    f"   [CircuitBreaker] CLOSED → OPEN（连续失败 {self._failures} 次）"
                )
            elif self._state == "HALF_OPEN":
                self._state = "OPEN"

    def to_dict(self) -> Dict:
        return {
            "state": self._state,
            "failures": self._failures,
            "last_fail": self._last_fail_time,
        }


class ProviderFailover:
    """Provider 故障转移管理器。

    按 priority 顺序尝试各 Provider，每个 Provider 由独立 CircuitBreaker 保护。
    全部失败 → 抛出 AllProvidersFailedError。
    """

    def __init__(self, priority: Optional[List[str]] = None):
        self.priority = priority or getattr(
            settings, "PROVIDER_PRIORITY", ["zhipu", "aliyun", "siliconflow"]
        )
        self._breakers: Dict[str, CircuitBreaker] = {
            p: CircuitBreaker(
                failure_threshold=getattr(settings, f"{p}_failure_threshold", 3),
                timeout_seconds=getattr(settings, f"{p}_timeout_seconds", 60),
            )
            for p in self.priority
        }
        self._current_provider: Optional[str] = None
        logger.info(f"🔌 ProviderFailover 初始化: {self.priority}")

    @property
    def current_provider(self) -> Optional[str]:
        return self._current_provider

    def get_status(self) -> Dict[str, Dict]:
        """返回各 Provider 的熔断状态快照。"""
        return {p: cb.to_dict() for p, cb in self._breakers.items()}

    async def ask_with_failover(
        self,
        prompt: str,
        ask_fn: Callable[[str, str], Awaitable[str]],
        **kwargs: Any,
    ) -> str:
        """按优先级顺序尝试 Provider，失败自动切换。

        Args:
            prompt: 发送给 LLM 的提示词。
            ask_fn: 接受 (provider, prompt) 的异步函数，返回模型响应文本。
            **kwargs: 透传给 ask_fn 的额外参数。

        Returns:
            模型响应文本。

        Raises:
            AllProvidersFailedError: 所有 Provider 均失败。
        """
        last_error: Optional[Exception] = None
        for provider in self.priority:
            breaker = self._breakers[provider]
            state = breaker.state
            if state == "OPEN":
                logger.info(f"   [Failover] {provider} 熔断中，跳过")
                continue
            try:
                result = await ask_fn(provider, prompt, **kwargs)
                await breaker.on_success()
                self._current_provider = provider
                logger.debug(f"   [Failover] {provider} 调用成功")
                return result
            except Exception as exc:
                await breaker.on_failure()
                last_error = exc
                logger.warning(
                    f"   [Failover] {provider} 失败({breaker.failures}/{breaker.failure_threshold}): {exc}"
                )
                continue
        raise AllProvidersFailedError(
            f"所有 Provider 均失败，最后错误: {last_error}"
        )


# --- 全局单例 ---
_failover: Optional[ProviderFailover] = None


def get_provider_failover() -> ProviderFailover:
    """获取全局 ProviderFailover 单例。"""
    global _failover
    if _failover is None:
        _failover = ProviderFailover()
    return _failover
