# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/v100/rate_limiter.py
"""
自适应限流器 - 彻底修复版
修复：类型安全、500错误处理、冷却逻辑优化
"""

import asyncio
import time
from collections import deque, defaultdict

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings  # <--- 添加这行
from typing import Dict


class AdaptiveRateLimiter:
    def __init__(self, initial_qps: int = 3):
        self.initial_qps = initial_qps
        self.current_qps = initial_qps
        self._lock = asyncio.Lock()

        self._request_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=120))
        self._models = ["glm-4-flash", "glm-4.7", "deepseek-ai/DeepSeek-V3.1-Terminus", "qwen-plus-2025-07-28"]
        self._failures = {m: 0 for m in self._models}
        self._cooldown_until = {m: 0 for m in self._models}
        self._model_qps = {m: initial_qps for m in self._models}

        self._rate_limit_count = 0
        self._total_requests = 0
        self._success_requests = 0
        self._last_adjust_time = time.time()

        self._min_qps = 0.5
        self._max_qps = 20
        self._cooldown_base = getattr(settings, 'rate_limiter_cooldown_base', 30)
        self._max_wait_time = getattr(settings, 'rate_limiter_max_wait', 60)

        self._success_window = deque(maxlen=20)
        self._failure_window = deque(maxlen=20)

        logger.info(f"⏱️ 自适应限流器初始化: {initial_qps} QPS")

    def _ensure_model(self, model: str) -> None:
        """模型桶动态扩展：首次见到的模型名自动建桶（调用方须已持锁）。"""
        if model not in self._model_qps:
            self._model_qps[model] = self.initial_qps
            self._failures[model] = 0
            self._cooldown_until[model] = 0.0

    async def acquire(self, model: str = "glm-4-flash") -> float:
        async with self._lock:
            self._total_requests += 1
            self._ensure_model(model)

            if model in self._cooldown_until:
                cooldown_end = self._cooldown_until[model]
                if cooldown_end > time.time():
                    wait = cooldown_end - time.time() + 0.5
                    return wait

            current_qps = self._model_qps.get(model, self.current_qps)
            history = self._request_history[model]
            now = time.time()
            recent = [t for t in history if t > now - 1.0]
            request_count = len(recent)

            if request_count >= current_qps:
                wait = 1.0 / current_qps
                wait += (self._total_requests % 10) * 0.01
                return wait

            history.append(now)
            return 0

    async def set_qps(self, qps: float, model: str = "glm-4-flash") -> None:
        """运行时动态调整限流 QPS（目标请求能力探测结果应用）。

        只改指定 model 桶（默认 HTTP 通道），LLM 各模型桶不受影响；
        封顶在 [_min_qps, _max_qps]，加锁避免与 acquire 竞态。
        """
        qps = max(self._min_qps, min(float(qps), self._max_qps))
        async with self._lock:
            self._ensure_model(model)
            self.current_qps = qps
            self._model_qps[model] = qps
            self._cooldown_until[model] = 0.0

    def available_tokens(self, window: float = 1.0) -> float:
        """P3-1: 当前可用令牌余量（所有模型容量合计 − 近 window 秒已发请求）。

        用于流式验证批大小的自适应：余量充足时放大批次，紧张时收窄。
        估算用途，不加锁（轻微竞态可接受）。
        """
        now = time.time()
        recent = sum(
            1
            for hist in self._request_history.values()
            for t in hist
            if t > now - window
        )
        capacity = sum(self._model_qps.values()) * window
        return max(0.0, capacity - recent)

    async def record_success(self, model: str = "glm-4-flash"):
        async with self._lock:
            self._success_requests += 1
            self._ensure_model(model)
            self._success_window.append(1)
            self._failure_window.append(0)

            if model in self._failures:
                self._failures[model] = max(0, self._failures[model] - 1)

            now = time.time()
            success_rate = sum(self._success_window) / max(1, len(self._success_window))

            if success_rate > 0.9 and len(self._success_window) >= 5:
                if now - self._last_adjust_time > 20:
                    old_qps = self._model_qps.get(model, self.current_qps)
                    new_qps = min(self._max_qps, old_qps * 1.5)
                    if new_qps > old_qps + 0.5:
                        self._model_qps[model] = new_qps
                        self.current_qps = new_qps
                        self._last_adjust_time = now
                        logger.info(f"📈 QPS提升: {old_qps:.1f} → {new_qps:.1f} ({model})")

    async def record_failure(self, model: str = "glm-4-flash", status_code: int = 0, error_msg: str = ""):
        """记录失败 - 彻底修复类型安全"""
        # ===== 强制转为字符串 =====
        if not isinstance(error_msg, str):
            try:
                error_msg = str(error_msg)
            except BaseException:
                error_msg = repr(error_msg)
        if len(error_msg) > 200:
            error_msg = error_msg[:200] + "..."

        async with self._lock:
            self._failure_window.append(1)
            self._success_window.append(0)
            self._ensure_model(model)

            if model in self._failures:
                self._failures[model] += 1

            # ===== 500错误处理：降低QPS但不长时间冷却 =====
            if status_code == 500 or "500" in error_msg or "Internal Server Error" in error_msg:
                old_qps = self._model_qps.get(model, self.current_qps)
                new_qps = max(self._min_qps, old_qps * 0.7)
                self._model_qps[model] = new_qps
                self.current_qps = new_qps
                self._cooldown_until[model] = time.time() + 3  # 短暂冷却
                logger.warning(f"⚠️ 模型 {model} 返回500错误，QPS降为 {new_qps:.1f}")
                return

            if status_code == 429 or "429" in error_msg or "RateLimit" in error_msg:
                self._rate_limit_count += 1
                if time.time() - self._last_adjust_time < 60:
                    logger.debug(f"⏳ 模型 {model} 在启动60秒内触发429，暂不施加惩罚")
                    return
                old_qps = self._model_qps.get(model, self.current_qps)
                new_qps = max(self._min_qps, old_qps * 0.4)
                self._model_qps[model] = new_qps
                self.current_qps = new_qps
                self._cooldown_until[model] = time.time() + self._cooldown_base * (1 + self._failures.get(model, 0) * 0.5)
                logger.warning(f"⚠️ 模型 {model} 触发限流(429)，QPS: {old_qps:.1f} → {new_qps:.1f}")
                return

            if status_code in (401, 403):
                self._cooldown_until[model] = time.time() + 120
                logger.error(f"❌ 模型 {model} 认证失败({status_code})，冷却120秒")
                return

            if "Timeout" in error_msg or "timeout" in error_msg.lower():
                self._cooldown_until[model] = time.time() + 5
                logger.warning(f"⏰ 模型 {model} 超时，冷却5秒")
                return

            # 其他错误：短暂冷却
            self._cooldown_until[model] = time.time() + 2
            logger.debug(f"⚠️ 模型 {model} 错误: {error_msg[:50]}")

    async def get_stats(self) -> Dict:
        async with self._lock:
            now = time.time()
            return {
                "current_qps": self.current_qps,
                "initial_qps": self.initial_qps,
                "model_qps": dict(self._model_qps),
                "total_requests": self._total_requests,
                "success_requests": self._success_requests,
                "rate_limit_count": self._rate_limit_count,
                "failures": dict(self._failures),
                "cooldowns": {m: max(0, t - now) for m, t in self._cooldown_until.items()},
                "success_rate": f"{self._success_requests / max(1, self._total_requests) * 100:.1f}%"
            }

    def get_wait_time(self, model: str = "glm-4-flash") -> float:
        if model in self._cooldown_until:
            cooldown_end = self._cooldown_until[model]
            if cooldown_end > time.time():
                return cooldown_end - time.time()
        return 0

    def is_available(self, model: str = "glm-4-flash") -> bool:
        if model in self._cooldown_until:
            if self._cooldown_until[model] > time.time():
                return False
        return True

    async def reset(self):
        async with self._lock:
            self.current_qps = self.initial_qps
            self._model_qps = {m: self.initial_qps for m in self._models}
            self._failures = {m: 0 for m in self._models}
            self._cooldown_until = {m: 0 for m in self._models}
            self._request_history.clear()
            self._success_window.clear()
            self._failure_window.clear()
            self._total_requests = 0
            self._success_requests = 0
            self._rate_limit_count = 0
            self._last_adjust_time = time.time()
            logger.info("🔄 限流器已重置")


_rate_limiter = None


def get_rate_limiter(initial_qps: int = 3) -> AdaptiveRateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = AdaptiveRateLimiter(initial_qps)
    return _rate_limiter


__all__ = ['AdaptiveRateLimiter', 'get_rate_limiter']