# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 1 模块 4：自适应并发控制。

根据目标响应时间和错误率动态调整 --agents 数量，避免压垮目标。
- avg_rt < 1s 且 error_rate < 5% → 增加并发
- avg_rt > 5s 或 error_rate > 20% → 减少并发
- 50% 超时 → 降到 min=1

集成点：scan.py 中 --agents 参数可由 AdaptiveConcurrency 动态覆盖。
"""
import asyncio
import re
import time

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from typing import Dict, Optional


class AdaptiveConcurrency:
    """自适应并发控制器。

    通过探测请求的响应时间和错误率，动态推荐合理的并发数。
    """

    def __init__(
        self,
        initial: Optional[int] = None,
        min_val: Optional[int] = None,
        max_val: Optional[int] = None,
    ):
        if initial is None:
            initial = settings.adaptive_concurrency_initial
        if min_val is None:
            min_val = settings.adaptive_concurrency_min
        if max_val is None:
            max_val = settings.adaptive_concurrency_max
        self.initial = initial
        self.min_val = min_val
        self.max_val = max_val
        self._current = initial
        self._lock = asyncio.Lock()
        logger.info(
            f"📊 AdaptiveConcurrency 初始化: initial={initial} range=[{min_val}, {max_val}]"
        )

    # 起步值动态化（H.3）：对"已知不会限流"的目标（本机回环/私网/本地靶场），
    # 从 3 爬到可用并发要浪费好几轮试探；这类目标允许更高的起步值。
    # 外部目标不受影响（反扫描敏感，起步值保持 settings 默认的保守值）。
    _LOCAL_HOST_MARKERS = ("127.0.0.1", "localhost", "::1", "0.0.0.0")

    @classmethod
    def _is_local_target(cls, target: str) -> bool:
        """回环 / 私网（RFC1918）/ *.local / 内网主机名 视为'可高起步'目标。"""
        if not target:
            return False
        low = target.lower()
        if any(m in low for m in cls._LOCAL_HOST_MARKERS):
            return True
        if ".local" in low or "testphp" in low or "vulnweb" in low:
            return True
        m = re.search(r"//([0-9.]+)", low)
        if m:
            parts = m.group(1).split(".")
            if len(parts) == 4:
                a, b = int(parts[0]), int(parts[1])
                if a == 10 or a == 192 and b == 168:
                    return True
                if a == 172 and 16 <= b <= 31:
                    return True
        return False

    def _boost_initial_for(self, target: str) -> int:
        """按目标类型返回本次探测的起步并发（可高起步目标 ×local_boost，封顶 max）。"""
        boost = getattr(settings, "adaptive_concurrency_local_boost", 3)
        if boost <= 1 or not self._is_local_target(target):
            return self.initial
        return min(self.max_val, self.initial * boost)

    @property
    def current(self) -> int:
        return self._current

    def get_current(self) -> int:
        """返回当前推荐并发数。"""
        return self._current

    async def probe(self, target: str) -> int:
        """发送探测请求，根据响应时间和错误率推荐并发数。

        发送 5 个并发探测请求，统计：
        - 平均响应时间 (avg_rt)
        - 错误率 (error_rate = 失败数 / 总数)

        调整规则：
        - avg_rt < 1s 且 error_rate < 5%  → current * 1.5
        - avg_rt > 5s 或 error_rate > 20% → current * 0.5
        - error_rate >= 50%               → min_val
        """
        from vulnclaw.core.utils import async_get

        probe_count = 5
        results: list = []

        async def _single_probe() -> Dict:
            start = time.time()
            try:
                resp = await async_get(target, timeout=10)
                elapsed = time.time() - start
                # 判断是否错误（4xx/5xx 或异常）
                status = resp.get("status", 200) if isinstance(resp, dict) else 200
                is_error = status >= 400
                return {"rt": elapsed, "error": is_error}
            except Exception:
                return {"rt": 10.0, "error": True}

        # 并发发送探测请求
        tasks = [asyncio.create_task(_single_probe()) for _ in range(probe_count)]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        rts = [r["rt"] for r in results if not isinstance(r, Exception)]
        errors = sum(1 for r in results if isinstance(r, Exception) or r.get("error"))
        error_rate = errors / probe_count
        avg_rt = sum(rts) / len(rts) if rts else 10.0

        logger.info(
            f"   [AdaptiveConcurrency] 探测 {target}: avg_rt={avg_rt:.2f}s "
            f"error_rate={error_rate:.0%}"
        )

        async with self._lock:
            # H.3 起步值动态化：本地/私网目标直接从高起步值开始本轮调整
            # （外部目标保持跨 probe 持久化的旧值，行为不变）。
            self._current = self._boost_initial_for(target)
            if error_rate >= 0.5:
                self._current = self.min_val
            elif avg_rt < 1.0 and error_rate < 0.05:
                self._current = min(self.max_val, int(self._current * 1.5))
            elif avg_rt > 5.0 or error_rate > 0.2:
                self._current = max(self.min_val, int(self._current * 0.5))

        logger.info(f"   [AdaptiveConcurrency] 推荐并发数: {self._current}")
        return self._current

    async def adjust(self, metrics: Dict) -> int:
        """扫描过程中根据实时指标动态调整并发数。

        Args:
            metrics: {"avg_rt": float, "error_rate": float, "active_tasks": int}

        Returns:
            调整后的并发数。
        """
        avg_rt = metrics.get("avg_rt", 2.0)
        error_rate = metrics.get("error_rate", 0.0)

        async with self._lock:
            if error_rate >= 0.5:
                self._current = self.min_val
            elif avg_rt < 1.0 and error_rate < 0.05:
                self._current = min(self.max_val, self._current + 1)
            elif avg_rt > 5.0 or error_rate > 0.2:
                self._current = max(self.min_val, self._current - 1)

        return self._current


# --- 全局单例 ---
_instance: Optional[AdaptiveConcurrency] = None


def get_adaptive_concurrency() -> AdaptiveConcurrency:
    """获取全局 AdaptiveConcurrency 单例。"""
    global _instance
    if _instance is None:
        # 修复：原来用 getattr(settings, "ADAPTIVE_CONCURRENCY_INITIAL", 3)——
        # pydantic 字段名是小写，大写属性不存在 → 环境变量配置被静默无视、永远回退 3。
        _instance = AdaptiveConcurrency(
            initial=settings.adaptive_concurrency_initial,
            min_val=settings.adaptive_concurrency_min,
            max_val=settings.adaptive_concurrency_max,
        )
    return _instance
