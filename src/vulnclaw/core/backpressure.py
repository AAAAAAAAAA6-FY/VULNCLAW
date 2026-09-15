#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""任务侧背压闸门（P3-9，2026-09-15）。

问题：攻击阶段持续产出 finding 进 `_pending_verify`（上限 2000 仅在 verify
开始时截断），当 verify 消费慢于产出（大目标/慢目标）时 pending 无界堆积
→ 内存压力与 verify 延迟膨胀。

本闸门：pending ≥ high 时暂停攻击 worker 取新任务；回落到 < low 再放行。

纪律：
- **默认关**（settings.backpressure_enabled=False）→ should_proceed 恒 True，
  worker 循环路径与现状逐字节一致（零回归）；
- 单例读 settings（`get_backpressure_gate()`），不依赖 orchestrator 构造顺序；
- 轮询用 asyncio.sleep（0.2s），不做复杂唤醒接线——verify 侧后台协程
  会持续消费 pending，轮询即可闭环。
"""
from __future__ import annotations

from typing import Callable, Optional


class BackpressureGate:
    """pending 高/低水位闸门（enabled=False 时恒放行）。"""

    def __init__(self, high: int = 500, low: int = 200, enabled: bool = False,
                 poll: float = 0.2):
        self.high = max(1, int(high))
        self.low = max(0, min(int(low), self.high - 1))
        self.enabled = bool(enabled)
        self.poll = max(0.05, float(poll))

    def should_proceed(self, pending: int) -> bool:
        """pending 未达高水位 → 放行；已阻塞且未回落低水位 → 继续等。"""
        if not self.enabled:
            return True
        try:
            n = int(pending)
        except (TypeError, ValueError):
            return True
        return n < self.high


_gate: Optional[BackpressureGate] = None


def get_backpressure_gate() -> BackpressureGate:
    """进程级单例：从 settings 读开关与水位（缺省 = 关闭）。"""
    global _gate
    if _gate is None:
        try:
            from vulnclaw.core.settings import settings
            _gate = BackpressureGate(
                high=int(getattr(settings, "backpressure_high", 500) or 500),
                low=int(getattr(settings, "backpressure_low", 200) or 200),
                enabled=bool(getattr(settings, "backpressure_enabled", False)),
            )
        except Exception:  # noqa: BLE001
            _gate = BackpressureGate()
    return _gate


def reset_backpressure_gate() -> None:
    """测试用：清空单例（配置变更后重建）。"""
    global _gate
    _gate = None


__all__ = ["BackpressureGate", "get_backpressure_gate", "reset_backpressure_gate"]
