# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""D4.2 采集→任务实时生成（SP15.3/SP15.5，A 线）。

经手的请求统一进 RequestFeed（三源归一 + 精确去重），在
settings.live_intake_enabled 开启时把质量达标的**新参数注入面**
实时翻译成 engine_bundle 补测任务（目标延迟 <10s，不依赖下一轮 taskgen）。

- 默认开关关闭 → hit() 全短路，零行为回归；
- 评分阈值 live_intake_min_score 控噪声预算（D4.5 acq_score）；
- feed 精确去重 + 发射 (path,param) 去重 双层防重，同注入面只补测一次。
"""
from collections.abc import Callable

from vulnclaw.core.settings import settings
from vulnclaw.modules.request_feed import RequestFeed, acq_score


def _pick_engines(priority: int = 8) -> list[str]:
    """默认高优引擎集（与 taskgen 消费侧口径一致，取 max_engines_per_param 个）。"""
    try:
        from vulnclaw.ai.v100.phases import phases_taskgen as _ptg
        es = sorted(_ptg.engine_priority.items(), key=lambda x: x[1], reverse=True)
        out = [e for e, _ in es[: getattr(settings, "max_engines_per_param", 3)]]
        return out or []
    except Exception:  # noqa: BLE001 - 引擎选择兜底（缺依赖时返回空集由调用方容错）
        return []


class LiveIntake:
    """采集→任务实时生成挂钩。emit None 时 hit 返回任务列表由调用方入队。"""

    def __init__(self, feed: RequestFeed | None = None,
                 emit: Callable[[dict], None] | None = None):
        self._feed = feed if feed is not None else RequestFeed()
        self._emit = emit
        self._emitted = set()          # (path, param) 防重
        self._emitted_count = 0
        self._rejected_low_score = 0

    def hit(self, url: str, method: str = "GET",
            params: dict[str, str] | None = None,
            source: str = "live") -> list[dict] | None:
        """馈入一次经手请求。返回生成的补测任务列表（未开/未达标/重复返回 None）。"""
        if not getattr(settings, "live_intake_enabled", False):
            return None
        if not self._feed.add(url, method=method, params=params, source=source):
            return None
        rec = self._feed.records()[-1]
        score = acq_score(rec)
        if score < getattr(settings, "live_intake_min_score", 4):
            self._rejected_low_score += 1
            return None
        tasks: list[dict] = []
        target = url.split("?", 1)[0]
        for param in (rec.params or {}):
            key = (rec.path, param)
            if key in self._emitted:
                continue
            self._emitted.add(key)
            self._emitted_count += 1
            prio = getattr(settings, "live_intake_priority", 8)
            td = {
                "type": "engine_bundle",
                "engines": _pick_engines(prio),
                "target": target,
                "param": param,
                "priority": prio,
                "payload_limit": 10,
                "created_at": rec.ts,
                "source": f"live:{rec.source or 'unknown'}",
                "live_score": score,
            }
            tasks.append(td)
            if self._emit is not None:
                self._emit(td)
        return tasks or None

    # ---- 统计 / 测试钩子 ----
    def stats(self) -> dict:
        return {
            "feed_records": len(self._feed),
            "emitted": self._emitted_count,
            "rejected_low_score": self._rejected_low_score,
        }