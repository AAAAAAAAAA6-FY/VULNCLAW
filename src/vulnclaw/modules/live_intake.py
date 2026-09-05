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
    def has_emit(self) -> bool:
        """是否挂了 emit 回调（无回调时任务进全局 pending 等主链路统一入队）。"""
        return self._emit is not None

    def stats(self) -> dict:
        return {
            "feed_records": len(self._feed),
            "emitted": self._emitted_count,
            "rejected_low_score": self._rejected_low_score,
        }


# ============================================================
# R2-A S1: 采集点全局回注入口（浏览器 render 流 / Burp 流量流）
#
# 背景：SP15.3 只接了 crawler 一源（orchestrator._feed_live_intake 喂
# crawled_endpoints）。render/burp 两源的采集点拿不到 orchestrator 实例，
# 故在此提供进程级单例 + 同步可用的 feed_live()：
#   - 开关关闭 / 无实例 → 立即返回 None（零成本短路，零行为回归）；
#   - 有 emit 回调 → 任务直接交回调；
#   - 无 emit（多数同步采集上下文）→ 任务进 pending，由 orchestrator
#     _feed_live_intake 统一异步入队（本轮即入队，不等下一轮扫描）。
# ============================================================
_LIVE: "LiveIntake | None" = None
_LIVE_PENDING: list = []


def set_live_intake(live: "LiveIntake | None") -> None:
    """登记/注销全局 LiveIntake（主链路构造好后调用；扫描结束传 None 清理）。"""
    global _LIVE
    _LIVE = live


def get_live_intake() -> "LiveIntake | None":
    return _LIVE


def feed_live(url: str, method: str = "GET",
              params: dict[str, str] | None = None,
              source: str = "live") -> list[dict] | None:
    """采集点回注一次经手请求（同步可用，异常全吞）。返回生成的任务或 None。"""
    live = _LIVE
    if live is None or not getattr(settings, "live_intake_enabled", False):
        return None
    try:
        tasks = live.hit(url, method=method, params=params, source=source)
    except Exception:  # noqa: BLE001 - 采集侧回注失败绝不影响采集主流程
        return None
    if not tasks:
        return None
    if not live.has_emit():
        _LIVE_PENDING.extend(tasks)
    return tasks


def drain_pending() -> list[dict]:
    """取出并清空累积的补测任务（主链路统一异步入队）。"""
    global _LIVE_PENDING
    out, _LIVE_PENDING = list(_LIVE_PENDING), []
    return out


def pending_count() -> int:
    return len(_LIVE_PENDING)