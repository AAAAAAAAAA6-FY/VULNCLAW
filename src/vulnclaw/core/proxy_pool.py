# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/proxy_pool.py
"""
代理池健康检查与自动剔除（P3-4）。

- 启动时对 settings.proxy_list 中每个代理发 http://httpbin.org/ip 探测；
- 连续失败 BAN_THRESHOLD(3) 次 → 临时封禁 BAN_SECONDS(5 分钟)；
- 累计成功率 < LOW_SUCCESS_RATE(0.5) → 本次扫描永久下线；
- 每个代理的状态变化均记录日志。
"""
import asyncio
import time
from typing import Dict, List, Optional

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings

PROBE_URL = "http://httpbin.org/ip"
BAN_THRESHOLD = 3       # 连续失败次数 → 临时封禁
BAN_SECONDS = 300       # 封禁时长：5 分钟
LOW_SUCCESS_RATE = 0.5  # 累计成功率下限 → 永久下线
PROBE_TIMEOUT = 10      # 单代理探测超时（秒）


class ProxyPool:
    """代理池：健康检查、临时封禁、永久下线、最优代理选择。"""

    def __init__(self, proxies: Optional[List[str]] = None):
        self._proxies: List[str] = list(proxies or [])
        self._state: Dict[str, Dict] = {}
        for p in self._proxies:
            self._state[p] = {
                "fail_streak": 0,
                "success": 0,
                "total": 0,
                "banned_until": 0.0,
                "dead": False,
            }

    @property
    def active_proxies(self) -> List[str]:
        """当前可用代理（未永久下线且未在封禁期）。"""
        now = time.time()
        out = []
        for p in self._proxies:
            st = self._state.get(p, {})
            if st.get("dead"):
                continue
            if st.get("banned_until", 0) > now:
                continue
            out.append(p)
        return out

    async def health_check(self, probe_url: str = PROBE_URL) -> Dict[str, str]:
        """对每个代理并发发探测请求，返回 {proxy: state}。"""
        if not self._proxies:
            return {}
        results = await asyncio.gather(
            *(self._check_one(p, probe_url) for p in self._proxies),
            return_exceptions=True,
        )
        return {p: s for p, s in results if isinstance(s, str)}

    async def _check_one(self, proxy: str, probe_url: str):
        from vulnclaw.core.utils import async_get
        st = self._state.setdefault(proxy, {
            "fail_streak": 0, "success": 0, "total": 0,
            "banned_until": 0.0, "dead": False,
        })
        ok = False
        try:
            resp = await async_get(probe_url, proxy=proxy, timeout=PROBE_TIMEOUT)
            status = resp[0] if resp and len(resp) > 0 else None
            text = resp[1] if resp and len(resp) > 1 else ""
            ok = status is not None and 200 <= status < 400 and "origin" in (text or "")
        except Exception:
            ok = False

        st["total"] += 1
        if ok:
            st["success"] += 1
            st["fail_streak"] = 0
        else:
            st["fail_streak"] += 1

        # 连续失败 3 次 → 临时封禁 5 分钟
        if st["fail_streak"] >= BAN_THRESHOLD:
            st["banned_until"] = time.time() + BAN_SECONDS
        # 累计成功率 < 50% → 本次扫描永久下线
        if st["total"] >= 2 and st["success"] / st["total"] < LOW_SUCCESS_RATE:
            st["dead"] = True

        if st["dead"]:
            state = "dead"
        elif st["banned_until"] > time.time():
            state = "banned"
        elif ok:
            state = "healthy"
        else:
            state = "unstable"
        logger.info(
            "🔌 [ProxyPool] %s → %s (success=%s/%s, streak=%s%s)",
            proxy, state, st["success"], st["total"], st["fail_streak"],
            f", banned {BAN_SECONDS}s" if st["banned_until"] > time.time() and not st["dead"] else "",
        )
        return proxy, state

    def get_next_proxy(self) -> Optional[str]:
        """按成功率从高到低选取可用代理（供请求层兜底使用）。"""
        active = self.active_proxies
        if not active:
            return None
        active.sort(
            key=lambda p: self._state[p]["success"] / max(1, self._state[p]["total"]),
            reverse=True,
        )
        return active[0]

    def get_status(self) -> Dict[str, Dict]:
        """导出全部代理状态（供报告/调试）。"""
        return {
            p: dict(st)
            for p, st in self._state.items()
        }


_pool: Optional[ProxyPool] = None


def get_proxy_pool() -> ProxyPool:
    """代理池单例（懒加载：从 settings.proxy_list 初始化）。"""
    global _pool
    if _pool is None:
        _pool = ProxyPool(list(getattr(settings, "proxy_list", None) or []))
    return _pool


async def init_proxy_pool() -> ProxyPool:
    """P3-4: 扫描启动时探测全部代理并剔除坏代理（总超时兜底，不阻塞扫描）。"""
    pool = get_proxy_pool()
    if not pool._proxies:
        logger.info("🔌 [ProxyPool] 未配置 PROXY_LIST，跳过健康检查")
        return pool
    logger.info(f"🔌 [ProxyPool] 健康检查 {len(pool._proxies)} 个代理: {pool._proxies}")
    try:
        await asyncio.wait_for(pool.health_check(), timeout=20)
    except asyncio.TimeoutError:
        logger.warning("⏰ [ProxyPool] 健康检查超时（20s），保留未检查代理")
    except Exception as exc:
        logger.warning(f"⚠️ [ProxyPool] 健康检查异常: {exc}")
    active = pool.active_proxies
    logger.info(
        f"🔌 [ProxyPool] 存活代理 {len(active)}/{len(pool._proxies)}: {active}"
    )
    return pool


def get_active_proxy() -> Optional[str]:
    """请求层兜底：settings.proxy 为空时从代理池取最优可用代理。"""
    try:
        return get_proxy_pool().get_next_proxy()
    except Exception:
        return None


__all__ = [
    "ProxyPool", "get_proxy_pool", "init_proxy_pool", "get_active_proxy",
    "PROBE_URL", "BAN_THRESHOLD", "BAN_SECONDS", "LOW_SUCCESS_RATE",
]
