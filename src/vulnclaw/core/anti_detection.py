# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/anti_detection.py
"""
WAF 自适应策略链（P0-3）

5 级策略：
  0. none            正常请求
  1. jitter          请求前随机延迟 1~3s
  2. ua_rotate       随机切换浏览器 UA
  3. header_inject   注入 X-Forwarded-For / X-Real-IP（RFC5737 保留段）
  4. encoding_bypass 参数值编码（预留钩子，由调用方实现）
  5. proxy_pool      代理池（无可用代理时回退"最低频模式"）

规则：
  - 连续 3 次 429/403 触发策略升级
  - 每级策略用 GET / 探测，状态 200 即锁定当前策略，避免反复升级
  - 最高级无代理时回退最低频模式（更大延迟 + UA 轮换）
"""
import asyncio
import random
from typing import Dict, Optional
from urllib.parse import urlparse

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings


class AdaptiveAntiDetection:
    LEVEL_NAMES = [
        "none",
        "jitter",
        "ua_rotate",
        "header_inject",
        "encoding_bypass",
        "proxy_pool",
    ]

    _UA_POOL = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    ]
    # RFC5737 保留测试段，避免伪造真实第三方 IP
    _XFF_POOL = [
        "203.0.113.10", "203.0.113.55", "198.51.100.20", "198.51.100.77",
        "192.0.2.30", "192.0.2.99",
    ]

    def __init__(self, consecutive_blocks: int = 3):
        self._consecutive_blocks = consecutive_blocks
        self._lock = asyncio.Lock()
        self._states: Dict[str, Dict] = {}

    # ---------- 内部 ----------
    @staticmethod
    def _key(url: str) -> str:
        return urlparse(url).netloc or url

    @staticmethod
    def _default_state() -> Dict:
        return {"level": 0, "blocks": 0, "locked": False}

    def _level(self, url: str) -> int:
        try:
            return self._states.get(self._key(url), self._default_state())["level"]
        except Exception:
            return 0

    # ---------- 对外接口 ----------
    async def record_block(self, url: str) -> str:
        """记录一次 429/403；连续 N 次触发策略升级，返回当前策略名。"""
        key = self._key(url)
        async with self._lock:
            st = self._states.setdefault(key, self._default_state())
            st["blocks"] += 1
            if st["blocks"] >= self._consecutive_blocks and st["level"] < len(self.LEVEL_NAMES) - 1:
                st["level"] += 1
                st["blocks"] = 0
                logger.warning(
                    f"🛡️ 反检测策略升级: {self.LEVEL_NAMES[st['level']]} "
                    f"@ {key}（连续 {self._consecutive_blocks} 次 429/403）"
                )
            return self.LEVEL_NAMES[st["level"]]

    async def record_success(self, url: str) -> None:
        """记录一次成功响应；策略等级 >0 时锁定当前策略。"""
        key = self._key(url)
        async with self._lock:
            st = self._states.setdefault(key, self._default_state())
            st["blocks"] = 0
            if st["level"] > 0 and not st["locked"]:
                st["locked"] = True
                logger.info(f"✅ 反检测策略已锁定: {self.LEVEL_NAMES[st['level']]} @ {key}")

    async def probe(self, url: str, session=None) -> bool:
        """用当前策略发 GET / 探测；状态 200 即锁定该策略。"""
        from vulnclaw.core.utils import async_get
        try:
            parsed = urlparse(url)
            probe_url = f"{parsed.scheme}://{parsed.netloc}/"
            headers = self.get_headers(url) or None
            resp = await async_get(probe_url, session=session, headers=headers, timeout=10, no_retry=True)
            if isinstance(resp, tuple) and resp and resp[0] == 200:
                await self.record_success(url)
                return True
        except Exception as exc:
            logger.debug(f"🛡️ 反检测探测失败 {url}: {exc}")
        return False

    def get_delay(self, url: str) -> float:
        """按当前策略返回请求前延迟秒数（0=无延迟）。"""
        level = self._level(url)
        if level >= 5:
            return random.uniform(3.0, 6.0)  # 最低频模式（代理不可用时的回退）
        if level >= 1:
            return random.uniform(1.0, 3.0)  # jitter
        return 0.0

    def get_headers(self, url: str) -> Dict[str, str]:
        """按当前策略返回注入头（UA 轮换 / XFF）。"""
        level = self._level(url)
        headers: Dict[str, str] = {}
        if level >= 2:
            headers["User-Agent"] = random.choice(self._UA_POOL)
        if level >= 3:
            fake_ip = random.choice(self._XFF_POOL)
            headers["X-Forwarded-For"] = fake_ip
            headers["X-Real-IP"] = fake_ip
            headers["X-Originating-IP"] = fake_ip
        return headers

    def current_level(self, url: str) -> str:
        return self.LEVEL_NAMES[self._level(url)]

    async def get_stats(self) -> Dict:
        async with self._lock:
            return {
                host: {
                    "level": st["level"],
                    "level_name": self.LEVEL_NAMES[st["level"]],
                    "blocks": st["blocks"],
                    "locked": st["locked"],
                }
                for host, st in self._states.items()
            }


_anti_detection: Optional[AdaptiveAntiDetection] = None


def get_anti_detection() -> AdaptiveAntiDetection:
    """全局反检测策略单例。"""
    global _anti_detection
    if _anti_detection is None:
        _anti_detection = AdaptiveAntiDetection(
            consecutive_blocks=int(getattr(settings, "anti_detection_threshold", 3))
        )
    return _anti_detection


__all__ = ["AdaptiveAntiDetection", "get_anti_detection"]
