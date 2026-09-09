# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/state_chain.py
"""
StateChainEngine —— 状态链/多步漏洞引擎

检测需要多请求时序/状态依赖才显形的漏洞：
  1. 二次/存储型触发：先注入存储标记载荷，再在消费端点触发回显；
  2. 越序直达/状态校验缺失：跳过前置登录/步骤，直达步骤 N。

现有引擎均为单请求检测；本引擎专注"时序依赖"类漏洞。

谨慎原则（宁缺毋滥）：
  - 二次触发必须用随机唯一标记 + 严格在"非注入页面"检出才算证据；
    拿不到 endpoints 列表就跳过二次触发分支。
  - 越序直达必须有 has_response_diff 支持 + 登录词过滤；模糊场景一律不报。
  - 异常全部 try/except，只记 debug，不 re-raise。
"""
import asyncio
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import async_get, build_attack_url
from vulnclaw.engines.base import BaseEngine


__all__ = ['StateChainEngine']


# 阶段类端点关键字（越序直达启发）
_STAGE_KEYWORD_RE = re.compile(
    r"(?:/|^)(?:step|confirm|pay|checkout|admin|verify|finalize|commit|complete|activate)(?:/|$|[_-])",
    re.IGNORECASE,
)
# 存储标记：stchain_ + 8 位 hex，精确随机，防止与其他引擎探测串扰
_MARKER_RE = re.compile(r"stchain_[0-9a-f]{8}\b")
# 登录/未授权关键词（出现即视为受保护，不报越序）
_LOGIN_KEYWORDS = (
    "login", "signin", "sign in", "请登录", "登录",
    "unauthorized", "unauthenticated", "forbidden access",
)


class StateChainEngine(BaseEngine):
    """状态链/多步漏洞引擎（二次存储触发 / 越序直达）。"""

    name: str = "state_chain"
    description: str = "状态链/多步漏洞引擎（二次存储触发 / 越序直达）"

    # 每个 URL 最多额外探测请求数（幂等控制，绝不放大流量）
    _MAX_PROBE_PER_URL: int = 3
    _STEP: float = 0.05

    # ------------------------------------------------------------------
    # 公共入口
    # ------------------------------------------------------------------
    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        """参数级入口：二次存储触发（重点）+ 越序直达。"""
        findings: List[Dict] = []

        # 1) 二次/存储型触发：需要消费端点列表，拿不到则跳过
        endpoints = kwargs.get("endpoints") or kwargs.get("consumers") or []
        second_order = await self._detect_second_order(
            url, param, parsed_query, endpoints, session
        )
        if second_order:
            findings.append(second_order)

        # 2) 越序直达 / 状态校验缺失
        bypass = await self._detect_bypass(url, session)
        if bypass:
            findings.append(bypass)

        if not findings:
            return None
        # 参数级入口单条返回（二次触发证据最显著优先）
        return findings[0]

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        """全局入口：端点直达真伪嗅探 + 越序直达探测。"""
        findings: List[Dict] = []
        bypass = await self._detect_bypass(target, session)
        if bypass:
            findings.append(bypass)
        logger.debug(f"StateChainEngine.scan: {len(findings)} findings")
        return findings

    # ------------------------------------------------------------------
    # 1) 二次/存储型触发
    # ------------------------------------------------------------------
    async def _detect_second_order(
        self,
        url: str,
        param: str,
        parsed_query: str,
        endpoints: List[str],
        session,
    ) -> Optional[Dict]:
        if not endpoints:
            return None  # 无消费端点 -> 跳过二次触发分支（宁缺毋滥）

        token = "stchain_" + secrets.token_hex(4)  # 精确随机 8 hex
        cur_path = self._path_of(url)
        current_paths = {cur_path}

        # 注入标记载荷（单次）
        try:
            inject_url = build_attack_url(url, param, token, parsed_query)
            inject_resp = await async_get(inject_url, session=session, timeout=10, no_retry=True)
            await asyncio.sleep(self._STEP)
            if not isinstance(inject_resp, tuple) or not inject_resp:
                return None
        except Exception as exc:
            logger.debug(f"state_chain 二次注入失败: {exc}")
            return None

        # 消费端点（最多 _MAX_PROBE_PER_URL-1 个 = 2 个）
        consumer_hits: List[Tuple[str, int, str]] = []
        for ep in list(endpoints)[: self._MAX_PROBE_PER_URL - 1]:
            try:
                resp = await async_get(ep, session=session, timeout=10, no_retry=True)
                await asyncio.sleep(self._STEP)
            except Exception as exc:
                logger.debug(f"state_chain 消费端点请求失败: {exc}")
                continue
            if not isinstance(resp, tuple) or len(resp) < 2:
                continue
            status = resp[0]
            text = resp[1] or ""
            if str(status)[0] in ("4", "5"):
                continue  # 错误/未授权端点不算消费证据
            if self._path_of(ep) in current_paths:
                continue  # 跳过当前注入页面
            if _MARKER_RE.search(text):
                consumer_hits.append((ep, status, text))

        if not consumer_hits:
            return None

        consumer_url, status, text = consumer_hits[0]
        snippet = self._snippet(text, token, 40)
        is_stored = status == 200
        return {
            "type": "stored_second_order",
            "severity": "high" if is_stored else "medium",
            "title": "存储型二次触发（State Chain）",
            "description": (
                f"参数 {param} 注入的存储标记 {token} 被持久化，并在消费端点 "
                f"{consumer_url} 被回显，说明用户可控输入可被写入存储并在其他上下文"
                f"二次触发，存在存储型 XSS / 存储注入等风险。"
            ),
            "evidence": (
                f"标记 {token} 在 {consumer_url}（HTTP {status}）响应中回显: "
                f"...{snippet}..."
            ),
            "remediation": (
                "对存储数据进行输入验证与上下文相关编码；消费端对输出进行转义/净化，"
                "避免二次触发（存储型 XSS / 二次注入）。"
            ),
            "recommendation": (
                "确认存储内容是否来自用户输入；对存储与回显两侧分别施加最小权限与输出编码，"
                "并在消费端点增加 CSP 与 Content-Type 校验。"
            ),
            "url": consumer_url,
            "parameter": param,
            "method": "GET",
            "confidence": "high" if is_stored else "medium",
            "cvss": 7.5 if is_stored else 6.5,
        }

    # ------------------------------------------------------------------
    # 2) 越序直达 / 状态校验缺失
    # ------------------------------------------------------------------
    async def _detect_bypass(self, url: str, session) -> Optional[Dict]:
        path = self._path_of(url)
        if not _STAGE_KEYWORD_RE.search(path):
            return None  # 非阶段类端点，不做越序探测

        # 直接请求（无前置状态/ Cookie）
        try:
            resp = await async_get(url, session=session, timeout=10, no_retry=True)
            await asyncio.sleep(self._STEP)
        except Exception as exc:
            logger.debug(f"state_chain 越序探测失败: {exc}")
            return None
        if not isinstance(resp, tuple) or len(resp) < 2:
            return None
        status = resp[0]
        text = resp[1] or ""

        # (b) 非 4xx/3xx 跳转，且为 2xx 业务页
        if not (200 <= status < 300):
            return None
        # 业务页面形态：非登录/错误页，长度足够
        if len(text) <= 200:
            return None
        # (c) 不含登录关键词
        if self._has_login_keywords(text):
            return None

        # 正常流程首步应为登录/前置页 -> 探测登录端点
        login_url = self._login_url(url)
        try:
            login_resp = await async_get(login_url, session=session, timeout=10, no_retry=True)
            await asyncio.sleep(self._STEP)
        except Exception as exc:
            logger.debug(f"state_chain 登录端点探测失败: {exc}")
            return None
        if not isinstance(login_resp, tuple) or len(login_resp) < 2:
            return None
        login_status = login_resp[0]
        login_text = login_resp[1] or ""
        if not login_status or not self._has_login_keywords(login_text):
            return None

        # (a) 业务页 vs 登录页差异显著
        try:
            has_diff, ratio = self.has_response_diff(
                (status, text, {}),
                (login_status, login_text, {}),
                threshold=0.3,
            )
        except Exception as exc:
            logger.debug(f"state_chain 差异判定失败: {exc}")
            return None
        if not has_diff:
            return None

        return {
            "type": "state_order_bypass",
            "severity": "medium",
            "title": "越序直达 / 状态校验缺失（State Chain）",
            "description": (
                f"阶段端点 {url} 可在无前置状态/Cookie 的情况下直接访问并返回业务页面"
                f"（HTTP {status}），而正常流程首步为登录页 {login_url}，说明该端点缺少"
                f"状态校验，攻击者可跳过前置步骤直达关键业务逻辑。"
            ),
            "evidence": (
                f"直接请求 {url} 返回业务页（HTTP {status}，len={len(text)}），"
                f"对照登录页 {login_url} 差异比 {ratio:.0%}"
            ),
            "remediation": (
                "对阶段端点增加会话/状态/权限校验，未经前置流程直接访问时返回 302/403，"
                "并校验步骤令牌与角色权限。"
            ),
            "recommendation": (
                "按业务流程前置条件校验令牌、步骤状态与用户身份，禁止越序直达关键业务端点。"
            ),
            "url": url,
            "parameter": "",
            "method": "GET",
            "confidence": "medium",
            "cvss": 5.0,
        }

    # ------------------------------------------------------------------
    # 工具方法
    # ------------------------------------------------------------------
    def _path_of(self, url: str) -> str:
        try:
            return urlparse(url).path.rstrip("/") or "/"
        except Exception:  # noqa: BLE001
            return "/"

    def _login_url(self, url: str) -> str:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        return origin + "/login"

    def _has_login_keywords(self, text: str) -> bool:
        low = (text or "").lower()
        return any(k in low for k in _LOGIN_KEYWORDS)

    @staticmethod
    def _snippet(text: str, needle: str, radius: int = 40) -> str:
        if not text:
            return ""
        idx = text.find(needle)
        if idx < 0:
            idx = max(0, len(text) // 2)
        start = max(0, idx - radius)
        end = min(len(text), idx + radius)
        return text[start:end]