# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""
通用反射证据验证器（核心升级 ⑥）
- 为所有"响应差异类"漏洞（SQLi/WAF/缓存投毒）提供统一的反射证据门槛
- 注入唯一 12 位随机 token → 剥离基线噪声后确认 token 在 body/头/JS 中新出现
- 无反射一律返回 False → 调用方必须降级（不允许报 High）
- 天然抗 SPA 假 404 / 参数化回显 / 响应抖动噪声
"""

import asyncio
import random
import re
import secrets
import time
from typing import Dict, List, Optional, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import build_attack_url, async_get, async_post


class ReflectiveValidator:
    """通用反射证据验证器"""

    TOKEN_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"

    def __init__(self, session=None):
        self.session = session
        self.token_length = 12
        self.timeout = 25
        self._rng = secrets.SystemRandom()

    def _generate_unique_token(self) -> str:
        """生成唯一 12 位随机 token（不含易混淆字符）"""
        return "".join(self._rng.choice(self.TOKEN_ALPHABET) for _ in range(12))

    async def _do_request(
        self,
        url: str,
        method: str = "GET",
        data=None,
        headers: Optional[Dict] = None
    ) -> Tuple[int, str, Dict]:
        """统一请求入口，兼容 tuple 与 aiohttp.Response 返回值"""
        session = self.session
        try:
            if method == "POST":
                resp = await async_post(url, data=data, session=session, timeout=self.timeout, headers=headers)
            else:
                resp = await async_get(url, session=session, timeout=self.timeout, headers=headers)
            if isinstance(resp, tuple) and len(resp) >= 2:
                status = resp[0]
                text = resp[1] if resp[1] else ""
                resp_headers = resp[2] if len(resp) > 2 else {}
                return status, text, resp_headers
            if hasattr(resp, "status"):
                status = resp.status
                text = await resp.text()
                resp_headers = dict(getattr(resp, "headers", {}) or {})
                return status, text, resp_headers
        except asyncio.TimeoutError:
            logger.debug("[ReflectiveValidator] 请求超时")
        except Exception as e:
            logger.debug(f"[ReflectiveValidator] 请求失败: {e}")
        return 0, "", {}

    def _token_in_body(self, token: str, text: str) -> bool:
        if not text or not token:
            return False
        if token in text:
            return True
        # URL 编码形态（部分目标会把参数原样回显但做了编码）
        from urllib.parse import quote
        enc = quote(token, safe="")
        if enc and enc in text:
            return True
        return False

    def _token_in_headers(self, token: str, headers: Dict) -> bool:
        if not headers:
            return False
        for key, value in headers.items():
            if not isinstance(value, str):
                continue
            if token in value:
                return True
        return False

    def _token_in_js(self, token: str, text: str) -> bool:
        """检测 token 是否出现在 JS 上下文（script 标签内）"""
        if not text or not token:
            return False
        for m in re.finditer(r"<script[^>]*>(.*?)</script>", text, re.IGNORECASE | re.DOTALL):
            if token in m.group(1):
                return True
        return token in text if "<script" not in text.lower() else False

    async def validate_reflection(
        self,
        url: str,
        param: str,
        payload: str,
        parsed_query: str,
        session,
        method: str = "GET",
        data=None,
        headers: Optional[Dict] = None,
        baseline_resp: Optional[Tuple[int, str, Dict]] = None
    ) -> Tuple[bool, str]:
        """核心反射验证：
        注入 12 位唯一 token 到攻击 payload → 剥离基线后确认 token 在 body/头/JS 中新出现。

        参数：
            url          目标 URL
            param        注入参数名
            payload      攻击 payload 前缀（如 `' AND 1=1`）
            parsed_query 原始查询串（用于精确替换保留字）
            session      aiohttp session
            method       请求方法
            data         POST body
            headers      附加请求头
            baseline_resp 可选：外部已获取的基线响应（避免重复请求）

        返回：
            (True, 证据描述) 反射确认； (False, "") 无反射。
        """
        self.session = self.session or session
        token = self._generate_unique_token()

        if baseline_resp and isinstance(baseline_resp, tuple) and len(baseline_resp) >= 2:
            baseline_status, baseline_text, baseline_headers = (
                baseline_resp[0], baseline_resp[1] or "", baseline_resp[2] if len(baseline_resp) > 2 else {}
            )
        else:
            baseline_status, baseline_text, baseline_headers = await self._do_request(url, method, data, headers)

        # 构造"payload + 唯一token"的攻击参数值
        attack_value = f"{payload}{token}"
        attack_url = build_attack_url(url, param, attack_value, parsed_query)

        attack_status, attack_text, attack_headers = await self._do_request(attack_url, method, data, headers)
        if attack_status == 0:
            return False, ""

        # 反射判定：token 在攻击响应中"新出现"，且不在基线中
        if self._token_in_body(token, attack_text) and not self._token_in_body(token, baseline_text):
            where = "响应体"
            if self._token_in_js(token, attack_text):
                where = "JS上下文"
            return True, f"反射确认（{where}）: 注入 token `{token}` 在攻击响应中唯一出现"

        if self._token_in_headers(token, attack_headers) and not self._token_in_headers(token, baseline_headers):
            return True, f"反射确认（响应头）: 注入 token `{token}` 在攻击响应头中唯一出现"

        return False, ""

    async def validate_injection(
        self,
        url: str,
        param: str,
        payload: str,
        parsed_query: str,
        session,
        method: str = "GET",
        data=None,
        headers: Optional[Dict] = None
    ) -> Tuple[bool, str]:
        """与 validate_reflection 语义一致的外部兼容入口"""
        return await self.validate_reflection(
            url, param, payload, parsed_query, session,
            method=method, data=data, headers=headers
        )


if __name__ == "__main__":
    pass