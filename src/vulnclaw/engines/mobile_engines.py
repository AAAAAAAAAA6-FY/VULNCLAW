# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/mobile_engines.py
"""
移动端 API 安全检测引擎（v105）

检测 iOS / Android 移动端 API 常见漏洞：
1. 弱认证（Weak Authentication）：API 匿名可达、依赖弱认证令牌
2. 明文传输（Cleartext Traffic）：http 明文端点、缺少 HSTS
3. 越权（Broken Object Level Authorization）：对象级授权缺失（BOLA / IDOR）

规则库：rules/mobile_weak_auth.yaml（可独立编辑，无需改动引擎代码）
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import yaml

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import async_get
from vulnclaw.engines.base import BaseEngine

_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "mobile_weak_auth.yaml"

_MOBILE_API_MARKERS = ("/api/", "/mobile/", "/app/", "/v1/", "/v2/", "/v3/", "/v4/")
_MOBILE_UA_MARKERS = ("ios", "iphone", "ipad", "android", "okhttp", "dart", "flutter")
_WEAK_TOKEN_HEADERS = ("x-api-key", "apikey", "api_key", "client-secret", "client_secret", "access-key")

_ID_PATH_RE = re.compile(
    r"(?i)/(users?|accounts?|orders?|items?|profiles?|posts?|products?|messages?|files?|devices?|tickets?)/"
    r"(\d{1,10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[/?]?"
)


def _bump_object_id(url: str) -> Optional[str]:
    """将 URL 中最后一个对象 ID 递增（1 -> 2，UUID -> 全 0 的 2），失败返回 None。"""
    m = _ID_PATH_RE.search(url)
    if not m:
        return None
    start, end = m.start(2), m.end(2)
    ident = m.group(2)
    if ident.isdigit():
        new_id = str(int(ident) + 1)
    else:
        new_id = "00000000-0000-0000-0000-000000000002"
    return url[:start] + new_id + url[end:]


class MobileAPIEngine(BaseEngine):
    """移动端 API 安全检测引擎 - 弱认证 / 明文传输 / 越权。"""

    name = "mobile_api"
    description = "移动端 API 安全检测（弱认证 / 明文传输 / 越权）"

    def __init__(self):
        super().__init__()
        self._rules: Dict[str, Any] = {}

    async def check(self, url, param, normal_resp, parsed_query, session, **kwargs):
        # 移动端检测为全局扫描型引擎（scan 入口），不参与参数级单点检测
        return None

    # ------------------------------------------------------------
    # 规则库加载
    # ------------------------------------------------------------
    def _load_rules(self) -> Dict[str, Any]:
        if self._rules:
            return self._rules
        try:
            with open(_RULES_PATH, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
            self._rules = loaded.get("mobile_weak_auth") or {}
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"⚠️ [Mobile] 规则库加载失败 {_RULES_PATH.name}: {exc}")
            self._rules = {}
        return self._rules

    def _rule(self, section: str, key: str) -> Dict[str, Any]:
        rules = self._load_rules()
        for item in rules.get(section, []) or []:
            if isinstance(item, dict) and item.get("id") == key:
                return item
        return {}

    # ------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------
    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        """扫描移动端 API：弱认证 / 明文传输 / 越权。"""
        findings: List[Dict] = []
        self._load_rules()
        base = target.rstrip("/")
        parsed = urlparse(base)

        logger.info(f"   🚀 [Mobile] 移动端 API 安全检测: {base}")

        # 1. 弱认证
        try:
            findings.extend(await self._check_weak_auth(base, session))
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[Mobile] 弱认证检测异常: {exc}")

        # 2. 明文传输
        try:
            findings.extend(await self._check_cleartext(base, parsed, session))
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[Mobile] 明文传输检测异常: {exc}")

        # 3. 越权（BOLA / IDOR）
        try:
            findings.extend(await self._check_broken_object_auth(base, session))
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[Mobile] 越权检测异常: {exc}")

        logger.info(f"   ✅ [Mobile] 移动端 API 检测完成，发现 {len(findings)} 个问题")
        return findings

    # ------------------------------------------------------------
    # 1. 弱认证
    # ------------------------------------------------------------
    async def _check_weak_auth(self, base: str, session) -> List[Dict]:
        """弱认证检测：API 匿名可达返回业务数据 / 弱认证令牌头。"""
        findings: List[Dict] = []
        rule = self._rule("weak_auth", "anonymous_access")
        rule = rule or {"name": "API 匿名可达", "severity": "high"}

        probe_paths = ["", "/api", "/api/v1", "/mobile", "/user", "/users", "/account", "/me"]
        for path in probe_paths:
            url = base + path
            try:
                resp = await async_get(url, session=session, timeout=8, no_retry=True)
                if resp is None:
                    continue
                status = resp[0]
                text = resp[1] or ""
                headers = resp[2] if len(resp) > 2 and resp[2] else {}
                content_type = str(headers.get("content-type", "") or "").lower()
                is_json = "application/json" in content_type or text.lstrip().startswith(("{", "["))
                if status == 200 and is_json:
                    findings.append({
                        "url": url,
                        "type": rule.get("name", "API 匿名可达"),
                        "severity": str(rule.get("severity", "high")).capitalize(),
                        "ai_verdict": "高",
                        "evidence": f"API 端点匿名可达且返回 JSON 数据: {url} (HTTP {status})",
                        "method": "mobile_anonymous_access",
                    })
                    break
            except BaseException:
                continue
        return findings

    # ------------------------------------------------------------
    # 2. 明文传输
    # ------------------------------------------------------------
    async def _check_cleartext(self, base: str, parsed, session) -> List[Dict]:
        """明文传输检测：http 明文端点 / https 缺少 HSTS。"""
        findings: List[Dict] = []

        if parsed.scheme == "http":
            rule = self._rule("cleartext", "http_transport")
            rule = rule or {"name": "移动端明文传输", "severity": "high"}
            findings.append({
                "url": base,
                "type": rule.get("name", "移动端明文传输"),
                "severity": str(rule.get("severity", "high")).capitalize(),
                "ai_verdict": "高",
                "evidence": f"API 使用 http 明文传输: {base}，移动端流量可被中间人窃听/篡改",
                "method": "mobile_cleartext_http",
            })

        if parsed.scheme == "https":
            rule = self._rule("cleartext", "missing_hsts")
            rule = rule or {"name": "移动端 API 缺少 HSTS", "severity": "low"}
            try:
                resp = await async_get(base, session=session, timeout=8, no_retry=True)
                if resp is not None and len(resp) > 2:
                    headers = resp[2] or {}
                    hsts = str(headers.get("strict-transport-security", "") or "").strip()
                    if not hsts:
                        findings.append({
                            "url": base,
                            "type": rule.get("name", "移动端 API 缺少 HSTS"),
                            "severity": str(rule.get("severity", "low")).capitalize(),
                            "ai_verdict": "低",
                            "evidence": f"HTTPS API 未启用 Strict-Transport-Security: {base}",
                            "method": "mobile_missing_hsts",
                        })
            except BaseException:
                logger.debug("suppressed exception (engine audit)")
        return findings

    # ------------------------------------------------------------
    # 3. 越权（BOLA / IDOR）
    # ------------------------------------------------------------
    async def _check_broken_object_auth(self, base: str, session) -> List[Dict]:
        """越权检测：路径含对象 ID 时尝试访问相邻 ID，判断对象级授权缺失。"""
        findings: List[Dict] = []
        rule = self._rule("broken_object_auth", "object_id_access")
        rule = rule or {"name": "对象级越权", "severity": "high"}

        candidates: List[str] = []
        if _ID_PATH_RE.search(base):
            candidates.append(base)
        else:
            for obj in ("users", "accounts", "orders", "items", "messages", "profiles"):
                candidates.append(f"{base}/{obj}/1")

        seen = set()
        for url in candidates:
            if url in seen:
                continue
            seen.add(url)
            try:
                resp_a = await async_get(url, session=session, timeout=8, no_retry=True)
                if resp_a is None:
                    continue
                status_a = resp_a[0]
                text_a = resp_a[1] or ""
                alt_url = _bump_object_id(url)
                if not alt_url or alt_url == url:
                    continue
                resp_b = await async_get(alt_url, session=session, timeout=8, no_retry=True)
                if resp_b is None:
                    continue
                status_b = resp_b[0]
                text_b = resp_b[1] or ""
                is_json_a = text_a.lstrip().startswith(("{", "["))
                same_body = text_a.strip() and text_a.strip() == text_b.strip()
                if status_a == status_b and same_body and is_json_a:
                    findings.append({
                        "url": url,
                        "type": rule.get("name", "对象级越权"),
                        "severity": str(rule.get("severity", "high")).capitalize(),
                        "ai_verdict": "高",
                        "evidence": (f"相邻对象 ID 返回相同 JSON 资源，存在对象级越权(BOLA)风险: "
                                     f"{url} vs {alt_url}"),
                        "method": "mobile_bola_idor",
                        "pair": [url, alt_url],
                    })
                    break
            except BaseException:
                continue
        return findings


__all__ = ["MobileAPIEngine"]
