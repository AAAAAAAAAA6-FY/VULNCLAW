# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""
WebSocket 深度安全检测引擎
- CSWSH (Cross-Site WebSocket Hijacking)：恶意 Origin 握手是否被接受
- Sec-WebSocket-Accept 校验（RFC 6455）
签名修复：check() 与 base 一致；scan(target, session) 与 global_scan 调用方一致。
"""

import asyncio
import base64
import hashlib
import os
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import async_get
from vulnclaw.engines.base import BaseEngine


class WebSocketSecurityEngine(BaseEngine):
    """WebSocket 安全检测引擎"""

    name: str = "websocket_security"
    description: str = "WebSocket 深度安全检测（CSWSH、密钥校验）"

    # WebSocket 握手常量
    WS_GUID: str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    # 常见 WebSocket 端点路径
    WS_PATHS: List[str] = [
        "/ws", "/websocket", "/socket", "/socket.io/", "/sockjs",
        "/wss", "/chat", "/realtime", "/stream", "/live",
        "/api/ws", "/api/websocket", "/graphql/ws",
    ]

    # 恶意 Origin（CSWSH 检测用，指向攻击者域）
    EVIL_ORIGIN: str = "https://evil-cswsh-attacker.example.com"

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        """参数级入口：WebSocket 检测与 URL 参数无关，统一走 scan() 全局扫描。"""
        return None

    async def scan(self, target: str, session, **kwargs: Any) -> List[Dict[str, Any]]:
        """扫描 WebSocket 安全问题：对常见 WS 路径做真实握手探测。"""
        findings: List[Dict[str, Any]] = []
        base_url = target.rstrip('/')

        for ws_path in self.WS_PATHS:
            ws_url = base_url + ws_path
            try:
                finding = await self._probe_ws_endpoint(ws_url, session)
                if finding:
                    findings.append(finding)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug(f"[websocket_security] 探测 {ws_url} 异常: {exc}")

        # A7 增强：明文 ws:// 检测（仅 HTTPS 站点对比 wss vs ws）
        parsed = urlparse(target)
        if parsed.scheme == "https":
            clear_base = "ws://" + parsed.netloc
            own_origin = f"https://{parsed.netloc}"
            for ws_path in self.WS_PATHS:
                clear_url = clear_base + ws_path
                try:
                    finding = await self._probe_cleartext(clear_url, session, own_origin)
                    if finding:
                        findings.append(finding)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.debug(f"[websocket_security] 明文探测 {clear_url} 异常: {exc}")

        logger.info(f"WebSocketSecurityEngine: {len(findings)} findings")
        return findings

    async def _probe_ws_endpoint(self, ws_url: str, session, evil_origin: str = None) -> Optional[Dict[str, Any]]:
        """对单个端点发送带恶意 Origin 的 WebSocket 升级请求，依据真实响应判定。"""
        evil = evil_origin or self.EVIL_ORIGIN
        sec_key = base64.b64encode(os.urandom(16)).decode("utf-8")
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": sec_key,
            "Sec-WebSocket-Version": "13",
            "Origin": evil,
        }

        try:
            resp = await async_get(ws_url, session=session, timeout=8, no_retry=True, headers=headers, allow_redirects=False)
        except Exception:
            return None
        if not isinstance(resp, tuple) or len(resp) < 2:
            return None

        status = resp[0]
        resp_headers = resp[2] if len(resp) > 2 else {}

        # 未升级（404/200 普通页面等）→ 不是 WS 端点，直接跳过
        if status != 101:
            return None

        # 验证 Sec-WebSocket-Accept 头是否正确（不符合 RFC 6455 不判 CSWSH）
        expected_accept = self._compute_accept_key(headers["Sec-WebSocket-Key"])
        actual_accept = resp_headers.get("Sec-WebSocket-Accept")
        if actual_accept != expected_accept:
            return None

        # 101 Switching Protocols：恶意 Origin 被接受 → CSWSH（真实握手证据）
        finding = self._build_finding(
            ws_url,
            {
                "type": "websocket_cswsh",
                "severity": "high",
                "title": "WebSocket CSWSH（跨站 WebSocket 劫持）",
                "description": (
                    f"WebSocket 端点接受任意 Origin（{evil}）的升级请求并返回 101，"
                    "未做 Origin 白名单校验，攻击者页面可建立跨站 WebSocket 连接冒充用户。"
                ),
                "remediation": "服务端校验 Origin 头，仅允许白名单域名发起握手",
                "payload": f"Origin: {evil}",
                "cvss": 8.5,
            },
            sec_key=sec_key,
            resp_headers=resp_headers,
            status=status,
        )
        # A7 增强：Origin 反射检测（Access-Control-Allow-Origin == 我们发送的恶意 Origin）
        acao = next((str(v) for k, v in (resp_headers or {}).items()
                     if str(k).lower() == "access-control-allow-origin"), None)
        if acao and acao.strip() == evil:
            finding["evidence"] += f"；响应回显 Access-Control-Allow-Origin={acao}（Origin 反射），CSWSH 实锤性更高"
            finding["origin_reflected"] = True
        return finding

    async def _probe_cleartext(self, ws_url: str, session, own_origin: str) -> Optional[Dict[str, Any]]:
        """A7 增强：检测 HTTPS 站点是否同时接受明文 ws:// 升级（未强制 TLS）。"""
        sec_key = base64.b64encode(os.urandom(16)).decode("utf-8")
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": sec_key,
            "Sec-WebSocket-Version": "13",
            "Origin": own_origin,
        }
        try:
            resp = await async_get(ws_url, session=session, timeout=8, no_retry=True, headers=headers, allow_redirects=False)
        except Exception:
            return None
        if not isinstance(resp, tuple) or len(resp) < 2:
            return None
        status = resp[0]
        resp_headers = resp[2] if len(resp) > 2 else {}
        if status != 101:
            return None
        expected_accept = self._compute_accept_key(sec_key)
        actual_accept = resp_headers.get("Sec-WebSocket-Accept")
        if actual_accept != expected_accept:
            return None
        return {
            "url": ws_url,
            "parameter": "",
            "type": "websocket_cleartext",
            "severity": "medium",
            "title": "WebSocket 明文传输（ws:// 未强制 TLS）",
            "description": (
                f"HTTPS 站点上的 WebSocket 端点同时接受明文 ws:// 升级（101），"
                "未强制使用 wss://，攻击者可对 WebSocket 流量实施中间人窃听/篡改。"
            ),
            "remediation": "对所有 WebSocket 端点强制使用 wss://（TLS）",
            "payload": f"Origin: {own_origin}",
            "evidence": f"HTTP {status} (101 Switching Protocols) 于明文 ws:// 端点",
            "confidence": "high",
            "method": "GET",
            "cvss": 6.0,
        }

    def _build_finding(
        self,
        ws_url: str,
        base: Dict[str, Any],
        sec_key: str,
        resp_headers: Dict[str, Any],
        status: int,
    ) -> Dict[str, Any]:
        """补充 Sec-WebSocket-Accept 校验与统一字段。"""
        finding = dict(base)
        finding.update({
            "url": ws_url,
            "parameter": "",
            "evidence": f"HTTP {status} (101 Switching Protocols)，恶意 Origin 握手成功",
            "confidence": "high",
            "method": "GET",
        })

        accept = None
        for k, v in (resp_headers or {}).items():
            if str(k).lower() == "sec-websocket-accept":
                accept = v
                break

        if accept:
            expected = self._compute_accept_key(sec_key)
            if expected != accept:
                finding["type"] = "websocket_accept_mismatch"
                finding["severity"] = "medium"
                finding["title"] = "Sec-WebSocket-Accept 校验失败"
                finding["description"] = (
                    f"服务端返回的 Accept 值不正确 (expected: {expected}, got: {accept})，"
                    "握手实现不符合 RFC 6455。"
                )
                finding["remediation"] = "确保服务端正确实现 RFC 6455 的握手逻辑"
                finding["cvss"] = 5.0
                finding["evidence"] = f"Sec-WebSocket-Accept mismatch: got={accept}, expected={expected}"

        return finding

    def _compute_accept_key(self, key: str) -> str:
        """计算 RFC 6455 的 Sec-WebSocket-Accept"""
        combined = key.strip() + self.WS_GUID
        sha1 = hashlib.sha1(combined.encode("utf-8")).digest()
        return base64.b64encode(sha1).decode("utf-8")
