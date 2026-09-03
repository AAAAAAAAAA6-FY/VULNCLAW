# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""
API 版本差异检测引擎
- 对比 v1/v2/v3 端点行为差异（真实探测两个版本是否同时存活）
- 检测版本间安全控制降级（安全响应头对比）
签名修复：check() 与 base 一致；scan(target, session) 与 global_scan 调用方一致。
"""

from typing import Any, Dict, List, Optional, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import async_get
from vulnclaw.engines.base import BaseEngine


__all__ = ['APIVersionEngine']
class APIVersionEngine(BaseEngine):
    """API 版本差异检测引擎"""

    name: str = "api_version"
    description: str = "API 版本差异检测（v1/v2/v3 端点对比）"

    # 常见 API 版本模式：(旧版本片段, 新版本片段)
    VERSION_PATTERNS: List[Tuple[str, str]] = [
        ("/v1/", "/v2/"),
        ("/v2/", "/v3/"),
        ("/api/v1/", "/api/v2/"),
        ("/api/v2/", "/api/v3/"),
    ]

    REQUIRED_SECURITY_HEADERS = [
        "x-content-type-options",
        "x-frame-options",
        "strict-transport-security",
        "content-security-policy",
    ]

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        """参数级入口：版本差异与 URL 参数无关，统一走 scan() 全局扫描。"""
        return None

    async def scan(self, target: str, session, **kwargs: Any) -> List[Dict[str, Any]]:
        """扫描 API 版本差异：真实探测多版本端点存活与安全头差异。"""
        findings: List[Dict[str, Any]] = []
        base_url = target.rstrip('/')

        old_ver, new_ver = self._detect_version_pair(target)
        if not old_ver:
            logger.info("APIVersionEngine: 目标 URL 无可比较的版本片段，跳过")
            return findings

        old_url = base_url.replace(old_ver, new_ver) if old_ver in base_url else base_url
        old_resp = await self._probe(old_url, session)
        new_resp = await self._probe(base_url, session)

        # 1. 多版本同时暴露（两个版本均存活才有证据）
        if old_resp and new_resp:
            findings.append({
                "type": "api_multiple_versions",
                "severity": "low",
                "title": f"API 多版本同时暴露: {old_ver} + {new_ver}",
                "description": (
                    f"旧版本端点 {old_url}（HTTP {old_resp[0]}）与新版本端点 {base_url}"
                    f"（HTTP {new_resp[0]}）同时存活，可能导致版本间安全控制不一致。"
                ),
                "remediation": "废弃旧版本或确保所有版本安全控制一致",
                "url": base_url,
                "parameter": "",
                "evidence": f"两个版本端点均返回 2xx/3xx（{old_resp[0]} / {new_resp[0]}）",
                "confidence": "high",
                "method": "GET",
                "cvss": 3.5,
            })

            # 2. 新版本安全控制是否弱于旧版本（安全头对比）
            degradation = self._compare_security_headers(old_resp, new_resp)
            if degradation:
                findings.append({
                    "type": "api_security_degradation",
                    "severity": "medium",
                    "title": "API 新版本安全头缺失（安全控制降级）",
                    "description": (
                        f"新版本 {base_url} 相比旧版本 {old_url} 缺失安全头: "
                        f"{', '.join(degradation)}"
                    ),
                    "remediation": "在所有 API 版本中添加统一的安全响应头",
                    "url": base_url,
                    "parameter": "",
                    "evidence": f"新版本缺失头: {', '.join(degradation)}",
                    "confidence": "high",
                    "method": "GET",
                    "cvss": 5.0,
                })

        logger.info(f"APIVersionEngine: {len(findings)} findings")
        return findings

    def _detect_version_pair(self, target: str) -> Tuple[str, str]:
        """从目标 URL 提取可比较的版本片段。"""
        for old_ver, new_ver in self.VERSION_PATTERNS:
            if old_ver in target:
                return old_ver, new_ver
        return "", ""

    async def _probe(self, url: str, session) -> Optional[Tuple[int, Dict[str, str]]]:
        """探测端点存活，返回 (status, 小写头字典) 或 None。"""
        try:
            resp = await async_get(url, session=session, timeout=8, no_retry=True)
        except Exception:
            return None
        if not isinstance(resp, tuple) or len(resp) < 2:
            return None
        status = resp[0]
        if not (200 <= status < 400):
            return None
        headers = {str(k).lower(): str(v) for k, v in (resp[2] or {}).items()} if len(resp) > 2 else {}
        return status, headers

    def _compare_security_headers(
        self, old_resp: Tuple[int, Dict[str, str]], new_resp: Tuple[int, Dict[str, str]]
    ) -> List[str]:
        """新版本缺失而旧版本存在的安全头列表。"""
        old_headers, new_headers = old_resp[1], new_resp[1]
        return [
            h for h in self.REQUIRED_SECURITY_HEADERS
            if h in old_headers and h not in new_headers
        ]
