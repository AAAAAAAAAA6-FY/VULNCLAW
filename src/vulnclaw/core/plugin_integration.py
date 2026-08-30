# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/plugin_integration.py
"""
扫描器与 Burp 插件能力集成
把 burp_plugin_emulator 的结果融入扫描流程
"""

from typing import Any, Dict, List, Optional

from vulnclaw.core.logger import logger

# 导入 burp_plugin_emulator（带容错）
try:
    from vulnclaw.modules.collectors import run_all_burp_plugins_checks
    BURP_PLUGIN_AVAILABLE = True
except ImportError:
    BURP_PLUGIN_AVAILABLE = False
    logger.warning("⚠️ burp_plugin_emulator 不可用，Burp 插件集成功能受限")


class BurpPluginIntegration:
    """
    把 Burp 插件能力整合到扫描器主流程中
    """

    def __init__(self, session):
        self.session = session
        self.results = {}

    async def run_checks(
        self,
        url: str,
        js_content: str = "",
        jwt_token: str = "",
        params: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        执行所有 Burp 插件风格的检测
        """
        if not BURP_PLUGIN_AVAILABLE:
            logger.warning("⚠️ Burp 插件功能不可用，跳过检测")
            return {}

        logger.info(f"🧩 对 {url} 执行 Burp 插件综合检测...")

        try:
            self.results = await run_all_burp_plugins_checks(
                url=url,
                session=self.session,
                js_content=js_content or "",
                jwt_token=jwt_token or "",
                params=params or []
            )
        except Exception as e:
            logger.warning(f"Burp 插件检测失败: {e}")
            self.results = {}

        return self.results

    def get_all_vulnerabilities(self) -> List[Dict]:
        if not self.results:
            return []
        """提取所有发现的漏洞"""
        if not self.results:
            return []

        vulns = []

        # JWT 问题
        for issue in self.results.get("jwt_issues", []):
            vulns.append({
                "type": issue.get("type", "JWT"),
                "severity": issue.get("severity", "Medium"),
                "evidence": issue.get("detail", ""),
                "source": "burp_plugin_jwt"
            })

        # CORS 问题
        for issue in self.results.get("cors_issues", []):
            vulns.append({
                "type": issue.get("type", "CORS"),
                "severity": issue.get("severity", "Medium"),
                "evidence": issue.get("detail", ""),
                "source": "burp_plugin_cors"
            })

        # 原型污染
        for issue in self.results.get("prototype_pollution", []):
            vulns.append({
                "type": "Prototype Pollution",
                "severity": "High",
                "evidence": str(issue.get("payload", "")),
                "source": "burp_plugin_sspp"
            })

        # 403 Bypass
        for issue in self.results.get("403_bypass", []):
            if issue.get("success"):
                vulns.append({
                    "type": "403 Bypass",
                    "severity": "Medium",
                    "evidence": issue.get("technique", ""),
                    "source": "burp_plugin_403_bypass"
                })

        # GraphQL
        for endpoint in self.results.get("graphql_endpoints", []):
            vulns.append({
                "type": "GraphQL Endpoint",
                "severity": "Info",
                "evidence": endpoint,
                "source": "burp_plugin_graphql"
            })

        # NoSQL
        for issue in self.results.get("nosql_issues", []):
            vulns.append({
                "type": "NoSQL Injection",
                "severity": issue.get("severity", "High"),
                "evidence": issue.get("payload", ""),
                "source": "burp_plugin_nosql"
            })

        # Log4j
        for issue in self.results.get("log4j_issues", []):
            vulns.append({
                "type": "Log4Shell",
                "severity": "Critical",
                "evidence": issue.get("payload", ""),
                "source": "burp_plugin_log4j"
            })

        return vulns

    def get_api_endpoints(self) -> List[str]:
        """提取发现的 API 端点"""
        if not self.results:
            return []
        endpoints = []
        js_miner = self.results.get("js_miner", {})
        for ep in js_miner.get("api_endpoints", []):
            if isinstance(ep, dict):
                path = ep.get("path", "")
                if path:
                    endpoints.append(path)
            elif isinstance(ep, str):
                endpoints.append(ep)
        return list(set(endpoints))

    def get_subdomains(self) -> List[str]:
        """提取发现的子域名"""
        if not self.results:
            return []
        js_miner = self.results.get("js_miner", {})
        return list(set(js_miner.get("subdomains", [])))

    def get_secrets(self) -> List[Dict]:
        """提取发现的密钥"""
        if not self.results:
            return []
        js_miner = self.results.get("js_miner", {})
        return js_miner.get("secrets", [])


__all__ = ['BurpPluginIntegration']
