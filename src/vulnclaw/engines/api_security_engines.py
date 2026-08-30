# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""
API 安全深度检测引擎
覆盖：GraphQL 批量查询 DoS、速率限制绕过、JWT 重放
"""
import asyncio
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import async_get, async_post
from vulnclaw.engines.base import BaseEngine


class APISecurityEngine(BaseEngine):
    """API 安全深度检测引擎"""

    name = "api_security"
    description = "API 安全深度检测（GraphQL DoS、速率限制绕过、JWT 重放）"

    # GraphQL 别名碰撞检测配置
    GRAPHQL_ALIAS_COUNT = 100
    GRAPHQL_TIMEOUT = 10

    # 速率限制绕过配置
    RATE_LIMIT_CONCURRENCY = 30
    RATE_LIMIT_TIMEOUT = 5

    # JWT 重放检测配置
    JWT_REPLAY_INTERVAL = 2
    JWT_REPLAY_COUNT = 3

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        """检测单个 API 端点的安全问题"""
        # 检测是否为 GraphQL 端点
        if await self._is_graphql_endpoint(url, session):
            return {
                "url": url,
                "type": "GraphQL 端点发现",
                "severity": "Info",
                "evidence": f"发现 GraphQL 端点: {url}",
                "confidence": "高",
                "suggestion": "建议执行 GraphQL 深度检测",
            }

        # 检测速率限制（仅对可能受限制的端点）
        if await self._has_rate_limit_header(url, session):
            bypass_result = await self._test_rate_limit_bypass(url, session)
            if bypass_result:
                return bypass_result

        return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        """全局 API 安全扫描"""
        findings = []
        logger.info(f"🔍 [APISecurity] 扫描 API 安全: {target}")

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 1. GraphQL DoS 检测
        graphql_endpoints = await self._discover_graphql_endpoints(base_url, session)
        for endpoint in graphql_endpoints:
            result = await self._test_graphql_alias_dos(endpoint, session)
            if result:
                findings.append(result)

        # 2. 速率限制绕过检测（仅对 API 路径）
        api_urls = await self._discover_api_endpoints(base_url, session)
        for url in api_urls[:5]:
            result = await self._test_rate_limit_bypass(url, session)
            if result:
                findings.append(result)

        # 3. JWT 重放检测（如果提供了 token）
        token = kwargs.get("jwt_token")
        if token:
            result = await self._test_jwt_replay(target, token, session)
            if result:
                findings.append(result)

        logger.info(f"   ✅ APISecurity 完成，发现 {len(findings)} 个风险")
        return findings

    async def _is_graphql_endpoint(self, url: str, session) -> bool:
        """检测是否为 GraphQL 端点"""
        try:
            resp = await async_post(
                url,
                json={"query": "query { __typename }"},
                session=session,
                timeout=5,
            )
            if isinstance(resp, tuple):
                text = resp[1]
                status = resp[0]
            else:
                text = await resp.text()
                status = resp.status

            return status in (200, 400) and ("__typename" in text or "data" in text)
        except Exception:
            return False

    async def _discover_graphql_endpoints(self, base_url: str, session) -> List[str]:
        """发现 GraphQL 端点"""
        endpoints = []
        paths = ["/graphql", "/graphiql", "/api/graphql", "/query", "/gql", "/v1/graphql"]

        for path in paths:
            url = base_url.rstrip("/") + path
            if await self._is_graphql_endpoint(url, session):
                endpoints.append(url)
                logger.info(f"   📊 发现 GraphQL 端点: {url}")

        return endpoints

    async def _discover_api_endpoints(self, base_url: str, session) -> List[str]:
        """发现 API 端点（简单探测）"""
        urls = []
        paths = ["/api", "/api/v1", "/api/v2", "/rest", "/v1", "/v2"]

        for path in paths:
            url = base_url.rstrip("/") + path
            try:
                resp = await async_get(url, session=session, timeout=3)
                if isinstance(resp, tuple):
                    status = resp[0]
                else:
                    status = resp.status
                if status in (200, 401, 403):
                    urls.append(url)
            except Exception:
                continue

        return urls

    async def _has_rate_limit_header(self, url: str, session) -> bool:
        """检测是否包含速率限制响应头"""
        try:
            resp = await async_get(url, session=session, timeout=3)
            if isinstance(resp, tuple):
                headers = resp[2] if len(resp) > 2 else {}
            else:
                headers = resp.headers

            rate_limit_headers = [
                "X-RateLimit-Limit",
                "X-RateLimit-Remaining",
                "X-RateLimit-Reset",
                "RateLimit-Limit",
                "Retry-After",
            ]
            return any(h in headers for h in rate_limit_headers)
        except Exception:
            return False

    async def _test_graphql_alias_dos(self, endpoint: str, session) -> Optional[Dict]:
        """测试 GraphQL 别名碰撞 DoS"""
        aliases = " ".join([f"a{i}: __typename" for i in range(self.GRAPHQL_ALIAS_COUNT)])
        query = f"query {{ {aliases} }}"

        try:
            start = time.time()
            resp = await async_post(
                endpoint,
                json={"query": query},
                session=session,
                timeout=self.GRAPHQL_TIMEOUT,
            )
            elapsed = time.time() - start

            if isinstance(resp, tuple):
                status = resp[0]
                text = resp[1]
            else:
                status = resp.status
                text = await resp.text()

            if status == 200 and elapsed > 3:
                return {
                    "url": endpoint,
                    "type": "GraphQL 别名碰撞 DoS",
                    "severity": "High",
                    "evidence": f"{self.GRAPHQL_ALIAS_COUNT} 个别名查询耗时 {elapsed:.1f}s",
                    "confidence": "高",
                    "suggestion": "限制别名数量，启用查询复杂度分析",
                }

            if status == 400 and "timeout" in text.lower():
                return {
                    "url": endpoint,
                    "type": "GraphQL 别名碰撞 DoS（超时）",
                    "severity": "Critical",
                    "evidence": "别名查询导致超时",
                    "confidence": "高",
                    "suggestion": "启用查询超时限制",
                }

        except asyncio.TimeoutError:
            return {
                "url": endpoint,
                "type": "GraphQL 别名碰撞 DoS（超时）",
                "severity": "Critical",
                "evidence": f"{self.GRAPHQL_ALIAS_COUNT} 个别名查询导致超时",
                "confidence": "高",
                "suggestion": "限制别名数量，设置查询超时",
            }

        return None

    async def _test_rate_limit_bypass(self, url: str, session) -> Optional[Dict]:
        """测试速率限制绕过（并发请求）"""
        try:
            # 并发发送请求
            tasks = [async_get(url, session=session, timeout=self.RATE_LIMIT_TIMEOUT) for _ in range(self.RATE_LIMIT_CONCURRENCY)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            success_count = 0
            error_count = 0
            status_codes = []

            for resp in responses:
                if isinstance(resp, Exception):
                    error_count += 1
                    continue
                if isinstance(resp, tuple):
                    status = resp[0]
                else:
                    status = resp.status
                status_codes.append(status)
                if 200 <= status < 300:
                    success_count += 1

            # 如果大部分请求成功且没有 429，说明速率限制可能被绕过
            success_rate = success_count / max(1, self.RATE_LIMIT_CONCURRENCY)
            if success_rate > 0.7 and 429 not in status_codes:
                return {
                    "url": url,
                    "type": "速率限制绕过风险",
                    "severity": "Medium",
                    "evidence": f"并发 {self.RATE_LIMIT_CONCURRENCY} 次请求，成功率 {success_rate:.0%}，无限流响应",
                    "confidence": "中",
                    "suggestion": "启用速率限制，设置合理的并发阈值",
                }

        except Exception as e:
            logger.debug(f"速率限制检测异常: {e}")

        return None

    async def _test_jwt_replay(self, url: str, token: str, session) -> Optional[Dict]:
        """测试 JWT 重放攻击"""
        if not token:
            return None

        headers = {"Authorization": f"Bearer {token}"}

        try:
            # 第一次请求
            resp1 = await async_get(url, session=session, headers=headers, timeout=5)
            if isinstance(resp1, tuple):
                status1 = resp1[0]
                text1 = resp1[1]
            else:
                status1 = resp1.status
                text1 = await resp1.text()

            await asyncio.sleep(self.JWT_REPLAY_INTERVAL)

            # 第二次请求（重放）
            resp2 = await async_get(url, session=session, headers=headers, timeout=5)
            if isinstance(resp2, tuple):
                status2 = resp2[0]
                text2 = resp2[1]
            else:
                status2 = resp2.status
                text2 = await resp2.text()

            # 如果两次响应一致，可能存在重放风险
            if status1 == status2 and text1 == text2:
                return {
                    "url": url,
                    "type": "JWT 重放攻击风险",
                    "severity": "High",
                    "evidence": "相同 Token 两次请求返回相同响应，可能存在重放风险",
                    "confidence": "中",
                    "suggestion": "在 JWT 中添加 jti 字段，设置合理的过期时间",
                }

        except Exception as e:
            logger.debug(f"JWT 重放检测异常: {e}")

        return None