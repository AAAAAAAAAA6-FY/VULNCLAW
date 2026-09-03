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


__all__ = ['APISecurityEngine', 'MassAssignmentEngine']
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



async def _api_verb_engine(method: str, url: str, payload: Dict, session, timeout: int):
    """模块级辅助：以指定 HTTP 方法（PUT/PATCH）发送 JSON body。"""
    import aiohttp
    try:
        async with session.request(
            method, url, json=payload, timeout=aiohttp.ClientTimeout(total=timeout)
        ) as resp:
            text = await resp.text()
            return resp.status, text
    except Exception:
        return None, ""


class MassAssignmentEngine(BaseEngine):
    """批量赋值（Mass Assignment / 自动绑定）检测引擎

    原理：向 API 端点提交特权字段（is_admin / role / balance 等），
    若服务端将该字段绑定进业务对象并在响应中回显（甚至持久化），
    即存在批量赋值漏洞（CWE-915）。

    误报控制：
    1. 字段值使用唯一标记串，只有服务端真正接受并回显才算命中（避免“任意 200 即报”）；
    2. 要求基线请求（无害字段）的响应中不含该字段，排除 API 本就返回该字段的情况；
    3. 命中后再发一次 GET 确认标记是否被持久化，区分“回显”与“已写入”。
    """

    name = "mass_assignment"
    description = "批量赋值/自动绑定漏洞检测（特权字段注入，CWE-915）"

    MARKER = "vulnclaw_ma_7f3c"

    # 特权字段：字段名 -> 是否属高危（权限/角色类）
    PRIVILEGE_FIELDS = (
        ("is_admin", True), ("isAdmin", True), ("admin", True),
        ("role", True), ("roles", True), ("group", True),
        ("user_type", True), ("permission", True), ("permissions", True),
        ("is_active", False), ("isActive", False), ("verified", False),
        ("email_verified", False), ("approved", False), ("status", False),
        ("balance", False), ("credit", False), ("level", False), ("vip", False),
    )

    # 候选 API 端点（避免注册类路径，防止创建账号等副作用）
    API_PATHS = (
        "/api/profile", "/api/account", "/api/me", "/api/settings",
        "/api/user", "/api/users", "/api/v1/profile", "/api/v1/me",
        "/api/v1/account", "/profile", "/account", "/settings", "/api/user/update",
    )

    MAX_ENDPOINTS = 6
    TIMEOUT = 6

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        """参数级入口：批量赋值需提交 JSON 请求体，统一走 scan() 全局扫描。"""
        return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        from vulnclaw.config.settings import settings as _st
        if not _st.api_bola_test:
            return []

        """扫描 API 端点的批量赋值风险。"""
        findings: List[Dict] = []
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        logger.info(f"🔍 [MassAssignment] 扫描批量赋值: {target}")

        endpoints = await self._discover_endpoints(base_url, session)
        if not endpoints:
            logger.info("   ℹ️ 未发现可用 API 端点，跳过批量赋值检测")
            return findings

        for url in endpoints[: self.MAX_ENDPOINTS]:
            base_status, base_text = await self._send(session, url, {"vulnclaw_probe": "1"})
            if base_status is None:
                continue

            # 组合探测：一次性提交全部特权字段，先判断是否值得展开
            combined = {field: self.MARKER for field, _ in self.PRIVILEGE_FIELDS}
            status, text = await self._send(session, url, combined)
            used_method = "POST"
            # B6 扩展：POST 未绑定特权字段时，尝试 PATCH 与表单（内容型/方法型绕过）
            if status is not None and (not (200 <= status < 300) or self.MARKER not in (text or "")):
                for alt_method, alt_form in (("PATCH", False), ("PUT", False), ("POST", True)):
                    m_status, m_text = await self._send(session, url, combined, method=alt_method, as_form=alt_form)
                    if m_status is not None and (200 <= m_status < 300) and self.MARKER in (m_text or ""):
                        status, text, used_method = m_status, m_text, alt_method
                        break
            if status is None or not (200 <= status < 300) or self.MARKER not in (text or ""):
                continue

            # 命中后逐字段定位（沿用命中的方法通道），确认到底是哪个字段被绑定
            for field, high_risk in self.PRIVILEGE_FIELDS:
                f_status, f_text = await self._send(
                    session, url, {field: self.MARKER}, method=used_method
                )
                if f_status is None or not (200 <= f_status < 300):
                    continue
                if self.MARKER not in (f_text or ""):
                    continue
                if self._contains_field(base_text, field):
                    continue  # 基线本就返回该字段，非本次注入所致

                persisted = await self._persisted(session, url)
                findings.append({
                    "url": url,
                    "type": "mass_assignment_privilege_field",
                    "severity": "High" if high_risk else "Medium",
                    "title": f"批量赋值：特权字段 {field} 可被客户端写入",
                    "description": (
                        f"向 {url} 提交特权字段 `{field}` 后，服务端接受并在响应中回显该值"
                        + ("，且再次读取该资源时标记仍存在（已被持久化）。" if persisted else "。")
                        + " 攻击者可借此直接提升自身权限或篡改账户属性（CWE-915）。"
                    ),
                    "remediation": (
                        "使用白名单显式声明允许客户端写入的字段，"
                        "敏感字段（角色/权限/余额/审核状态）只在服务端赋值。"
                    ),
                    "recommendation": "服务端采用字段白名单绑定，禁止客户端提交特权字段。",
                    "parameter": field,
                    "method": used_method,
                    "evidence": (
                        f"POST {url} {{\"{field}\": \"{self.MARKER}\"}} -> HTTP {f_status}，"
                        f"响应回显标记值"
                        + ("；再次 GET 仍返回该标记（持久化）" if persisted else "")
                    ),
                    "confidence": "high" if persisted else "medium",
                    "cvss": 8.8 if high_risk else 6.5,
                })

        logger.info(f"   ✅ MassAssignment 完成，发现 {len(findings)} 个问题")
        return findings

    async def _discover_endpoints(self, base_url: str, session) -> List[str]:
        """探测存活的 API 端点（仅 GET，无副作用）。"""
        endpoints: List[str] = []
        for path in self.API_PATHS:
            url = base_url.rstrip("/") + path
            try:
                resp = await async_get(url, session=session, timeout=self.TIMEOUT, no_retry=True)
                if isinstance(resp, tuple):
                    status = resp[0]
                else:
                    status = resp.status
                if status in (200, 401, 403, 405, 422):
                    endpoints.append(url)
            except Exception:
                continue
        return endpoints

    async def _send(self, session, url: str, payload: Dict, method: str = "POST",
                    as_form: bool = False):
        """发送请求，返回 (status, text)。

        method 支持 POST/PUT/PATCH；as_form=True 时以 application/x-www-form-urlencoded
        发送（内容型绕过：部分框架仅表单绑定，对 JSON body 宽松/严格不同，测试双通道）。
        """
        try:
            if as_form:
                from urllib.parse import urlencode as _ue
                import aiohttp
                form = aiohttp.FormData(payload)
                resp = await async_post(
                    url, data=form, session=session, timeout=self.TIMEOUT, no_retry=True,
                )
            elif method in ("PUT", "PATCH"):
                resp = await _api_verb_engine(method, url, payload, session, self.TIMEOUT)
            else:
                resp = await async_post(
                    url, json=payload, session=session, timeout=self.TIMEOUT, no_retry=True
                )
            if isinstance(resp, tuple):
                return resp[0], resp[1] or ""
            return resp.status, (await resp.text()) or ""
        except Exception:
            return None, ""

    async def _persisted(self, session, url: str) -> bool:
        """再次读取资源，确认标记是否被持久化存储。"""
        try:
            resp = await async_get(url, session=session, timeout=self.TIMEOUT, no_retry=True)
            if isinstance(resp, tuple):
                text = resp[1] or ""
            else:
                text = (await resp.text()) or ""
            return self.MARKER in text
        except Exception:
            return False

    @staticmethod
    def _contains_field(text: str, field: str) -> bool:
        return bool(text) and f'"{field}"' in text