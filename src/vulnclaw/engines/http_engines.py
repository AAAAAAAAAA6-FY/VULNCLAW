# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/http_engines.py
"""
合并 HTTP 安全引擎模块
功能：安全头、Host头、开放重定向、竞争条件、缓存投毒 检测
修复：RaceConditionEngine 过滤 GET 请求
"""

import re
import asyncio
import hashlib
from vulnclaw.core.utils import async_post, async_put, async_delete
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get
from vulnclaw.engines.base import BaseEngine
from typing import Dict, List, Optional, Tuple


# ============================================================
# SecurityHeadersEngine
# ============================================================
class SecurityHeadersEngine(BaseEngine):
    """HTTP 安全头检测引擎"""

    name = "security_headers"
    description = "HTTP 安全头检测引擎"

    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "required": True,
            "description": "HSTS - 强制 HTTPS",
            "severity": "High",
            "expected": "max-age",
            "min_age": 31536000,
            "check_preload": True,
        },
        "Content-Security-Policy": {
            "required": True,
            "description": "CSP - 内容安全策略",
            "severity": "High",
            "expected": "default-src",
            "check_default_src": True,
        },
        "X-Frame-Options": {
            "required": True,
            "description": "点击劫持防护",
            "severity": "Medium",
            "expected": ["DENY", "SAMEORIGIN"],
        },
        "X-Content-Type-Options": {
            "required": True,
            "description": "MIME 嗅探防护",
            "severity": "Medium",
            "expected": "nosniff",
        },
        "Referrer-Policy": {
            "required": True,
            "description": "Referrer 策略",
            "severity": "Medium",
            "expected": ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"],
        },
        "Permissions-Policy": {
            "required": False,
            "description": "权限策略",
            "severity": "Low",
            "expected": ["geolocation", "microphone", "camera"],
        },
        "X-XSS-Protection": {
            "required": False,
            "description": "XSS 防护（已废弃）",
            "severity": "Low",
            "expected": ["1", "1; mode=block"],
        },
        "Cache-Control": {
            "required": False,
            "description": "缓存控制",
            "severity": "Medium",
            "expected": "no-cache, no-store, must-revalidate",
        },
        "Pragma": {
            "required": False,
            "description": "缓存控制（兼容）",
            "severity": "Low",
            "expected": "no-cache",
        },
    }

    COOKIE_SECURITY_FLAGS = {
        "Secure": "Cookie 仅通过 HTTPS 传输",
        "HttpOnly": "Cookie 不可被 JavaScript 访问",
        "SameSite": "Cookie 跨站请求限制",
        "SameSite=Strict": "Cookie 仅同站发送",
        "SameSite=Lax": "Cookie 同站或顶层导航发送",
    }

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        return None

    async def scan(
        self,
        target: str,
        session,
        **kwargs
    ) -> List[Dict]:
        findings = []
        score = 100
        score_details = []

        logger.info(f"🛡️ 开始 HTTP 安全头检测: {target}")

        try:
            resp = await async_get(target, session=session, timeout=settings.timeout)
            if isinstance(resp, tuple):
                resp[0]
                headers = resp[2] if len(resp) > 2 else {}
                text = resp[1]
            else:
                headers = resp.headers
                text = await resp.text()

            for header_name, config in self.SECURITY_HEADERS.items():
                header_value = headers.get(header_name, "")
                result = self._check_security_header(header_name, header_value, config)

                if result:
                    findings.append(result)
                    if result.get("severity") == "Critical":
                        score -= 30
                    elif result.get("severity") == "High":
                        score -= 20
                    elif result.get("severity") == "Medium":
                        score -= 10
                    elif result.get("severity") == "Low":
                        score -= 5

                    score_details.append(result.get("evidence", ""))

            cookie_findings = self._check_cookie_security(headers)
            findings.extend(cookie_findings)

            info_findings = self._check_info_leak(headers, text)
            findings.extend(info_findings)

        except Exception as e:
            logger.error(f"安全头检测失败: {e}")
            return [{
                'url': target,
                'type': '安全头检测失败',
                'severity': 'Info',
                'evidence': f'无法获取响应头: {e}',
                'recommendation': '检查目标是否可达'
            }]

        score = max(0, score)
        severity = "High" if score < 60 else "Medium" if score < 80 else "Low" if score < 90 else "Info"

        if findings:
            findings.append({
                'url': target,
                'type': 'Security Headers 综合评分',
                'severity': severity,
                'evidence': f'评分: {score}/100, 发现 {len([f for f in findings if f.get("severity") in ["Critical", "High"]])} 个高危问题',
                'score': score,
                'total_issues': len(findings),
                'recommendation': self._get_recommendation(score, findings)
            })

        logger.info(f"✅ 安全头检测完成: 评分 {score}/100, 发现 {len(findings)} 个问题")
        return findings

    def _check_security_header(
        self,
        header_name: str,
        header_value: str,
        config: Dict
    ) -> Optional[Dict]:
        if not header_value:
            if config.get("required", False):
                return {
                    'type': f'缺少安全头: {header_name}',
                    'severity': config.get("severity", "Medium"),
                    'evidence': f'{header_name} 响应头缺失',
                    'recommendation': f'添加 {header_name} 响应头: {self._get_example(header_name)}'
                }
            else:
                return {
                    'type': f'建议添加安全头: {header_name}',
                    'severity': 'Low',
                    'evidence': f'{header_name} 响应头缺失（非必须）',
                    'recommendation': f'考虑添加 {header_name} 响应头增强安全'
                }

        config.get("expected")

        if header_name == "Strict-Transport-Security":
            return self._check_hsts(header_value, config)

        if header_name == "Content-Security-Policy":
            return self._check_csp(header_value, config)

        if header_name == "X-Frame-Options":
            return self._check_xfo(header_value, config)

        if header_name == "X-Content-Type-Options":
            if "nosniff" not in header_value.lower():
                return {
                    'type': f'{header_name} 配置错误',
                    'severity': config.get("severity", "Medium"),
                    'evidence': f'{header_name}: {header_value} (应为 nosniff)',
                    'recommendation': '设置 X-Content-Type-Options: nosniff'
                }

        if header_name == "Referrer-Policy":
            if not any(exp in header_value.lower() for exp in config.get("expected", [])):
                return {
                    'type': f'{header_name} 配置弱',
                    'severity': 'Low',
                    'evidence': f'{header_name}: {header_value} (建议使用 no-referrer 或 strict-origin)',
                    'recommendation': '设置 Referrer-Policy: no-referrer 或 strict-origin'
                }

        if header_name == "Cache-Control":
            if "no-cache" not in header_value.lower() and "no-store" not in header_value.lower():
                return {
                    'type': f'{header_name} 缺乏缓存控制',
                    'severity': 'Medium',
                    'evidence': f'{header_name}: {header_value}',
                    'recommendation': '设置 Cache-Control: no-cache, no-store, must-revalidate'
                }

        return None

    def _check_hsts(self, header_value: str, config: Dict) -> Optional[Dict]:
        header_lower = header_value.lower()

        if "max-age" not in header_lower:
            return {
                'type': 'HSTS 缺乏 max-age',
                'severity': config.get("severity", "High"),
                'evidence': f'Strict-Transport-Security: {header_value} (缺乏 max-age)',
                'recommendation': 'HSTS 必须包含 max-age 参数'
            }

        max_age_match = re.search(r'max-age\s*=\s*(\d+)', header_lower)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            min_age = config.get("min_age", 31536000)
            if max_age < min_age:
                return {
                    'type': 'HSTS max-age 过短',
                    'severity': 'Medium',
                    'evidence': f'HSTS max-age: {max_age} 秒 (建议至少 {min_age} 秒)',
                    'recommendation': f'设置 max-age 至少 {min_age} 秒'
                }

        if "includesubdomains" not in header_lower:
            return {
                'type': 'HSTS 缺乏 includeSubDomains',
                'severity': 'Low',
                'evidence': 'HSTS 未包含 includeSubDomains',
                'recommendation': '添加 includeSubDomains 保护子域名'
            }

        return None

    def _check_csp(self, header_value: str, config: Dict) -> Optional[Dict]:
        header_lower = header_value.lower()

        if "default-src" not in header_lower:
            return {
                'type': 'CSP 缺乏 default-src',
                'severity': 'High',
                'evidence': 'Content-Security-Policy 未包含 default-src',
                'recommendation': '在 CSP 中设置 default-src \'self\' 作为后备'
            }

        if "unsafe-inline" in header_lower:
            return {
                'type': 'CSP 允许 unsafe-inline',
                'severity': 'Medium',
                'evidence': 'CSP 包含 unsafe-inline，可能被 XSS 利用',
                'recommendation': '避免使用 unsafe-inline，改用 nonce 或 hash'
            }

        if "unsafe-eval" in header_lower:
            return {
                'type': 'CSP 允许 unsafe-eval',
                'severity': 'Medium',
                'evidence': 'CSP 包含 unsafe-eval，可能被代码注入利用',
                'recommendation': '避免使用 unsafe-eval'
            }

        if "default-src *" in header_lower or "default-src 'self' *" in header_lower:
            return {
                'type': 'CSP default-src 过于宽泛',
                'severity': 'Medium',
                'evidence': 'CSP default-src 包含通配符 *',
                'recommendation': '限制 default-src 为具体域名'
            }

        return None

    def _check_xfo(self, header_value: str, config: Dict) -> Optional[Dict]:
        header_lower = header_value.lower()

        if "deny" in header_lower:
            return None
        elif "sameorigin" in header_lower:
            return None
        else:
            return {
                'type': 'X-Frame-Options 配置无效',
                'severity': 'Medium',
                'evidence': f'X-Frame-Options: {header_value} (应为 DENY 或 SAMEORIGIN)',
                'recommendation': '设置 X-Frame-Options: DENY 或 SAMEORIGIN'
            }

    def _check_cookie_security(self, headers: Dict) -> List[Dict]:
        findings = []
        set_cookie = headers.get("Set-Cookie", "")
        if not set_cookie:
            return findings

        cookies = self._parse_set_cookie(set_cookie)

        for cookie in cookies:
            cookie_lower = cookie.lower()

            if "secure" not in cookie_lower:
                findings.append({
                    'type': 'Cookie 缺乏 Secure 标志',
                    'severity': 'Medium',
                    'evidence': f'Cookie 未设置 Secure 标志: {cookie[:50]}...',
                    'recommendation': '在 Set-Cookie 中添加 Secure 标志，确保 Cookie 仅通过 HTTPS 传输'
                })

            if "httponly" not in cookie_lower:
                findings.append({
                    'type': 'Cookie 缺乏 HttpOnly 标志',
                    'severity': 'Medium',
                    'evidence': f'Cookie 未设置 HttpOnly 标志: {cookie[:50]}...',
                    'recommendation': '在 Set-Cookie 中添加 HttpOnly 标志，防止 XSS 窃取 Cookie'
                })

            if "samesite" not in cookie_lower:
                findings.append({
                    'type': 'Cookie 缺乏 SameSite 标志',
                    'severity': 'Low',
                    'evidence': f'Cookie 未设置 SameSite 标志: {cookie[:50]}...',
                    'recommendation': '设置 SameSite=Lax 或 Strict 防止 CSRF'
                })

        return findings

    def _parse_set_cookie(self, set_cookie: str) -> List[str]:
        cookies = []
        for cookie in set_cookie.split(","):
            cookie = cookie.strip()
            if "=" in cookie:
                cookies.append(cookie)
        return cookies

    def _check_info_leak(self, headers: Dict, text: str) -> List[Dict]:
        findings = []

        server = headers.get("Server", "")
        if server and re.search(r'nginx/(\d+\.\d+\.\d+)', server):
            findings.append({
                'type': '服务器版本泄露',
                'severity': 'Low',
                'evidence': f'Server: {server} (包含版本号)',
                'recommendation': '隐藏或移除 Server 头中的版本号'
            })

        x_powered_by = headers.get("X-Powered-By", "")
        if x_powered_by:
            findings.append({
                'type': 'X-Powered-By 头泄露技术栈',
                'severity': 'Low',
                'evidence': f'X-Powered-By: {x_powered_by}',
                'recommendation': '移除 X-Powered-By 头'
            })

        sensitive_patterns = [
            (r'<!--', 'HTML 注释'),
            (r'DB_USERNAME', '数据库用户名'),
            (r'DB_PASSWORD', '数据库密码'),
            (r'API_KEY', 'API Key'),
        ]

        for pattern, label in sensitive_patterns:
            if re.search(pattern, text, re.I):
                findings.append({
                    'type': f'响应体包含敏感信息: {label}',
                    'severity': 'Medium',
                    'evidence': f'响应体包含 {label}',
                    'recommendation': '移除响应体中的敏感信息'
                })
                break

        return findings

    def _get_example(self, header_name: str) -> str:
        examples = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' https://cdn.example.com",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "X-XSS-Protection": "1; mode=block",
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
        }
        return examples.get(header_name, "")

    def _get_recommendation(self, score: int, findings: List[Dict]) -> str:
        if score >= 90:
            return "安全头配置良好，继续保持"
        elif score >= 70:
            high_issues = [f for f in findings if f.get("severity") in ["Critical", "High"]]
            if high_issues:
                return f"存在 {len(high_issues)} 个高危问题，建议优先修复: {', '.join([f.get('type', '') for f in high_issues[:3]])}"
            return "建议加强安全头配置"
        else:
            critical_issues = [f for f in findings if f.get("severity") == "Critical"]
            high_issues = [f for f in findings if f.get("severity") == "High"]
            if critical_issues:
                return f"存在 {len(critical_issues)} 个严重问题，请立即修复: {', '.join([f.get('type', '') for f in critical_issues[:3]])}"
            elif high_issues:
                return f"存在 {len(high_issues)} 个高危问题，建议优先修复"
            return "建议全面检查安全头配置"


# ============================================================
# HostHeaderEngine
# ============================================================
class HostHeaderEngine(BaseEngine):
    """Host 头注入检测引擎"""

    name = "host_header"
    description = "Host 头注入检测引擎"

    MALICIOUS_HOSTS = [
        "evil.com",
        "evil.com:8080",
        "localhost",
        "localhost:8080",
        "127.0.0.1",
        "127.0.0.1:8080",
        "attacker.com",
        "evil.evil.com",
        "host-header-injection.com",
        "internal-admin.local",
        "admin.internal",
        "172.16.0.1",
        "192.168.1.1",
        "10.0.0.1",
    ]

    HOST_INJECTION_INDICATORS = [
        'evil.com',
        'attacker.com',
        'host-header-injection.com',
        'internal-admin.local',
        'admin.internal',
        'localhost',
        '127.0.0.1',
        '172.16.0.1',
        '192.168.1.1',
        '10.0.0.1',
    ]

    VIRTUAL_HOSTS = [
        "admin",
        "admin.internal",
        "internal",
        "internal.local",
        "intranet",
        "intranet.local",
        "dev",
        "dev.internal",
        "staging",
        "staging.internal",
        "test",
        "test.internal",
        "beta",
        "beta.internal",
        "api",
        "api.internal",
        "auth",
        "auth.internal",
        "portal",
        "portal.internal",
        "dashboard",
        "dashboard.internal",
        "console",
        "console.internal",
        "manager",
        "manager.internal",
        "cms",
        "cms.internal",
        "wp",
        "wp.admin",
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
        return None

    async def scan(
        self,
        target: str,
        session,
        **kwargs
    ) -> List[Dict]:
        findings = []

        logger.info(f"🌐 开始 Host 头注入检测: {target}")

        parsed = urlparse(target)
        original_host = parsed.netloc

        reflection_result = await self._test_host_reflection(
            target, original_host, session
        )
        if reflection_result:
            findings.append(reflection_result)

        cache_result = await self._test_cache_poisoning(
            target, original_host, session
        )
        if cache_result:
            findings.append(cache_result)

        reset_result = await self._test_password_reset_bypass(
            target, original_host, session
        )
        if reset_result:
            findings.append(reset_result)

        vhost_results = await self._probe_virtual_hosts(
            target, original_host, session
        )
        findings.extend(vhost_results)

        for malicious_host in self.MALICIOUS_HOSTS[:5]:
            result = await self._test_single_host(
                target, malicious_host, original_host, session
            )
            if result:
                findings.append(result)

        unique_findings = []
        seen = set()
        for f in findings:
            key = (f.get('type', ''), f.get('host', ''))
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        logger.info(f"✅ Host 头注入检测完成，发现 {len(unique_findings)} 个问题")
        return unique_findings

    async def _test_single_host(
        self,
        target: str,
        malicious_host: str,
        original_host: str,
        session
    ) -> Optional[Dict]:
        try:
            headers = {"Host": malicious_host}
            resp = await async_get(target, session=session, headers=headers, timeout=settings.timeout)

            if isinstance(resp, tuple):
                status = resp[0]
                text = resp[1]
                resp_headers = resp[2] if len(resp) > 2 else {}
            else:
                status = resp.status
                text = await resp.text()
                resp_headers = resp.headers

            waf_type = await self.detect_waf(text)
            if waf_type:
                self.log_debug(f"检测到 WAF ({waf_type})，跳过 Host 头检测")
                return None

            if self._is_host_reflected(text, malicious_host):
                return {
                    'url': target,
                    'type': 'Host 头注入-反射',
                    'severity': 'High',
                    'host': malicious_host,
                    'evidence': f'响应中包含注入的 Host 头值: {malicious_host}',
                    'status': status,
                    'recommendation': '不要将 Host 头值反射到响应中'
                }

            location = resp_headers.get('Location', '')
            if location and malicious_host in location:
                return {
                    'url': target,
                    'type': 'Host 头注入-重定向劫持',
                    'severity': 'High',
                    'host': malicious_host,
                    'evidence': f'重定向到注入的 Host: {location}',
                    'location': location,
                    'recommendation': '验证 Host 头值，防止重定向劫持'
                }

            if self._is_host_in_urls(text, malicious_host):
                return {
                    'url': target,
                    'type': 'Host 头注入-链接篡改',
                    'severity': 'Medium',
                    'host': malicious_host,
                    'evidence': f'响应中的 URL 包含注入的 Host 头值: {malicious_host}',
                    'recommendation': '使用相对路径或固定域名生成 URL'
                }

            if status == 200 and malicious_host in text:
                return {
                    'url': target,
                    'type': 'Host 头注入-内容篡改',
                    'severity': 'Medium',
                    'host': malicious_host,
                    'evidence': f'响应内容包含注入的 Host 头值: {malicious_host}',
                    'recommendation': '不要将 Host 头值直接用于内容生成'
                }

        except Exception as e:
            self.log_debug(f"Host 头测试失败 {malicious_host}: {e}")

        return None

    async def _test_host_reflection(
        self,
        target: str,
        original_host: str,
        session
    ) -> Optional[Dict]:
        test_host = "reflection-test-123456.com"

        try:
            headers = {"Host": test_host}
            resp = await async_get(target, session=session, headers=headers, timeout=settings.timeout)

            if isinstance(resp, tuple):
                text = resp[1]
            else:
                text = await resp.text()

            if self._is_host_reflected(text, test_host):
                return {
                    'url': target,
                    'type': 'Host 头反射',
                    'severity': 'High',
                    'evidence': f'Host 头值 "{test_host}" 在响应中反射',
                    'recommendation': '不要将 Host 头值反射到响应中'
                }

        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        return None

    def _is_host_reflected(self, text: str, host: str) -> bool:
        if host in text:
            return True

        encoded_host = host.replace('.', '%2e')
        if encoded_host in text:
            return True

        return False

    def _is_host_in_urls(self, text: str, host: str) -> bool:
        url_pattern = r'https?://[^"\'\s<>]+'
        urls = re.findall(url_pattern, text)

        for url in urls:
            if host in url:
                return True

        return False

    async def _test_cache_poisoning(
        self,
        target: str,
        original_host: str,
        session
    ) -> Optional[Dict]:
        test_host1 = "cache-test-1.com"
        test_host2 = "cache-test-2.com"

        try:
            headers1 = {"Host": test_host1}
            resp1 = await async_get(target, session=session, headers=headers1, timeout=settings.timeout)

            if isinstance(resp1, tuple):
                headers1_resp = resp1[2] if len(resp1) > 2 else {}
            else:
                headers1_resp = resp1.headers

            headers2 = {"Host": test_host2}
            resp2 = await async_get(target, session=session, headers=headers2, timeout=settings.timeout)

            if isinstance(resp2, tuple):
                headers2_resp = resp2[2] if len(resp2) > 2 else {}
            else:
                headers2_resp = resp2.headers

            cache_control1 = headers1_resp.get('Cache-Control', '')
            headers2_resp.get('Cache-Control', '')

            if 'public' in cache_control1.lower() or 'max-age' in cache_control1.lower():
                return {
                    'url': target,
                    'type': 'Host 头缓存投毒（潜在）',
                    'severity': 'Medium',
                    'evidence': '响应包含缓存头，Host 头可能影响缓存键',
                    'cache_control': cache_control1,
                    'recommendation': '在缓存键中包含 Host 头，或禁用缓存'
                }

        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        return None

    async def _test_password_reset_bypass(
        self,
        target: str,
        original_host: str,
        session
    ) -> Optional[Dict]:
        test_host = "reset-hijack.com"
        reset_paths = [
            "/reset-password",
            "/password/reset",
            "/auth/reset",
            "/forgot-password",
            "/api/reset",
            "/password/forgot",
        ]

        for path in reset_paths:
            test_url = target.rstrip('/') + path
            try:
                headers = {"Host": test_host}
                resp = await async_get(test_url, session=session, headers=headers, timeout=settings.timeout)

                if isinstance(resp, tuple):
                    text = resp[1]
                    status = resp[0]
                else:
                    text = await resp.text()
                    status = resp.status

                if status == 200:
                    url_pattern = r'https?://[^"\'\s<>]+'
                    urls = re.findall(url_pattern, text)

                    for url in urls:
                        if test_host in url:
                            return {
                                'url': test_url,
                                'type': 'Host 头注入-密码重置劫持',
                                'severity': 'Critical',
                                'evidence': f'密码重置链接包含注入的 Host: {url}',
                                'reset_url': url,
                                'recommendation': '在生成重置链接时使用固定域名'
                            }

            except BaseException:
                logger.debug("suppressed exception (engine audit)")

        return None

    async def _probe_virtual_hosts(
        self,
        target: str,
        original_host: str,
        session
    ) -> List[Dict]:
        findings = []

        parsed = urlparse(target)
        base_host = parsed.netloc

        for vhost in self.VIRTUAL_HOSTS:
            test_host = f"{vhost}.{base_host}" if not vhost.endswith('.' + base_host) else vhost

            try:
                headers = {"Host": test_host}
                resp = await async_get(target, session=session, headers=headers, timeout=5)

                if isinstance(resp, tuple):
                    status = resp[0]
                    text = resp[1]
                else:
                    status = resp.status
                    text = await resp.text()

                if status == 200 and len(text) > 100:
                    if "Not Found" not in text and "404" not in text:
                        findings.append({
                            'url': target,
                            'type': '虚拟主机发现',
                            'severity': 'Info',
                            'host': test_host,
                            'evidence': f'虚拟主机 "{test_host}" 可访问，返回 {status}',
                            'status': status,
                            'content_length': len(text),
                            'recommendation': '检查虚拟主机配置是否正确'
                        })

            except BaseException:
                logger.debug("suppressed exception (engine audit)")

        return findings


# ============================================================
# OpenRedirectEngine
# ============================================================
class OpenRedirectEngine(BaseEngine):
    """开放重定向检测引擎"""

    name = "open_redirect"
    description = "开放重定向检测引擎"

    priority_params = [
        "redirect", "return", "next", "url", "to", "goto",
        "redir", "redirect_uri", "redirect_url", "return_to",
        "return_url", "success_url", "failure_url", "cancel_url",
        "callback", "callback_url", "continue", "forward",
        "target", "dest", "destination", "href", "link",
        "page", "view", "referer", "referrer",
    ]

    REDIRECT_PAYLOADS = [
        ("//evil.com", "协议相对-基础"),
        ("http://evil.com", "HTTP-基础"),
        ("https://evil.com", "HTTPS-基础"),
        ("//evil.com/", "协议相对-带斜杠"),
        ("http://evil.com/", "HTTP-带斜杠"),
        ("//evil.com%2f..", "协议相对-编码"),
        ("http://evil.com%2f..", "HTTP-编码"),
        ("//evil.com%2e%2e", "协议相对-双重编码"),
        ("http://evil.com%2e%2e", "HTTP-双重编码"),
        ("/../evil.com", "路径遍历"),
        ("/..//evil.com", "路径遍历2"),
        ("/../../evil.com", "深层路径遍历"),
        ("/%2e%2e/evil.com", "URL编码路径遍历"),
        ("/%252e%252e/evil.com", "双重编码路径遍历"),
        ("evil.com", "裸域名"),
        ("evil.com/", "裸域名带斜杠"),
        ("@evil.com", "@绕过"),
        ("evil.com@evil.com", "重复域名"),
        ("evil.com.evil.com", "子域名绕过"),
        ("evil.com%2f..", "编码绕过"),
        ("javascript:alert(1)", "javascript伪协议"),
        ("data:text/html,<script>alert(1)</script>", "data伪协议"),
        ("//evil.com%0d%0aLocation:evil", "CRLF注入"),
        ("//evil.com/<script>alert(1)</script>", "XSS组合"),
        ("http://evil.com/<img src=x onerror=alert(1)>", "XSS组合2"),
        ("//localhost", "localhost"),
        ("http://localhost", "localhost HTTP"),
        ("//127.0.0.1", "127.0.0.1"),
        ("http://127.0.0.1", "127.0.0.1 HTTP"),
        ("//0.0.0.0", "0.0.0.0"),
        ("http://0.0.0.0", "0.0.0.0 HTTP"),
    ]
    payloads = REDIRECT_PAYLOADS

    REDIRECT_STATUS_CODES = [301, 302, 303, 307, 308]

    META_REFRESH_PATTERN = r'<meta\s+http-equiv=["\']refresh["\']\s+content=["\'][^"\']*url=([^"\']+)["\']'

    JS_REDIRECT_PATTERNS = [
        r'window\.location\s*=\s*["\']([^"\']+)["\']',
        r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
        r'window\.location\.replace\s*\(\s*["\']([^"\']+)["\']\s*\)',
        r'window\.location\.assign\s*\(\s*["\']([^"\']+)["\']\s*\)',
        r'document\.location\s*=\s*["\']([^"\']+)["\']',
        r'document\.location\.href\s*=\s*["\']([^"\']+)["\']',
        r'location\.href\s*=\s*["\']([^"\']+)["\']',
        r'location\.replace\s*\(\s*["\']([^"\']+)["\']\s*\)',
        r'location\.assign\s*\(\s*["\']([^"\']+)["\']\s*\)',
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
        if isinstance(normal_resp, tuple):
            _normal_status, _normal_text = normal_resp[0], normal_resp[1]
        else:
            _normal_status, _normal_text = normal_resp.status, await normal_resp.text()

        compliant = kwargs.get('compliant', False)
        is_static = kwargs.get('is_static', False)

        if not await self._is_redirect_param(url, param, session):
            self.log_debug(f"参数 {param} 不像是重定向参数，跳过检测")
            return None

        payloads = self.reorder_payloads_by_param(param)

        if is_static:
            payloads = payloads[:10]

        for payload, desc in payloads:
            if compliant:
                await asyncio.sleep(0.3)

            attack_url = self._build_redirect_url(url, param, payload, parsed_query)

            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout, allow_redirects=False)

                if isinstance(resp, tuple):
                    status = resp[0]
                    headers = resp[2] if len(resp) > 2 else {}
                    text = resp[1]
                else:
                    status = resp.status
                    headers = resp.headers
                    text = await resp.text()

                location = headers.get("Location", "")
                if location:
                    if self._is_malicious_redirect(location, payload):
                        return {
                            'url': attack_url,
                            'parameter': param,
                            'payload': payload,
                            'type': f'开放重定向({desc})',
                            'severity': 'Medium',
                            'ai_verdict': '高',
                            'evidence': f'Location 头包含恶意地址: {location}',
                            'status_code': status,
                            'location': location,
                            'recommendation': '校验重定向地址白名单'
                        }

                meta_url = self._extract_meta_redirect(text)
                if meta_url and self._is_malicious_redirect(meta_url, payload):
                    return {
                        'url': attack_url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'开放重定向-Meta({desc})',
                        'severity': 'Medium',
                        'ai_verdict': '高',
                        'evidence': f'Meta 重定向指向恶意地址: {meta_url}',
                        'meta_url': meta_url,
                        'recommendation': '校验重定向地址白名单'
                    }

                js_url = self._extract_js_redirect(text)
                if js_url and self._is_malicious_redirect(js_url, payload):
                    return {
                        'url': attack_url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'开放重定向-JS({desc})',
                        'severity': 'Medium',
                        'ai_verdict': '高',
                        'evidence': f'JavaScript 重定向指向恶意地址: {js_url}',
                        'js_url': js_url,
                        'recommendation': '校验重定向地址白名单'
                    }

                if status in self.REDIRECT_STATUS_CODES:
                    return {
                        'url': attack_url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'开放重定向-疑似({desc})',
                        'severity': 'Low',
                        'ai_verdict': '中',
                        'evidence': f'响应状态码 {status}，但 Location 头为空',
                        'status_code': status,
                        'recommendation': '手动验证是否存在重定向'
                    }

            except Exception as e:
                self.log_debug(f"开放重定向检测异常 {param}: {e}")

        return None

    async def _is_redirect_param(self, url: str, param: str, session) -> bool:
        param_lower = param.lower()
        for p in self.priority_params:
            if p in param_lower:
                return True
        return False

    def _build_redirect_url(self, url: str, param: str, payload: str, parsed_query: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def _is_malicious_redirect(self, location: str, payload: str) -> bool:
        if not location:
            return False

        location_lower = location.lower()
        payload_lower = payload.lower()

        payload_domain = self._extract_domain(payload)
        if payload_domain:
            if payload_domain in location_lower:
                return True
            if payload_domain.replace('.', '%2e') in location_lower:
                return True

        if payload_lower in location_lower:
            return True

        if 'javascript:' in location_lower:
            return True

        return False

    def _extract_domain(self, url_str: str) -> Optional[str]:
        if url_str.startswith('//'):
            url_str = 'http:' + url_str

        try:
            parsed = urlparse(url_str)
            netloc = parsed.netloc or parsed.path
            domain_match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,})', netloc)
            if domain_match:
                return domain_match.group(1)
        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        domain_match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,})', url_str)
        if domain_match:
            return domain_match.group(1)

        return None

    def _extract_meta_redirect(self, text: str) -> Optional[str]:
        if not text:
            return None

        match = re.search(self.META_REFRESH_PATTERN, text, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1)

        meta_patterns = [
            r'<meta\s+http-equiv=["\']refresh["\']\s+content=["\'][^"\']*url=([^"\']+)',
            r'<meta\s+content=["\'][^"\']*url=([^"\']+)["\']\s+http-equiv=["\']refresh["\']',
            r'<meta\s+http-equiv=["\']refresh["\']\s+content=["\']\d+;url=([^"\']+)',
        ]

        for pattern in meta_patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1)

        return None

    def _extract_js_redirect(self, text: str) -> Optional[str]:
        if not text:
            return None

        for pattern in self.JS_REDIRECT_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                url = match.group(1)
                if url.startswith(('http', '//', '/')) or 'javascript:' in url:
                    return url

        return None

    # 全局扫描时探测的常见重定向参数名（聚焦高频项，控制请求量）
    GLOBAL_REDIRECT_PARAMS = [
        "redirect", "return", "next", "url", "to", "goto", "redir",
        "redirect_uri", "redirect_url", "return_to", "callback",
        "continue", "forward", "target", "dest", "link", "ref",
    ]
    # 全局扫描用的高信噪比 payload（命中即报，不过量探测）
    GLOBAL_REDIRECT_PROBES = ["//evil.com", "https://evil.com", "http://evil.com"]

    async def _quick_redirect_test(self, url: str, param: str, session) -> Optional[Dict]:
        """单 (端点,参数) 快速探测：发少量高信噪比 payload，命中即返回。"""
        for payload in self.GLOBAL_REDIRECT_PROBES:
            attack_url = self._build_redirect_url(url, param, payload, "")
            try:
                resp = await async_get(attack_url, session=session,
                                       timeout=settings.timeout, allow_redirects=False)
                if isinstance(resp, tuple):
                    status, headers = resp[0], (resp[2] if len(resp) > 2 else {})
                else:
                    status, headers = resp.status, resp.headers
                location = headers.get("Location", "")
                if location and self._is_malicious_redirect(location, payload):
                    return {
                        'url': attack_url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'开放重定向(全局-{payload})',
                        'severity': 'Medium',
                        'ai_verdict': '高',
                        'evidence': f'Location 头包含恶意地址: {location}',
                        'status_code': status,
                        'location': location,
                        'recommendation': '校验重定向地址白名单',
                    }
            except Exception:
                continue
        return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        """目标级扫描：对 recon 发现的每个端点，用常见重定向参数名探测开放重定向。

        作为全局（目标级）引擎运行，避免被参数级 top-3 优先级挤出
        （redirect 类参数常被 xss/sqli 等高优先级引擎挤掉而漏检）。
        """
        findings: List[Dict] = []
        endpoints = kwargs.get("endpoints") or [target]
        seen = set()
        for ep in endpoints:
            if not ep or ep.lower().startswith(("javascript:", "data:", "file:")):
                continue
            for param in self.GLOBAL_REDIRECT_PARAMS:
                try:
                    r = await asyncio.wait_for(
                        self._quick_redirect_test(ep, param, session), timeout=30)
                except Exception:
                    r = None
                if r:
                    key = (r.get("url", "").split("?")[0], r.get("parameter"))
                    if key not in seen:
                        seen.add(key)
                        findings.append(r)
                    break  # 同一端点找到一个开放重定向即足够
        self.log_info(f"OpenRedirectEngine(全局): {len(findings)} findings / {len(endpoints)} endpoints")
        return findings


# ============================================================
# RaceConditionEngine（修复：过滤 GET 请求）
# ============================================================
class RaceConditionEngine(BaseEngine):
    """竞争条件检测引擎 - 修复版"""

    name = "race_condition"
    description = "竞争条件检测引擎"

    priority_params = [
        "id", "order", "product", "sku", "coupon", "voucher",
        "credit", "points", "balance", "amount", "price",
        "inventory", "stock", "qty", "quantity", "count",
        "user", "account", "customer", "member",
    ]

    RACE_ENDPOINT_KEYWORDS = [
        "order", "checkout", "purchase", "buy", "add-to-cart",
        "claim", "redeem", "withdraw", "transfer", "pay",
        "apply", "submit", "register", "signup", "create",
        "update", "delete", "modify", "change", "cancel",
        "refund", "return", "exchange", "swap",
        "lottery", "draw", "raffle", "giveaway",
        "bonus", "reward", "cashback", "discount",
    ]

    SUCCESS_INDICATORS = [
        "success", "ok", "true", "completed", "finished",
        "created", "saved", "updated", "deleted",
        "已成功", "成功", "完成", "已创建",
        "200", "201", "202", "204",
    ]

    RACE_ERROR_INDICATORS = [
        "duplicate", "conflict", "already", "exists",
        "not enough", "insufficient", "invalid", "expired",
        "并发", "冲突", "已存在", "不足", "已使用",
        "409", "412", "422", "429",
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
        if await self._is_race_target(url):
            return {
                'url': url,
                'type': '竞争条件候选端点',
                'ai_verdict': '信息',
                'evidence': f'发现可能存在竞争条件的端点: {url}',
                'diff_ratio': 0.0,
                'is_candidate': True
            }
        return None

    async def _is_race_target(self, url: str) -> bool:
        url_lower = url.lower()
        for keyword in self.RACE_ENDPOINT_KEYWORDS:
            if keyword in url_lower:
                return True
        return False

    async def test_race_condition(
        self,
        url: str,
        method: str = "POST",
        data: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        session=None,
        concurrency: int = 10,
        threshold: int = 2
    ) -> Optional[Dict]:
        # 修复：对 GET 请求不执行竞争条件检测
        if method.upper() == "GET":
            return None

        try:
            if method.upper() == "GET":
                base_resp = await async_get(url, session=session, timeout=settings.timeout)
            elif method.upper() == "POST":
                if json_data:
                    base_resp = await async_post(url, json=json_data, session=session, timeout=settings.timeout)
                else:
                    base_resp = await async_post(url, data=data, session=session, timeout=settings.timeout)
            elif method.upper() == "PUT":
                base_resp = await async_put(url, json=json_data or data, session=session, timeout=settings.timeout)
            elif method.upper() == "DELETE":
                base_resp = await async_delete(url, session=session, timeout=settings.timeout)
            else:
                return None

            if isinstance(base_resp, tuple):
                base_status = base_resp[0]
                base_text = base_resp[1]
            else:
                base_status = base_resp.status
                base_text = await base_resp.text()

            if not self._is_success(base_status, base_text):
                return None

            tasks = []
            for i in range(concurrency):
                if method.upper() == "GET":
                    task = async_get(url, session=session, timeout=settings.timeout)
                elif method.upper() == "POST":
                    if json_data:
                        task = async_post(url, json=json_data, session=session, timeout=settings.timeout)
                    else:
                        task = async_post(url, data=data, session=session, timeout=settings.timeout)
                elif method.upper() == "PUT":
                    task = async_put(url, json=json_data or data, session=session, timeout=settings.timeout)
                elif method.upper() == "DELETE":
                    task = async_delete(url, session=session, timeout=settings.timeout)
                else:
                    return None
                tasks.append(task)

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            success_count = 0
            error_count = 0
            unique_responses = set()

            for resp in responses:
                if isinstance(resp, Exception):
                    error_count += 1
                    continue

                if isinstance(resp, tuple):
                    status = resp[0]
                    text = resp[1]
                else:
                    status = resp.status
                    text = await resp.text()

                if self._is_success(status, text):
                    success_count += 1
                    unique_responses.add(hashlib.md5(text[:500].encode()).hexdigest())
                else:
                    error_count += 1

            if success_count >= threshold:
                has_different_responses = len(unique_responses) > 1

                return {
                    'url': url,
                    'type': '竞争条件检测',
                    'severity': 'High' if success_count >= concurrency * 0.5 else 'Medium',
                    'evidence': f'并发 {concurrency} 次请求，成功 {success_count} 次，错误 {error_count} 次，唯一响应 {len(unique_responses)} 种',
                    'success_count': success_count,
                    'error_count': error_count,
                    'concurrency': concurrency,
                    'unique_responses': len(unique_responses),
                    'has_different_responses': has_different_responses,
                    'method': method,
                    'recommendation': '使用数据库事务、锁机制或乐观锁防止竞争条件'
                }

        except Exception as e:
            logger.debug(f"竞争条件检测异常: {e}")

        return None

    def _is_success(self, status: int, text: str) -> bool:
        if 200 <= status < 300:
            return True

        text_lower = text.lower()
        for indicator in self.SUCCESS_INDICATORS:
            if indicator.lower() in text_lower:
                return True

        return False

    def _is_race_error(self, status: int, text: str) -> bool:
        text_lower = text.lower()
        for indicator in self.RACE_ERROR_INDICATORS:
            if indicator.lower() in text_lower:
                return True
        return False


# ============================================================
# CachePoisonEngine
# ============================================================
class CachePoisonEngine(BaseEngine):
    """缓存投毒/缓存欺骗检测引擎 - 增强版"""

    name = "cache_poison"
    description = "缓存投毒与缓存欺骗检测引擎"

    # 注意：探测值必须"独特"——旧版用 'http'/'127.0.0.1'/'PUT' 这类泛化值，
    # 'http' 会匹配任何含链接的正常页面（如 httpbin.org 首页），造成头反射误报。
    TEST_HEADERS = [
        ("X-Forwarded-Host", "evil-cache-test.com"),
        ("X-Forwarded-For", "203.0.113.77"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("X-HTTP-Method-Override", "PURGE"),
        ("X-Forwarded-Scheme", "cacheprobe"),
        ("X-Real-IP", "203.0.113.77"),
        ("X-Host", "evil-cache-test.com"),
        ("X-Cache-Key", "evil-cache-test.com"),
        ("X-Originating-IP", "203.0.113.77"),
        ("X-Client-IP", "203.0.113.77"),
        ("X-Forwarded-Host", "evil.com"),
        ("X-Forwarded-Proto", "cacheprobe"),
    ]

    EXTRA_POISON_HEADERS = [
        ("X-Cache-Key", "polluted"),
        ("X-Cache-Tag", "polluted"),
        ("X-Cache-Group", "polluted"),
        ("X-Varnish", "polluted"),
        ("X-Squid", "polluted"),
        ("X-Proxy-Cache", "polluted"),
    ]

    CACHE_HEADERS = [
        "Cache-Control", "Pragma", "Expires", "Vary", "Age"
    ]

    UNSAFE_CACHE_PATTERNS = [
        ("public", "Cache-Control 允许公共缓存"),
        ("max-age", "Cache-Control 设置了 max-age 且未禁用缓存"),
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
        return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings = []
        urlparse(target)
        timeout = getattr(settings, 'timeout', 30)

        logger.info(f"🔗 开始缓存投毒检测: {target}")

        try:
            normal_resp = await async_get(target, session=session, timeout=timeout)
            if isinstance(normal_resp, tuple):
                normal_status, normal_text, normal_headers = normal_resp
            else:
                normal_status = normal_resp.status
                normal_text = await normal_resp.text()
                normal_headers = dict(normal_resp.headers)
        except Exception as e:
            logger.warning(f"获取基准响应失败: {e}")
            return findings

        cache_hdr_info = self._analyze_cache_headers(normal_headers)
        if cache_hdr_info:
            findings.append(cache_hdr_info)

        for header_name, header_value in self.TEST_HEADERS:
            result = await self._test_header_injection(
                target, header_name, header_value,
                normal_status, normal_text, session
            )
            if result:
                findings.append(result)
                break

        for header_name, header_value in self.EXTRA_POISON_HEADERS:
            result = await self._test_header_injection(
                target, header_name, header_value,
                normal_status, normal_text, session
            )
            if result:
                findings.append(result)

        deception_findings = await self._test_cache_deception(target, normal_headers, session)
        findings.extend(deception_findings)

        poison_key_findings = await self._test_cache_key_pollution(target, session)
        findings.extend(poison_key_findings)

        unique_findings = []
        seen = set()
        for f in findings:
            key = (f.get('type', ''), f.get('url', ''))
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        logger.info(f"✅ 缓存投毒检测完成，发现 {len(unique_findings)} 个问题")
        return unique_findings

    def _analyze_cache_headers(self, headers: Dict) -> Optional[Dict]:
        cache_control = headers.get("Cache-Control", "")
        pragma = headers.get("Pragma", "")
        vary = headers.get("Vary", "")

        if not cache_control and not pragma:
            return {
                "type": "缓存策略未配置",
                "url": "",
                "severity": "Low",
                "evidence": "响应中未设置 Cache-Control 或 Pragma 头，可能被缓存代理缓存",
                "recommendation": "建议设置 Cache-Control: no-store, no-cache, must-revalidate"
            }

        cache_control_lower = cache_control.lower() if cache_control else ""
        if "public" in cache_control_lower:
            return {
                "type": "缓存投毒风险（Cache-Control: public）",
                "url": "",
                "severity": "Medium",
                "evidence": f"Cache-Control: {cache_control} 允许公共缓存，可能导致缓存投毒",
                "recommendation": "避免使用 public，对敏感页面使用 private 或 no-store"
            }

        if "no-store" not in cache_control_lower and "no-cache" not in cache_control_lower:
            if "max-age" in cache_control_lower or "s-maxage" in cache_control_lower:
                return {
                    "type": "缓存投毒风险（允许缓存）",
                    "url": "",
                    "severity": "Medium",
                    "evidence": f"Cache-Control: {cache_control} 允许缓存，且未禁止 no-store",
                    "recommendation": "对敏感页面设置 Cache-Control: no-store"
                }

        if vary and "host" in vary.lower():
            return {
                "type": "缓存键包含 Host（潜在缓存投毒）",
                "url": "",
                "severity": "Low",
                "evidence": f"Vary: {vary} 包含 Host，若 Host 可被注入则可能影响缓存键",
                "recommendation": "检查 Host 头是否可被用户控制"
            }

        return None

    async def _test_header_injection(
        self,
        url: str,
        header_name: str,
        header_value: str,
        normal_status: int,
        normal_text: str,
        session
    ) -> Optional[Dict]:
        timeout = getattr(settings, 'timeout', 30)
        try:
            # 第一阶段：带注入头请求（期望缓存Miss）
            headers = {header_name: header_value}
            resp1 = await async_get(url, headers=headers, session=session, timeout=timeout)
            if isinstance(resp1, tuple):
                status1, text1, resp_headers1 = resp1
            else:
                status1 = resp1.status
                text1 = await resp1.text()
                resp_headers1 = dict(resp1.headers)

            # 检查是否为缓存Miss（通常状态码为200，但可能包含缓存相关头）
            cache_control1 = (resp_headers1.get("Cache-Control") or "").lower()
            cacheable1 = bool(resp_headers1.get("Expires")) or (
                cache_control1 and "no-store" not in cache_control1 and "private" not in cache_control1
            )
            
            # 如果不可缓存，直接返回（不是缓存投毒场景）
            if not cacheable1:
                return None

            # 第二阶段：同URL不带注入头请求，检查是否仍包含注入token
            resp2 = await async_get(url, session=session, timeout=timeout)
            if isinstance(resp2, tuple):
                status2, text2, resp_headers2 = resp2
            else:
                status2 = resp2.status
                text2 = await resp2.text()
                resp_headers2 = dict(resp2.headers)

            # 检查注入值是否在第二阶段响应中反射
            if header_value in text2 or header_value in str(resp_headers2.values()):
                # 确认是缓存投毒（High）
                return {
                    "type": f"缓存投毒-头反射({header_name})",
                    "url": url,
                    "severity": "High",
                    "evidence": f"第一阶段带注入头请求后，第二阶段响应仍反射注入值 {header_value}",
                    "payload": f"{header_name}: {header_value}",
                    "recommendation": "禁止在响应中反射用户可控的头，或确保缓存键安全"
                }

            # 如果第一阶段响应有差异且可缓存，但第二阶段没有反射，可能是Info级别
            if status1 != normal_status or abs(len(text1) - len(normal_text)) > 100:
                cache_control = (resp_headers1.get("Cache-Control") or "").lower()
                cacheable = bool(resp_headers1.get("Expires")) or (
                    cache_control and "no-store" not in cache_control and "private" not in cache_control
                )
                if cacheable:
                    return {
                        "type": f"缓存投毒-响应差异({header_name})",
                        "url": url,
                        "severity": "Info",
                        "evidence": f"注入 {header_name} 后响应变化，但未确认缓存投毒",
                        "payload": f"{header_name}: {header_value}",
                        "recommendation": "进一步验证缓存行为"
                    }

        except Exception as e:
            logger.debug(f"缓存投毒测试失败: {e}")
        
        return None

    async def _test_cache_deception(
        self,
        url: str,
        normal_headers: Dict,
        session
    ) -> List[Dict]:
        findings = []
        urlparse(url)
        timeout = getattr(settings, 'timeout', 30)

        static_exts = ["css", "js", "png", "jpg", "svg", "ico", "txt", "pdf", "html", "json"]

        for ext in static_exts:
            test_url = url.rstrip('/') + f"/test.{ext}"
            try:
                resp = await async_get(test_url, session=session, timeout=timeout, allow_redirects=False)
                if isinstance(resp, tuple):
                    status, text, resp_headers = resp
                else:
                    status = resp.status
                    text = await resp.text()
                    resp_headers = dict(resp.headers)

                content_type = resp_headers.get("Content-Type", "")
                if status == 200 and ("html" in content_type.lower() or "json" in content_type.lower()):
                    if len(text) > 100 and ("<html" in text.lower() or "{" in text):
                        findings.append({
                            "type": "缓存欺骗(Web Cache Deception)",
                            "url": test_url,
                            "severity": "High",
                            "evidence": f"访问 {test_url} 返回了 {content_type} 内容（正常应返回静态资源），可能存在缓存欺骗",
                            "payload": f"/test.{ext}",
                            "recommendation": "确保静态资源路径不会返回动态内容，并对缓存键进行严格控制"
                        })
                        break

            except Exception as e:
                logger.debug(f"缓存欺骗检测失败 {ext}: {e}")

        return findings

    async def _test_cache_key_pollution(
        self,
        url: str,
        session
    ) -> List[Dict]:
        findings = []
        timeout = getattr(settings, 'timeout', 30)

        # 准确率修复：探测值必须"独特"——旧版 ("normal", "1") 的 "1"
        # 几乎出现在任何 HTML 页面（httpbin 主页即误报），且缺少基线对比。
        test_params = [
            ("normal", "cacheprobe7x9q"),
            ("evil", "<script>alert(1)</script>"),
            ("evil", "../../../etc/passwd"),
            ("evil", "http://evil.com"),
        ]

        # 基线：不带额外参数的原始响应（仅取一次）
        baseline_text = ""
        try:
            base_resp = await async_get(url, session=session, timeout=timeout)
            if isinstance(base_resp, tuple):
                baseline_text = base_resp[1] or ""
            else:
                baseline_text = await base_resp.text()
        except Exception:
            baseline_text = ""

        for param_name, param_value in test_params:
            try:
                if '?' in url:
                    test_url = f"{url}&{param_name}={param_value}"
                else:
                    test_url = f"{url}?{param_name}={param_value}"

                resp = await async_get(test_url, session=session, timeout=timeout)
                if isinstance(resp, tuple):
                    status, text, resp_headers = resp
                else:
                    text = await resp.text()
                    resp_headers = dict(resp.headers)

                # 只有"注入后新出现"的值才算反射（基线中已存在则跳过）
                if param_value in text and param_value not in baseline_text:
                    findings.append({
                        "url": test_url,
                        "type": f"缓存键污染-参数反射({param_name})",
                        "severity": "Medium",
                        "evidence": f"参数 {param_name}={param_value} 被反射到响应中",
                        "param": param_name,
                        "value": param_value,
                        "recommendation": "避免将用户输入作为缓存键的一部分"
                    })

                cache_control = resp_headers.get("Cache-Control", "")
                if "public" in cache_control.lower() or "max-age" in cache_control.lower():
                    if (param_value in text and param_value not in baseline_text) or (
                        param_value in str(resp_headers) and "evil" in param_name
                    ):
                        findings.append({
                            "url": test_url,
                            "type": "缓存键污染-可缓存参数",
                            "severity": "High",
                            "evidence": f"包含参数的响应被缓存 ({param_name}={param_value})",
                            "param": param_name,
                            "value": param_value,
                            "recommendation": "不要在缓存键中包含用户输入"
                        })

            except Exception as e:
                logger.debug(f"缓存键污染检测失败: {e}")

        return findings


# ============================================================
# 导出
# ============================================================
__all__ = [
    'SecurityHeadersEngine',
    'HostHeaderEngine',
    'OpenRedirectEngine',
    'RaceConditionEngine',
    'CachePoisonEngine',
]
