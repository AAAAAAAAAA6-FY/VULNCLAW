# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ============================================================
# 合并自: modules/idor_scanner.py
# ============================================================

# modules/idor_scanner.py
"""
IDOR（越权访问）扫描器模块 - 高准确率版
修复：_deep_compare_json 增加循环引用检测
"""
import re
import json
import random
import uuid
import base64
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import clean_ai_json
from vulnclaw.ai.core import get_llm_client


class IDORScanner:
    """
    IDOR 越权访问扫描器 - 高准确率版
    """

    ID_PARAMS = [
        "id", "user_id", "uid", "uuid", "guid",
        "order_id", "invoice_id", "account_id", "profile_id",
        "document_id", "file_id", "product_id", "category_id",
        "customer_id", "client_id", "employee_id", "member_id",
        "subscription_id", "ticket_id", "payment_id", "transaction_id",
        "cart_id", "address_id", "phone_id", "email_id",
        "token", "access_token", "session_id"
    ]

    PUBLIC_PATHS_ONLY = [
        "/", "/index", "/index.html", "/index.php", "/index.jsp",
        "/home", "/default", "/main", "/welcome"
    ]

    PRIVATE_INDICATORS = [
        "email", "@", "phone", "mobile", "tel",
        "address", "street", "city", "zip", "postal",
        "credit_card", "card", "cvv", "expiry",
        "ssn", "social", "id_card", "passport",
        "balance", "amount", "transaction", "order",
        "profile", "avatar", "picture", "photo",
        "birthday", "age", "gender", "name"
    ]

    ADMIN_KEYWORDS = [
        "/admin", "/manage", "/dashboard", "/root", "/superuser",
        "/administrator", "/system", "/control", "/panel",
        "/console", "/operator", "/staff", "/internal"
    ]

    SENSITIVE_PATTERNS = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'phone': r'1[3-9]\d{9}',
        'id_card': r'\d{18}|\d{17}X',
        'credit_card': r'\d{16,19}',
        'jwt': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'internal_ip': r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
        'password_hash': r'[a-f0-9]{32,64}',
    }

    def __init__(self, session_manager=None):
        self.session_manager = session_manager
        self.client = get_llm_client()
        self._hashids_available = self._check_hashids()

    def _check_hashids(self) -> bool:
        try:
            import hashids  # noqa: F401  (可用性探测)
            return True
        except ImportError:
            return False

    def _is_public_page_only(self, url: str) -> bool:
        parsed = urlparse(url)
        path = parsed.path.rstrip('/')
        if '/api/' in path or '/graphql' in path or '/v1/' in path or '/v2/' in path:
            return False
        if path in self.PUBLIC_PATHS_ONLY:
            return True
        if path == '' or path == '/':
            return True
        return False

    def _is_public_param(self, param: str) -> bool:
        param_lower = param.lower()
        public_params = [
            "page", "p", "offset", "limit", "size", "per_page",
            "sort", "order", "dir", "asc", "desc",
            "filter", "search", "q", "query", "keyword",
            "category", "tag", "type", "status",
            "format", "callback", "_", "timestamp", "nonce",
            "version", "v", "lang", "locale", "timezone",
            "utm_source", "utm_medium", "utm_campaign", "utm_term"
        ]
        if param_lower in public_params:
            return True
        for p in public_params:
            if p in param_lower:
                return True
        return False

    def _extract_id_params(self, url: str) -> List[Tuple[str, str]]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        id_params = []

        for param, values in qs.items():
            if not values:
                continue
            value = values[0] if isinstance(values, list) else values
            if not value:
                continue

            if self._is_public_param(param):
                continue

            param_lower = param.lower()
            if any(id_param == param_lower for id_param in self.ID_PARAMS):
                id_params.append((param, value))
                continue

            if self._is_id_value(value):
                id_params.append((param, value))

        return id_params

    def _is_id_value(self, value: str) -> bool:
        if re.match(r'^\d+$', value) and len(value) > 1:
            return True
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
            return True
        if re.match(r'^[0-9a-f]{32,64}$', value, re.I):
            return True
        if re.match(r'^[A-Za-z0-9+\-_/]+=*$', value) and len(value) >= 8:
            return True
        return False

    def _generate_id_mutations(self, original_id: str) -> List[str]:
        mutations = []

        if original_id.isdigit():
            try:
                num = int(original_id)
                if num > 2:
                    mutations.append(str(num - 1))
                    mutations.append(str(num - 2))
                mutations.append(str(num + 1))
                mutations.append(str(num + 2))
                mutations.append(str(num + random.randint(3, 10)))
                mutations.append("1")
                mutations.append("999999")
                mutations.append("0")
                mutations.append("-1")
            except BaseException:
                pass

        elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', original_id, re.I):
            mutations.append(str(uuid.uuid4()))
            mutations.append("00000000-0000-0000-0000-000000000000")
            mutations.append("ffffffff-ffff-ffff-ffff-ffffffffffff")
            mutations.append(original_id[:8])
            if original_id[-1].isdigit():
                new_last = str((int(original_id[-1]) + 1) % 10)
                mutations.append(original_id[:-1] + new_last)

        elif re.match(r'^[A-Za-z0-9+\-_/]+=*$', original_id) and len(original_id) >= 8:
            mutations.append(original_id[:-1] + ('A' if original_id[-1] != 'A' else 'B'))
            mutations.append(original_id + 'A')
            if len(original_id) > 4:
                mutations.append(original_id[:len(original_id) // 2])
                mutations.append(original_id[len(original_id) // 2:])
            try:
                # 修复：使用 url-safe base64 解码
                url_safe = original_id.replace('-', '+').replace('_', '/')
                padding = 4 - (len(url_safe) % 4)
                if padding != 4:
                    url_safe += '=' * padding
                decoded = base64.urlsafe_b64decode(url_safe)
                if decoded:
                    new_encoded = base64.urlsafe_b64encode(decoded).decode().rstrip('=')
                    if new_encoded != original_id:
                        mutations.append(new_encoded)
            except BaseException:
                pass

        elif re.match(r'^[0-9a-f]{32,64}$', original_id, re.I):
            if original_id[-1].isdigit():
                new_last = str((int(original_id[-1]) + 1) % 10)
                mutations.append(original_id[:-1] + new_last)
            else:
                char_map = {'a': 'b', 'b': 'c', 'c': 'd', 'd': 'e', 'e': 'f', 'f': '0'}
                if original_id[-1].lower() in char_map:
                    mutations.append(original_id[:-1] + char_map[original_id[-1].lower()])
            mutations.append(original_id[:16])
            mutations.append(original_id[:8])
            mutations.append('0' * len(original_id))
            mutations.append('f' * len(original_id))

        if self._hashids_available and len(original_id) > 3:
            try:
                import hashids
                common_salts = ["", "salt", "secret", "key", "id", "default"]
                for salt in common_salts:
                    try:
                        h = hashids.Hashids(salt=salt)
                        decoded = h.decode(original_id)
                        if decoded:
                            for offset in [1, 2, 3]:
                                new_nums = [d + offset for d in decoded]
                                new_id = h.encode(*new_nums)
                                if new_id and new_id != original_id:
                                    mutations.append(new_id)
                            break
                    except BaseException:
                        continue
            except BaseException:
                pass

        mutations.append('null')
        mutations.append('undefined')
        mutations.append('')
        mutations.append('0')
        mutations.append('1')
        mutations.append('-1')
        mutations.append('admin')
        mutations.append('root')
        mutations.append('guest')
        mutations.append('test')

        mutations = list(dict.fromkeys(mutations))
        if original_id in mutations:
            mutations.remove(original_id)
        return mutations[:15]

    # ============================================================
    # 结构化 JSON Diff（修复：增加循环引用检测）
    # ============================================================
    def _compute_structured_diff(self, responses: Dict[str, Tuple[int, str, Dict]]) -> Tuple[float, bool]:
        if len(responses) < 2:
            return 0.0, False

        texts = []
        statuses = []
        parsed_jsons = []
        is_json = False

        for role, (status, text, headers) in responses.items():
            texts.append(text[:500])
            statuses.append(status)
            try:
                data = json.loads(text)
                parsed_jsons.append(data)
                is_json = True
            except BaseException:
                parsed_jsons.append(None)

        unique_statuses = len(set(statuses))
        status_score = min(1.0, (unique_statuses - 1) / 2)

        content_diff = 0.0

        if is_json and len(parsed_jsons) >= 2:
            json_diffs = []
            for i in range(len(parsed_jsons) - 1):
                for j in range(i + 1, len(parsed_jsons)):
                    if parsed_jsons[i] is not None and parsed_jsons[j] is not None:
                        diff = self._deep_compare_json(parsed_jsons[i], parsed_jsons[j])
                        json_diffs.append(diff)
            if json_diffs:
                content_diff = sum(json_diffs) / len(json_diffs)
        else:
            if len(texts) >= 2:
                words_sets = [set(t.split()) for t in texts]
                intersection = words_sets[0]
                union = words_sets[0]
                for s in words_sets[1:]:
                    intersection = intersection.intersection(s)
                    union = union.union(s)
                if union:
                    jaccard = len(intersection) / len(union)
                    content_diff = 1 - jaccard
                else:
                    content_diff = 0.0

        lengths = [len(t) for t in texts]
        if lengths and sum(lengths) > 0:
            mean_len = sum(lengths) / len(lengths)
            if mean_len > 0:
                variance = sum((l - mean_len) ** 2 for l in lengths) / len(lengths)
                cv = (variance ** 0.5) / mean_len
                length_score = min(1.0, cv * 2)
            else:
                length_score = 0
        else:
            length_score = 0

        total_score = status_score * 0.15 + length_score * 0.25 + content_diff * 0.6

        return total_score, False

    def _deep_compare_json(self, obj1: Any, obj2: Any, path: str = "", seen: Set[int] = None) -> float:
        """
        深度比较 JSON 对象 - 修复：增加循环引用检测
        """
        if seen is None:
            seen = set()

        # 检测循环引用
        obj1_id = id(obj1)
        obj2_id = id(obj2)
        if obj1_id in seen or obj2_id in seen:
            return 0.0
        seen.add(obj1_id)
        seen.add(obj2_id)

        if not isinstance(obj1, type(obj2)):
            return 1.0

        if isinstance(obj1, dict):
            if not isinstance(obj2, dict):
                return 1.0
            all_keys = set(obj1.keys()) | set(obj2.keys())
            if not all_keys:
                return 0.0
            diffs = []
            for key in all_keys:
                v1 = obj1.get(key)
                v2 = obj2.get(key)
                if key in obj1 and key in obj2:
                    diff = self._deep_compare_json(v1, v2, f"{path}.{key}" if path else key, seen)
                elif key in obj1 and key not in obj2:
                    diff = 0.5
                else:
                    diff = 0.5
                diffs.append(diff)
            return sum(diffs) / len(diffs)

        elif isinstance(obj1, list):
            if not isinstance(obj2, list):
                return 1.0
            if not obj1 and not obj2:
                return 0.0
            max_len = max(len(obj1), len(obj2))
            diffs = []
            for i in range(max_len):
                if i < len(obj1) and i < len(obj2):
                    diff = self._deep_compare_json(obj1[i], obj2[i], f"{path}[{i}]", seen)
                elif i < len(obj1):
                    diff = 0.5
                else:
                    diff = 0.5
                diffs.append(diff)
            return sum(diffs) / len(diffs)

        else:
            if obj1 == obj2:
                return 0.0
            return 1.0

    async def _detect_private_data(self, responses: Dict[str, Tuple[int, str, Dict]]) -> bool:
        for role, (status, text, headers) in responses.items():
            if status != 200:
                continue
            text_lower = text.lower()
            indicator_count = 0
            for indicator in self.PRIVATE_INDICATORS:
                if indicator in text_lower:
                    indicator_count += 1
                    if indicator_count >= 2:
                        return True
            for label, pattern in self.SENSITIVE_PATTERNS.items():
                if re.search(pattern, text, re.I):
                    return True
            if any(kw in text_lower for kw in ["welcome", "hello", "hi", "greetings"]):
                if any(kw in text_lower for kw in ["user", "account", "profile", "member"]):
                    return True
        return False

    async def _ai_verify_idor_v2(
        self,
        url: str,
        roles: List[str],
        responses: Dict[str, Tuple[int, str, Dict]],
        diff_score: float,
        is_private: bool
    ) -> Dict:
        comparison = []
        for role, (status, text, headers) in responses.items():
            snippet = text[:800]
            sensitive = self._extract_sensitive_from_text(text)
            comparison.append(
                f"角色: {role}\n"
                f"状态码: {status}\n"
                f"敏感数据: {', '.join(sensitive[:3]) if sensitive else '无'}\n"
                f"响应片段: {snippet}\n"
            )

        prompt = f"""
你是一位严谨的安全分析专家。请判断以下是否存在权限绕过（IDOR）漏洞。

目标 URL: {url}
响应差异分数: {diff_score:.2f} (0-1，越高差异越大)

响应对比：
{chr(10).join(comparison)}

严格判断标准（必须同时满足才算漏洞）：
1. 不同角色返回的数据结构必须包含"用户特定"的内容（如用户名、邮箱、订单详情等）
2. 低权限用户能访问到"高权限用户"的数据
3. 仅当响应的状态码和内容有"显著差异"时才判定为越权
4. 如果不同角色返回的数据完全相同，或者是公共数据（如首页、文章列表），则不是漏洞
5. 如果所有角色都返回相同的"无权限"或"登录页"，则不是漏洞
6. 401/403 状态码视为"认证缺失"，不视为越权

输出 JSON：
{{
  "is_idor": true/false,
  "confidence": "高/中/低",
  "severity": "Critical/High/Medium",
  "evidence": "判断依据（50字以内）",
  "recommendation": "修复建议"
}}
"""
        try:
            result = await self.client.ask(
                prompt,
                system="只输出 JSON，不要解释。",
                temperature=0.1,
                wrap_data=True
            )
            cleaned = clean_ai_json(result)
            json_match = re.search(r'\{.*\}', cleaned, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                if diff_score < 0.01:
                    data['is_idor'] = False
                    data['confidence'] = '低'
                    data['evidence'] = '响应几乎无差异'
                return data
        except Exception as e:
            logger.debug(f"AI 验证 IDOR 失败: {e}")

        if diff_score > 0.15 and is_private:
            return {
                "is_idor": True,
                "confidence": "中",
                "severity": "High",
                "evidence": f"响应差异 {diff_score:.1%} 且包含敏感数据",
                "recommendation": "建议检查权限控制逻辑"
            }

        if diff_score > 0.05 and is_private:
            return {
                "is_idor": True,
                "confidence": "低",
                "severity": "Medium",
                "evidence": f"响应差异 {diff_score:.1%}，建议人工复核",
                "recommendation": "建议手动验证"
            }

        return {"is_idor": False, "confidence": "低", "evidence": "AI 分析未确认"}

    def _extract_sensitive_from_text(self, text: str) -> List[str]:
        found = []
        for label, pattern in self.SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, text, re.I)
            if matches:
                found.extend(matches[:2])
        return found

    async def scan_url_with_roles(
        self,
        url: str,
        roles: List[str],
        session_manager=None,
        **kwargs
    ) -> List[Dict]:
        if session_manager:
            self.session_manager = session_manager

        if not self.session_manager:
            logger.warning("⚠️ IDOR 扫描需要 SessionManager")
            return []

        if len(roles) < 2:
            logger.warning("⚠️ IDOR 检测需要至少 2 个角色")
            return []

        findings = []

        id_params = self._extract_id_params(url)
        if not id_params:
            logger.debug(f"URL 无 ID 参数，跳过 IDOR 检测: {url}")
            return findings

        if self._is_public_page_only(url):
            logger.debug(f"URL 是公开首页，跳过 IDOR 检测: {url}")
            return findings

        logger.info(f"🔐 检测 IDOR: {url}，参数: {id_params}")

        for param, original_value in id_params:
            if self._is_public_param(param):
                logger.debug(f"   ⏭️ 跳过公共参数: {param}")
                continue

            if not original_value:
                continue

            mutations = self._generate_id_mutations(original_value)

            for mutated_value in mutations[:10]:
                try:
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query)
                    qs[param] = [mutated_value]
                    new_query = urlencode(qs, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))

                    responses = await self.session_manager.compare_requests(
                        test_url, "GET", roles
                    )

                    diff_score, is_private = self._compute_structured_diff(responses)

                    if diff_score > 0.05 or is_private:
                        ai_result = await self._ai_verify_idor_v2(
                            test_url, roles, responses, diff_score, is_private
                        )

                        if ai_result.get('is_idor', False):
                            finding = {
                                'url': test_url,
                                'parameter': param,
                                'original_value': original_value,
                                'mutated_value': mutated_value,
                                'type': 'IDOR-越权访问',
                                'severity': ai_result.get('severity', 'High'),
                                'ai_verdict': ai_result.get('confidence', '高'),
                                'confidence': 'high' if ai_result.get('confidence') == '高' else 'medium',
                                'evidence': ai_result.get('evidence', ''),
                                'diff_score': diff_score,
                                'has_private_data': is_private,
                                'recommendation': ai_result.get('recommendation', '')
                            }
                            findings.append(finding)
                            logger.warning(f"🚨 发现 IDOR: {test_url} ({param}={mutated_value})")
                            break

                except Exception as e:
                    logger.debug(f"IDOR 测试异常: {e}")

        return findings

    async def scan_vertical_privilege(
        self,
        base_url: str,
        session_manager=None,
        roles: List[str] = None
    ) -> List[Dict]:
        if session_manager:
            self.session_manager = session_manager

        if not self.session_manager:
            logger.warning("⚠️ IDOR 扫描需要 SessionManager")
            return []

        if not roles:
            roles = self.session_manager.get_roles()

        if len(roles) < 2:
            return []

        findings = []

        admin_paths = [
            "/admin", "/admin/dashboard", "/admin/users", "/admin/api",
            "/manage", "/manage/users", "/manage/api",
            "/dashboard", "/dashboard/admin", "/dashboard/api",
            "/console", "/console/admin",
            "/panel", "/panel/admin",
            "/system", "/system/status",
            "/internal", "/internal/admin",
            "/api/admin", "/api/manage", "/api/system",
            "/v1/admin", "/v2/admin",
        ]

        base = base_url.rstrip('/')
        for path in admin_paths[:12]:
            test_url = base + path

            try:
                responses = await self.session_manager.compare_requests(test_url, "GET", roles)

                admin_roles = []
                for role, (status, text, headers) in responses.items():
                    if status == 200 and len(text) > 100:
                        admin_indicators = ['admin', 'dashboard', 'users', 'manage', 'system', 'config', 'settings']
                        score = sum(1 for ind in admin_indicators if ind in text.lower())
                        if score >= 2:
                            admin_roles.append(role)

                if admin_roles:
                    if len(admin_roles) == len(roles):
                        continue

                    findings.append({
                        'url': test_url,
                        'type': '垂直越权-管理路径访问',
                        'severity': 'High',
                        'ai_verdict': '高',
                        'confidence': 'high',
                        'evidence': f"低权限角色可访问管理路径: {', '.join([r for r in roles if r not in admin_roles])}",
                        'accessible_roles': admin_roles,
                        'recommendation': '检查权限中间件配置'
                    })
            except Exception as e:
                logger.debug(f"垂直越权检测异常: {e}")

        return findings


async def scan_idor(
    url: str,
    session_manager,
    roles: List[str] = None
) -> List[Dict]:
    if not roles:
        roles = session_manager.get_roles()

    scanner = IDORScanner(session_manager)
    return await scanner.scan_url_with_roles(url, roles, session_manager)


async def scan_vertical_privilege(
    base_url: str,
    session_manager,
    roles: List[str] = None
) -> List[Dict]:
    if not roles:
        roles = session_manager.get_roles()

    scanner = IDORScanner(session_manager)
    return await scanner.scan_vertical_privilege(base_url, session_manager, roles)


__all__ = [
    'IDORScanner',
    'scan_idor',
    'scan_vertical_privilege',
]

# ============================================================
# 合并自: modules/default_cred_checker.py
# ============================================================

# modules/default_cred_checker.py
"""
默认凭证检测器 - 完整版 v2.1
修复：
1. CSRF Token 提取增强：支持 meta 标签、JS 变量、JSON 中的 Token
2. 登录成功判定优化：增加更多成功标志
3. 表单智能解析增强：支持多表单、多字段名模式
4. 支持现代 SPA（React/Vue）的 Token 提取
"""

import re
import json
from urllib.parse import urljoin, urlparse
from typing import Any, Dict, List, Optional, Set, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.core.scanner import safe_request
from vulnclaw.ai.core import get_llm_client

# 常见默认凭证
DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "123456"), ("admin", "password"),
    ("admin", "admin123"), ("root", "root"), ("root", "123456"),
    ("user", "user"), ("user", "password"), ("test", "test"),
    ("guest", "guest"), ("administrator", "administrator"),
    ("administrator", "password"), ("system", "system"),
    ("oracle", "oracle"), ("tomcat", "tomcat"), ("weblogic", "weblogic"),
    ("jboss", "jboss"), ("jenkins", "jenkins"), ("nexus", "nexus"),
    ("gitlab", "password"), ("gitlab", "gitlab"),
]

TECH_DEFAULT_CREDS = {
    "wordpress": [("admin", "admin"), ("admin", "password")],
    "jenkins": [("admin", "admin"), ("admin", "password")],
    "gitlab": [("root", "password"), ("admin", "admin123")],
    "confluence": [("admin", "admin"), ("admin", "password")],
    "tomcat": [("admin", "admin"), ("tomcat", "tomcat")],
    "weblogic": [("weblogic", "weblogic")],
    "jboss": [("admin", "admin"), ("jboss", "jboss")],
    "nexus": [("admin", "admin123"), ("nexus", "nexus")],
    "grafana": [("admin", "admin")],
    "kibana": [("elastic", "changeme")],
    "rabbitmq": [("guest", "guest")],
    "redis": [("default", "")],
    "mongodb": [("admin", "admin")],
}

LOGIN_PATHS = [
    "/admin", "/administrator", "/login", "/signin", "/auth/login",
    "/user/login", "/wp-login.php", "/admin/login", "/cms/admin",
    "/dashboard", "/manage", "/console", "/cp", "/cpanel", "/webmail",
    "/owa", "/ecp", "/remote", "/exchange",
    "/api/login", "/api/auth", "/api/signin",
]

# ============================================================
# CSRF Token 提取（增强版 - 支持 SPA）
# ============================================================


def _extract_csrf_token_enhanced(html: str) -> Optional[Tuple[str, str]]:
    """
    从 HTML 中提取 CSRF Token（增强版）
    支持：input 标签、meta 标签、JS 变量、JSON 数据
    返回: (field_name, token_value) 或 None
    """
    if not html:
        return None

    # 方法1：查找 input 标签（传统表单）
    input_pattern = r'<input[^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']+)["\']'
    for match in re.finditer(input_pattern, html, re.IGNORECASE):
        name, value = match.group(1), match.group(2)
        if _is_csrf_field(name):
            return name, value

    # 方法2：查找 meta 标签（常见于 React/Next.js）
    meta_patterns = [
        r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']',
        r'<meta\s+name=["\']_csrf["\']\s+content=["\']([^"\']+)["\']',
        r'<meta\s+name=["\']csrf-param["\']\s+content=["\']([^"\']+)["\']',
        r'<meta\s+name=["\']csrf_token["\']\s+content=["\']([^"\']+)["\']',
    ]
    for pattern in meta_patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return "csrf_token", match.group(1)

    # 方法3：查找 JavaScript 变量（常见于 Vue/React）
    js_patterns = [
        r'window\.csrfToken\s*=\s*["\']([^"\']+)["\']',
        r'window\._csrf\s*=\s*["\']([^"\']+)["\']',
        r'let\s+csrfToken\s*=\s*["\']([^"\']+)["\']',
        r'const\s+csrfToken\s*=\s*["\']([^"\']+)["\']',
        r'csrfToken:\s*["\']([^"\']+)["\']',
        r'_csrf:\s*["\']([^"\']+)["\']',
        r'data-csrf=["\']([^"\']+)["\']',
    ]
    for pattern in js_patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return "csrf_token", match.group(1)

    # 方法4：查找 JSON 数据中的 Token
    json_pattern = r'["\'](csrf_token|csrf-token|_csrf|authenticity_token)["\']\s*[:=]\s*["\']([^"\']+)["\']'
    match = re.search(json_pattern, html, re.IGNORECASE)
    if match:
        return match.group(1), match.group(2)

    # 方法5：查找 data 属性中的 Token
    data_patterns = [
        r'data-csrf-token=["\']([^"\']+)["\']',
        r'data-csrf=["\']([^"\']+)["\']',
        r'data-token=["\']([^"\']+)["\']',
    ]
    for pattern in data_patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return "csrf_token", match.group(1)

    return None


def _is_csrf_field(name: str) -> bool:
    """判断字段名是否为 CSRF Token 字段"""
    name_lower = name.lower()
    csrf_keywords = ['csrf', 'token', 'authenticity', '_token', '_csrf']
    return any(kw in name_lower for kw in csrf_keywords)


# ============================================================
# 表单解析（增强版）
# ============================================================

def _extract_form_fields_enhanced(html: str, base_url: str) -> Dict[str, Any]:
    """
    从 HTML 中提取表单信息（增强版）
    返回: {
        'action': str,
        'method': str,
        'fields': {'name': 'value', ...},
        'username_field': str,
        'password_field': str,
        'csrf_field': str,
        'forms': [{'action': ..., 'fields': {...}}, ...]  # 多个表单
    }
    """
    result = {
        'action': '',
        'method': 'POST',
        'fields': {},
        'username_field': None,
        'password_field': None,
        'csrf_field': None,
        'has_file_upload': False,
        'forms': [],
        'is_spa': False
    }

    if not html:
        return result

    # 检测是否为 SPA (React/Vue/Angular)
    spa_indicators = ['react', 'vue', 'angular', 'ng-', 'data-react', 'v-']
    if any(ind in html.lower() for ind in spa_indicators):
        result['is_spa'] = True

    # 查找所有表单
    form_pattern = r'<form[^>]*>(.*?)</form>'
    forms = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)

    if not forms:
        # 无表单，检查是否有独立的登录输入框
        inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
        username_field = None
        password_field = None
        for name in inputs:
            name_lower = name.lower()
            if any(p in name_lower for p in ['username', 'user', 'email', 'login']):
                username_field = name
            elif any(p in name_lower for p in ['password', 'pass', 'pwd']):
                password_field = name
        if username_field and password_field:
            result['username_field'] = username_field
            result['password_field'] = password_field
            # 尝试从 meta 或 script 中提取 CSRF Token
            csrf_result = _extract_csrf_token_enhanced(html)
            if csrf_result:
                result['csrf_field'] = csrf_result[0]
                result['fields'][csrf_result[0]] = csrf_result[1]
            return result
        return result

    best_form = None
    best_score = -1

    for form_html in forms:
        # 提取表单属性
        action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)

        action = action_match.group(1) if action_match else ''
        method = method_match.group(1).upper() if method_match else 'POST'

        # 提取所有 input 字段
        input_pattern = r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>'
        fields = {}
        username_field = None
        password_field = None
        csrf_field = None
        has_file = False

        # 先尝试提取 CSRF Token（从整个页面）
        csrf_result = _extract_csrf_token_enhanced(form_html)
        if csrf_result:
            csrf_field = csrf_result[0]
            fields[csrf_field] = csrf_result[1]

        for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
            input_html = input_match.group(0)
            name = input_match.group(1)

            # 提取 value
            value_match = re.search(r'value=["\']([^"\']+)["\']', input_html, re.IGNORECASE)
            value = value_match.group(1) if value_match else ''

            # 检查类型
            type_match = re.search(r'type=["\']([^"\']+)["\']', input_html, re.IGNORECASE)
            input_type = type_match.group(1).lower() if type_match else 'text'

            if input_type == 'file':
                has_file = True
                continue
            if input_type in ['submit', 'button', 'reset', 'image']:
                if value:
                    fields[name] = value
                continue

            # 识别字段类型
            name_lower = name.lower()
            if any(p in name_lower for p in ['username', 'user', 'email', 'login', 'user_name', 'userid', 'uid']):
                username_field = name
                fields[name] = value
            elif any(p in name_lower for p in ['password', 'pass', 'pwd', 'user_password', 'passwd']):
                password_field = name
                fields[name] = value
            elif _is_csrf_field(name):
                csrf_field = name
                fields[name] = value
            else:
                fields[name] = value

        # 评分
        score = 0
        if password_field:
            score += 10
        if username_field:
            score += 5
        if csrf_field:
            score += 2

        if score > best_score:
            best_score = score
            best_form = {
                'action': action,
                'method': method,
                'fields': fields,
                'username_field': username_field,
                'password_field': password_field,
                'csrf_field': csrf_field,
                'has_file_upload': has_file
            }

    # 如果没找到好表单，使用页面级别的 CSRF Token
    if best_form is None or best_score <= 0:
        csrf_result = _extract_csrf_token_enhanced(html)
        if csrf_result:
            result['csrf_field'] = csrf_result[0]
            result['fields'][csrf_result[0]] = csrf_result[1]

        # 尝试从页面中找用户名/密码输入
        inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
        for name in inputs:
            name_lower = name.lower()
            if any(p in name_lower for p in ['username', 'user', 'email', 'login']):
                result['username_field'] = name
            elif any(p in name_lower for p in ['password', 'pass', 'pwd']):
                result['password_field'] = name

        if result['username_field'] and result['password_field']:
            return result
        return result

    # 如果 action 是相对路径，拼接 base_url
    if best_form['action'] and not best_form['action'].startswith(('http://', 'https://')):
        best_form['action'] = urljoin(base_url, best_form['action'])

    result.update(best_form)
    return result


# ============================================================
# 登录页面发现（增强版）
# ============================================================

async def _smart_discover_login_pages(target_url: str, session, timeout: int = 10) -> List[Dict[str, Any]]:
    """智能发现登录页面"""
    login_pages = []
    get_llm_client()
    base_url = target_url.rstrip('/')

    # 方法1：硬编码路径探测
    for path in LOGIN_PATHS:
        test_url = base_url + path
        try:
            resp = await safe_request(test_url, session, method="GET", timeout=3)
            if resp is not None:
                status, html, headers = resp
                if status in (200, 403, 401):
                    form = _extract_form_fields_enhanced(html, base_url)
                    login_pages.append({
                        'url': test_url,
                        'html': html,
                        'form': form,
                        'status': status
                    })
                    logger.debug(f"发现登录入口: {test_url}")
        except BaseException:
            pass

    # 方法2：从首页提取链接（AI 辅助）
    try:
        resp = await safe_request(target_url, session, method="GET", timeout=timeout)
        if resp is not None:
            status, html, headers = resp
            if html and len(html) > 500:
                # 提取所有包含登录关键词的链接
                login_links = re.findall(
                    r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>.*?(?:login|signin|sign in|登录|登陆).*?</a>',
                    html, re.IGNORECASE | re.DOTALL
                )
                for link in login_links:
                    if link.startswith('/'):
                        link = urljoin(target_url, link)
                    if link.startswith(('http://', 'https://')):
                        if not any(page.get('url') == link for page in login_pages):
                            try:
                                resp2 = await safe_request(link, session, method="GET", timeout=3)
                                if resp2 is not None:
                                    status2, html2, headers2 = resp2
                                    form = _extract_form_fields_enhanced(html2, base_url)
                                    login_pages.append({
                                        'url': link,
                                        'html': html2,
                                        'form': form,
                                        'status': status2
                                    })
                            except BaseException:
                                pass
    except Exception as e:
        logger.debug(f"首页链接提取失败: {e}")

    return login_pages


# ============================================================
# 凭证生成（增强版）
# ============================================================

async def _generate_custom_creds(login_url: str, tech_stack: List[str] = None, page_html: str = "", form: Dict = None) -> List[Tuple[str, str]]:
    """生成自定义凭证列表"""
    creds = []
    if tech_stack:
        for tech in tech_stack:
            tech_lower = tech.lower()
            for key, tech_creds in TECH_DEFAULT_CREDS.items():
                if key in tech_lower:
                    creds.extend(tech_creds)
    creds.extend(DEFAULT_CREDENTIALS)

    # AI 辅助生成（增强版）
    if page_html and len(page_html) > 200:
        client = get_llm_client()

        # 提取页面品牌信息
        brand = ''
        title_match = re.search(r'<title>([^<]+)</title>', page_html, re.IGNORECASE)
        if title_match:
            brand = title_match.group(1).strip()

        # 提取可能的 CSRF Token 字段名
        csrf_hint = ''
        if form and form.get('csrf_field'):
            csrf_hint = f"页面上有 CSRF Token 字段: {form['csrf_field']}"

        prompt = f"""分析以下登录页面，生成 3-5 个最可能有效的用户名/密码组合。
规则：
1. 查看页面中是否有隐藏的默认用户名提示
2. 查看页面标题或品牌名称（如 "Jenkins" 则用 jenkins:jenkins）
3. {csrf_hint}
4. 输出 JSON 数组：[["username1","password1"], ["username2","password2"]]

页面标题: {brand}
页面 HTML（前 2000 字符）:
{page_html[:2000]}
"""
        try:
            result = await client.ask(prompt, system="只输出 JSON 数组。", temperature=0.2, wrap_data=True)
            json_match = re.search(r'\[.*\]', result, re.DOTALL)
            if json_match:
                ai_creds = json.loads(json_match.group())
                if isinstance(ai_creds, list):
                    for item in ai_creds:
                        if isinstance(item, list) and len(item) == 2:
                            creds.append((item[0], item[1]))
        except Exception as e:
            logger.debug(f"AI 生成凭证失败: {e}")

    # 去重
    seen = set()
    unique = []
    for u, p in creds:
        key = f"{u}:{p}"
        if key not in seen:
            seen.add(key)
            unique.append((u, p))
    return unique


# ============================================================
# 登录成功判定（增强版）
# ============================================================

def _is_login_success(status: int, text: str, headers: Dict, action_url: str) -> Tuple[bool, str]:
    text_lower = text.lower()

    # 1. 重定向检测
    if status in (302, 303, 301):
        location = headers.get('Location', '')
        if location and ('login' in location.lower() or 'signin' in location.lower()):
            return False, "重定向回登录页"
        if location and ('error' in location.lower() or 'invalid' in location.lower()):
            return False, "重定向到错误页"
        if location:
            if '?' in location and ('error' in location.lower() or 'fail' in location.lower()):
                return False, "重定向包含错误参数"
            return True, f"重定向到 {location}"
    # 2. 状态码检测
    if status == 200:
        # 检查是否包含错误关键词
        error_keywords = [
            'error', 'invalid', 'incorrect', 'wrong',
            'login', 'sign in', '请登录', '错误', '失败',
            'username or password', 'credentials', 'authentication failed',
            '登录失败', '用户名或密码错误', '账户锁定'
        ]
        has_error = any(kw in text_lower for kw in error_keywords)

        if not has_error:
            # 检查是否包含成功关键词
            success_keywords = [
                'dashboard', 'welcome', 'profile', 'account', 'settings',
                'logout', 'signout', '管理后台', '控制台', '个人中心',
                'success', 'successful', '已登录', '欢迎回来'
            ]
            if any(kw in text_lower for kw in success_keywords):
                return True, "页面包含成功关键词"

        # 如果页面没有错误关键词且不是登录页，可能成功
        if not has_error and 'login' not in text_lower and 'sign in' not in text_lower:
            return True, "无错误关键词，非登录页"

        return False, "包含错误关键词或仍为登录页"

    # 3. Set-Cookie 检测（包含 session 相关 Cookie）
    set_cookie = headers.get('Set-Cookie', '')
    if set_cookie:
        # 检查是否设置了 session 相关 Cookie
        session_keywords = ['session', 'sid', 'token', 'auth', 'login', 'user']
        for kw in session_keywords:
            if kw.lower() in set_cookie.lower():
                return True, f"设置了 {kw} Cookie"

    return False, "未知状态"


# ============================================================
# 主检测函数
# ============================================================

async def check_default_credentials(
    target_url: str,
    session,
    tech_stack: List[str] = None,
    timeout: int = 10,
    max_attempts: int = 30
) -> List[Dict]:
    """检测默认凭证 - 修复版"""
    findings = []
    login_pages = await _smart_discover_login_pages(target_url, session, timeout)

    if not login_pages:
        logger.info("ℹ️ 未发现登录入口，跳过默认凭证检测")
        return []

    logger.info(f"🔍 发现 {len(login_pages)} 个登录入口")

    for page_info in login_pages:
        login_url = page_info.get('url')
        page_html = page_info.get('html', '')
        form = page_info.get('form', {})

        if not login_url:
            continue

        logger.info(f"🔐 测试登录入口: {login_url}")
        logger.debug(f"   表单信息: action={form.get('action', '')}, method={form.get('method', 'POST')}")
        logger.debug(f"   字段: username={form.get('username_field')}, password={form.get('password_field')}, csrf={form.get('csrf_field')}")

        credentials = await _generate_custom_creds(login_url, tech_stack, page_html, form)
        if len(credentials) > max_attempts:
            credentials = credentials[:max_attempts]

        # 构建请求 URL
        action_url = form.get('action') if form.get('action') else login_url
        if not action_url.startswith(('http://', 'https://')):
            action_url = urljoin(login_url, action_url)

        for username, password in credentials:
            try:
                # 构建表单数据
                data = {}

                username_field = form.get('username_field')
                password_field = form.get('password_field')

                if username_field and password_field:
                    data[username_field] = username
                    data[password_field] = password
                else:
                    data['username'] = username
                    data['password'] = password

                # 添加 CSRF Token
                csrf_field = form.get('csrf_field')
                if csrf_field and csrf_field in form.get('fields', {}):
                    data[csrf_field] = form['fields'][csrf_field]
                else:
                    csrf_result = _extract_csrf_token_enhanced(page_html)
                    if csrf_result:
                        field_name, token_value = csrf_result
                        data[field_name] = token_value
                        logger.debug(f"   从页面提取 CSRF Token: {field_name}={token_value[:10]}...")

                # 添加表单中的其他隐藏字段
                for field_name, field_value in form.get('fields', {}).items():
                    if field_name not in data and field_name not in [username_field, password_field, csrf_field]:
                        data[field_name] = field_value

                # 发送登录请求
                resp = await safe_request(
                    action_url,
                    session,
                    method="POST",
                    timeout=timeout,
                    data=data
                )

                if resp is None:
                    continue

                status, text, headers = resp

                # 判断登录成功
                success, reason = _is_login_success(status, text, headers, action_url)

                if success:
                    finding = {
                        "type": "默认凭证登录",
                        "url": login_url,
                        "action_url": action_url,
                        "username": username,
                        "password": password,
                        "severity": "Critical",
                        "confidence": "高",
                        "evidence": f"使用 {username}/{password} 成功登录 ({reason})",
                        "status_code": status,
                        "csrf_used": bool(csrf_field),
                        "method": "default_credential"
                    }
                    findings.append(finding)
                    logger.warning(f"🚨 发现默认凭证: {username}/{password} @ {login_url}")
                    break  # 成功登录后不再测试该入口的其他凭证

            except Exception as e:
                logger.debug(f"尝试 {login_url} 失败: {e}")

    return findings


__all__ = [
    'IDORScanner',
    'scan_idor',
    'scan_vertical_privilege',
    'check_default_credentials',
]
