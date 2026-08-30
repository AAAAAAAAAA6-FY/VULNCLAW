# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/context.py
"""扫描上下文 - 精简版 v2.7"""
import asyncio
import time
import re
import json
import os
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict
from urllib.parse import urlparse, urljoin

from vulnclaw.core.logger import logger

MAX_STORED_RESPONSE = 50000
MAX_RESPONSES = 500
MAX_ROLE_RESPONSES = 10


class ScanContext:
    """扫描上下文 - 带 LRU 限制的响应存储"""

    def __init__(self):
        self._lock = asyncio.Lock()
        self.url_graph: Dict[str, Set[str]] = defaultdict(set)
        self.param_index: Dict[str, Set[str]] = defaultdict(set)
        self._responses = {}
        self._max_responses = MAX_RESPONSES
        self.responses = self._responses
        self.subdomains: List[str] = []
        self.sensitive_leaks: List[Dict] = []
        self.interesting_endpoints: Set[str] = set()
        self.normal_responses: Dict[str, Tuple[int, str, Dict]] = {}
        self.normal_response_timestamps: Dict[str, float] = {}
        self.history_vuln_counts: Dict[str, int] = defaultdict(int)
        self._priority_cache: Dict[str, float] = {}
        self.review_clues: List[Dict] = []
        self._clue_id_counter: int = 0
        self._ai_test_guides: Dict[str, Dict] = {}
        self.scanned_urls: Set[str] = set()
        self.total_urls: int = 0
        self.tech_stack: List[str] = []
        self.verified_vulns: List[Dict] = []
        self.suspected_vulns: List[Dict] = []
        self.discovered_apis: List[str] = []
        self.burp_issues: List[Dict] = []
        self.burp_history: List[Dict] = []
        self.browser_attack_surfaces: List[Dict] = []
        # 角色响应存储（用于0day检测）
        self._role_responses: Dict[str, Dict[str, str]] = {}
        self._max_role_responses_per_url = MAX_ROLE_RESPONSES
        self._enable_0day = os.getenv("ENABLE_0DAY_DETECTION", "true").lower() == "true"

    async def add_response(self, url: str, status: int, text: str, headers: Dict, role: str = "") -> None:
        """添加响应 - 自动收集角色响应"""
        original_len = len(text)
        if len(text) > MAX_STORED_RESPONSE:
            text = text[:MAX_STORED_RESPONSE] + f"\n... [响应体过大（原始 {original_len} 字符，已截断至 {MAX_STORED_RESPONSE} 字符]"

        async with self._lock:
            # LRU 淘汰
            if len(self._responses) >= self._max_responses:
                oldest = next(iter(self._responses))
                del self._responses[oldest]
            self._responses[url] = {
                "status": status,
                "text": text,
                "headers": headers,
                "role": role,
                "timestamp": time.time()
            }
            self._extract_links(url, text)
            self._extract_params(url)
            self._extract_sensitive(text, url)

            # 自动收集角色响应（用于0day检测）
            if role and self._enable_0day and status == 200:
                await self._store_role_response_internal(role, url, text)

    async def _store_role_response_internal(self, role: str, url: str, response_text: str):
        if not self._enable_0day:
            return
        if len(response_text) > MAX_STORED_RESPONSE:
            response_text = response_text[:MAX_STORED_RESPONSE] + "\n... [响应体过大，已截断]"

        if url not in self._role_responses:
            self._role_responses[url] = {}
        if len(self._role_responses[url]) < self._max_role_responses_per_url:
            self._role_responses[url][role] = response_text

    def get_response(self, url: str) -> Optional[Dict]:
        return self._responses.get(url)

    def get_normal_response(self, url: str, force_refresh: bool = False) -> Optional[Tuple[int, str, Dict]]:
        if force_refresh:
            return None
        if url in self.normal_responses:
            if time.time() - self.normal_response_timestamps.get(url, 0) < 60:
                return self.normal_responses[url]
        return None

    async def set_normal_response(self, url: str, status: int, text: str, headers: Dict) -> None:
        if len(text) > MAX_STORED_RESPONSE:
            text = text[:MAX_STORED_RESPONSE] + "\n... [响应体过大，已截断]"
        async with self._lock:
            self.normal_responses[url] = (status, text, headers)
            self.normal_response_timestamps[url] = time.time()

    def _extract_links(self, base_url: str, html: str) -> None:
        hrefs = re.findall(r'(?:href|src)=["\']([^"\']+)["\']', html)
        for link in hrefs:
            if link.startswith(('http://', 'https://')):
                full = link
            else:
                full = urljoin(base_url, link)
            if full.startswith(('http://', 'https://')):
                self.url_graph[base_url].add(full)

    def _extract_params(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    name = param.split('=')[0]
                    self.param_index[url].add(name)

    def _extract_sensitive(self, text: str, source: str) -> None:
        patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'1[3-9]\d{9}',
            'ipv4_internal': r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
            'password_hash': r'[a-f0-9]{32,64}',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'jwt': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            'private_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'api_key': r'(?:api[_-]?key|apikey|API_KEY)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
        }
        for label, pattern in patterns.items():
            matches = re.findall(pattern, text, re.I)
            if matches:
                for match in set(matches[:3]):
                    if match:
                        self.sensitive_leaks.append({
                            "source": source,
                            "type": label,
                            "value": match[:100],
                            "context": text[:200],
                            "timestamp": time.time()
                        })

    def _flatten_keys(self, obj: Any, prefix: str = "", max_depth: int = 10, max_chars: int = 100000) -> Set[str]:
        """递归展开JSON对象的所有键 - 修复：增加深度到10"""
        keys = set()
        if max_depth <= 0:
            return keys
        try:
            obj_str = str(obj)
            if len(obj_str) > max_chars:
                logger.debug(f"⚠️ JSON 对象过大 ({len(obj_str)} 字符)，跳过递归解析")
                return keys
        except BaseException:
            return keys

        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else k
                keys.add(full_key)
                if isinstance(v, (dict, list)):
                    keys.update(self._flatten_keys(v, full_key, max_depth - 1, max_chars))
                elif isinstance(v, str) and len(v) < max_chars:
                    try:
                        parsed = json.loads(v)
                        if isinstance(parsed, (dict, list)):
                            keys.update(self._flatten_keys(parsed, full_key, max_depth - 1, max_chars))
                    except BaseException:
                        pass
        elif isinstance(obj, list):
            for i, item in enumerate(obj[:100]):
                if isinstance(item, (dict, list)):
                    keys.update(self._flatten_keys(item, prefix, max_depth - 1, max_chars))
                elif isinstance(item, str) and len(item) < max_chars:
                    try:
                        parsed = json.loads(item)
                        if isinstance(parsed, (dict, list)):
                            keys.update(self._flatten_keys(parsed, prefix, max_depth - 1, max_chars))
                    except BaseException:
                        pass
        return keys

    async def find_anomalous_fields(self) -> List[Dict]:
        """
        检测越权字段（0day检测）
        修复：增加深度到10，扩充关键词
        """
        if not self._enable_0day or not self._role_responses:
            return []

        async with self._lock:
            snapshot = dict(self._role_responses)

        sensitive_keywords = [
            # 权限相关
            'admin', 'secret', 'token', 'credit', 'password',
            'role', 'privilege', 'permission', 'root', 'superuser',
            'is_admin', 'can_delete', 'can_edit', 'owner', 'manager',
            'moderator', 'supervisor', 'executive', 'director',
            'is_staff', 'is_superuser', 'user_type', 'member_type',
            'access_level', 'clearance', 'rank', 'grade', 'level',
            'auth', 'authorized', 'can_approve', 'can_reject',
            'can_view_all', 'can_manage', 'system_role',
            'role_id', 'permission_id', 'privilege_id', 'group_id',
            'is_verified', 'is_active', 'is_locked', 'is_banned',
            'can_access', 'can_write', 'can_read', 'can_execute',
            'is_owner', 'is_creator', 'is_member', 'is_moderator',
            'scope', 'scopes', 'audience', 'grant', 'granted',
            'sudo', 'su', 'elevated', 'elevated_privileges',
            'bypass', 'override', 'unrestricted', 'full_access'
        ]

        anomalies = []
        for url, roles_data in snapshot.items():
            if len(roles_data) < 2:
                continue

            role_fields = {}
            for role, text in roles_data.items():
                try:
                    data = json.loads(text)
                    if isinstance(data, dict):
                        fields = self._flatten_keys(data, max_depth=10, max_chars=100000)
                    elif isinstance(data, list) and data and isinstance(data[0], dict):
                        fields = self._flatten_keys(data[0], max_depth=10, max_chars=100000)
                    else:
                        fields = set()
                except BaseException:
                    fields = set(re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:', text[:10000]))
                role_fields[role] = fields

            all_roles = list(role_fields.keys())
            if len(all_roles) >= 2:
                admin_role = None
                for role in all_roles:
                    role_lower = role.lower()
                    if any(kw in role_lower for kw in ['admin', 'root', 'superuser', 'manager']):
                        admin_role = role
                        break
                if admin_role is None:
                    admin_role = all_roles[0]
                    logger.debug(f"⚠️ 未找到 admin 角色，使用 '{admin_role}' 作为高权限角色")

                high_role = admin_role
                low_roles = [r for r in all_roles if r != high_role]
                high_fields = role_fields.get(high_role, set())
                low_fields_union = set()
                for r in low_roles:
                    low_fields_union.update(role_fields.get(r, set()))

                suspicious = high_fields - low_fields_union
                for field in suspicious:
                    field_lower = field.lower()
                    matched_keywords = [kw for kw in sensitive_keywords if kw in field_lower]
                    if matched_keywords:
                        high_keywords = ['admin', 'root', 'secret', 'password', 'credit', 'sudo', 'superuser']
                        mid_keywords = ['privilege', 'permission', 'role', 'can_delete', 'scope', 'grant']

                        if any(kw in field_lower for kw in high_keywords):
                            risk = "Critical"
                        elif any(kw in field_lower for kw in mid_keywords):
                            risk = "High"
                        else:
                            risk = "Medium"

                        anomalies.append({
                            "url": url,
                            "field": field,
                            "risk": risk,
                            "matched_keywords": matched_keywords[:3],
                            "suggestion": f"检查低权限用户是否可通过修改参数获取 '{field}' 字段",
                            "confidence": "高" if risk == "Critical" else "中"
                        })
        return anomalies

    async def store_role_response(self, role: str, url: str, response_text: str):
        """存储角色响应（公开接口）"""
        if not self._enable_0day:
            return
        if len(response_text) > MAX_STORED_RESPONSE:
            response_text = response_text[:MAX_STORED_RESPONSE] + "\n... [响应体过大，已截断]"
        async with self._lock:
            if url not in self._role_responses:
                self._role_responses[url] = {}
            if len(self._role_responses[url]) < self._max_role_responses_per_url:
                self._role_responses[url][role] = response_text

    def get_role_responses(self, url: str = None) -> Dict:
        if url:
            return self._role_responses.get(url, {})
        return self._role_responses

    def clear_role_responses(self):
        self._role_responses.clear()

    async def add_review_clue(
        self,
        clue_type: str,
        url: str,
        params: Optional[Dict[str, str]] = None,
        evidence: str = "",
        priority: str = "medium",
        suggestion: str = "",
        raw_data: Optional[Dict] = None
    ) -> int:
        async with self._lock:
            priority = priority or "medium"
            for existing in self.review_clues:
                if existing.get('url') == url and existing.get('type') == clue_type:
                    priority_order = {'high': 0, 'medium': 1, 'low': 2}
                    current_priority = existing.get('priority', 'medium') or 'medium'
                    if priority_order.get(priority, 1) < priority_order.get(current_priority, 1):
                        existing['priority'] = priority
                        existing['evidence'] = evidence or existing['evidence']
                        existing['suggestion'] = suggestion or existing['suggestion']
                        existing['raw'] = raw_data or existing.get('raw', {})
                    return existing['id']
            self._clue_id_counter += 1
            clue = {
                'id': self._clue_id_counter,
                'type': clue_type,
                'url': url,
                'params': params or {},
                'evidence': evidence,
                'priority': priority,
                'suggestion': suggestion,
                'raw': raw_data or {},
                'timestamp': time.time()
            }
            self.review_clues.append(clue)
            return clue['id']

    async def get_review_clues_sorted(self) -> List[Dict]:
        async with self._lock:
            priority_order = {'high': 0, 'medium': 1, 'low': 2}
            return sorted(
                self.review_clues,
                key=lambda x: (priority_order.get(x.get('priority', 'medium') or 'medium', 1), x.get('timestamp', 0))
            )

    async def get_review_clues_by_priority(self, priority: str) -> List[Dict]:
        async with self._lock:
            return [c for c in self.review_clues if c.get('priority') == priority]

    def clear_review_clues(self) -> None:
        self.review_clues.clear()
        self._clue_id_counter = 0

    def mark_scanned(self, url: str) -> None:
        self.scanned_urls.add(url)

    def is_scanned(self, url: str) -> bool:
        return url in self.scanned_urls

    def get_progress(self) -> float:
        if self.total_urls <= 0:
            return 0.0
        return len(self.scanned_urls) / self.total_urls * 100

    def set_total_urls(self, count: int) -> None:
        self.total_urls = count

    def clear_cache(self) -> None:
        self.normal_responses.clear()
        self.normal_response_timestamps.clear()
        self._priority_cache.clear()

    def get_summary(self) -> Dict:
        links_count = sum(len(v) for v in self.url_graph.values() if isinstance(v, set))
        params_count = sum(len(v) for v in self.param_index.values() if isinstance(v, set))
        return {
            "total_urls": len(self._responses),
            "links_count": links_count,
            "params_count": params_count,
            "sensitive_leaks": len(self.sensitive_leaks),
            "interesting_endpoints": len(self.interesting_endpoints),
            "review_clues_count": len(self.review_clues),
            "review_clues_high": len([c for c in self.review_clues if c.get('priority') == 'high']),
            "review_clues_medium": len([c for c in self.review_clues if c.get('priority') == 'medium']),
            "review_clues_low": len([c for c in self.review_clues if c.get('priority') == 'low']),
            "scanned_urls": len(self.scanned_urls),
            "total_urls": self.total_urls,
            "progress": f"{self.get_progress():.1f}%",
            "tech_stack": self.tech_stack,
            "verified_vulns_count": len(self.verified_vulns),
            "suspected_vulns_count": len(self.suspected_vulns),
            "discovered_apis_count": len(self.discovered_apis),
            "role_responses_count": len(self._role_responses) if self._enable_0day else 0,
            "subdomains_count": len(self.subdomains),
            "0day_detection_enabled": self._enable_0day
        }


_scan_context: Optional[ScanContext] = None


def get_scan_context() -> ScanContext:
    global _scan_context
    if _scan_context is None:
        _scan_context = ScanContext()
    return _scan_context


def reset_scan_context() -> None:
    global _scan_context
    _scan_context = ScanContext()
    logger.info("🔄 扫描上下文已重置")


__all__ = ['ScanContext', 'get_scan_context', 'reset_scan_context']
