# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/v100/local_filter.py
"""
本地规则引擎 - 0成本预筛选
修复：阈值改为从 settings 读取
"""

import re

from vulnclaw.core.settings import settings
from typing import Dict, Optional, Tuple


class LocalFilter:
    """
    本地预筛选规则
    - 不需要API调用
    - 快速过滤明显无漏洞的情况
    - 减少80%的AI调用
    """

    def __init__(self):
        self._stats = {
            "total_checked": 0,
            "skipped": 0,
            "passed": 0,
            "direct_findings": 0
        }

        # 从 settings 读取阈值
        self._min_interval = getattr(settings, 'filter_min_interval', 10)
        self._skip_threshold = getattr(settings, 'filter_skip_threshold', 50)

        # 静态资源扩展名
        self._static_extensions = {
            '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4', '.webp',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar', '.gz',
            '.json', '.xml', '.yaml', '.yml',
            '.txt', '.csv', '.tsv', '.log',
            '.ico', '.webmanifest', '.map',
            '.min.js', '.min.css'
        }

        # 非攻击参数
        self._safe_params = {
            'callback', '_', 'timestamp', 'nonce', 'version', 'format',
            'cors', 't', 'v', 'ver', 'ts', 'time', 'rand', 'random',
            'session', 'token', 'csrf', 'authenticity_token', 'utf8',
            'limit', 'offset', 'per_page', 'page_size'
        }

        # 盲注豁免参数（这些参数即使响应很短也不跳过）
        self._blind_params = {
            'id', 'user', 'uid', 'uuid', 'guid', 'page', 'file', 'path',
            'order', 'order_id', 'invoice', 'invoice_id', 'account', 'account_id',
            'profile', 'profile_id', 'product', 'product_id', 'customer', 'customer_id',
            'email', 'username', 'login', 'name', 'key', 'token'
        }

        # 盲注响应特征
        self._blind_response_patterns = {
            'true': r'^(true|yes|1|ok|success|valid|exist)$',
            'false': r'^(false|no|0|error|invalid|not exist|fail)$',
        }

        # SQL错误模式
        self._sql_error_patterns = [
            r'SQL syntax.*?error',
            r'You have an error in your SQL syntax',
            r'Unclosed quotation mark',
            r'Microsoft OLE DB Provider for ODBC Drivers',
            r'MySQLSyntaxErrorException',
            r'PostgreSQL.*?ERROR',
            r'SQLite error',
            r'ORA-\d{5}',
            r'Warning: mysql_',
            r'Invalid query',
            r'Database error',
            r'SQLSTATE',
            r'ODBC Driver',
            r'DB2 SQL Error',
            r'SQL Server.*?Error',
        ]
        self._sql_error_re = re.compile('|'.join(self._sql_error_patterns), re.IGNORECASE)

        # XSS模式
        self._xss_patterns = [
            r'<script>',
            r'alert\s*\(',
            r'onerror\s*=',
            r'onload\s*=',
            r'onclick\s*=',
            r'javascript:',
            r'<img[^>]+onerror',
            r'<svg[^>]+onload',
            r'<iframe[^>]+src=javascript',
            r'<body[^>]+onload',
        ]
        self._xss_re = re.compile('|'.join(self._xss_patterns), re.IGNORECASE)

        # 敏感文件内容模式
        self._sensitive_patterns = [
            r'root:x:0:0:',
            r'\[boot loader\]',
            r'\[operating systems\]',
            r'DB_PASSWORD',
            r'SECRET_KEY',
            r'APP_KEY',
            r'-----BEGIN.*?PRIVATE KEY-----',
            r'AKIA[0-9A-Z]{16}',
            r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            r'gh[pousr]_[A-Za-z0-9]{36}',
            r'sk-[a-zA-Z0-9]{20,}',
        ]
        self._sensitive_re = re.compile('|'.join(self._sensitive_patterns), re.IGNORECASE)

        # 错误页面模式
        self._error_page_patterns = [
            r'404 Not Found',
            r'403 Forbidden',
            r'Access Denied',
            r'Page not found',
            r'页面不存在',
            r'访问被拒绝',
            r'Unauthorized',
            r'Authentication required',
            r'Permission denied',
        ]

        # 盲注关键词
        self._blind_keywords = ['true', 'false', 'yes', 'no', '1', '0', 'ok', 'error']

    def should_skip(self, url: str, param: str, response_text: str = "", status_code: int = 0) -> Tuple[bool, str]:
        """
        判断是否跳过这个参数的AI分析
        返回 (should_skip, reason)
        """
        self._stats["total_checked"] += 1

        # 1. 静态资源跳过
        url_lower = url.lower()
        for ext in self._static_extensions:
            if url_lower.endswith(ext):
                self._stats["skipped"] += 1
                return True, f"静态资源 ({ext})"

        # 2. 参数名明显不相关
        param_lower = param.lower()
        if param_lower in self._safe_params:
            self._stats["skipped"] += 1
            return True, f"非攻击参数 ({param})"

        # 3. 短响应处理（盲注豁免）
        if response_text and len(response_text) < self._skip_threshold:
            is_blind_param = any(p in param_lower for p in self._blind_params)
            if is_blind_param:
                self._stats["passed"] += 1
                return False, f"盲注候选参数 ({param})"

            if response_text:
                text_lower = response_text.lower().strip()
                if text_lower in ['true', 'false', 'yes', 'no', '1', '0']:
                    self._stats["passed"] += 1
                    return False, f"盲注响应特征 ({param})"

            self._stats["skipped"] += 1
            return True, "响应体过小（非盲注参数）"

        # 4. 响应体是明确错误页
        if response_text:
            for pattern in self._error_page_patterns:
                if pattern.lower() in response_text.lower():
                    self._stats["skipped"] += 1
                    return True, f"错误页面 ({pattern})"

        # 5. 状态码 4xx 跳过优化
        if status_code:
            is_blind_param = any(p in param_lower for p in self._blind_params)
            if status_code in (401, 403) and is_blind_param:
                self._stats["passed"] += 1
                return False, f"越权候选 ({status_code}, {param})"

            if 400 <= status_code < 500 and status_code not in (401, 403):
                self._stats["skipped"] += 1
                return True, f"状态码 {status_code}"

        # 6. 无参数URL跳过
        if '?' not in url and not param:
            self._stats["skipped"] += 1
            return True, "无参数"

        self._stats["passed"] += 1
        return False, "需要分析"

    def quick_rule_check(self, param: str, response: str, url: str = "") -> Optional[Dict]:
        """
        快速规则检查 - 发现明显的漏洞迹象
        不需要AI调用，直接返回结果
        返回 None 表示未发现，返回 Dict 表示发现明显漏洞
        """
        if not response:
            return None

        response_lower = response.lower()

        # 盲注特征检测（短响应）
        if len(response) < self._skip_threshold:
            stripped = response_lower.strip()
            if stripped in ('true', 'false', 'yes', 'no', '1', '0'):
                return {
                    "type": f"盲注特征 ({stripped})",
                    "severity": "High",
                    "confidence": "高（规则检测）",
                    "evidence": f"响应为 '{stripped}'，可能为布尔盲注",
                    "parameter": param,
                    "url": url,
                    "method": "boolean_blind",
                    "source": "local_filter"
                }

        # 1. SQL错误特征
        if self._sql_error_re.search(response):
            self._stats["direct_findings"] += 1
            evidence = self._extract_evidence(response, self._sql_error_re)
            return {
                "type": "SQL注入",
                "severity": "High",
                "confidence": "高（规则检测）",
                "evidence": f"检测到SQL错误: {evidence}",
                "parameter": param,
                "url": url,
                "method": "error_based",
                "source": "local_filter"
            }

        # 2. XSS特征
        if self._xss_re.search(response):
            self._stats["direct_findings"] += 1
            evidence = self._extract_evidence(response, self._xss_re)
            return {
                "type": "XSS跨站脚本",
                "severity": "High",
                "confidence": "高（规则检测）",
                "evidence": f"检测到XSS特征: {evidence}",
                "parameter": param,
                "url": url,
                "method": "reflected",
                "source": "local_filter"
            }

        # 3. 敏感信息泄露
        if self._sensitive_re.search(response):
            self._stats["direct_findings"] += 1
            evidence = self._extract_evidence(response, self._sensitive_re)
            return {
                "type": "敏感信息泄露",
                "severity": "Critical",
                "confidence": "高（规则检测）",
                "evidence": f"检测到敏感信息: {evidence}",
                "parameter": param,
                "url": url,
                "method": "disclosure",
                "source": "local_filter"
            }

        return None

    def _extract_evidence(self, response: str, pattern: re.Pattern) -> str:
        """提取匹配证据"""
        match = pattern.search(response)
        if match:
            match.group(0)
            start = max(0, match.start() - 30)
            end = min(len(response), match.end() + 30)
            context = response[start:end].replace('\n', ' ')
            if len(context) > 100:
                context = context[:100] + "..."
            return context
        return response[:100]

    def get_stats(self) -> Dict:
        """获取统计信息"""
        total = self._stats["total_checked"]
        return {
            **self._stats,
            "skip_rate": f"{self._stats['skipped'] / max(1, total) * 100:.1f}%",
            "direct_findings": self._stats["direct_findings"],
            "min_interval": self._min_interval,
            "skip_threshold": self._skip_threshold
        }


_local_filter = None


def get_local_filter() -> LocalFilter:
    global _local_filter
    if _local_filter is None:
        _local_filter = LocalFilter()
    return _local_filter


__all__ = ['LocalFilter', 'get_local_filter']
