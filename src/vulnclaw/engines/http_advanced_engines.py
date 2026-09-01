# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/http_advanced_engines.py
"""
进阶 HTTP 逻辑安全引擎组（v104 新增）
CSRFEngine / WebCacheDeceptionEngine
设计原则：只报告可事实取证的现象（缺少 Token 的表单 / 路径混淆+缓存命中），控制误报。
"""
import re
import secrets
from urllib.parse import urlparse, urlunparse
from typing import Dict, List, Optional, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get
from vulnclaw.engines.base import BaseEngine, CaseInsensitiveDict


# ============================================================
# CSRFEngine
# ============================================================
class CSRFEngine(BaseEngine):
    """CSRF 防护缺失检测引擎（scan 型：解析 HTML 表单的 Token 防护）"""

    name = "csrf"
    description = "CSRF 检测引擎（表单缺少 CSRF Token / 状态变更 GET 表单）"

    FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
    INPUT_RE = re.compile(r"<input\b[^>]*>", re.I | re.S)
    NAME_ATTR_RE = re.compile(r"""name\s*=\s*["']([^"']+)["']""", re.I)
    METHOD_ATTR_RE = re.compile(r"""method\s*=\s*["']?([a-z]+)["']?""", re.I)
    ACTION_ATTR_RE = re.compile(r"""action\s*=\s*["']([^"']*)["']""", re.I)

    TOKEN_NAME_RE = re.compile(
        r"(csrf|xsrf|nonce|authenticity|requestverification|midwaretoken|token)",
        re.I,
    )
    STATEFUL_ACTION_RE = re.compile(
        r"(login|logout|register|signup|signin|password|passwd|profile|setting|"
        r"admin|order|pay|cart|checkout|purchase|transfer|withdraw|upload|"
        r"delete|remove|update|edit|subscribe|comment|message|vote|reset)",
        re.I,
    )

    MAX_FINDINGS = 5

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        try:
            resp = await async_get(target, session=session, timeout=settings.timeout, no_retry=True)
            if resp is None:
                return findings
            status, text = resp[0], resp[1] or ""
            if status != 200 or not isinstance(text, str) or "<form" not in text.lower():
                self.log_debug("目标响应无可解析表单（或 JS 渲染），跳过")
                return findings

            seen: set = set()
            form_count = 0
            for form_match in self.FORM_RE.finditer(text):
                form_count += 1
                if form_count > 15 or len(findings) >= self.MAX_FINDINGS:
                    break
                form_tag = form_match.group(0)
                method = "get"
                m = self.METHOD_ATTR_RE.search(form_tag)
                if m:
                    method = (m.group(1) or "get").lower()
                action = ""
                m = self.ACTION_ATTR_RE.search(form_tag)
                if m:
                    action = m.group(1)

                input_names: List[str] = []
                has_token = False
                for input_tag in self.INPUT_RE.findall(form_match.group(1)):
                    m = self.NAME_ATTR_RE.search(input_tag)
                    if not m:
                        continue
                    iname = m.group(1)
                    input_names.append(iname)
                    if self.TOKEN_NAME_RE.match(iname):
                        has_token = True

                if has_token or not input_names:
                    continue

                dedupe_key = (method, action)
                if dedupe_key in seen:
                    continue

                stateful = bool(self.STATEFUL_ACTION_RE.search(action)) if action else None
                if method == "post" or stateful:
                    seen.add(dedupe_key)
                    findings.append({
                        'url': target,
                        'parameter': ','.join(input_names[:10]),
                        'payload': '',
                        'type': 'CSRF防护缺失(表单无Token)',
                        'severity': 'Medium',
                        'ai_verdict': '高',
                        'confidence': 'medium',
                        'evidence': f'{method.upper()} 表单 action="{action}" 未发现 CSRF Token（字段: {", ".join(input_names[:8])}）',
                        'recommendation': '状态变更表单加入随机 CSRF Token（同步器令牌模式）并服务端校验',
                    })
        except Exception as e:
            logger.debug(f"[{self.name}] CSRF 检测异常: {e}")
        return findings

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


# ============================================================
# WebCacheDeceptionEngine
# ============================================================
class WebCacheDeceptionEngine(BaseEngine):
    """Web 缓存欺骗检测引擎（scan 型）

    检测链：路径混淆（动态页被 .css 后缀命中并返回相同内容）+ 缓存证据头。
    两者同时成立才报高危；仅路径混淆报低危提示。
    """

    name = "web_cache_deception"
    description = "Web 缓存欺骗检测引擎（路径混淆 + 缓存命中证据）"

    CONFUSION_LEN_RATIO = 0.25
    MIN_BODY_LEN = 100

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        try:
            resp = await async_get(target, session=session, timeout=settings.timeout, no_retry=True)
            if resp is None:
                return findings
            base_status, base_text = resp[0], resp[1] or ""
            base_headers = CaseInsensitiveDict.from_dict(resp[2]) if len(resp) > 2 else CaseInsensitiveDict()
            if base_status != 200 or not isinstance(base_text, str) or len(base_text) < self.MIN_BODY_LEN:
                self.log_debug("基线响应非稳定 200 页面，跳过")
                return findings

            cache_evidence_base = self._cache_evidence(base_headers)

            marker = "vlcwcd" + secrets.token_hex(4)
            conf_url = self._confusion_url(target, marker)
            resp2 = await async_get(conf_url, session=session, timeout=settings.timeout, no_retry=True)
            if resp2 is None:
                return findings
            conf_status, conf_text = resp2[0], resp2[1] or ""
            conf_headers = CaseInsensitiveDict.from_dict(resp2[2]) if len(resp2) > 2 else CaseInsensitiveDict()

            len_ratio = abs(len(conf_text) - len(base_text)) / max(1, len(base_text)) if isinstance(conf_text, str) else 1.0
            confused = conf_status == 200 and isinstance(conf_text, str) and len_ratio < self.CONFUSION_LEN_RATIO

            if not confused:
                self.log_debug(f"路径混淆未复现（状态 {conf_status}，长度比 {len_ratio:.0%}），跳过")
                return findings

            cache_evidence_conf = self._cache_evidence(conf_headers)

            if cache_evidence_conf:
                findings.append({
                    'url': conf_url,
                    'parameter': '',
                    'payload': f'{marker}.css',
                    'type': 'Web缓存欺骗(路径混淆+缓存命中)',
                    'severity': 'High',
                    'ai_verdict': '高',
                    'confidence': 'high',
                    'evidence': (
                        f'动态内容经 {conf_url} 可被 .css 伪装路径访问（长度比 {len_ratio:.0%}），'
                        f'且响应带缓存证据: {", ".join(cache_evidence_conf)}。'
                        f'基线缓存证据: {", ".join(cache_evidence_base) if cache_evidence_base else "无"}'
                    ),
                    'recommendation': 'URL 路径白名单/规范化处理；对带扩展名请求禁用缓存；CDN 缓存规则排除认证内容',
                })
            else:
                findings.append({
                    'url': conf_url,
                    'parameter': '',
                    'payload': f'{marker}.css',
                    'type': 'Web缓存欺骗-疑似(路径混淆,无缓存头)',
                    'severity': 'Low',
                    'ai_verdict': '中',
                    'confidence': 'low',
                    'evidence': f'动态内容可通过 .css 伪装路径访问（长度比 {len_ratio:.0%}），但未检出缓存命中证据头，请人工确认 CDN/代理缓存行为',
                    'recommendation': '人工确认前端缓存/代理是否缓存此类带扩展名路径',
                })
        except Exception as e:
            logger.debug(f"[{self.name}] 缓存欺骗检测异常: {e}")
        return findings

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

    @staticmethod
    def _confusion_url(target: str, marker: str) -> str:
        parsed = urlparse(target)
        path = parsed.path or "/"
        prefix = path if path.endswith("/") else path + "/"
        new_path = f"{prefix}{marker}.css"
        return urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment))

    @staticmethod
    def _cache_evidence(headers: CaseInsensitiveDict) -> List[str]:
        evidence: List[str] = []
        x_cache = str(headers.get("x-cache", "") or "").lower()
        if x_cache in ("hit", "hit, hit", "hit from cloudfront"):
            evidence.append(f"x-cache:{x_cache}")
        cf = str(headers.get("cf-cache-status", "") or "").lower()
        if cf in ("hit", "dynamic"):
            evidence.append(f"cf-cache-status:{cf}")
        age = str(headers.get("age", "") or "").strip()
        if age.isdigit() and int(age) > 0:
            evidence.append(f"age:{age}")
        cache_control = str(headers.get("cache-control", "") or "").lower()
        if "public" in cache_control and "no-cache" not in cache_control and "no-store" not in cache_control:
            evidence.append(f"cache-control:{cache_control[:40]}")
        return evidence


__all__ = [
    'CSRFEngine',
    'WebCacheDeceptionEngine',
]