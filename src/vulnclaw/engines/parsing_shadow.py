# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""
ParsingShadowEngine —— 解析差异 / 语义分歧检测引擎

侧重点不同于 HPPEngine（专注注入面），本引擎专注"解析语义分歧面"：
  同一参数名不同取值组合 / 分隔符 / 路径变体导致的鉴权、校验旁路（如 403→200）。

两类检测：
  A. 鉴权关键参数语义分歧（check() 参数级）
     当参数名命中鉴权类关键字或参数值为布尔形态时，对比
     "显式否定值"、"显式肯定值" 与 "分歧变体"（同名多值、大小写、类型变体），
     若变体绕过否定值且与肯定值一致 -> 解析分歧旁路信号。

  B. 路径解析分歧（scan() 路径级差分）
     基线 403/404 但路径变体（尾斜杠、重复斜杠、分号参数、大小写、%00 ...）返回
     200 业务页且内容非错误页 -> 路径归一化差异导致防护绕过。

谨慎原则：核心证据是"状态码 + 响应内容双重分歧"，单一状态码变化不算；
所有请求 try/except，异常仅 debug 日志，不 re-raise；宁缺毋滥。
"""

import asyncio
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import async_get
from vulnclaw.engines.base import BaseEngine

__all__ = ['ParsingShadowEngine']


# 鉴权/状态类参数关键字（命中即视为"具鉴权语义"）
_AUTH_KEYWORDS = (
    "admin", "isadmin", "is_admin", "role", "privilege", "super", "permission",
    "level", "verified", "active", "approved", "status", "type", "access",
    "visible", "owner", "auth", "grant", "flag",
)

# 布尔形态取值
_BOOL_VALUE_RE = re.compile(r'^(true|false|0|1|yes|no)$', re.IGNORECASE)

# 错误/拒绝页常见关键词
_ERROR_WORDS = (
    "forbidden", "access denied", "not found", "unauthorized", "blocked",
    "invalid request", "error 403", "error 404", "access denied by policy",
)


class ParsingShadowEngine(BaseEngine):
    """解析差异 / 语义分歧检测引擎。"""

    name: str = "parsing_shadow"
    description: str = "解析差异/语义分歧检测（鉴权参数语义分歧 + 路径归一化分歧）"

    ENABLE_PATH_SCAN: bool = True
    MAX_PARAM_VARIANTS: int = 4
    MAX_PATH_VARIANTS: int = 4
    LENGTH_DIFF_THRESHOLD: float = 0.30
    MIN_MEANINGFUL_LEN: int = 150
    PAUSE: float = 0.05
    REQUESTS_PER_URL_MAX: int = 5

    # ------------------------------------------------------------
    # 公共接口
    # ------------------------------------------------------------
    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        """参数级检测：鉴权关键参数语义分歧。非鉴权参数直接返回 None。"""
        try:
            if not self._is_auth_param(param, parsed_query):
                return None
            await asyncio.sleep(self.PAUSE)
            return await self._check_auth_semantic(url, param, parsed_query, session)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug(f"[parsing_shadow] check 异常: {e}")
            return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        """全局扫描：路径解析分歧差分。"""
        findings: List[Dict] = []
        try:
            if getattr(self, "ENABLE_PATH_SCAN", True):
                each = await self._check_path_normalization(target, session)
                if each:
                    findings.append(each)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug(f"[parsing_shadow] scan 异常: {e}")
        return findings

    # ------------------------------------------------------------
    # A. 鉴权参数语义分歧
    # ------------------------------------------------------------
    def _is_auth_param(self, param: str, parsed_query: str) -> bool:
        pname = (param or "").strip().lower()
        if any(kw in pname for kw in _AUTH_KEYWORDS):
            return True
        val = self._first_param_value(parsed_query, param)
        return bool(val) and bool(_BOOL_VALUE_RE.match(val.strip().lower()))

    def _first_param_value(self, query: str, param: str) -> str:
        try:
            qs = parse_qs(query or "")
            vals = qs.get(param)
            return vals[0] if vals else ""
        except Exception:
            return ""

    async def _check_auth_semantic(self, url, param, parsed_query, session) -> Optional[Dict]:
        base_path = self._strip_query(url)

        try:
            other = parse_qs(parsed_query or "")
        except Exception:
            other = {}
        other_pairs = [(k, v) for k, v in self._flatten(other) if k != param]

        # 1. 正向基线：param=true -> 期待 2xx 业务页
        pos = await self._fetch(base_path, [(param, "true")] + other_pairs, session)
        if not pos or not (200 <= pos[0] < 400):
            return None
        # 2. 显式否定值：param=false -> 期待 4xx 拒绝
        neg = await self._fetch(base_path, [(param, "false")] + other_pairs, session)
        if not neg:
            return None
        if not (neg[0] and neg[0] >= 400):
            # 目标不区分真假值（全部 2xx/一致）-> 不报
            return None

        await asyncio.sleep(self.PAUSE)

        # 3. 分歧变体：同名多值 / 大小写 / 类型
        variants = [
            [(param, "true"), (param, "false")],   # 肯定在前、尾部否定被忽略
            [(param, "false"), (param, "true")],   # 否定在前
            [(param, "TRUE")],                     # 大小写
            [(param, "0")],                        # 类型强转（数字 0）
        ][: self.MAX_PARAM_VARIANTS]

        for pairs in variants:
            await asyncio.sleep(self.PAUSE)
            resp = await self._fetch(base_path, pairs + other_pairs, session)
            if not resp:
                continue
            vstatus, vtext = resp[0], resp[1] or ""
            if self._is_divergence(vstatus, vtext, pos, neg):
                return self._build_auth_finding(url, param, pairs, pos, neg, resp)
        return None

    def _is_divergence(self, vstatus, vtext, pos, neg) -> bool:
        """双重分歧：状态码 + 响应内容。单一状态码变化不算。"""
        pos_status = pos[0]
        neg_status, neg_text = neg[0], neg[1]

        # 变体与正向均须为可访问业务响应，否定须为拒绝
        if not (200 <= vstatus < 400):
            return False
        if not (200 <= pos_status < 400):
            return False
        if not (neg_status and neg_status >= 400):
            return False
        if vstatus == neg_status:
            return False

        try:
            diff_neg, _ = self.has_response_diff(neg, (vstatus, vtext, {}), threshold=0.20)
            diff_pos, _ = self.has_response_diff(pos, (vstatus, vtext, {}), threshold=0.25)
        except Exception:
            logger.debug("[parsing_shadow] 差异计算异常（suppressed）")
            diff_neg = diff_pos = False

        len_neg = abs(len(vtext) - len(neg_text or "")) / max(1, len(neg_text or " "))

        # 与"显式否定"明显不同（状态 + 内容/长度），且与"显式肯定"一致
        differs_neg = diff_neg or len_neg > self.LENGTH_DIFF_THRESHOLD
        consistent_pos = vstatus == pos_status and not diff_pos
        return differs_neg and consistent_pos

    def _build_auth_finding(self, url, param, variant_pairs, pos, neg, resp) -> Dict:
        vstatus, vtext = resp[0], resp[1]
        neg_status, neg_text = neg[0], neg[1]
        variant_query = urlencode(variant_pairs, doseq=True)
        return {
            "type": "parsing_shadow_auth_semantic_divergence",
            "severity": "medium",
            "title": "鉴权/状态参数存在解析语义分歧，可致权限校验旁路",
            "description": (
                f"参数 {param} 用于鉴权/状态判定，但针对相同取值的'显式否定'（HTTP {neg_status}）"
                f"与'形态变体'（HTTP {vstatus}）返回了不同的授权结果：变体 {variant_query} "
                f"绕过了否定值约束，表明服务端采用 first/last/大小写/类型强转等非规范化解析规则，"
                f"权限校验可被欺骗。"
            ),
            "remediation": "对鉴权/状态类参数实施严格白名单校验（仅接受精确枚举值），"
                           "规范化同名多值与形态变体，并统一单一取值规则",
            "recommendation": f"审查参数解析层：同一参数 {param} 多值应拒绝或明确合并；"
                              f"布尔/类型变体应规范化为单一枚举后再做权限判定",
            "url": url,
            "parameter": param,
            "evidence": (
                f"variants={variant_query} status={neg_status}->{vstatus}; "
                f"负（{neg_status}，{len(neg_text or '')}B）→ 变体（{vstatus}，{len(vtext or '')}B）；"
                f"与肯定态一致、与否定态差异明显"
            ),
            "confidence": "medium",
            "method": "GET",
            "cvss": 5.0,
        }

    # ------------------------------------------------------------
    # B. 路径解析分歧
    # ------------------------------------------------------------
    async def _check_path_normalization(self, target, session) -> Optional[Dict]:
        parsed = urlparse(target)
        path = parsed.path or "/"
        base_wo_q = urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, "", parsed.fragment))

        await asyncio.sleep(self.PAUSE)
        baseline = await self._fetch(base_wo_q, [], session)
        if not baseline:
            return None
        base_status, base_text = baseline[0], baseline[1] or ""
        # 仅当基线为 403/404 等拒绝才判定
        if not (base_status and base_status >= 400):
            return None

        variants = self._path_variants(path)[: self.MAX_PATH_VARIANTS]
        for vpath in variants:
            await asyncio.sleep(self.PAUSE)
            vurl = urlunparse((parsed.scheme, parsed.netloc, vpath, parsed.params, parsed.query, parsed.fragment))
            resp = await self._fetch(vurl, [], session)
            if not resp:
                continue
            vs, vt = resp[0], resp[1] or ""
            if not (200 <= vs < 400):
                continue
            if vs == base_status:
                continue
            # 内容非错误页且足够有意义（业务页）
            if self._looks_like_error(vt):
                continue
            if len(vt) < self.MIN_MEANINGFUL_LEN:
                continue
            severity = "medium" if (base_status in (401, 403, 404) and self._looks_like_error(base_text)) else "low"
            return self._build_path_finding(target, vpath, baseline, resp, severity)
        return None

    def _path_variants(self, path: str) -> List[str]:
        if not path.startswith("/"):
            path = "/" + path
        base = path.rstrip("/")
        variants = {
            base + "/",
            base + "//",
            base + "/;shadow=1",
            base + "%00",
            base.upper(),
        }
        return sorted(variants)

    def _build_path_finding(self, target, vpath, baseline, resp, severity) -> Dict:
        vs, vt = resp[0], resp[1]
        bs = baseline[0]
        return {
            "type": "parsing_shadow_path_normalization_bypass",
            "severity": severity,
            "title": "路径归一化差异导致防护绕过（拒绝→200）",
            "description": (
                f"目标 {target} 基线返回 HTTP {bs}（拒绝），但对路径变体 {vpath} 返回 HTTP {vs} 业务内容，"
                f"表明网关/前端与后端对路径（编码、尾斜杠、重复斜杠、分号参数、大小写、%00）归一化规则不一致，"
                f"可在鉴权/WAF 前置防护下暴露受限资源。"
            ),
            "remediation": "在网关/前端与后端对路径采用一致的归一化（解码、去除 ../、尾斜杠、分号参数、大小写归一）后再鉴权",
            "recommendation": "统一路径解析规则并放在鉴权之前规范化，阻断通过路径变体绕过防护",
            "url": target,
            "parameter": "",
            "evidence": f"status {bs}->{vs}; variant={vpath}; len {len(baseline[1] or '')}->{len(vt or '')}B; 内容非错误页",
            "confidence": "medium" if severity == "medium" else "low",
            "method": "GET",
            "cvss": 5.0 if severity == "medium" else 3.5,
        }

    # ------------------------------------------------------------
    # 工具
    # ------------------------------------------------------------
    def _looks_like_error(self, text: str) -> bool:
        t = (text or "").lower()
        return any(w in t for w in _ERROR_WORDS)

    def _strip_query(self, url: str) -> str:
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))

    @staticmethod
    def _flatten(qs_dict: Dict) -> List[Tuple[str, str]]:
        pairs: List[Tuple[str, str]] = []
        for key, vals in qs_dict.items():
            for v in vals:
                pairs.append((key, v))
        return pairs

    async def _fetch(self, base_path: str, pairs: List[Tuple[str, str]], session) -> Optional[Tuple[int, str, Dict]]:
        qs = urlencode(pairs, doseq=True) if pairs else ""
        full = f"{base_path}?{qs}" if qs else base_path
        try:
            resp = await async_get(full, session=session, timeout=10, no_retry=True)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug(f"[parsing_shadow] 请求异常 {full}: {e}")
            return None
        if not isinstance(resp, tuple) or len(resp) < 2:
            return None
        status = resp[0]
        text = resp[1] if resp[1] else ""
        headers = resp[2] if len(resp) > 2 else {}
        return status, text, headers