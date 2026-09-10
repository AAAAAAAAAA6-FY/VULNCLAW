# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""声明执行器：按 VulnSpec 声明驱动探测（一套代码跑所有声明）。

流程：
    请求 spec -> 枚举可控点 -> (声明 × 点 × payload) -> 渲染注入 -> 发送 -> oracle 判定

关键：执行器**不认识任何具体漏洞类型**，它只认识四类 oracle
（regex / reflect / time / diff）。漏洞知识全在声明里。
"""
from __future__ import annotations

from dataclasses import replace

import difflib
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from vulnclaw.core.attack_surface import enumerate_points, render
from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get, async_post

from .builtin import BUILTIN_SPECS
from .model import (DETECT_DIFF, DETECT_HEADER, DETECT_REFLECT, DETECT_REGEX,
                    DETECT_TIME, VulnSpec)


class SpecRunner:
    """声明驱动执行器。"""

    def __init__(
        self,
        specs: Optional[List[VulnSpec]] = None,
        session=None,
        requester: Optional[Callable[..., Any]] = None,
        timeout: int = 10,
    ):
        self.specs = list(specs) if specs is not None else list(BUILTIN_SPECS)
        self.session = session
        self.requester = requester
        self.timeout = timeout

    # ------------------------------------------------------------------
    async def run(
        self,
        spec,
        points=None,
        specs: Optional[List[VulnSpec]] = None,
        budget: Optional[int] = None,
    ) -> List[Dict]:
        """对一个请求的所有可控点执行声明，返回 findings。"""
        if points is None:
            points = enumerate_points(spec)
        points = list(points)
        if not points:
            return []

        max_requests = int(
            budget or getattr(settings, "vulnspec_request_budget", 60) or 60
        )
        used = 0

        base_resp, base_elapsed = await self._send(spec)
        used += 1
        baseline = (base_resp[0] if isinstance(base_resp, tuple) else 0,
                    base_resp[1] if isinstance(base_resp, tuple) else "")

        out: List[Dict] = []
        seen = set()
        for decl in (specs or self.specs):
            if not decl.enabled or used >= max_requests:
                continue
            for point in points:
                if used >= max_requests:
                    break
                loc = getattr(getattr(point, "location", None), "value",
                              str(getattr(point, "location", "")))
                if not decl.applies_to(loc, str(point.name)):
                    continue
                for payload in list(decl.payloads)[: decl.max_payloads]:
                    if used >= max_requests:
                        break
                    mutated = render(spec, point, payload)
                    if decl.request_headers:
                        hdrs = dict(mutated.headers)
                        hdrs.update(dict(decl.request_headers))
                        mutated = replace(mutated, headers=hdrs)
                    resp, elapsed = await self._send(mutated)
                    used += 1
                    if not isinstance(resp, tuple) or len(resp) < 2:
                        continue
                    status, text = resp[0], resp[1] or ""
                    resp_headers = resp[2] if len(resp) > 2 and isinstance(resp[2], dict) else {}
                    hit, evidence = self._judge(decl, payload, (status, text),
                                                baseline, elapsed - base_elapsed,
                                                resp_headers)
                    if not hit:
                        continue
                    key = (decl.id, point.label())
                    if key in seen:
                        break
                    seen.add(key)
                    out.append(self._finding(decl, point, payload, mutated,
                                             status, evidence, loc))
                    break  # 该点已命中，换下一个点
        return out

    # ------------------------------------------------------------------
    def _judge(
        self,
        decl: VulnSpec,
        payload: str,
        resp: Tuple[int, str],
        baseline: Tuple[int, str],
        delta_t: float,
        headers: Optional[Dict] = None,
    ) -> Tuple[bool, str]:
        """按声明的 oracle 判定（执行器唯一"认识"漏洞语义的地方，且是通用四类）。"""
        rule = decl.detect
        status, text = resp
        kind = rule.type

        # 上下文约束：如 XSS 要求 HTML 响应（JSON 回显不执行，判了就是误报）
        if rule.require_content_type:
            ctype = ""
            for k, v in (headers or {}).items():
                if str(k).lower() == "content-type":
                    ctype = str(v)
                    break
            if rule.require_content_type.lower() not in ctype.lower():
                return False, ""

        if kind == DETECT_REGEX:
            for pat in rule.compiled():
                m = pat.search(text or "")
                if bool(m) != bool(rule.negative):
                    if rule.negative:
                        return False, ""
                    snippet = (text[max(0, m.start() - 30): m.end() + 30]).replace("\n", " ")
                    return True, f"响应命中特征 {pat.pattern!r}: ...{snippet}..."
            return rule.negative, ("（未命中负向特征）" if rule.negative else "")

        if kind == DETECT_REFLECT:
            core = str(rule.extra.get("core") or payload)
            base_text = baseline[1] or ""
            # 基线里已存在的字符串不算反射（避免把正常回显当漏洞）
            if core in (text or "") and core not in base_text:
                # 转义检查：core 虽出现，但 HTML 元字符已被转义 -> 不可执行，不算漏洞
                if self._is_html_escaped(payload, text):
                    return False, ""
                return True, f"载荷核心 {core!r} 出现在响应中（基线中不存在）"
            return False, ""

        if kind == DETECT_TIME:
            if delta_t >= rule.threshold:
                return True, f"相对基线延时 {delta_t:.2f}s >= 阈值 {rule.threshold}s"
            return False, ""

        if kind == DETECT_DIFF:
            ratio = self._diff_ratio(baseline[1] or "", text or "")
            if ratio >= (rule.threshold or 0.3):
                return True, f"响应与基线差异 {ratio:.0%} >= 阈值 {rule.threshold or 0.3:.0%}"
            return False, ""

        if kind == DETECT_HEADER:
            def _hval(name: str) -> str:
                for k, v in (headers or {}).items():
                    if str(k).lower() == name.lower():
                        return str(v)
                return ""

            if rule.header_absent:
                if rule.header_name and not _hval(rule.header_name):
                    return True, f"响应缺失安全头 {rule.header_name}"
                return False, ""
            target = (_hval(rule.header_name) if rule.header_name
                      else "\n".join(f"{k}: {v}" for k, v in (headers or {}).items()))
            for pat in rule.compiled():
                if pat.search(target or ""):
                    return True, (f"响应头 {rule.header_name or '*'} 命中 {pat.pattern!r}"
                                  f"：{target[:60]}")
            return False, ""

        return False, ""

    # ------------------------------------------------------------------
    async def _send(self, spec) -> Tuple[Any, float]:
        """发送请求并测量耗时（供 time 型 oracle 使用）。"""
        start = time.perf_counter()
        try:
            if self.requester is not None:
                resp = await self.requester(spec)
            else:
                kw = spec.to_send_kwargs()
                if str(spec.method).upper() == "GET":
                    resp = await async_get(spec.url, session=self.session,
                                           headers=kw.get("headers"),
                                           timeout=self.timeout, no_retry=True)
                else:
                    resp = await async_post(spec.url, session=self.session,
                                            timeout=self.timeout, no_retry=True, **kw)
        except Exception as exc:  # noqa: BLE001 - 单请求失败不阻断
            logger.debug(f"vulnspec 请求失败: {exc}")
            resp = (0, "", {})
        return resp, time.perf_counter() - start

    @staticmethod
    def _is_html_escaped(payload: str, text: str) -> bool:
        """判断反射内容是否已被 HTML 转义（转义后不可执行，不算漏洞）。

        典型误报：站点正确地把 `<` 转成 `&lt;`，响应里仍能搜到 payload 的"核心词"，
        但它不会被执行——此时若只做字符串匹配就会误报 XSS。
        """
        if not payload or not text:
            return False
        if not any(ch in payload for ch in ("<", ">", '"', "'")):
            return False  # 载荷本身不含 HTML 元字符，无需转义判断
        low = text.lower()
        # payload 原样出现 -> 未被转义（可执行）
        if payload.lower() in low:
            return False
        # 只有转义实体版本出现 -> 已转义（不可执行）
        escaped_variant = (payload.replace("&", "&amp;").replace("<", "&lt;")
                                  .replace(">", "&gt;").replace('"', "&quot;"))
        return escaped_variant.lower() in low

    @staticmethod
    def _diff_ratio(a: str, b: str) -> float:
        if not a and not b:
            return 0.0
        la, lb = max(1, len(a)), max(1, len(b))
        length_part = abs(lb - la) / la * 0.35
        if la > 50 and lb > 50:
            wa, wb = set(a.split()), set(b.split())
            content = 0.0
            if wa and wb:
                union = wa | wb
                if union:
                    content = 1 - len(wa & wb) / len(union)
        else:
            content = 1.0 - difflib.SequenceMatcher(None, a, b).ratio()
        return min(1.0, length_part + content * 0.6)

    @staticmethod
    def _finding(decl, point, payload, mutated_spec, status, evidence, loc) -> Dict:
        return {
            "url": mutated_spec.url,
            "type": decl.id,
            "title": decl.name,
            "category": decl.category,
            "severity": decl.severity,
            "cvss": decl.cvss,
            "confidence": decl.confidence,
            "parameter": point.label(),
            "payload": payload,
            "evidence": f"{point.label()} 注入 {payload!r} -> HTTP {status}；{evidence}",
            "description": (
                f"按声明 `{decl.id}`（{decl.name}）在可控点 `{point.label()}` 注入载荷后，"
                f"oracle 判定命中：{evidence}"
            ),
            "remediation": decl.remediation,
            "recommendation": decl.recommendation,
            "method": f"vulnspec:{decl.id}",
            "point_location": loc,
        }


__all__ = ["SpecRunner"]
