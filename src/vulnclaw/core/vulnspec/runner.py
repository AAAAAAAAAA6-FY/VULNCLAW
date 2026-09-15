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

import asyncio
import difflib
import random
import re
import time
from urllib.parse import urlparse
from typing import Any, Callable, Dict, List, Optional, Tuple

from vulnclaw.core.attack_surface import enumerate_points, render, spec_from_url
from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get, async_post

from .builtin import BUILTIN_SPECS
from .model import (DETECT_BIZ, DETECT_COMPONENT, DETECT_DIFF, DETECT_DOM, DETECT_FLOW,
                    DETECT_HEADER, DETECT_IDOR, DETECT_OOB, DETECT_REFLECT, DETECT_REGEX,
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
        # 请求层失败计数（状态 0 = 未拿到响应）。**必须对外可读**：
        # 否则"网络/代理故障"与"目标确实干净"在结果里无法区分——真实目标上会静默全漏。
        self.request_errors = 0

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
        max_requests = int(
            budget or getattr(settings, "vulnspec_request_budget", 60) or 60
        )
        # 有状态 oracle（idor_multisession / flow）：需多次请求或跨身份，单请求循环表达不了 → 单独处理
        idor_out: List[Dict] = []
        for _d in (specs or self.specs):
            _t = getattr(_d.detect, "type", "")
            if not _d.enabled:
                continue
            if _t == DETECT_IDOR:
                _f = await self._probe_idor(spec, _d)
            elif _t == DETECT_FLOW:
                _f = await self._probe_flow(spec, _d)
            elif _t == DETECT_DOM:
                _f = await self._probe_dom_xss(spec, _d)
            elif _t == DETECT_BIZ:
                _f = await self._probe_biz(spec, _d)
            elif _t == DETECT_OOB:
                _f = await self._probe_oob(spec, _d)
            else:
                continue
            if _f:
                idor_out.append(_f)

        if not points:
            # 无可控点端点：仍有声明级 request_headers 的 oracle（CORS / Host 头等）需要探测
            _hdr = await self._probe_header_only(spec, specs=specs, budget=max_requests)
            return idor_out + _hdr
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
            if getattr(decl.detect, "type", "") in (DETECT_IDOR, DETECT_FLOW, DETECT_DOM,
                                                    DETECT_BIZ, DETECT_OOB):
                continue  # 已由 _probe_* 处理
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
                    # 时间型 oracle 在**真实网络**上单次极易误判：远端抖动/首个慢响应
                    # 就能凑出 ≥2s 的"延时"，而真盲注/真 RCE 的延时是确定性的。
                    # 因此要求原地复测一次仍达阈值才认（真实目标实测暴露：2.74s 抖动被当成 Log4Shell）。
                    if hit and getattr(decl.detect, "type", "") == DETECT_TIME:
                        resp2, elapsed2 = await self._send(mutated)
                        used += 1
                        if not isinstance(resp2, tuple) or len(resp2) < 2:
                            hit = False
                        else:
                            hit, evidence = self._judge(
                                decl, payload, (resp2[0], resp2[1] or ""), baseline,
                                elapsed2 - base_elapsed,
                                resp2[2] if len(resp2) > 2 and isinstance(resp2[2], dict) else {})
                    if not hit:
                        continue
                    key = (decl.id, point.label())
                    if key in seen:
                        break
                    seen.add(key)
                    out.append(self._finding(decl, point, payload, mutated,
                                             status, evidence, loc))
                    break  # 该点已命中，换下一个点
        return out + idor_out

    async def _probe_header_only(self, spec, specs=None, budget: int = 60) -> List[Dict]:
        """无可控点端点的 header-oracle 探测（声明级 request_headers，如 CORS / Host 头注入）。"""
        decls = [d for d in (specs or self.specs) if getattr(d, "request_headers", None)]
        if not decls:
            return []
        base_resp, base_elapsed = await self._send(spec)
        baseline = (base_resp[0] if isinstance(base_resp, tuple) else 0,
                    base_resp[1] if isinstance(base_resp, tuple) else "")
        out: List[Dict] = []
        used = 0
        for decl in decls:
            if not decl.enabled or used >= budget:
                continue
            hdrs = dict(spec.headers)
            hdrs.update(dict(decl.request_headers))
            mutated = replace(spec, headers=hdrs)
            resp, elapsed = await self._send(mutated)
            used += 1
            if not isinstance(resp, tuple) or len(resp) < 2:
                continue
            status, text = resp[0], resp[1] or ""
            resp_headers = resp[2] if len(resp) > 2 and isinstance(resp[2], dict) else {}
            hit, evidence = self._judge(decl, "", (status, text), baseline,
                                        elapsed - base_elapsed, resp_headers)
            if hit:
                out.append(self._finding(decl, None, "", mutated, status,
                                         evidence, "<header-oracle>"))
        return out

    # ------------------------------------------------------------------
    async def _probe_idor(self, spec, decl: VulnSpec) -> Optional[Dict]:
        """多身份对比证实对象级越权（IDOR）。

        同一资源分别用"属主"与"非属主"两种身份请求：
          1) 属主身份能读到属主数据 → 确认该资源/数据确实存在；
          2) 非属主身份**也能**读到同一属主数据 → 越权成立（IDOR 证实）。
        只报"两身份都读到属主数据"，天然排除"公开数据"（本就人人可读）与
        "属主都读不到"（数据不存在）两类假象——结论从"单请求线索"升级为"证实"。
        """
        ex = decl.detect.extra or {}
        owner_h = dict(ex.get("owner_headers") or {})
        attacker_h = dict(ex.get("attacker_headers") or {})
        marker = str(ex.get("owner_marker") or "")
        if not marker:
            return None
        base_hdrs = dict(getattr(spec, "headers", {}) or {})
        # 1) 属主身份：确认属主数据存在
        o_spec = replace(spec, headers={**base_hdrs, **owner_h})
        o_resp, _ = await self._send(o_spec)
        o_text = o_resp[1] if isinstance(o_resp, tuple) and len(o_resp) > 1 else ""
        if not re.search(marker, o_text or "", re.IGNORECASE):
            return None
        # 2) 非属主身份：访问同一资源，若仍读到属主数据 → IDOR 证实
        a_spec = replace(spec, headers={**base_hdrs, **attacker_h})
        a_resp, _ = await self._send(a_spec)
        a_text = a_resp[1] if isinstance(a_resp, tuple) and len(a_resp) > 1 else ""
        if re.search(marker, a_text or "", re.IGNORECASE):
            status = a_resp[0] if isinstance(a_resp, tuple) else 0
            ev = (f"多会话比对：属主（{owner_h}）与非属主（{attacker_h}）两种身份均读到"
                  f"属主数据（标记 {marker!r}）→ 对象级越权（IDOR）证实")
            return self._finding(decl, None, "", a_spec, status, ev, "<idor-multisession>")
        return None

    # ------------------------------------------------------------------
    async def _probe_flow(self, spec, decl: VulnSpec) -> Optional[Dict]:
        """多请求流程 oracle（有状态）：先按声明把 payload 写入一个可控点，再回读另一端点，
        对**回读响应**做断言。用于单请求看不见的存储型/二次漏洞：
          · mode=unescaped_reflect：回读响应中 payload 未被 HTML 转义 → 存储型 XSS 证实；
          · mode=regex：回读响应命中特征（如 SQL 报错）→ 二次注入证实。
        只有"写进去 & 读出来还在"才算，天然排除"未真正存储"的假象。"""
        ex = decl.detect.extra or {}
        fl = ex.get("flow") or {}
        w = fl.get("write") or {}
        r = fl.get("read") or {}
        ast = fl.get("assert") or {}
        w_path, r_path = w.get("path"), r.get("path")
        if not w_path or not r_path:
            return None
        from urllib.parse import urlencode, urlparse
        _u = urlparse(spec.url)
        if _u.path not in (w_path, r_path):
            return None  # 只在自身流程端点触发，避免在无关端点写入而误报
        base = f"{_u.scheme}://{_u.netloc}"
        read_url = base + r_path
        mode = str(ast.get("mode") or "unescaped_reflect")
        pats = [re.compile(p, re.IGNORECASE) for p in (ast.get("patterns") or [])]
        for payload in list(decl.payloads)[: decl.max_payloads]:
            w_url = base + w_path + "?" + urlencode({str(w.get("param") or "q"): payload})
            await self._send(spec_from_url(w_url, str(w.get("method") or "GET")))  # 写入
            r_spec = spec_from_url(read_url, "GET")
            resp, _ = await self._send(r_spec)  # 回读
            if not isinstance(resp, tuple) or len(resp) < 2:
                continue
            status, text = resp[0], resp[1] or ""
            if mode == "unescaped_reflect":
                if payload and payload in text and not self._is_html_escaped(payload, text):
                    ev = (f"流程型：写入 {w_path} 后回读 {r_path}，payload {payload!r} 未被转义"
                          f"（可执行）→ 存储型 XSS 证实")
                    return self._finding(decl, None, payload, r_spec, status, ev, "<flow-stored-xss>")
            else:
                for pat in pats:
                    if pat.search(text):
                        ev = (f"流程型：写入 {w_path} 后回读 {r_path} 命中 {pat.pattern!r}"
                              f"（payload {payload!r}）→ 二次注入证实")
                        return self._finding(decl, None, payload, r_spec, status, ev,
                                             "<flow-second-order>")
        return None

    # ------------------------------------------------------------------
    async def _probe_dom_xss(self, spec, decl: VulnSpec) -> Optional[Dict]:
        """浏览器执行 oracle（DOM 型 XSS）：经渲染会话打开带 payload 的 URL，监听 dialog(alert)。

        **只有真的弹出 dialog 才算命中**——渲染不可用/未触发一律不报，避免把"渲染失败"
        伪装成漏洞；且仅在声明自身端点触发，防止在无关端点空跑浏览器。"""
        from urllib.parse import quote, urlparse
        ex = decl.detect.extra or {}
        dom_path = str(ex.get("path") or "")
        if not dom_path or urlparse(spec.url).path != dom_path:
            return None
        try:
            from vulnclaw.core.render_session import RenderSession, render_available
        except Exception:  # noqa: BLE001
            return None
        if not render_available():
            return None  # 无浏览器后端 → 不报（宁可漏报，不可误报）
        base = spec.url.split("#")[0]
        inject = str(ex.get("inject") or "hash")
        param = str(ex.get("param") or "q")
        async with RenderSession() as rs:
            if rs is None:
                return None
            for payload in list(decl.payloads)[: decl.max_payloads]:
                if inject == "hash":
                    url = base + "#" + payload
                else:
                    sep = "&" if "?" in base else "?"
                    url = base + sep + param + "=" + quote(payload)
                res = await rs.render_for_dialog_ex(url)
                if res is not None:
                    dialog_hit, runtime_hits = res
                    if dialog_hit:
                        ev = (f"浏览器执行：{inject} 注入 payload {payload!r} 后触发 alert → "
                              f"DOM sink 可执行，DOM 型 XSS 证实")
                        return self._finding(decl, None, payload, spec, 200, ev, "<dom-xss>")
                    # P3-10：静默 DOM XSS（无弹窗）——但**必须确认是 payload 到达了 sink**：
                    # 页面自身 JS 初始化也会调用 innerHTML 等，若不关联 payload 会全站误报。
                    if runtime_hits:
                        _core = (payload.replace('<', '').replace('>', '')
                                 .replace('"', '').replace("'", "").strip()[:24])
                        _hit_by_payload = [
                            h for h in runtime_hits
                            if _core and _core.lower() in str(h.get("detail", "")).lower()
                        ]
                        if _hit_by_payload:
                            from vulnclaw.core.js_hooks import summarize_hits
                            sinks = summarize_hits(_hit_by_payload) or "unknown sink"
                            ev = (f"浏览器运行时监控：payload {payload!r} 数据流到达 [{sinks}] → "
                                  f"静默 DOM 型 XSS（无弹窗）证实")
                            return self._finding(decl, None, payload, spec, 200, ev, "<dom-xss>")
        return None

    # ------------------------------------------------------------------
    async def _probe_biz(self, spec, decl: VulnSpec) -> Optional[Dict]:
        """业务逻辑 oracle（不变量断言）：不看注入语法，而看**业务规则是否被遵守**。

          · mode=violation：把非法业务值（负数/零/超限）发给下单/计价点，
            若服务端接受并回显异常结果 → 业务校验缺失（不变量被破坏）；
          · mode=repeatable：把一次性操作（领券/核销）连续发两次，两次都成功
            → 可重复使用（不变量被破坏）。
        只在声明自身端点触发，避免在无关端点误判。"""
        from urllib.parse import urlencode, urlparse
        ex = decl.detect.extra or {}
        lg = ex.get("logic") or {}
        path = str(lg.get("path") or "")
        if not path or urlparse(spec.url).path != path:
            return None
        _u = urlparse(spec.url)
        base = f"{_u.scheme}://{_u.netloc}"
        method = str(lg.get("method") or "GET")
        param = str(lg.get("param") or "q")
        mode = str(lg.get("mode") or "violation")

        def _url(value: str) -> str:
            return base + path + "?" + urlencode({param: value})

        if mode == "repeatable":
            value = str(lg.get("value") or "")
            succ = [re.compile(p, re.IGNORECASE) for p in (lg.get("success_patterns") or [])]
            hits = 0
            for _ in range(2):  # 同一一次性操作连发两次
                resp, _ = await self._send(spec_from_url(_url(value), method))
                text = resp[1] if isinstance(resp, tuple) and len(resp) > 1 else ""
                if any(p.search(text or "") for p in succ):
                    hits += 1
            if hits >= 2:
                ev = (f"业务不变量：一次性操作 {value!r} 连续两次均成功（{path}）"
                      f"→ 可重复使用，业务逻辑漏洞证实")
                return self._finding(decl, None, value, spec, 200, ev, "<biz-repeatable>")
            return None

        viol = [re.compile(p, re.IGNORECASE)
                for p in ((lg.get("violation") or {}).get("patterns") or [])]
        for payload in list(decl.payloads)[: decl.max_payloads]:
            resp, _ = await self._send(spec_from_url(_url(payload), method))
            if not isinstance(resp, tuple) or len(resp) < 2:
                continue
            text = resp[1] or ""
            for pat in viol:
                if pat.search(text):
                    ev = (f"业务不变量：非法业务值 {payload!r} 被服务端接受"
                          f"（{path} 命中 {pat.pattern!r}）→ 业务校验缺失")
                    return self._finding(decl, None, payload, spec, resp[0], ev, "<biz-violation>")
        return None

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

        if kind == DETECT_COMPONENT:
            hits = rule.component_hits(text or "")
            if hits:
                _, _, ev = hits[0]
                return True, ev
            return False, ""

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
                if status == 0 and not headers:
                    return False, ""  # 请求失败/无响应 → 不判（避免把"没拿到响应"当成"缺头"）
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
    async def _probe_oob(self, spec, decl: VulnSpec) -> Optional[Dict]:
        """带外回连（OOB）：注入回调地址 → 目标侧主动回连 → 证实**盲**漏洞（盲 SSRF/RCE/XXE）。

        与其它 oracle 的根本区别：**证据不在响应里**，而在"目标是否回连了我们"。
        两个前提缺一不可，否则一律不探测（fail-closed：宁可漏报，绝不误报）：
          1) settings.oob_base_url   回调基址（注入到载荷里）
          2) settings.oob_hits_file  命中通道（监听器把每次回调的路径逐行写入）
        仅对 extra.path 指定的端点触发，避免对无关端点空跑等待。
        """
        ex = decl.detect.extra or {}
        want_path = str(ex.get("path") or "")
        if want_path and urlparse(spec.url).path != want_path:
            return None
        base = str(getattr(settings, "oob_base_url", "") or "").strip().rstrip("/")
        hits_file = str(getattr(settings, "oob_hits_file", "") or "").strip()
        if not base or not hits_file:
            return None
        wait_s = float(getattr(settings, "oob_wait_seconds", 6.0) or 6.0)
        token = f"vlc{int(time.time() * 1000)}{random.randint(1000, 9999)}"
        payload = f"{base}/{token}"

        point = mutated = None
        for p in enumerate_points(spec):
            loc = getattr(getattr(p, "location", None), "value", str(getattr(p, "location", "")))
            if not decl.applies_to(loc, str(p.name)):
                continue
            point = p
            mutated = render(spec, point, payload)
            await self._send(mutated)  # 注入：让目标去取该地址（响应内容无关）
            break
        if point is None or mutated is None:
            return None

        loc = getattr(getattr(point, "location", None), "value", str(getattr(point, "location", "")))
        deadline = time.time() + wait_s
        while time.time() < deadline:
            if self._oob_token_seen(hits_file, token):
                return self._finding(
                    decl, point, payload, mutated, 200,
                    f"目标侧主动回连 {base}/{token}（带外证据：响应中无任何痕迹）", loc)
            await asyncio.sleep(0.5)
        return None

    @staticmethod
    def _oob_token_seen(hits_file: str, token: str) -> bool:
        """轮询命中通道（文件）里是否出现本次回调 token。"""
        try:
            with open(hits_file, "r", encoding="utf-8", errors="ignore") as fh:
                return token in fh.read()
        except OSError:
            return False

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
        if isinstance(resp, tuple) and resp and resp[0] == 0:
            # 状态 0 = 根本没拿到响应（网络/代理/DNS）。计数以便上层把"执行失败"
            # 与"目标干净"区分开；不阻断探测本身。
            self.request_errors += 1
        return resp, time.perf_counter() - start

    @staticmethod
    def _is_html_escaped(payload: str, text: str) -> bool:
        """判断反射内容是否已被 HTML 转义（转义后不可执行，不算漏洞）。

        典型误报：站点正确地把 `<` 转成 `&lt;`，响应里仍能搜到 payload 的"核心词"，
        但它不会被执行——此时若只做字符串匹配就会误报 XSS。
        """
        if not payload or not text:
            return False
        metas = [ch for ch in ("<", ">", '"', "'") if ch in payload]
        if not metas:
            return False  # 载荷本身不含 HTML 元字符，无需转义判断
        low = text.lower()
        # payload 原样出现 -> 未被转义（可执行）
        if payload.lower() in low:
            return False
        # 转义实体版本出现 -> 已转义（不可执行）。
        # 实测坑（2026-09-12）：早期漏替换单引号 `'` → `&#39;`，
        # 于是 `'><svg/onload=alert(1)>` 这类载荷明明被转义却被判"未转义"而误报 XSS。
        escaped_variant = (payload.replace("&", "&amp;").replace("<", "&lt;")
                                  .replace(">", "&gt;").replace('"', "&quot;")
                                  .replace("'", "&#39;"))
        if escaped_variant.lower() in low:
            return True
        # 容错：部分实现把单引号转成命名实体 &apos; / &quot; 混用
        for alt in (escaped_variant.replace("&#39;", "&apos;"),
                    escaped_variant.replace("&#39;", "&quot;")):
            if alt.lower() in low:
                return True
        # 兜底：payload 的每个元字符都能在响应中找到实体形式（原样形式已排除）
        for ch, ent in (("<", "&lt;"), (">", "&gt;"), ('"', "&quot;")):
            if ch in payload and ent not in low:
                return False
        if "'" in payload and not ("&#39;" in low or "&apos;" in low):
            return False
        return True

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
            "parameter": point.label() if point else "<header-oracle>",
            "payload": payload,
            "evidence": (f"{point.label()} 注入 {payload!r} -> HTTP {status}；{evidence}" if point else f"注入声明级头 -> HTTP {status}；{evidence}"),
            "description": (
                f"按声明 `{decl.id}`（{decl.name}）在可控点 `{point.label() if point else '<header-oracle>'}` 注入载荷后，"
                f"oracle 判定命中：{evidence}"
            ),
            "remediation": decl.remediation,
            "recommendation": decl.recommendation,
            "method": f"vulnspec:{decl.id}",
            "point_location": loc,
        }


__all__ = ["SpecRunner"]
