# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""元orphic 不变量探针（Metamorphic Invariant Probes）——新范式最小切片。

核心思想：**不需要知道"什么是对的"，只检查"什么该保持一致"**。
传统引擎是"1 个漏洞类型 = 1 个引擎 = payload 列表 + 匹配规则"，复杂度随漏洞
类型线性增长；本探针用一组**跨业务通用**的元规则去覆盖一整类逻辑漏洞，
漏洞类型只是最后贴上的标签（后续由声明式知识库承载）。

三条元规则（v1）：
  1) 金额篡改（price tampering）：客户端提交的金额字段，服务端应重算。
     篡改为 0.01/0/-1 后若被接受且响应回显篡改值 → 服务端照单全收（价格篡改）。
  2) 重放幂等（replay idempotency）：同一请求串行重放两次，幂等实现应只产生
     一个资源；两次都成功且产出**不同**资源标识 → 非幂等/重复提交。
  3) ID 越权候选（idor candidate）：改 ID 类参数后仍返回业务数据、且与基线
     显著不同、又不是"无权限"页 → 越权候选（只读探测，零副作用，需复核）。

副作用与开关（沿用 sequence 线的安全默认）：
  - 规则 3 是**只读**探测（GET），零副作用，随总开关默认开启；
  - 规则 1/2 会真实创建订单/重复提交（改变业务状态），
    受 `metamorphic_allow_state_changing` 控制，默认关闭。

fail-closed：识别不到目标字段、请求异常、5xx/429、判据不足 → 一律不产出。
不进通用参数级调度池（check 恒 None），由编排产线按预算调用。
"""
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get, async_post
from vulnclaw.engines.base import BaseEngine, enrich_finding
from vulnclaw.engines.sequence_engines import default_biz_oracle, extract_biz_identifiers


__all__ = [
    "MetamorphicEngine",
    "detect_amount_fields",
    "detect_id_fields",
]


# 金额类字段名（中英文常见命名）
_AMOUNT_FIELD_RE = re.compile(
    r"(?:^|[_\-.])(?:price|amount|total|money|fee|cost|sum|pay|payment|"
    r"price_?total|order_?amount|实付|金额|总价|价格|付费)(?:[_\-.]|$)",
    re.IGNORECASE,
)
# ID 类字段名
_ID_FIELD_RE = re.compile(
    r"(?:^|[_\-.])(?:id|uid|user_?id|account_?id|order_?id|member_?id|"
    r"customer_?id|no|num)(?:[_\-.]|$)",
    re.IGNORECASE,
)
# "无权限/不存在"关键词：命中即说明服务端有鉴权，不算越权
_NO_ACCESS_HINTS = (
    "unauthorized", "forbidden", "no permission", "not allowed", "access denied",
    "无权", "未授权", "禁止", "没有权限", "不存在", "not found", "404",
)
# 金额篡改候选值（由强到弱，命中即停）
_TAMPER_VALUES = ("0.01", "0", "-1")


def detect_amount_fields(params: Dict[str, Any]) -> List[str]:
    """识别请求参数中的金额类字段（不依赖业务知识，纯字段名启发式）。"""
    out = []
    for k in (params or {}):
        if _AMOUNT_FIELD_RE.search(str(k)):
            out.append(str(k))
    return out


def detect_id_fields(params: Dict[str, Any]) -> List[str]:
    """识别请求参数中的 ID 类字段（且当前值为可变的数字/短标识）。"""
    out = []
    for k, v in (params or {}).items():
        if not _ID_FIELD_RE.search(str(k)):
            continue
        s = str(v or "")
        if re.fullmatch(r"-?\d{1,18}", s) or re.fullmatch(r"[A-Za-z0-9_-]{4,32}", s):
            out.append(str(k))
    return out


class MetamorphicEngine(BaseEngine):
    """元orphic 不变量探针 v1.0（跨业务通用的逻辑漏洞元规则）。"""

    name = "metamorphic"
    description = "元orphic 不变量探针 v1.0（金额篡改 / 重放幂等 / ID 越权候选）"

    # ------------------------------------------------------------------
    # 通用参数级入口：不进通用池
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # 1) 金额篡改：客户端金额字段，服务端应重算
    # ------------------------------------------------------------------
    async def probe_price_tampering(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        session=None,
        method: str = "POST",
        requester: Optional[Callable[..., Any]] = None,
        **opts
    ) -> Optional[Dict]:
        if not self._enabled() or not self._state_changing_allowed():
            return None
        params = dict(params or {})
        fields = detect_amount_fields(params)
        if not fields:
            return None  # 没有金额字段 -> 不适用本元规则

        baseline = await self._send(endpoint, params, session, method, requester, **opts)
        if not self._ok(baseline):
            return None  # 基线就失败，无法比较

        for field in fields[:2]:
            original = str(params.get(field, ""))
            for tamper in _TAMPER_VALUES:
                if tamper == original:
                    continue
                mutated = dict(params)
                mutated[field] = tamper
                resp = await self._send(endpoint, mutated, session, method, requester, **opts)
                if not self._ok(resp):
                    continue
                status, text = resp[0], resp[1] or ""
                # 强证据：服务端把篡改值原样回显（说明直接采信了客户端金额）
                echoed = tamper in text
                if not echoed:
                    # 弱证据：响应与基线显著不同且业务成功 -> 仅作候选，需复核
                    try:
                        has_diff, ratio = self.has_response_diff(
                            (baseline[0], baseline[1] or "", {}), (status, text, {}), threshold=0.2
                        )
                    except Exception:  # noqa: BLE001
                        continue
                    if not has_diff:
                        continue

                finding = {
                    "url": endpoint,
                    "type": "price_tampering",
                    "severity": "high" if echoed else "medium",
                    "title": "金额篡改：服务端采信客户端提交的金额",
                    "description": (
                        f"参数 `{field}` 原值 {original} 被篡改为 {tamper} 后，服务端"
                        + ("原样回显该金额并判定业务成功，说明服务端未重新计算金额，"
                           "攻击者可修改金额字段以任意价格下单/支付。" if echoed else
                           "仍返回业务成功且响应与基线显著不同，疑似未校验金额，建议人工复核。")
                    ),
                    "evidence": (
                        f"{field}: {original} -> {tamper}；响应 HTTP {status}"
                        + ("，且响应中回显篡改值（服务端照单全收）" if echoed else
                           "，响应与基线差异显著（未见篡改值回显，需复核）")
                    ),
                    "remediation": (
                        "服务端必须依据商品/服务单价重新计算金额，禁止采信客户端提交的"
                        "price/amount/total 等字段；对金额做服务端签名或二次校验。"
                    ),
                    "recommendation": (
                        "订单金额一律服务端计算并落库；客户端仅提交商品 ID 与数量；"
                        "对异常金额（<=0、远低于原价）增加风控拦截与审计。"
                    ),
                    "parameter": field,
                    "method": "metamorphic_price_tampering",
                    "confidence": "high" if echoed else "medium",
                    "cvss": 8.1 if echoed else 6.5,
                    "original_value": original,
                    "tampered_value": tamper,
                }
                return enrich_finding(finding, method=method)
        return None

    # ------------------------------------------------------------------
    # 2) 重放幂等：同一请求串行重放，应只产生一个资源
    # ------------------------------------------------------------------
    async def probe_replay_idempotency(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        session=None,
        method: str = "POST",
        requester: Optional[Callable[..., Any]] = None,
        **opts
    ) -> Optional[Dict]:
        if not self._enabled() or not self._state_changing_allowed():
            return None
        params = dict(params or {})

        first = await self._send(endpoint, params, session, method, requester, **opts)
        if not self._ok(first):
            return None  # 首次就没成功 -> 端点/参数不对，无法判定幂等
        # 串行重放第二次（注意：不是并发，副作用可控在 2 次）
        second = await self._send(endpoint, params, session, method, requester, **opts)
        if not self._ok(second):
            return None  # 第二次被拒 -> 存在幂等/去重，正常

        ids_1 = extract_biz_identifiers(first[1] or "")
        ids_2 = extract_biz_identifiers(second[1] or "")
        if not ids_1 or not ids_2:
            return None  # 拿不到资源标识 -> 无法证明产生了两个资源，fail-closed
        if set(ids_1) & set(ids_2):
            return None  # 两次是同一资源 -> 幂等正常

        finding = {
            "url": endpoint,
            "type": "replay_not_idempotent",
            "severity": "medium",
            "title": "重放未幂等：相同请求重放产生了新资源",
            "description": (
                f"对 {endpoint} 串行重放同一请求两次均返回业务成功，且两次响应中的"
                f"资源标识不同（{ids_1[:2]} vs {ids_2[:2]}），说明该接口缺少幂等控制，"
                f"攻击者可重复提交造成重复下单/重复发放。"
            ),
            "evidence": (
                f"重放 2 次均成功（HTTP {first[0]}/{second[0]}）；"
                f"资源标识：第一次 {ids_1[:3]}，第二次 {ids_2[:3]}"
            ),
            "remediation": (
                "为写操作引入幂等键（Idempotency-Key）或业务唯一键；"
                "重复请求返回首次结果而不是新建资源。"
            ),
            "recommendation": (
                "接口层校验幂等键；数据库加唯一约束；"
                "对重复提交返回 409 或返回既有资源，避免产生新记录。"
            ),
            "parameter": "",
            "method": "metamorphic_replay",
            "confidence": "medium",
            "cvss": 6.5,
            "first_identifiers": ids_1[:3],
            "second_identifiers": ids_2[:3],
        }
        return enrich_finding(finding, method=method)

    # ------------------------------------------------------------------
    # 3) ID 越权候选（只读探测，零副作用）
    # ------------------------------------------------------------------
    async def probe_idor_candidate(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        session=None,
        method: str = "GET",
        requester: Optional[Callable[..., Any]] = None,
        **opts
    ) -> Optional[Dict]:
        if not self._enabled():
            return None
        params = dict(params or {})
        fields = detect_id_fields(params)
        if not fields:
            return None

        baseline = await self._send(endpoint, params, session, method, requester, **opts)
        if not self._ok(baseline):
            return None

        for field in fields[:2]:
            for mv in self._mutate_id(str(params.get(field, "")))[:3]:
                mutated = dict(params)
                mutated[field] = mv
                resp = await self._send(endpoint, mutated, session, method, requester, **opts)
                if not self._ok(resp):
                    continue
                status, text = resp[0], resp[1] or ""
                if self._looks_denied(text):
                    continue  # 服务端有鉴权 -> 正常
                try:
                    has_diff, ratio = self.has_response_diff(
                        (baseline[0], baseline[1] or "", {}), (status, text, {}), threshold=0.3
                    )
                except Exception:  # noqa: BLE001
                    continue
                if not has_diff:
                    continue

                finding = {
                    "url": self._with_param(endpoint, field, mv),
                    "type": "idor_candidate",
                    "severity": "medium",
                    "title": "越权候选：修改 ID 参数可获取不同的业务数据",
                    "description": (
                        f"参数 `{field}` 由 {params.get(field)} 改为 {mv} 后仍返回 200 业务数据，"
                        f"且响应与基线差异 {ratio:.0%}、不含无权限提示，说明服务端可能未做属主校验"
                        f"（IDOR/BOLA 候选）。本结论为只读探测所得，需权限差分或人工复核确认。"
                    ),
                    "evidence": (
                        f"{field}: {params.get(field)} -> {mv}；HTTP {status}，"
                        f"与基线差异 {ratio:.0%}，未出现无权限提示"
                    ),
                    "remediation": (
                        "服务端按资源属主做 ACL 校验：每次访问对象资源时断言当前身份是否为属主，"
                        "禁止仅依赖不可枚举性。"
                    ),
                    "recommendation": (
                        "对 id 类参数做属主校验；改用不可预测引用；"
                        "建议使用双会话差分线（idor_dual_session）进一步实锤。"
                    ),
                    "parameter": field,
                    "method": "metamorphic_idor_candidate",
                    "confidence": "medium",
                    "cvss": 6.5,
                    "mutated_value": mv,
                }
                return enrich_finding(finding, method=method)
        return None

    # ------------------------------------------------------------------
    # 批量：一次跑完适用的元规则（编排产线用）
    # ------------------------------------------------------------------
    async def probe_all(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        session=None,
        method: str = "POST",
        requester: Optional[Callable[..., Any]] = None,
        **opts
    ) -> List[Dict]:
        """按适用性依次执行元规则，返回 findings（去重后）。"""
        out: List[Dict] = []
        for probe in (
            self.probe_idor_candidate,       # 只读优先，零副作用
            self.probe_price_tampering,
            self.probe_replay_idempotency,
        ):
            try:
                f = await probe(endpoint, params, session=session, method=method,
                                requester=requester, **opts)
            except Exception as exc:  # noqa: BLE001 - 单条元规则失败不阻断其余
                logger.debug(f"metamorphic {probe.__name__} 失败: {exc}")
                continue
            if f:
                out.append(f)
        return out

    # ------------------------------------------------------------------
    # 工具方法
    # ------------------------------------------------------------------
    def _enabled(self) -> bool:
        return bool(getattr(settings, "metamorphic_enabled", True))

    def _state_changing_allowed(self) -> bool:
        """金额篡改/重放会改变业务状态（创建订单/重复提交），需显式授权。"""
        return bool(getattr(settings, "metamorphic_allow_state_changing", False))

    def _ok(self, resp) -> bool:
        """响应可用且判定为业务成功（fail-closed）。"""
        if not isinstance(resp, tuple) or len(resp) < 2:
            return False
        try:
            st = int(resp[0] or 0)
        except (TypeError, ValueError):
            return False
        if st in (0, 429) or st >= 500:
            return False
        try:
            return bool(default_biz_oracle(st, resp[1] or ""))
        except Exception:  # noqa: BLE001
            return False

    @staticmethod
    def _looks_denied(text: str) -> bool:
        low = (text or "").lower()
        return any(h in low for h in _NO_ACCESS_HINTS)

    @staticmethod
    def _mutate_id(value: str) -> List[str]:
        """生成邻近 ID 变体（数值 ±1/±2；非数字返回空）。"""
        s = str(value or "")
        if not re.fullmatch(r"-?\d{1,18}", s):
            return []
        n = int(s)
        return [str(n + 1), str(n - 1), str(n + 2)]

    async def _send(
        self,
        endpoint: str,
        params: Dict[str, Any],
        session,
        method: str,
        requester: Optional[Callable[..., Any]] = None,
        **opts
    ):
        method = str(method or "POST").upper()
        timeout = opts.get("timeout", 10)
        if requester is not None:
            return await requester(endpoint, params, method)
        if method == "GET":
            return await async_get(self._with_params(endpoint, params), session=session,
                                   timeout=timeout, no_retry=True)
        return await async_post(endpoint, data=params, session=session,
                                timeout=timeout, no_retry=True)

    @staticmethod
    def _with_params(endpoint: str, params: Dict[str, Any]) -> str:
        if not params:
            return endpoint
        parsed = urlparse(endpoint)
        q = dict(parse_qsl(parsed.query))
        q.update({str(k): str(v) for k, v in params.items()})
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                           parsed.params, urlencode(q), parsed.fragment))

    @staticmethod
    def _with_param(endpoint: str, key: str, value: str) -> str:
        return MetamorphicEngine._with_params(endpoint, {key: value})

    # ------------------------------------------------------------------
    # 新范式入口：基于统一攻击面 ControlledPoint / RequestSpec
    # ------------------------------------------------------------------
    async def _send_spec(self, spec, session=None,
                         requester: Optional[Callable[..., Any]] = None, **opts):
        """发送一个 RequestSpec：支持 query / path / header / cookie / form / json 任一位置。"""
        timeout = opts.get("timeout", 10)
        if requester is not None:
            return await requester(spec)
        kw = spec.to_send_kwargs()
        if str(spec.method).upper() == "GET":
            headers = kw.get("headers")
            return await async_get(spec.url, session=session, headers=headers,
                                   timeout=timeout, no_retry=True)
        return await async_post(spec.url, session=session, timeout=timeout, no_retry=True, **kw)

    @staticmethod
    def detect_amount_points(points) -> List[Any]:
        """从可控点中筛出金额类（点名或 JSON 路径末段命中即算）。"""
        out = []
        for p in points or []:
            key = str(p.json_path or p.name or "").rsplit(".", 1)[-1]
            if _AMOUNT_FIELD_RE.search(key) or _AMOUNT_FIELD_RE.search(str(p.name)):
                out.append(p)
        return out

    @staticmethod
    def detect_id_points(points) -> List[Any]:
        """从可控点中筛出 ID 类（且当前值可枚举）。"""
        out = []
        for p in points or []:
            s = str(p.value or "")
            looks_enumerable = (re.fullmatch(r"-?\d{1,18}", s)
                                or re.fullmatch(r"[A-Za-z0-9_-]{4,32}", s))
            # 路径段的"名字"就是值本身（如 /user/1001 没有参数名），
            # 因此 PATH 点只要值可枚举就视为 ID 点。
            loc = getattr(getattr(p, "location", None), "value", str(getattr(p, "location", "")))
            if loc == "path":
                if looks_enumerable:
                    out.append(p)
                continue
            key = str(p.json_path or p.name or "").rsplit(".", 1)[-1]
            if not _ID_FIELD_RE.search(key):
                continue
            if looks_enumerable:
                out.append(p)
        return out

    async def probe_spec(
        self,
        spec,
        points: Optional[List[Any]] = None,
        session=None,
        requester: Optional[Callable[..., Any]] = None,
        **opts
    ) -> List[Dict]:
        """新范式主入口：给定请求与其可控点，跑所有适用的元规则。

        与"参数在哪个位置"解耦——query / header / cookie / JSON 里的金额或 ID
        一律可测，这是旧 `build_attack_url` 路径做不到的。
        """
        if not self._enabled():
            return []
        from vulnclaw.core.attack_surface import enumerate_points

        pts = list(points) if points is not None else enumerate_points(spec)
        out: List[Dict] = []

        # 1) ID 越权候选：只读，零副作用，默认执行
        for p in self.detect_id_points(pts)[:2]:
            f = await self._idor_on_point(spec, p, session, requester, **opts)
            if f:
                out.append(f)
                break
        # 2) 金额篡改：会创建订单，需显式授权
        if self._state_changing_allowed():
            for p in self.detect_amount_points(pts)[:2]:
                f = await self._price_on_point(spec, p, session, requester, **opts)
                if f:
                    out.append(f)
                    break
        return out

    async def _price_on_point(self, spec, point, session, requester, **opts) -> Optional[Dict]:
        from vulnclaw.core.attack_surface import render

        baseline = await self._send_spec(spec, session, requester, **opts)
        if not self._ok(baseline):
            return None
        for tamper in _TAMPER_VALUES:
            if tamper == str(point.value):
                continue
            resp = await self._send_spec(render(spec, point, tamper), session, requester, **opts)
            if not self._ok(resp):
                continue
            status, text = resp[0], resp[1] or ""
            echoed = tamper in text
            if not echoed:
                try:
                    has_diff, _ratio = self.has_response_diff(
                        (baseline[0], baseline[1] or "", {}), (status, text, {}), threshold=0.2
                    )
                except Exception:  # noqa: BLE001
                    continue
                if not has_diff:
                    continue
            finding = {
                "url": spec.url,
                "type": "price_tampering",
                "severity": "high" if echoed else "medium",
                "title": "金额篡改：服务端采信客户端提交的金额",
                "description": (
                    f"可控点 `{point.label()}` 原值 {point.value} 被篡改为 {tamper} 后，服务端"
                    + ("原样回显该金额并判定业务成功，说明服务端未重新计算金额。"
                       if echoed else "仍返回业务成功且响应与基线显著不同，疑似未校验金额，需复核。")
                ),
                "evidence": f"{point.label()}: {point.value} -> {tamper}；HTTP {status}"
                            + ("，响应回显篡改值" if echoed else "，响应差异显著（需复核）"),
                "remediation": "服务端依据商品单价重算金额，禁止采信客户端提交的金额字段。",
                "recommendation": "订单金额一律服务端计算并落库；对异常金额增加风控拦截与审计。",
                "parameter": point.label(),
                "method": "metamorphic_price_tampering",
                "confidence": "high" if echoed else "medium",
                "cvss": 8.1 if echoed else 6.5,
                "original_value": str(point.value),
                "tampered_value": tamper,
                "point_location": getattr(point.location, "value", str(point.location)),
            }
            return enrich_finding(finding, method=spec.method)
        return None

    async def _idor_on_point(self, spec, point, session, requester, **opts) -> Optional[Dict]:
        from vulnclaw.core.attack_surface import render

        baseline = await self._send_spec(spec, session, requester, **opts)
        if not self._ok(baseline):
            return None
        for mv in self._mutate_id(str(point.value))[:3]:
            resp = await self._send_spec(render(spec, point, mv), session, requester, **opts)
            if not self._ok(resp):
                continue
            status, text = resp[0], resp[1] or ""
            if self._looks_denied(text):
                continue
            try:
                has_diff, ratio = self.has_response_diff(
                    (baseline[0], baseline[1] or "", {}), (status, text, {}), threshold=0.3
                )
            except Exception:  # noqa: BLE001
                continue
            if not has_diff:
                continue
            finding = {
                "url": spec.url,
                "type": "idor_candidate",
                "severity": "medium",
                "title": "越权候选：修改 ID 类可控点可获取不同的业务数据",
                "description": (
                    f"可控点 `{point.label()}` 由 {point.value} 改为 {mv} 后仍返回 200 业务数据，"
                    f"与基线差异 {ratio:.0%} 且无无权限提示，疑似缺少属主校验（IDOR/BOLA 候选）。"
                ),
                "evidence": f"{point.label()}: {point.value} -> {mv}；HTTP {status}，差异 {ratio:.0%}",
                "remediation": "服务端按资源属主做 ACL 断言，禁止仅依赖不可枚举性。",
                "recommendation": "建议交双会话差分线（idor_dual_session）进一步实锤。",
                "parameter": point.label(),
                "method": "metamorphic_idor_candidate",
                "confidence": "medium",
                "cvss": 6.5,
                "mutated_value": mv,
                "point_location": getattr(point.location, "value", str(point.location)),
            }
            return enrich_finding(finding, method=spec.method)
        return None
