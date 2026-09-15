# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)

"""B2 L3 差分不变量引擎（InvariantDiffEngine）。

对"动作语义端点"跑四组不变量检查器（绑定/金额守恒/一次性/状态跳跃），
成对请求差分，violation → finding。角色差分由现 dual_session 线承接（不重复基建）。

信号 traceability（聚合引擎红线）：每条 finding 携带
{family: "invariant_diff", kind: <检查器名>, marker: <差分标记>} 与人类可读证据链。

Safety（红线）：
- 只读 GET 探测，不重复提交真实业务副作用（状态检查用 ok=1 幂等变体，无退款/扣减）
- 所有异常 fail-closed 返回 None，绝不影响主扫描
- 产出一律 ai_verdict="待验证"，走 verify/AI 复核与终稿收敛门，防误报
"""
from __future__ import annotations

import asyncio
import random
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from typing import Dict, List, Optional

from vulnclaw.core.logger import logger

# 动作语义 hint 词（路径命中即视为可疑业务端点；中英双语，与 _collect_write_candidates 风格一致）
_KIND_HINTS: Dict[str, str] = {
    "binding": r"(?:reset|forgot|activate|confirm|verify|recover|找回|重置|激活|验证)",
    "amount": r"(?:charge|balance|recharge|topup|transfer|withdraw|amount|price|wallet|充值|余额|提现|转账|金额)",
    "once": r"(?:coupon|claim|redeem|voucher|reward|领取|兑换|优惠券|红包)",
    "state": r"(?:pay|ship|complete|finish|checkout|settle|支付|发货|结账|完成)",
}
ACTION_HINTS = re.compile("|".join(_KIND_HINTS.values()), re.I)
# 拒绝词：响应命中即视为"服务端拒绝了该请求"，不算不变量违反
_REJECT_WORDS = re.compile(
    r"(?:negative|reject|invalid|forbidden|denied|used|redeemed|claimed|already|"
    r"fail|required|not_allowed|非法|拒绝|已使用|已领取|失败|无权|无效)", re.I)
# 成功词：状态检查判定"业务动作确实发生"的最低语义门槛
_OK_WORDS = re.compile(r"(?:ok|success|paid|shipped|done|成功|支付|完成)", re.I)

_SEV = {"High": 3, "Medium": 2, "Low": 1}


def _set_param(url: str, name: str, value: str) -> str:
    u = urlparse(url)
    qs = [(k, v) for k, v in parse_qsl(u.query, keep_blank_values=True) if k != name]
    qs.append((name, value))
    return urlunparse(u._replace(query=urlencode(qs, doseq=True)))


def _pick_param(rest: List[tuple], pattern: str) -> Optional[str]:
    return next((k for k, _ in rest if re.search(pattern, k, re.I)), None)


class InvariantDiffEngine:
    """L3 差分不变量引擎：对单个动作语义端点做多组不变量检查。"""

    kind_map = {kind: re.compile(pat, re.I) for kind, pat in _KIND_HINTS.items()}

    def __init__(self, timeout: int = 10):
        self._timeout = timeout

    # -- 请求原语（只读 GET）---------------------------------------
    async def _get(self, url: str) -> tuple:
        import aiohttp

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self._timeout), raise_for_status=False
        ) as s:
            try:
                async with s.get(url) as r:
                    body = (await r.text(errors="replace"))[:2000] or ""
                    return int(r.status), body
            except asyncio.TimeoutError:
                return 0, ""
            except Exception as e:  # noqa: BLE001
                logger.debug(f"[INVARIANT] get {url} failed: {e}")
                return -1, ""

    @staticmethod
    def _kind_of(url: str) -> List[str]:
        p = url.split("?")[0]
        return [k for k, pat in InvariantDiffEngine.kind_map.items() if pat.search(p)]

    # -- 检查器：绑定不变量（token 必须绑定属主）-------------------
    async def _binding_check(self, url: str) -> Optional[dict]:
        rest = [(k, v) for k, v in parse_qsl(urlparse(url).query, keep_blank_values=True) if v]
        token_p = _pick_param(rest, r"token|code|^t$")
        ident_p = _pick_param(rest, r"user|uid|email|account|username")
        if not token_p or not ident_p or len(rest) < 2:
            return None
        token_val = next(v for k, v in rest if k == token_p)
        ident_val = next(v for k, v in rest if k == ident_p)
        swapped = ident_val + "_x" if not str(ident_val).endswith(("_a", "_b", "_c")) else f"{ident_val}_alt"
        s1, b1 = await self._get(url)
        s2, b2 = await self._get(_set_param(_set_param(url, token_p, token_val), ident_p, swapped))
        if s1 and s2 and s1 < 400 and s2 < 400 and not _REJECT_WORDS.search(b2):
            return {
                "kind": "binding",
                "marker": f"200_swap_identity_{s2}",
                "severity": "High",
                "evidence": (
                    f"同一凭据/令牌 {token_p}={token_val} 仅替换身份参数 {ident_p}={swapped} "
                    f"仍返回 {s2}（原 {ident_p}={ident_val} → {s1}），凭据未绑定属主，存在越权重置/激活他人账号风险"
                ),
            }
        return None

    # -- 检查器：金额守恒（负值/非法金额应被拒绝）-----------------
    async def _amount_check(self, url: str) -> Optional[dict]:
        rest = [(k, v) for k, v in parse_qsl(urlparse(url).query, keep_blank_values=True) if v]
        amt_p = _pick_param(rest, r"amt|amount|price|money|value")
        if not amt_p:
            return None
        sn, bn = await self._get(_set_param(url, amt_p, "-1"))
        sp, bp = await self._get(_set_param(url, amt_p, "1"))
        if sn and sp and sn < 400 and sp < 400 and not _REJECT_WORDS.search(bn):
            return {
                "kind": "amount",
                "marker": "negative_value_accepted",
                "severity": "High",
                "evidence": (
                    f"金额参数 {amt_p}=-1 返回 {sn}（对照 {amt_p}=1 → {sp}），负值金额未被拒绝，"
                    f"存在资金守恒破坏（负价下单/余额扣成负数）风险"
                ),
            }
        return None

    # -- 检查器：一次性（同一码不得重复领取）-----------------------
    async def _once_check(self, url: str) -> Optional[dict]:
        rest = [(k, v) for k, v in parse_qsl(urlparse(url).query, keep_blank_values=True) if v]
        code_p = _pick_param(rest, r"code|coupon|voucher|promo|reward")
        if not code_p:
            return None
        cv = f"INV-{random.randint(10**8, 10**9)}"
        s1, b1 = await self._get(_set_param(url, code_p, cv))
        s2, b2 = await self._get(_set_param(url, code_p, cv))
        if s1 and s2 and s1 < 400 and s2 < 400 and not _REJECT_WORDS.search(b2):
            return {
                "kind": "once",
                "marker": "repeat_redeem_ok",
                "severity": "Medium",
                "evidence": (
                    f"同一兑换码/优惠码 {code_p}={cv} 连续两次请求均成功（{s1} / {s2}），"
                    f"未被判定为已领取，存在重复领取/幂等缺失风险"
                ),
            }
        return None

    # -- 检查器：状态跳跃（未完成前置步骤不应直达终态）-------------
    async def _state_skip_check(self, url: str) -> Optional[dict]:
        s0, b0 = await self._get(url)
        s1, b1 = await self._get(_set_param(url, "ok", "1"))
        if s1 and s1 < 400 and _OK_WORDS.search(b1) and not _REJECT_WORDS.search(b1):
            return {
                "kind": "state",
                "marker": "skip_step_ok",
                "severity": "Medium",
                "evidence": (
                    f"直接携带 ok=1 调用即返回 {s1}（裸请求 → {s0}）且含业务成功语义，"
                    f"存在状态机前置校验缺失（跳过支付/验证直达终态）风险"
                ),
            }
        return None

    # -- 主入口 ------------------------------------------------------
    async def diagnose(self, url: str) -> Optional[Dict]:
        """对单个端点跑命中的检查器，聚合为 finding；任何失败 fail-closed None。"""
        kinds = self._kind_of(url)
        if not kinds:
            logger.debug(f"[INVARIANT] 端点无动作语义，跳过: {url}")
            return None
        checks = {
            "binding": self._binding_check,
            "amount": self._amount_check,
            "once": self._once_check,
            "state": self._state_skip_check,
        }
        results: List[dict] = []
        for kind in kinds:
            fn = checks.get(kind)
            if not fn:
                continue
            try:
                r = await fn(url)
            except Exception as e:  # noqa: BLE001
                logger.debug(f"[INVARIANT] {kind} check on {url} failed: {e}")
                continue
            if r:
                r["url"] = url
                results.append(r)
        if not results:
            return None
        return self._build_finding(url, results)

    def _build_finding(self, url: str, results: List[dict]) -> Dict:
        top = max(results, key=lambda r: _SEV.get(r["severity"], 1))
        kinds = ",".join(r["kind"] for r in results)
        desc = "；".join(r["evidence"] for r in results)
        return {
            "url": url,
            "type": "业务逻辑不变量违反（差分证实）",
            "severity": top["severity"],
            "title": f"业务逻辑不变量违反：{kinds}（{top['marker']}）",
            "description": desc,
            "evidence": desc + f" [family=invariant_diff, kinds={kinds}]",
            "evidence_trace": [
                {"family": "invariant_diff", "kind": r["kind"], "marker": r["marker"]} for r in results
            ],
            "ai_verdict": "待验证",
            "confidence": "medium",
            "method": "invariant_diff",
            "cvss": self._cvss(top["severity"], kinds),
            "remediation": "服务端对关键业务动作强制校验不变量（凭据属主绑定/金额非负/幂等键/状态机前置条件）",
            "recommendation": "按资源属主与流程前置条件做强校验；关键动作加幂等键；资金类动作拒绝负数",
        }

    @staticmethod
    def _cvss(severity: str, kinds: str) -> str:
        if severity == "High":
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"


__all__ = ["ACTION_HINTS", "InvariantDiffEngine"]