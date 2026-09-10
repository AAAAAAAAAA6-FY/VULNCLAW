# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""多步序列 / 并发竞态漏洞引擎。

覆盖两类"单请求引擎看不见"的复杂漏洞：
  1) 并发竞态（race condition）：非幂等业务动作（领券/下单/提现/扣减）并发 N 次，
     本应只成功 1 次；若业务 oracle 判出 >=2 次成功 → 竞态（重复发放/超发）。
     强证据：多次成功且响应中出现 >=2 个不同业务标识（订单号/券码/交易号）。
  2) 多步序列（sequence chain）：按步骤依次请求，步骤间用正则提取变量注入后续
     步骤（{{var}} 占位），末步用业务 oracle 判定——支撑"取 token 后改密"这类
     跨步骤业务链。

设计对齐 DualSessionOracleEngine：不进通用参数级调度池（check 恒 None），
由编排产线按预算调用；fail-closed（oracle 无法裁决/请求异常/5xx/429 不产出）。
"""
import asyncio
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get, async_post
from vulnclaw.engines.base import BaseEngine, enrich_finding


__all__ = ["SequenceChainEngine", "default_biz_oracle", "extract_biz_identifiers"]


# 业务"成功"信号（宽口径）；失败信号优先命中即否决
_SUCCESS_HINTS = (
    "success", '"ok":true', "ok", "领取成功", "下单成功", "提交成功", "支付成功",
    "order_id", "orderid", "order_no", "orderno", "订单", "coupon", "券",
)
_FAIL_HINTS = (
    "fail", "error", "拒绝", "失败", "已领取", "重复", "invalid", "denied",
    "too many", "限流", "已存在",
)

# 业务资源标识（订单号/券码/交易号）——竞态强证据来源
_ID_RE = re.compile(
    r"(?:order[_-]?id|order[_-]?no|orderid|trade[_-]?no|coupon[_-]?code|code|id)"
    r"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_-]{6,})",
    re.IGNORECASE,
)


def default_biz_oracle(status: int, text: str) -> bool:
    """默认业务 oracle：2xx 且含成功信号、且不含失败信号。

    复杂漏洞往往不报错，故判据是"业务成功信号"而非错误特征；
    无法裁决时返回 False（fail-closed）。
    """
    try:
        st = int(status or 0)
    except (TypeError, ValueError):
        return False
    if not (200 <= st < 300):
        return False
    low = (text or "").lower()
    if any(f in low for f in _FAIL_HINTS):
        return False
    return any(s in low for s in _SUCCESS_HINTS)


def extract_biz_identifiers(text: str) -> List[str]:
    """从响应中提取业务资源标识（订单号/券码/交易号），用于竞态强证据。"""
    if not text:
        return []
    return list(dict.fromkeys(_ID_RE.findall(text)))


class SequenceChainEngine(BaseEngine):
    """多步序列 / 并发竞态漏洞引擎 v1.0。"""

    name = "sequence_chain"
    description = "多步序列 / 并发竞态漏洞引擎 v1.0（不进通用调度池，编排按预算调用）"

    _MAX_STEPS = 5

    # ------------------------------------------------------------------
    # 通用参数级入口：本引擎不参与（多步/并发是端点级动作）
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
    # 1) 并发竞态
    # ------------------------------------------------------------------
    async def detect_race(
        self,
        url: str,
        session=None,
        method: str = "POST",
        data: Any = None,
        json_body: Any = None,
        concurrency: Optional[int] = None,
        oracle: Optional[Callable[[int, str], bool]] = None,
        requester: Optional[Callable[..., Any]] = None,
        **opts
    ) -> Optional[Dict]:
        """对单个业务端点做并发竞态探测。返回 finding 或 None（fail-closed）。"""
        if not getattr(settings, "sequence_chain_enabled", True):
            return None
        if not str(url or "").startswith(("http://", "https://")):
            return None

        method = str(method or "POST").upper()
        if method == "GET" and not opts.get("allow_get"):
            return None  # GET 默认幂等查询，不做竞态（避免误报）

        conc = int(concurrency or getattr(settings, "sequence_race_concurrency", 8) or 8)
        conc = max(2, min(conc, 20))
        oracle = oracle or default_biz_oracle
        req = requester or (async_post if method != "GET" else async_get)

        # ---- 串行预检：先串行 2 次判断是否已有基础防重 ----
        # 有防重的正常系统（幂等键/频控/已领取）在这里即被判"无竞态"并返回，
        # 完全不进入并发：既不放大流量，也不对正常系统造成任何重复提交。
        pre = await self._preflight(req, url, session, method, data, json_body, oracle, **opts)
        if pre is not True:
            return None

        try:
            results = await asyncio.gather(
                *[self._fire(req, url, session, method, data, json_body, **opts)
                  for _ in range(conc)],
                return_exceptions=True,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"sequence_chain 竞态请求失败: {exc}")
            return None

        successes: List[Tuple[int, str]] = []
        for r in results:
            if isinstance(r, Exception) or not isinstance(r, tuple) or len(r) < 2:
                continue
            status, text = r[0], r[1] or ""
            try:
                st = int(status or 0)
            except (TypeError, ValueError):
                continue
            if st in (0, 429) or st >= 500:
                continue  # 连接失败/限流/服务端错误不算业务成功
            try:
                if oracle(st, text):
                    successes.append((st, text))
            except Exception:  # noqa: BLE001 - oracle 自行裁决，异常即跳过
                continue

        if len(successes) < 2:
            return None  # 幂等正常（<=1 次成功）→ 不报

        identifiers: List[str] = []
        for _st, text in successes:
            identifiers.extend(extract_biz_identifiers(text))
        uniq = list(dict.fromkeys(identifiers))
        strong = len(uniq) >= 2  # 多次成功且产出不同业务标识 = 重复发放/超发

        finding = {
            "url": url,
            "type": "race_condition",
            "severity": "high" if strong else "medium",
            "title": "并发竞态：非幂等业务动作被重复成功执行",
            "description": (
                f"对 {url} 并发 {conc} 次 {method} 请求，其中 {len(successes)} 次被业务"
                f"判定为成功（幂等实现下本应仅 1 次）。"
                + (f"响应中出现 {len(uniq)} 个不同的业务标识（订单号/券码等），"
                   f"说明资源被重复发放或超发。" if strong else
                   "存在重复提交/重复扣减风险，建议人工复核服务端幂等实现。")
            ),
            "evidence": (
                f"并发 {conc} 次 → {len(successes)} 次业务成功"
                f"（状态码 {sorted({s for s, _ in successes})}）"
                + (f"；业务标识样本: {uniq[:3]}" if uniq else "")
            ),
            "remediation": (
                "对非幂等写操作加幂等键（Idempotency-Key）/ 分布式锁 / 数据库唯一约束，"
                "服务端按业务唯一键去重后再执行。"
            ),
            "recommendation": (
                "数据库层加唯一索引 + 乐观锁；接口层校验幂等键；"
                "对发放/扣减类动作改为事务内条件更新，避免并发重复生效。"
            ),
            "parameter": "",
            "method": "race_condition",
            "confidence": "high" if strong else "medium",
            "cvss": 7.5 if strong else 6.5,
            "race_concurrency": conc,
            "race_success_count": len(successes),
            "race_identifiers": uniq[:5],
        }
        return enrich_finding(finding, method=method)

    async def _preflight(
        self,
        req: Callable[..., Any],
        url: str,
        session,
        method: str,
        data: Any,
        json_body: Any,
        oracle: Callable[[int, str], bool],
        **opts
    ) -> Optional[bool]:
        """串行预检：判断是否值得进入并发。

        Returns:
            True  -> 可进入并发（串行两次都成功，疑似无基础防重）
            False -> 已有基础防重（第二次被拒/未成功），无竞态，**不并发**
            None  -> 端点不可用或单次即失败，fail-closed 不并发
        """
        try:
            first = await self._fire(req, url, session, method, data, json_body, **opts)
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"sequence_chain 预检1失败: {exc}")
            return None
        if not isinstance(first, tuple) or len(first) < 2:
            return None
        try:
            f_st = int(first[0] or 0)
        except (TypeError, ValueError):
            return None
        if f_st in (0, 429) or f_st >= 500:
            return None
        try:
            if not oracle(f_st, first[1] or ""):
                return None  # 单次都没成功 -> 端点/参数不对，不并发
        except Exception:  # noqa: BLE001
            return None

        try:
            second = await self._fire(req, url, session, method, data, json_body, **opts)
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"sequence_chain 预检2失败: {exc}")
            return None
        if not isinstance(second, tuple) or len(second) < 2:
            return None
        try:
            s_st = int(second[0] or 0)
        except (TypeError, ValueError):
            return None
        ok = s_st not in (0, 429) and s_st < 500
        if ok:
            try:
                ok = bool(oracle(s_st, second[1] or ""))
            except Exception:  # noqa: BLE001
                ok = False
        if not ok:
            # 串行第二次即被拒 -> 存在基础防重，无竞态，零并发
            return False
        return True

    # ------------------------------------------------------------------
    # 2) 多步序列
    # ------------------------------------------------------------------
    async def run_sequence(
        self,
        steps: List[Dict],
        session=None,
        oracle: Optional[Callable[[int, str], bool]] = None,
        variables: Optional[Dict[str, str]] = None,
        requester: Optional[Callable[..., Any]] = None,
        **opts
    ) -> Optional[Dict]:
        """按步骤执行业务链，步骤间提取变量注入后续步骤；末步由 oracle 裁决。"""
        if not getattr(settings, "sequence_chain_enabled", True):
            return None
        if not steps:
            return None
        max_steps = int(getattr(settings, "sequence_max_steps", self._MAX_STEPS) or self._MAX_STEPS)
        steps = list(steps)[:max_steps]
        oracle = oracle or default_biz_oracle

        ctx: Dict[str, str] = dict(variables or {})
        last_status, last_text, last_url = 0, "", ""

        for idx, step in enumerate(steps, 1):
            if not isinstance(step, dict):
                return None
            url = self._render(str(step.get("url") or ""), ctx)
            if not url.startswith(("http://", "https://")):
                return None
            method = str(step.get("method") or "GET").upper()
            data = self._render_obj(step.get("data"), ctx)
            json_body = self._render_obj(step.get("json"), ctx)
            req = requester or (async_post if method != "GET" else async_get)

            try:
                resp = await self._fire(req, url, session, method, data, json_body, **opts)
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"sequence_chain 步骤 {idx} 请求失败: {exc}")
                return None
            if not isinstance(resp, tuple) or len(resp) < 2:
                return None

            last_status, last_text, last_url = resp[0], resp[1] or "", url

            # 变量提取：正则命名组优先 group(1)，否则整匹配
            for var, pattern in (step.get("extract") or {}).items():
                try:
                    m = re.search(str(pattern), last_text)
                except re.error:
                    continue
                if m:
                    ctx[str(var)] = m.group(1) if m.groups() else m.group(0)

        if not last_url:
            return None
        try:
            st = int(last_status or 0)
        except (TypeError, ValueError):
            return None
        if st in (0, 429) or st >= 500:
            return None
        try:
            if not oracle(st, last_text):
                return None
        except Exception:  # noqa: BLE001
            return None

        finding = {
            "url": last_url,
            "type": "sequence_chain",
            "severity": "medium",
            "title": "多步序列业务链可达（Sequence Chain）",
            "description": (
                f"按 {len(steps)} 步业务链依次请求可达末步并满足业务成功判据（HTTP {st}），"
                f"说明该流程缺少跨步骤的状态/令牌/权限校验，攻击者可按序重放关键业务动作"
                f"（如取 token 后改密、加购后改价下单）。"
            ),
            "evidence": (
                f"序列 {len(steps)} 步执行完成，末步 {last_url}（HTTP {st}）命中业务成功信号；"
                f"链上变量: {sorted(ctx)}"
            ),
            "remediation": (
                "对关键业务链增加跨步骤校验：步骤令牌（一次性 nonce）、前置状态断言、"
                "角色与属主校验，并对敏感动作做频率限制与审计。"
            ),
            "recommendation": (
                "服务端维护流程状态机，禁止跳过/重放前置步骤；"
                "一次性令牌用完即失效，关键动作记录审计日志。"
            ),
            "parameter": "",
            "method": "sequence_chain",
            "confidence": "medium",
            "cvss": 6.5,
            "sequence_steps": len(steps),
            "sequence_variables": dict(ctx),
        }
        return enrich_finding(finding, method="GET")

    # ------------------------------------------------------------------
    # 工具方法
    # ------------------------------------------------------------------
    async def _fire(
        self,
        req: Callable[..., Any],
        url: str,
        session,
        method: str,
        data: Any = None,
        json_body: Any = None,
        **opts
    ):
        """统一发请求：屏蔽 GET/写方法在 async_get/async_post 上的签名差异。"""
        timeout = opts.get("timeout", 10)
        if method == "GET":
            return await req(url, session=session, timeout=timeout, no_retry=True)
        return await req(
            url, data=data, json=json_body, session=session, timeout=timeout, no_retry=True
        )

    @staticmethod
    def _render(tpl: str, ctx: Dict[str, str]) -> str:
        if not tpl or "{{" not in tpl:
            return tpl
        out = tpl
        for k, v in ctx.items():
            out = out.replace("{{" + str(k) + "}}", str(v))
        return out

    def _render_obj(self, obj: Any, ctx: Dict[str, str]) -> Any:
        if isinstance(obj, dict):
            return {k: self._render(str(v), ctx) for k, v in obj.items()}
        if isinstance(obj, str):
            return self._render(obj, ctx)
        return obj
