# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""A4.4: 任务分层成本路由——便宜快模型粗筛在前，贵模型只做真验证。

验收判据：同任务成本下降可量化。

两层机制：
1. pre_screen：对一批候选 finding 用 filter 档（便宜快）模型做一次批量粗筛，
   只把「把握非常高的明显误报」筛出，转本地规则复核，不再上 verify 大模型投票。
   任何异常/解析失败 → 该批全部放行进 verify（宁漏筛勿误杀，不降准确率）。
2. VerifyBudgetGate：verify 档 LLM 调用次数预算门（同任务内）。超门后剩余候选
   全部走本地规则/技术验证（0 LLM 成本），防止验证阶段成本失控。

成本量化：粗筛调用打 usage_site="filter:prescreen"，verify 投票/批量分别打
"verify:cross"/"verify:batch"，UsageLedger site 维度即可出前后对比成本表。
"""
import asyncio

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings

__all__ = ["VerifyBudgetGate", "pre_screen_candidates"]

PRESCREEN_SITE = "filter:prescreen"


def _parse_fp_indices(raw, batch_len: int) -> set:
    """解析粗筛输出；任何失败返回空集（放行全批）。"""
    data = None
    try:
        from vulnclaw.modules.vuln_scanner import safe_extract_json

        data = safe_extract_json(raw)
    except Exception:  # noqa: BLE001
        return set()
    if isinstance(data, dict):
        data = data.get("false_positives") or data.get("fp") or data.get("indices")
    if not isinstance(data, list):
        return set()
    out = set()
    for item in data:
        try:
            j = int(item.get("index")) if isinstance(item, dict) else int(item)
        except (TypeError, ValueError):
            continue
        if 0 <= j < batch_len:
            out.add(j)
    return out


async def _tier_ask_ai(orch, tier, prompt, system, temperature, max_tokens, usage_site):
    """档位路由辅助：开关开启且能取到档位客户端时走档位直调，否则回退 orch._ask_ai。

    任何异常（未配置开关/取客户端失败/档位调用失败）一律回退原路径，绝不破坏扫描；
    开关关闭时行为与旧版完全一致。
    """
    try:
        if not getattr(settings, "model_tier_routing", False):
            return await orch._ask_ai(
                prompt, system=system, temperature=temperature,
                max_tokens=max_tokens, task_type="filter", usage_site=usage_site,
            )
        from vulnclaw.ai.v100.provider_balancer import get_tier_client

        client, _provider_key, _model = await get_tier_client(tier)
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[A4.4] 档位客户端不可用，回退 orch._ask_ai: {exc}")
        return await orch._ask_ai(
            prompt, system=system, temperature=temperature,
            max_tokens=max_tokens, task_type="filter", usage_site=usage_site,
        )
    # 档位直调：与 orchestrator._ask_ai 同口径的 90s 硬超时，失败回退原路径
    try:
        return await asyncio.wait_for(
            client.ask(
                prompt,
                system=system,
                temperature=temperature,
                max_tokens=max_tokens,
                wrap_data=True,
                retries=2,
                use_cache=False,
                usage_site=usage_site or None,
            ),
            timeout=90.0,
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[A4.4] 档位直调失败，回退 orch._ask_ai: {exc}")
        return await orch._ask_ai(
            prompt, system=system, temperature=temperature,
            max_tokens=max_tokens, task_type="filter", usage_site=usage_site,
        )


async def pre_screen_candidates(orch, candidates: list, batch_size: int = 40, tier: str = "cheap") -> tuple:
    """A4.4 第一段（便宜）：filter 档模型批量粗筛明显误报。

    Args:
        orch: orchestrator（用其 _ask_ai 以复用模型路由/降级链）。
        candidates: 候选 finding dict 列表。
        batch_size: 单次粗筛打包条数（prompt 有界）。
        tier: 模型档位（默认 cheap 便宜快档）。开关 model_tier_routing 关闭时
              自动回退 orch._ask_ai 原路径，行为与旧版一致。

    Returns:
        (fp_ids, calls)：fp_ids = 判为明显误报的 id(vuln) 集合；calls = 实际粗筛调用次数。
        粗筛不可用/解析失败 → 空集合（全量进 verify，不降准确率）。
    """
    fp_ids: set = set()
    calls = 0
    if not candidates:
        return fp_ids, calls
    for start in range(0, len(candidates), max(1, batch_size)):
        batch = candidates[start : start + max(1, batch_size)]
        lines = []
        for i, v in enumerate(batch):
            lines.append(
                f"[{i}] type={v.get('type', '?')} | severity={v.get('severity', '?')} | "
                f"url={v.get('url', '')} | param={v.get('parameter') or v.get('param', '')} | "
                f"evidence={str(v.get('evidence', ''))[:200]}"
            )
        prompt = (
            "你是安全扫描结果的粗筛器。以下是疑似漏洞候选列表。"
            "请只标记「把握非常高的明显误报」（如静态资源误报、超时兜底、纯 404 推断、"
            "无任何证据的猜测）。宁漏勿误：不确定的条目不要标记，它们会进入昂贵的"
            "大模型投票验证。\n\n"
            + "\n".join(lines)
            + '\n\n只输出 JSON：{"false_positives": [明显误报的 index]}'
        )
        try:
            calls += 1  # 尝试即计数（含失败调用，便于量化粗筛开销）
            raw = await _tier_ask_ai(
                orch,
                tier,
                prompt,
                system="只输出 JSON，不要解释。",
                temperature=0.0,
                max_tokens=400,
                usage_site=PRESCREEN_SITE,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[A4.4] 粗筛调用失败，剩余候选全量进 verify: {exc}")
            break
        for j in _parse_fp_indices(raw, len(batch)):
            fp_ids.add(id(batch[j]))
    if fp_ids:
        logger.info(
            f"🪶 [A4.4] 便宜模型粗筛: 拦截 {len(fp_ids)}/{len(candidates)} 候选"
            f"（省约 {len(fp_ids)} 次大模型投票），转入本地规则复核"
        )
    return fp_ids, calls


class VerifyBudgetGate:
    """A4.4 第二段：verify 档 LLM 调用次数预算门（同任务内）。

    事件循环内同步计数（consume 无 await），并发下不会超卖。
    超门后 allow()=False，调用方把剩余候选降级为本地规则/技术验证（0 LLM 成本）。
    """

    def __init__(self, max_calls: int):
        self.max_calls = max(0, int(max_calls))
        self.used = 0

    def allow(self) -> bool:
        return self.used < self.max_calls

    def consume(self, n: int = 1) -> bool:
        """占用 n 次额度；返回是否仍在预算内。"""
        self.used += max(1, int(n))
        return self.used <= self.max_calls

    def stats(self) -> dict:
        return {"used": self.used, "max": self.max_calls}
