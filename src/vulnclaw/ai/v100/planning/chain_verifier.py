# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/v100/planning/chain_verifier.py
"""链验证 + 干跑 —— 规划出来的链**先自证闭合**，再谈执行。

两级可信度
----------
1. `verify_chain`（纯谓词求值，零网络）：第 i 步的 requires 必须被「初始事实 ∪ 前 i-1 步
   produces」覆盖；全覆盖才算闭合。**不闭合的链一律不准执行**。
2. `execute_chain`：默认 **dry-run**（只回放校验轨迹）；要真跑必须同时满足
   `allow_real=True` **且** 过 `danger_guard.require_approval("exploit_chain")`，并注入
   `runner`（真实执行器由上层提供；本模块不内置任何 HTTP 发送）。
"""
import inspect
from typing import Any, Callable, Dict, Optional, Sequence

from vulnclaw.core.logger import logger

from .planner import AttackChain, blocking_facts

__all__ = ["verify_chain", "dry_run", "execute_chain"]


def verify_chain(chain: AttackChain, caps: Optional[Sequence[Any]] = None,
                 initial_facts: Sequence[str] = ()) -> Dict[str, Any]:
    """逐步校验 pre/post 闭合。返回 {ok, violations, trace, final_facts, missing_goal}。

    `caps` 仅用于给出更可读的不可行原因（可选）。
    """
    facts = {str(f) for f in (initial_facts or ()) if f}
    violations: list = []
    trace: list = []
    steps = list(getattr(chain, "steps", None) or [])
    broken = False

    for i, st in enumerate(steps):
        if broken:
            # 链已断 → 后续步骤**未到达**：不累加其 produces，否则会把"没跑到"伪装成"已达成"
            trace.append({"step": i + 1, "capability": st.capability_id,
                          "requires": list(st.requires), "produces": list(st.produces),
                          "missing": [], "side_effect": bool(st.side_effect),
                          "reached": False})
            continue
        missing = sorted({str(x) for x in st.requires} - facts)
        if missing:
            violations.append({"step": i + 1, "capability": st.capability_id,
                               "missing": missing})
            broken = True
            trace.append({"step": i + 1, "capability": st.capability_id,
                          "requires": list(st.requires), "produces": list(st.produces),
                          "missing": missing, "side_effect": bool(st.side_effect),
                          "reached": False})
            continue
        facts |= {str(x) for x in st.produces}
        trace.append({"step": i + 1, "capability": st.capability_id,
                      "requires": list(st.requires), "produces": list(st.produces),
                      "missing": [], "side_effect": bool(st.side_effect),
                      "reached": True})

    goal_facts = {str(f) for f in (getattr(chain, "goal_facts", None) or ())}
    missing_goal = sorted(goal_facts - facts) if goal_facts else []
    ok = not violations and not missing_goal
    return {"ok": ok, "violations": violations, "trace": trace,
            "final_facts": sorted(facts), "missing_goal": missing_goal}


def dry_run(chain: AttackChain, caps: Optional[Sequence[Any]] = None,
            initial_facts: Sequence[str] = ()) -> Dict[str, Any]:
    """干跑：只做谓词回放（不发任何请求），返回与 `verify_chain` 同构的结果。"""
    result = verify_chain(chain, caps, initial_facts)
    result["dry_run"] = True
    if not result["ok"] and not getattr(chain, "feasible", False):
        result["reason"] = getattr(chain, "blocked_reason", "") or "链不可行"
    return result


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


async def execute_chain(chain: AttackChain, *,
                        runner: Optional[Callable[[Any], Any]] = None,
                        initial_facts: Sequence[str] = (),
                        caps: Optional[Sequence[Any]] = None,
                        allow_real: bool = False) -> Dict[str, Any]:
    """执行链。**三重闸**：链闭合 → allow_real → danger_guard；任一不过即不执行。"""
    ver = verify_chain(chain, caps, initial_facts)
    if not ver["ok"]:
        return {"executed": False, "reason": "链未闭合（pre/post 校验未通过）", "verify": ver}
    if not allow_real:
        return {"executed": False, "reason": "dry-run（默认不真跑）", "verify": ver}
    if runner is None:
        return {"executed": False, "reason": "未提供 runner（仅规划，不执行）", "verify": ver}

    try:
        from vulnclaw.core.danger_guard import guard

        detail = f"chain={getattr(chain, 'id', '')} goal={getattr(chain, 'goal', '')} steps={len(ver['trace'])}"
        if not guard.require_approval("exploit_chain", detail):
            return {"executed": False, "reason": "danger_guard 拒绝（默认 deny）", "verify": ver}
    except Exception as exc:  # noqa: BLE001 - 门卫异常一律按拒绝处理
        return {"executed": False, "reason": f"danger_guard 不可用: {exc}", "verify": ver}

    results = []
    for st in chain.steps:
        try:
            results.append({"capability": st.capability_id,
                            "result": await _maybe_await(runner(st))})
        except Exception as exc:  # noqa: BLE001 - 单步失败即中止（不继续盲跑）
            logger.debug(f"[CHAIN] 步骤 {st.capability_id} 失败: {exc}")
            results.append({"capability": st.capability_id, "error": str(exc)[:200]})
            return {"executed": False, "reason": "执行中途失败", "results": results, "verify": ver}
    return {"executed": True, "results": results, "verify": ver}
