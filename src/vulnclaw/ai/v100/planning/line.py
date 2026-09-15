# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/v100/planning/line.py
"""A3 产线：IR + 已有 findings → 动作集 → 目标链规划 → 干跑自证 → 候选 finding。

与 A1 产线同一套纪律：
  * **惰性**：brief 没有 IR 就先触发 A2 构建（失败即跳过，不影响任何其它线）。
  * **干跑优先**：规划结果必须先通过 pre/post 闭合校验，不闭合的链**直接丢弃**。
  * **默认不入报告**：`chain_planner_auto_report=False` 时只记日志；
    未真实执行的组合利用链只是"计划"，不是漏洞。
  * 任何异常 → warning + 返回 0（绝不阻断 extras）。
"""
from typing import Any, Dict, List, Sequence

from vulnclaw.core.logger import logger

from .capabilities import Capability, build_capabilities
from .chain_verifier import dry_run
from .planner import AttackChain, plan_chains

__all__ = ["CHAIN_VULN_TYPE", "initial_facts_for", "chains_to_findings", "run_chain_planner_line"]

CHAIN_VULN_TYPE = "利用链（多步组合）"


def _flag(name: str, default: Any) -> Any:
    """读开关。用 getattr 而非改 settings.py（避免与其它并行线争抢共享文件）。"""
    try:
        from vulnclaw.core.settings import settings

        return getattr(settings, name, default)
    except Exception:  # noqa: BLE001
        return default


def initial_facts_for(target: str) -> List[str]:
    """初始已具备的事实：能访问目标主机（可达性）。"""
    host = ""
    try:
        from urllib.parse import urlparse

        t = str(target or "")
        if t and not t.startswith(("http://", "https://")):
            t = "http://" + t
        host = urlparse(t).netloc or ""
    except Exception:  # noqa: BLE001
        host = ""
    return [f"access:{host}"] if host else []


def chains_to_findings(chains: Sequence[AttackChain], *, target: str = "") -> List[Dict[str, Any]]:
    """可行链 → 候选 finding（`needs_verification=True`，交验证层/人工确认）。"""
    out: List[Dict[str, Any]] = []
    for ch in chains or ():
        if not isinstance(ch, AttackChain) or not ch.feasible or not ch.steps:
            continue
        path = " -> ".join(s.capability_id for s in ch.steps)
        out.append({
            "type": f"{CHAIN_VULN_TYPE}: {path}",
            "severity": "High",
            "url": str(target or ""),
            "method": "",
            "parameter": "",
            "payload": "",
            "evidence": (f"干跑闭合：{[s.capability_id for s in ch.steps]}；"
                         f"目标 {ch.goal}（代价 {ch.cost}）"),
            "chain": ch.to_dict(),
            "source": "chain_planner",
            "deterministic": True,
            "needs_verification": True,
            "confidence": "中",
        })
    return out


async def run_chain_planner_line(orchestrator: Any) -> int:
    """执行 A3 产线；返回**入账**（进报告）的条数。默认 0（只记日志）。"""
    try:
        if not _flag("chain_planner_enabled", True):
            return 0
        brief = getattr(orchestrator, "_recon_brief", None)
        if not isinstance(brief, dict):
            return 0

        target = str(getattr(orchestrator, "target", "") or "")
        ir = brief.get("business_ir")
        if not ir:
            try:
                from vulnclaw.core.business_ir import attach_ir_to_brief, build_business_ir

                attach_ir_to_brief(brief, await build_business_ir(brief, target))
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"🔗 [链规划] IR 构建失败（跳过）: {exc}")
            ir = brief.get("business_ir")
        if not isinstance(ir, dict) or not ir.get("endpoints"):
            logger.debug("🔗 [链规划] 无可用 IR，跳过本轮")
            return 0

        allow_se = bool(_flag("chain_planner_allow_side_effect", False))
        findings = list(getattr(orchestrator, "findings", []) or [])
        caps: List[Capability] = build_capabilities(
            ir, findings, allow_side_effect=allow_se)
        initial = initial_facts_for(target)
        chains = plan_chains(
            ir=ir, findings=findings, capabilities=caps, initial_facts=initial,
            allow_side_effect=allow_se,
            max_chains=int(_flag("chain_planner_max_chains", 5) or 5),
            max_depth=int(_flag("chain_planner_max_depth", 8) or 8),
        )

        closed: List[AttackChain] = []
        for ch in chains:
            if not ch.feasible:
                continue
            ver = dry_run(ch, caps, initial)
            ch.verify = ver
            if ver["ok"]:
                closed.append(ch)
            else:
                ch.feasible = False
                ch.blocked_reason = "干跑未闭合: " + ",".join(ver["missing_goal"] or ["requires 缺口"])

        if not closed:
            logger.info("🔗 [链规划] 无可闭合的可行链（规划的链都被干跑否决）")
            return 0

        auto = bool(_flag("chain_planner_auto_report", False))
        made = 0
        for f in chains_to_findings(closed, target=target):
            if auto:
                try:
                    orchestrator._add_finding(f)
                    made += 1
                except Exception as exc:  # noqa: BLE001
                    logger.debug(f"🔗 [链规划] 入账失败: {exc}")
            else:
                logger.info(f"🔗 [链规划] 候选（待验证，未入报告）: {f['type']}")
        logger.info(f"🔗 [链规划] 可行链 {len(closed)} 条 → 入账 {made} 条（auto={auto}）")
        return made
    except Exception as exc:  # noqa: BLE001 - 产线异常不得阻断 extras
        logger.warning(f"⚠️ [链规划] 线异常（fail-closed）: {exc}")
        return 0
