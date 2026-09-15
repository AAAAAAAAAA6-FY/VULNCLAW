# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/symbolic_engine.py
"""SymbolicLogicEngine —— A1 符号执行支柱的引擎层入口（name="symbolic_logic"）。

与其它引擎的关系
----------------
本引擎**不做参数级 payload 盲扫**（`check()` 恒返回 None），因此不进
`global_engines` / `engine_priority` 参数调度池；它由 extras 产线按 **IR（业务模型）**
驱动：IR → 状态机 → 目标谓词 → 约束求解 → 候选 finding（交验证层）。

判定链（为什么低误报）
----------------------
① solver 证明"存在一组输入让业务不变量破缺"（给出见证载荷）；
② （上游可选）差分复核：拿见证真打一次，看服务端是否确实破缺。
只有 ① → `needs_verification=True`，交既有验证层处置；①+② 才升级置信度。
**无 IR / 无带值域的参数 → 返回 []（fail-closed）**，绝不默认"无界即可满足"。

安全：默认 **dry-run**（不发任何请求）。本引擎只做推导与规划；真正发包由上层
（extras 产线）决定，且写操作必须过 `danger_guard`。
"""
from typing import Any, Dict, List, Optional, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.engines.base import BaseEngine

from .symbolic.detectors import ENGINE_NAME, objective_to_finding
from .symbolic.executor import best_path, explore
from .symbolic.objectives import evaluate, objectives_for
from .symbolic.state import build_machine
from .symbolic.values import (
    Constraint,
    LinCmp,
    LinExpr,
    Sym,
    domain_from_dict,
)

__all__ = ["SymbolicLogicEngine"]


def _lin_from_spec(spec: Any) -> Optional[LinExpr]:
    """IR 的不变量表达式 → LinExpr。支持 LinExpr / {"coeffs":{...},"const":n}；其它 → None。"""
    if isinstance(spec, LinExpr):
        return spec
    if isinstance(spec, dict) and isinstance(spec.get("coeffs"), dict):
        try:
            return LinExpr(tuple((str(k), int(v)) for k, v in spec["coeffs"].items()),
                           int(spec.get("const", 0)))
        except (TypeError, ValueError):
            return None
    return None


def _invariants_from_ir(ir: Dict[str, Any]) -> List[Tuple[str, Constraint]]:
    """IR.invariants → [(id, LinCmp)]（`expr == 0` 表示不变量成立）。"""
    out: List[Tuple[str, Constraint]] = []
    for inv in (ir.get("invariants") or []):
        if not isinstance(inv, dict):
            continue
        expr = _lin_from_spec(inv.get("expr"))
        if expr is None:
            continue
        out.append((str(inv.get("id") or f"inv{len(out)}"), LinCmp.eq(expr)))
    return out


def _syms_from_ir(ir: Dict[str, Any]) -> Tuple[List[Sym], Dict[str, Any]]:
    """IR 参数 → 符号变量。**只有带值域的参数才建模**（无值域 → 不建，evaluate 判 undecidable）。"""
    syms: List[Sym] = []
    domains: Dict[str, Any] = {}
    for ep in (ir.get("endpoints") or []):
        if not isinstance(ep, dict):
            continue
        for p in (ep.get("params") or []):
            if not isinstance(p, dict):
                continue
            name = str(p.get("name") or "")
            if not name or name in domains:
                continue
            spec = p.get("domain")
            if not isinstance(spec, dict):
                continue
            d = domain_from_dict(spec)
            domains[name] = d
            syms.append(Sym(name, d, note=str(ep.get("id") or "")))
    return syms, domains


def _goals_from_ir(ir: Dict[str, Any]) -> List[Tuple[str, Tuple[str, ...]]]:
    goals: List[Tuple[str, Tuple[str, ...]]] = []
    for g in (ir.get("goals") or []):
        if isinstance(g, dict) and g.get("id"):
            goals.append((str(g["id"]), tuple(g.get("requires_facts") or ())))
    return goals


def _join(target: str, path: Any) -> str:
    base = str(target or "").rstrip("/")
    p = str(path or "")
    if not p:
        return base
    return base + (p if p.startswith("/") else "/" + p)


class SymbolicLogicEngine(BaseEngine):
    """符号执行逻辑洞引擎（越权 / 金额篡改 / 数量越界 / 流程跳跃 / 幂等 / 溢出）。"""

    name = ENGINE_NAME
    description = "符号执行逻辑洞引擎（越权/金额/数量/流程/幂等/溢出）"

    async def check(self, url: str, param: str, normal_resp, parsed_query: str,
                    session, **kwargs) -> Optional[Dict]:
        """本引擎不参与参数级 payload 盲扫 → 恒 None（不给调度池增加负担）。"""
        return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        """按 IR 求解逻辑洞候选。无 IR / 无带值域参数 → []（fail-closed，零网络）。"""
        try:
            brief = kwargs.get("recon_brief") if isinstance(kwargs.get("recon_brief"), dict) else {}
            ir = kwargs.get("ir") if isinstance(kwargs.get("ir"), dict) else brief.get("business_ir")
            if not isinstance(ir, dict) or not ir:
                logger.debug("🧠 [符号执行] 未提供 IR（business_ir），fail-closed 跳过")
                return []

            syms, domains = _syms_from_ir(ir)
            if not syms:
                logger.debug("🧠 [符号执行] IR 中没有带值域的参数，跳过")
                return []

            invariants = _invariants_from_ir(ir)
            raw_price = ir.get("unit_price")
            unit_price = (int(raw_price)
                          if isinstance(raw_price, int) and not isinstance(raw_price, bool)
                          else None)

            findings: List[Dict] = []
            for ep in (ir.get("endpoints") or []):
                if not isinstance(ep, dict):
                    continue
                names = [str(p.get("name")) for p in (ep.get("params") or [])
                         if isinstance(p, dict) and p.get("name")]
                if not names:
                    continue
                url = _join(target, ep.get("path"))
                for obj in objectives_for(names, unit_price=unit_price, domains=domains):
                    res = evaluate(obj, syms, invariants)
                    f = objective_to_finding(
                        res, url=url, method=str(ep.get("method") or "GET"),
                        parameter=(obj.params[0] if obj.params else None),
                        ir_ref={"objective": obj.id, "kind": obj.kind,
                                "endpoint": str(ep.get("id") or "")},
                    )
                    if f:
                        findings.append(f)

            goals = _goals_from_ir(ir)
            if goals:
                try:
                    r = explore(build_machine(ir), goals, syms)
                    p = best_path(r)
                    if p is not None:
                        logger.info(f"🧠 [符号执行] 可达目标 {p.goal}："
                                    f"{p.steps()} 步 {list(p.transitions)}")
                    elif r.truncated:
                        logger.debug(f"🧠 [符号执行] 路径探索被预算截断：{r.reason}")
                except Exception:  # noqa: BLE001 - 路径探索失败不影响逐点候选
                    logger.debug("suppressed exception (symbolic audit)")

            logger.info(f"🧠 [符号执行] 产出 {len(findings)} 条候选（needs_verification，交验证层）")
            return findings
        except Exception as e:  # noqa: BLE001 - 引擎绝不把异常抛进任务链
            logger.debug(f"🧠 [符号执行] 异常（fail-closed）: {e}")
            return []
