# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/symbolic/__init__.py
"""A1 符号执行支柱（symbolic execution pillar）。

对外入口只暴露**纯确定性**的建模与求解原语：
    from vulnclaw.engines.symbolic import IntInterval, Sym, LinExpr, LinCmp, solve

上层（state / executor / objectives / detectors / symbolic_engine）在此之上构建
应用状态机与路径探索；本包不发起任何网络请求、不依赖 LLM。
"""
from .values import (
    BOOL_DOMAIN,
    DEFAULT_WINDOW,
    Constraint,
    ConstraintSet,
    Domain,
    EnumDomain,
    FloatInterval,
    IntInterval,
    LinCmp,
    LinExpr,
    SetIn,
    StrDomain,
    Sym,
    domain_from_dict,
    sort_key,
)
from .solver import (
    all_solutions,
    is_satisfiable,
    optimize,
    propagate,
    solve,
    z3_available,
    z3_check,
)
from .objectives import (
    Objective,
    ObjectiveResult,
    admin_values_for,
    amount_objective,
    authz_objective,
    classify_param,
    evaluate,
    flow_objective,
    idempotency_objective,
    objectives_for,
    overflow_objective,
    quantity_objective,
)
from .state import AppState, StateMachine, Transition, build_machine
from .executor import ExplorationResult, Path, best_path, explore, render_plan
from .detectors import (
    ENGINE_NAME,
    differential_verdict,
    findings_from_results,
    invariant_holds,
    objective_to_finding,
    witness_to_payload,
)

__all__ = [
    # values
    "Domain",
    "IntInterval",
    "FloatInterval",
    "EnumDomain",
    "StrDomain",
    "BOOL_DOMAIN",
    "DEFAULT_WINDOW",
    "Sym",
    "LinExpr",
    "Constraint",
    "LinCmp",
    "SetIn",
    "ConstraintSet",
    "domain_from_dict",
    "sort_key",
    # solver
    "propagate",
    "is_satisfiable",
    "solve",
    "all_solutions",
    "optimize",
    "z3_available",
    "z3_check",
    # objectives
    "Objective",
    "ObjectiveResult",
    "classify_param",
    "authz_objective",
    "amount_objective",
    "quantity_objective",
    "flow_objective",
    "idempotency_objective",
    "overflow_objective",
    "objectives_for",
    "evaluate",
    "admin_values_for",
    # state
    "AppState",
    "StateMachine",
    "Transition",
    "build_machine",
    # executor
    "Path",
    "ExplorationResult",
    "explore",
    "best_path",
    "render_plan",
    # detectors
    "ENGINE_NAME",
    "witness_to_payload",
    "objective_to_finding",
    "findings_from_results",
    "invariant_holds",
    "differential_verdict",
]
