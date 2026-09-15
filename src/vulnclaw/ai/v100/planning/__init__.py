# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/v100/planning/__init__.py
"""A3：链规划器（多步攻击链）。

    from vulnclaw.ai.v100.planning import build_capabilities, plan_chains, verify_chain

分层：
    capabilities.py   动作能力模型（IR 端点 / IR 转移 / 已有 finding → 原子动作）
    planner.py        目标导向**后向搜索** → AttackChain（不可行必须给原因）
    chain_verifier.py pre/post 闭合校验 + 干跑；真跑需 allow_real + danger_guard('exploit_chain')
    line.py           extras 产线 `run_chain_planner_line(orchestrator)`
"""
from .capabilities import Capability, build_capabilities, produce_index, read_capabilities
from .chain_verifier import dry_run, execute_chain, verify_chain
from .line import CHAIN_VULN_TYPE, chains_to_findings, initial_facts_for, run_chain_planner_line
from .planner import AttackChain, ChainStep, blocking_facts, plan_chains, plan_goal

__all__ = [
    "Capability",
    "build_capabilities",
    "produce_index",
    "read_capabilities",
    "ChainStep",
    "AttackChain",
    "plan_goal",
    "plan_chains",
    "blocking_facts",
    "verify_chain",
    "dry_run",
    "execute_chain",
    "CHAIN_VULN_TYPE",
    "chains_to_findings",
    "initial_facts_for",
    "run_chain_planner_line",
]
