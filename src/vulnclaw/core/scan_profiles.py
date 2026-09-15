# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""扫描模式（scan profiles）——预设预算包，供 CLI/调度选择。

设计约束
--------
1. **纯数据 + 纯函数**：模式定义是冻结 dataclass，`apply_budget` 是确定性裁减，
   无 IO / 无网络 / 无时钟。
2. **成本口径唯一来源**：请求数估算一律走 ``core.cost_model.estimate_scan_cost``，
   不在此模块重复实现成本公式。
3. **fail-closed 裁减**：``apply_budget`` 超预算时**显式返回被裁项**，
   绝不静默降级；裁减顺序确定（低优先级 → 高成本 → 名称字典序）。
4. **与 CLI 解耦**：本模块不 import cli/scan；接线方式见 docs/RESOURCE_BUDGET.md。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from vulnclaw.core.cost_model import (
    DEFAULT_REQUEST_LATENCY_MS,
    CostEstimate,
    estimate_scan_cost,
    risk_benefit_ratio,
)

__all__ = [
    "ScanProfile",
    "BudgetResult",
    "PROFILES",
    "PRIORITY_P0",
    "PRIORITY_P1",
    "engine_priority",
    "get_profile",
    "list_profiles",
    "apply_budget",
]

# ---------------------------------------------------------------
# 引擎优先级（预算裁减时"先丢谁"的唯一事实源）
# ---------------------------------------------------------------
#: P0：检测价值最高、几乎必开的核心引擎
PRIORITY_P0: Tuple[str, ...] = (
    "sqli", "xss", "cmdi", "lfi", "ssrf", "ssti",
    "deserialization", "idor", "jwt", "file_upload",
)
#: P1：高价值但不属于 P0 的引擎
PRIORITY_P1: Tuple[str, ...] = (
    "xxe", "fastjson_deserialization", "log4shell", "shiro_rememberme",
    "struts2_ognl", "spring4shell", "nosql", "ldap", "graphql",
    "cors", "open_redirect", "info_leak", "api_security",
    "mass_assignment", "auth_enumeration", "idor_dual_session",
    "security_headers", "backup_file_leak", "source_code_leak",
)

_P0_SET = frozenset(PRIORITY_P0)
_P1_SET = frozenset(PRIORITY_P1)


def engine_priority(engine_name: str) -> int:
    """引擎优先级：P0=2 / P1=1 / 未登记=0（数值越大越先保留）。"""
    name = str(engine_name or "")
    if name in _P0_SET:
        return 2
    if name in _P1_SET:
        return 1
    return 0


# ---------------------------------------------------------------
# 模式定义
# ---------------------------------------------------------------
@dataclass(frozen=True)
class ScanProfile:
    """一次扫描的预算包。

    Attributes:
        name: 模式名（唯一键）。
        description: 人读说明。
        engines: 显式引擎清单；空元组 = "全部已加载引擎"（由调度侧展开）。
        payload_depth: 逐引擎 payload 深度覆盖（缺省用 default_payload_depth）。
        default_payload_depth: 清单内未覆盖引擎的 payload 深度。
        concurrency: 并发度。
        per_request_latency_ms: 单请求经验耗时（毫秒），用于估算。
        scan_timeout_s: 墙钟超时（秒；0 = 不限）。
        report_detail: 报告详细度（与 report_generator.compact_report 口径一致）。
        budget_requests: 请求预算上限（0 = 不限）；apply_budget 用它裁减。
    """

    name: str
    description: str
    engines: Tuple[str, ...]
    payload_depth: Dict[str, int] = field(default_factory=dict)
    default_payload_depth: int = 10
    concurrency: int = 5
    per_request_latency_ms: float = DEFAULT_REQUEST_LATENCY_MS
    scan_timeout_s: int = 0
    report_detail: str = "full"
    budget_requests: int = 0

    def payload_count_for(self, engine_name: str) -> int:
        """返回某引擎在本模式下的 payload 深度（显式覆盖优先）。"""
        return int(self.payload_depth.get(str(engine_name), self.default_payload_depth))

    def engine_spec(self) -> List[Tuple[str, int]]:
        """展开为 ``[(engine, payload_count), ...]``（顺序稳定）。"""
        return [(name, self.payload_count_for(name)) for name in self.engines]


#: 全部模式（顺序即 list_profiles 输出顺序）
PROFILES: Dict[str, ScanProfile] = {
    "fast": ScanProfile(
        name="fast",
        description="快速：仅 P0 引擎、浅 payload，先判断是否存在明显问题",
        engines=PRIORITY_P0,
        default_payload_depth=4,
        concurrency=10,
        scan_timeout_s=300,
        report_detail="summary",
        budget_requests=2_000,
    ),
    "standard": ScanProfile(
        name="standard",
        description="标准：P0+P1、常规 payload 深度（默认推荐）",
        engines=PRIORITY_P0 + PRIORITY_P1,
        default_payload_depth=8,
        concurrency=5,
        scan_timeout_s=1_800,
        report_detail="full",
        budget_requests=20_000,
    ),
    "deep": ScanProfile(
        name="deep",
        description="深度：P0+P1、加深 payload（含预算内全量），耗时长",
        engines=PRIORITY_P0 + PRIORITY_P1,
        default_payload_depth=16,
        concurrency=3,
        scan_timeout_s=7_200,
        report_detail="full",
        budget_requests=0,  # 不限
    ),
    "low-noise": ScanProfile(
        name="low-noise",
        description="低噪声：仅高价值验证型引擎 + 最浅 payload，适合生产窗口",
        engines=(
            "sqli", "cmdi", "lfi", "ssrf", "deserialization",
            "jwt", "xxe", "log4shell",
        ),
        default_payload_depth=2,
        concurrency=2,
        scan_timeout_s=900,
        report_detail="summary",
        budget_requests=400,
    ),
    "oob": ScanProfile(
        name="oob",
        description="带外专项：盲打类引擎（SSRF/XXE/Log4Shell/Fastjson）",
        engines=("ssrf", "xxe", "log4shell", "fastjson_deserialization"),
        default_payload_depth=6,
        concurrency=3,
        scan_timeout_s=1_200,
        report_detail="full",
        budget_requests=1_500,
    ),
    "api": ScanProfile(
        name="api",
        description="API 专项：接口/鉴权/组件类引擎",
        engines=(
            "api_security", "api_version", "api_version_diff", "graphql",
            "mass_assignment", "mobile_api", "idor", "idor_dual_session",
            "jwt", "oauth", "rate_limit", "cors",
        ),
        default_payload_depth=6,
        concurrency=5,
        scan_timeout_s=1_800,
        report_detail="full",
        budget_requests=4_000,
    ),
    "budget": ScanProfile(
        name="budget",
        description="预算模式：标准集 + 低请求上限，超限由 apply_budget 显式裁减",
        engines=PRIORITY_P0 + PRIORITY_P1,
        default_payload_depth=4,
        concurrency=5,
        scan_timeout_s=1_200,
        report_detail="summary",
        budget_requests=1_000,
    ),
}

#: 报告详细度合法值（与 report_generator.compact_report 对齐）
_VALID_DETAILS = frozenset({"full", "summary", "compact"})


def get_profile(name: str) -> ScanProfile:
    """按名取模式；未登记 → ``ValueError``（fail-closed，不静默回退）。"""
    key = str(name or "").strip().lower()
    if key not in PROFILES:
        raise ValueError(
            f"未登记的扫描模式 {name!r}；可用: {', '.join(sorted(PROFILES))}"
        )
    return PROFILES[key]


def list_profiles() -> List[str]:
    """全部模式名（声明顺序，确定性）。"""
    return list(PROFILES)


# ---------------------------------------------------------------
# 预算裁减
# ---------------------------------------------------------------
@dataclass(frozen=True)
class BudgetResult:
    """``apply_budget`` 的结果。

    Attributes:
        profile: 裁减后的模式（原模式未超限时原样返回）。
        estimate: 裁减后残余请求数估算。
        dropped: 被裁引擎（按裁减顺序）。
        dropped_estimate: 被裁引擎原请求数合计。
        reason: 人读原因（未裁减时为空串）。
    """

    profile: ScanProfile
    estimate: CostEstimate
    dropped: Tuple[str, ...] = ()
    dropped_estimate: int = 0
    reason: str = ""


def _estimate_profile(profile: ScanProfile) -> CostEstimate:
    return estimate_scan_cost(
        profile.engine_spec(),
        targets=1,
        concurrency=profile.concurrency,
        per_request_latency_ms=profile.per_request_latency_ms,
    )


def _drop_order(profile: ScanProfile) -> List[str]:
    """裁减候选顺序：低优先级 → 高请求成本 → 名称字典序（全确定）。"""
    costs = dict(profile.engine_spec())
    return sorted(
        profile.engines,
        key=lambda name: (
            engine_priority(name),
            -int(costs.get(name, 0)),
            str(name),
        ),
    )


def apply_budget(profile: ScanProfile, budget_requests: Optional[int] = None) -> BudgetResult:
    """按请求预算裁减引擎清单（确定、显式、可解释）。

    - ``budget_requests`` 缺省时用 ``profile.budget_requests``；0 = 不限。
    - 裁减总是从"低优先级 + 高成本"的引擎开始，P0 引擎尽可能保留；
    - 循环直到预算内或只剩 1 个引擎（最后 1 个 P0 引擎即使超限也保留，
      并把 ``reason`` 标注为不可再裁——探测"最小可用集"比"空扫描"诚实）。
    """
    budget = int(profile.budget_requests if budget_requests is None else budget_requests)
    if budget < 0:
        raise ValueError(f"budget_requests 不能为负：{budget}")

    estimate = _estimate_profile(profile)
    if budget == 0 or estimate.requests <= budget:
        return BudgetResult(profile=profile, estimate=estimate)

    remaining = list(profile.engines)
    dropped: List[str] = []
    reason = f"请求预算 {budget} < 估算 {estimate.requests}，按低优先级优先裁减"
    costs = dict(profile.engine_spec())
    for name in _drop_order(profile):
        if not remaining or estimate.requests <= budget:
            break
        if len(remaining) <= 1:
            reason += "；已到最小集，无法继续裁减"
            break
        remaining.remove(name)
        dropped.append(name)
        estimate = estimate_scan_cost(
            [(n, profile.payload_count_for(n)) for n in remaining],
            targets=1,
            concurrency=profile.concurrency,
            per_request_latency_ms=profile.per_request_latency_ms,
        )

    trimmed = ScanProfile(
        name=profile.name,
        description=profile.description,
        engines=tuple(remaining),
        payload_depth=dict(profile.payload_depth),
        default_payload_depth=profile.default_payload_depth,
        concurrency=profile.concurrency,
        per_request_latency_ms=profile.per_request_latency_ms,
        scan_timeout_s=profile.scan_timeout_s,
        report_detail=profile.report_detail,
        budget_requests=budget,
    )
    return BudgetResult(
        profile=trimmed,
        estimate=estimate,
        dropped=tuple(dropped),
        dropped_estimate=sum(int(costs.get(n, 0)) for n in dropped),
        reason=reason,
    )
