# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""自动成长桥接层：主流程最小接线（方向1 + 方向2 的副作用入口）。

设计约束（防冲突 + 零回归）：
- 全部默认关闭：开关走 settings 动态属性 getattr(..., False)，未声明即关，
  无需改 settings.py 显式字段；接入后对现有扫描行为零影响。
- 失败静默：桥接函数内部吞异常，扫描主流程不受任何影响。
- 接线位（scan_runner.main_async）：
    1. 扫描开始前  maybe_ingest_cves()    -> 方向1 情报增量摄入
    2. 扫描结束后  maybe_absorb_scan()    -> 方向2 经验回灌
  供给端 adaptive_payloads() 供 exploit_chain/taskgen 复用历史有效载荷。
"""
from typing import Any, Dict, List, Optional

from vulnclaw.core.logger import logger

# 开关键（settings 动态属性，默认 False）
GROWTH_FEEDBACK_KEY = "enable_growth_feedback"       # 方向2 回灌（吸收+推荐）
GROWTH_INGEST_KEY = "enable_growth_ingest"           # 方向1 情报摄入
GROWTH_INGEST_LLM_KEY = "enable_growth_ingest_llm"   # 方向1 草稿 LLM 增强


def _flag(key: str, default: bool = False) -> bool:
    try:
        from vulnclaw.config.settings import settings
        return bool(getattr(settings, key, default))
    except Exception:  # noqa: BLE001
        return default


def maybe_absorb_scan(report: Dict[str, Any]) -> bool:
    """方向2：扫描结束后吸收本次 findings 为经验事实。

    默认关（enable_growth_feedback=False 不落任何数据）。
    返回是否实际写入了经验。
    """
    if not _flag(GROWTH_FEEDBACK_KEY):
        return False
    try:
        from vulnclaw.growth.feedback_ledger import get_feedback_ledger
        vulns = report.get("vulnerabilities") or []
        if not vulns:
            return False
        n = get_feedback_ledger().absorb_scan(
            vulns, target=str(report.get("target", "")),
        )
        if n:
            logger.info(f"growth: 回灌吸收 {n} 条经验")
        return n > 0
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"growth: absorb 失败（忽略，不影响主流程）: {exc}")
        return False


def maybe_ingest_cves(limit: int = 50) -> Dict[str, Any]:
    """方向1：扫描开始前增量摄入 CVE -> 草稿（确定性骨架，LLM 增强按开关）。

    默认关（enable_growth_ingest=False 不摄入）。
    返回摄入统计或 {"skipped": True}。
    """
    if not _flag(GROWTH_INGEST_KEY):
        return {"skipped": True}
    try:
        from vulnclaw.growth.cve_ingest import CveIngest
        return CveIngest().ingest_batch(
            limit=limit, enable_llm=_flag(GROWTH_INGEST_LLM_KEY),
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"growth: CVE 摄入失败（忽略）: {exc}")
        return {"error": str(exc), "ingested": 0}


def adaptive_payloads(
    vuln_type: str,
    tech_stack: Optional[List[str]] = None,
    k: int = 3,
) -> List[str]:
    """方向2 供给端：按 漏洞类型 x 技术栈 返回历史有效载荷（默认关返回空）。

    供 exploit_chain / taskgen 复用；返回的 payload 均未被误报污染。
    """
    if not _flag(GROWTH_FEEDBACK_KEY):
        return []
    try:
        from vulnclaw.growth.feedback_ledger import get_feedback_ledger
        return get_feedback_ledger().recommend_payloads(vuln_type, tech_stack, k)
    except Exception:  # noqa: BLE001
        return []