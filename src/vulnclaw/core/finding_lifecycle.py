# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/finding_lifecycle.py
"""SP10 finding 生命周期台账：new / reconfirmed / fixed / deprecated。

DeepSec revalidate 会翻 git 历史确认"漏洞是否已修过"；动态扫描没有 git 可翻，
等价物是"跨扫描状态"。本模块把它工程化为两条路径：

1. apply_lifecycle(report) —— 单次报告路径（扫描收尾钩子）：
   查寿命账本（_runtime_cache/metrics/finding_lifecycle.json）决定 new/reconfirmed，
   注入 lifecycle 字段、按生命周期分组、更新账本（first_seen/last_seen/scan_count/history）。

2. migrate(baseline, current) —— 显式两次扫描对比路径（CI/复测脚本）：
   基线独有 -> fixed（保留基线证据）、当前独有 -> new、共存 -> reconfirmed。
   指纹键复用 SP2 的 findings_fingerprint（url|method|type|param，比 report_generator
   diff_reports 的 (url,type,param) 键更严，同根因同位置同向量视为同一漏洞）。

报告侧：report["lifecycle_groups"] + report["lifecycle_summary"] 供 HTML 渲染
（治理台账视角：新增/持续/已修复），与 SP3 覆盖账本同属"机器事实"口径。
"""
import json
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from vulnclaw.core.logger import logger
from vulnclaw.core.dedupe import findings_fingerprint

# ---------------------------------------------------------------------------
# 状态机定义
# ---------------------------------------------------------------------------
LIFECYCLE_NEW = "new"  # 本次扫描新出现
LIFECYCLE_RECONFIRMED = "reconfirmed"  # 上次存在、本次仍存在（持续暴露）
LIFECYCLE_FIXED = "fixed"  # 上次存在、本次消失（判定已修复，证据留存）
LIFECYCLE_DEPRECATED = "deprecated"  # 检测能力下线/不再适用（显式标注用）

VALID_LIFECYCLE = {LIFECYCLE_NEW, LIFECYCLE_RECONFIRMED, LIFECYCLE_FIXED, LIFECYCLE_DEPRECATED}
LIFECYCLE_ORDER = [LIFECYCLE_RECONFIRMED, LIFECYCLE_NEW, LIFECYCLE_FIXED, LIFECYCLE_DEPRECATED]

LIFECYCLE_FILENAME = "finding_lifecycle.json"
LIFECYCLE_SCHEMA_VERSION = 1

_LEDGER_DIR = os.path.join("_runtime_cache", "metrics")


def lifecycle_key(finding: Dict[str, Any]) -> str:
    """生命周期指纹键：与 SP2 去重指纹完全一致（同根因+同位置+同向量=同一漏洞）。"""
    return findings_fingerprint(finding)


def _strip_internal(v: Dict[str, Any]) -> Dict[str, Any]:
    """去掉内部字段（_lc_*），保持 finding 落盘/报告干净。"""
    return {k: val for k, val in v.items() if not str(k).startswith("_lc_")}


# ---------------------------------------------------------------------------
# 路径一：单次报告（扫描收尾）
# ---------------------------------------------------------------------------
def apply_lifecycle(report: Dict[str, Any], ledger_path: Optional[str] = None) -> Dict[str, Any]:
    """给报告注入生命周期分组并更新寿命账本（构建失败不阻塞，直接降级返回原报告）。"""
    try:
        findings = list((report or {}).get("vulnerabilities") or [])
        ledger = load_lifecycle_ledger(ledger_path)
        known = set(ledger.get("findings", {}))
        out: List[Dict[str, Any]] = []
        for f in findings:
            f = dict(f)
            key = lifecycle_key(f)
            f["_lc_key"] = key
            f["lifecycle"] = LIFECYCLE_RECONFIRMED if key in known else LIFECYCLE_NEW
            out.append(f)
        ledger = _upsert_ledger(ledger, out, target=report.get("target", ""))
        save_lifecycle_ledger(ledger, ledger_path)
        # 分组视图（内部字段剥离后再入组，避免 _lc_key 泄漏进报告）
        grouped = _group(out)
        report["vulnerabilities"] = [_strip_internal(f) for f in out]
        report["lifecycle_groups"] = grouped
        report["lifecycle_summary"] = {k: len(v) for k, v in grouped.items() if v}
        if report["lifecycle_summary"]:
            logger.info(
                "   SP10 生命周期台账: 新增 %d / 持续 %d",
                report["lifecycle_summary"].get(LIFECYCLE_NEW, 0),
                report["lifecycle_summary"].get(LIFECYCLE_RECONFIRMED, 0),
            )
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"SP10 finding 生命周期合并失败，报告降级跳过: {exc}")
    return report


def _group(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = {s: [] for s in LIFECYCLE_ORDER}
    for f in findings:
        state = str(f.get("lifecycle") or LIFECYCLE_NEW)
        groups.setdefault(state if state in VALID_LIFECYCLE else LIFECYCLE_NEW, []).append(_strip_internal(f))
    return groups


# ---------------------------------------------------------------------------
# 路径二：显式两次扫描对比
# ---------------------------------------------------------------------------
def migrate(baseline_report: Dict[str, Any], current_report: Dict[str, Any]) -> Dict[str, Any]:
    """跨扫描状态迁移。返回 current（注入 lifecycle）+ fixed（含基线证据）+ summary。"""
    baseline = {
        lifecycle_key(v): dict(v)
        for v in ((baseline_report or {}).get("vulnerabilities") or []) if lifecycle_key(v)
    }
    current = {
        lifecycle_key(v): dict(v)
        for v in ((current_report or {}).get("vulnerabilities") or []) if lifecycle_key(v)
    }
    b_keys, c_keys = set(baseline), set(current)
    fixed = [{**baseline[k], "lifecycle": LIFECYCLE_FIXED} for k in sorted(b_keys - c_keys)]
    current_out = []
    for k in sorted(c_keys):
        dup = dict(current[k])
        dup["lifecycle"] = LIFECYCLE_RECONFIRMED if k in b_keys else LIFECYCLE_NEW
        current_out.append(dup)
    summary = {
        "baseline_total": len(b_keys),
        "current_total": len(c_keys),
        "new_count": len(c_keys - b_keys),
        "reconfirmed_count": len(c_keys & b_keys),
        "fixed_count": len(b_keys - c_keys),
    }
    logger.info(
        "   SP10 migrate: 新增 %d / 持续 %d / 已修复 %d",
        summary["new_count"], summary["reconfirmed_count"], summary["fixed_count"],
    )
    return {"current": current_out, "fixed": fixed, "summary": summary}


def mark_fixed_in_ledger(current_keys: List[str], ledger_path: Optional[str] = None) -> Dict[str, Any]:
    """完整重扫场景：账本中存在但本次扫描未出现的键 -> 标 fixed（证据为历史记录）。"""
    ledger = load_lifecycle_ledger(ledger_path)
    now = time.time()
    cur = set(current_keys)
    changed = False
    for key, rec in ledger.get("findings", {}).items():
        if key not in cur and rec.get("state") != LIFECYCLE_FIXED:
            changed = True
            rec["state"] = LIFECYCLE_FIXED
            rec["last_seen"] = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
            rec.setdefault("history", []).append({"at": rec["last_seen"], "state": LIFECYCLE_FIXED})
    if changed:
        save_lifecycle_ledger(ledger, ledger_path)
    return ledger


# ---------------------------------------------------------------------------
# 寿命账本（_runtime_cache/metrics/）
# ---------------------------------------------------------------------------
def _default_ledger_path() -> str:
    return os.path.join(_LEDGER_DIR, LIFECYCLE_FILENAME)


def load_lifecycle_ledger(path: Optional[str] = None) -> Dict[str, Any]:
    try:
        with open(path or _default_ledger_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("findings"), dict):
            return data
    except (OSError, ValueError, TypeError):
        pass
    return {
        "schema_version": LIFECYCLE_SCHEMA_VERSION,
        "target": "",
        "updated_at": "",
        "findings": {},
    }


def save_lifecycle_ledger(ledger: Dict[str, Any], path: Optional[str] = None) -> str:
    out = path or _default_ledger_path()
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    ledger["schema_version"] = LIFECYCLE_SCHEMA_VERSION
    ledger["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(ledger, f, ensure_ascii=False, indent=2)
    return out


def _upsert_ledger(ledger: Dict[str, Any], findings: List[Dict[str, Any]],
                   target: str = "") -> Dict[str, Any]:
    now = time.time()
    stamp = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
    store = ledger.setdefault("findings", {})
    for f in findings:
        key = f.get("_lc_key") or lifecycle_key(f)
        rec = store.get(key)
        if rec is None:
            rec = {
                "key": key,
                "url": str(f.get("url", "")),
                "type": str(f.get("type", "")),
                "method": str(f.get("method", "") or "get"),
                "parameter": str(f.get("parameter", "") or ""),
                "severity": str(f.get("severity", "") or ""),
                "first_seen": stamp,
                "last_seen": stamp,
                "scan_count": 1,
                "state": str(f.get("lifecycle") or LIFECYCLE_NEW),
                "history": [{"at": stamp, "state": str(f.get("lifecycle") or LIFECYCLE_NEW)}],
            }
            store[key] = rec
        else:
            rec["scan_count"] = int(rec.get("scan_count") or 0) + 1
            rec["last_seen"] = stamp
            cur_state = str(f.get("lifecycle") or LIFECYCLE_NEW)
            if cur_state == LIFECYCLE_RECONFIRMED and rec.get("state") == LIFECYCLE_FIXED:
                cur_state = LIFECYCLE_RECONFIRMED  # 曾修过又重现 -> 回持续，最坏状态优先
            rec["state"] = cur_state
            rec["severity"] = rec.get("severity") or str(f.get("severity", "") or "")
            hist = rec.setdefault("history", [])
            if not hist or hist[-1].get("state") != cur_state:
                hist.append({"at": stamp, "state": cur_state})
    if target:
        ledger["target"] = str(target)
    return ledger


# ---------------------------------------------------------------------------
# 报告分组（SP10.3 治理台账视角）
# ---------------------------------------------------------------------------
def group_by_lifecycle(report: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """按 finding.lifecycle 分组并注入 report.lifecycle_groups / lifecycle_summary。"""
    findings = list((report or {}).get("vulnerabilities") or [])
    grouped = _group(findings)
    report["lifecycle_groups"] = grouped
    report["lifecycle_summary"] = {k: len(v) for k, v in grouped.items() if v}
    return grouped


__all__ = [
    "apply_lifecycle", "migrate", "group_by_lifecycle", "mark_fixed_in_ledger",
    "lifecycle_key", "load_lifecycle_ledger", "save_lifecycle_ledger",
    "LIFECYCLE_NEW", "LIFECYCLE_RECONFIRMED", "LIFECYCLE_FIXED", "LIFECYCLE_DEPRECATED",
    "LIFECYCLE_FILENAME", "LIFECYCLE_SCHEMA_VERSION",
]
