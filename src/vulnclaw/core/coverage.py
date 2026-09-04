# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/coverage.py
"""SP3 机器事实覆盖账本：asset x engine x status -> coverage.json（审计口径）。

strix 的 coverage 分 agent_reported（agent 自述）与 machine_observed（运行时事实），
并明说"agent 自述会造成幻觉"。本模块只做 machine_observed：引擎执行路径是确定性的，
每次 run_engine（或协调器/编排器直接调用）都落一行账，干净扫描也能回答
"检查了什么、哪些引擎被跳过/失败、为什么"。

账本行：asset | engine | status(ran/skipped/failed/blocked) | reason | findings | duration
聚合：
  - 引擎汇总（每引擎覆盖了哪些资产 / 失败次数）
  - 资产汇总（每资产跑了多少引擎 / 全过的干净面）
  - gaps（注册引擎全集 - 已记录引擎 -> 未覆盖；或已记录但 failed/blocked）
complete 标记：扫描闸门由调用方传入（scan_complete），绝不自行补写。
"""
import json
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from vulnclaw.core.logger import logger

COVERAGE_FILENAME = "coverage.json"
COVERAGE_SCHEMA_VERSION = 1

STATUS_RAN = "ran"
STATUS_SKIPPED = "skipped"
STATUS_FAILED = "failed"
STATUS_BLOCKED = "blocked"
VALID_STATUS = {STATUS_RAN, STATUS_SKIPPED, STATUS_FAILED, STATUS_BLOCKED}


class CoverageLedger:
    """机器事实覆盖账本。线程/协程内追加，交付时输出 JSON。"""

    def __init__(self, target: str = "", started_at: Optional[float] = None):
        self.target = target or ""
        self.started_at = started_at or time.time()
        self.completed_at: Optional[float] = None
        self.scan_complete: bool = False
        self._rows: List[Dict[str, Any]] = []

    # ---------- 记录 ----------
    def record(
        self,
        asset: str,
        engine: str,
        status: str,
        reason: str = "",
        findings: int = 0,
        duration: Optional[float] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        if status not in VALID_STATUS:
            status = STATUS_BLOCKED
        self._rows.append({
            "asset": str(asset or ""), "engine": str(engine or ""), "status": status,
            "reason": reason or "", "findings": int(findings or 0),
            "duration": duration if duration is not None else round(time.time() - self.started_at, 3),
            "ts": round(time.time(), 3),
            **(extra or {}),
        })

    def record_run(self, asset: str, engine: str, findings: int = 0,
                   duration: Optional[float] = None) -> None:
        self.record(asset, engine, STATUS_RAN, findings=findings, duration=duration)

    def record_skipped(self, asset: str, engine: str, reason: str) -> None:
        self.record(asset, engine, STATUS_SKIPPED, reason=reason)

    def record_failed(self, asset: str, engine: str, reason: str) -> None:
        self.record(asset, engine, STATUS_FAILED, reason=reason)

    def record_blocked(self, asset: str, engine: str, reason: str) -> None:
        self.record(asset, engine, STATUS_BLOCKED, reason=reason)

    # ---------- 上下文管理器（异常自动标记 failed） ----------
    def track(self, asset: str, engine: str):
        return _TrackGuard(self, asset, engine)

    # ---------- 聚合 ----------
    def _rollup(self, rows_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        by_engine: Dict[str, Dict[str, Any]] = {}
        by_asset: Dict[str, Dict[str, Any]] = {}
        for r in rows_list:
            eng = by_engine.setdefault(r["engine"], {"ran": 0, "skipped": 0, "failed": 0,
                                                     "blocked": 0, "assets": set(), "findings": 0})
            eng[r["status"]] = eng.get(r["status"], 0) + 1
            eng["assets"].add(r["asset"])
            eng["findings"] += int(r.get("findings") or 0)
            ast = by_asset.setdefault(r["asset"], {"ran": 0, "skipped": 0, "failed": 0,
                                                   "blocked": 0, "engines": set(), "findings": 0})
            ast[r["status"]] = ast.get(r["status"], 0) + 1
            ast["engines"].add(r["engine"])
            ast["findings"] += int(r.get("findings") or 0)
        out_eng = {k: {**{s: v[s] for s in VALID_STATUS}, "assets": sorted(v["assets"]),
                        "findings": v["findings"]} for k, v in by_engine.items()}
        out_ast = {k: {**{s: v[s] for s in VALID_STATUS}, "engines": sorted(v["engines"]),
                        "findings": v["findings"]} for k, v in by_asset.items()}
        return {"by_engine": out_eng, "by_asset": out_ast}

    def gaps(self, engine_fullset: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """未覆盖 / 失败 / 被阻断的引擎集合（审计红线）。"""
        gaps: List[Dict[str, Any]] = []
        ro = self._rollup(self._rows)
        blocked_or_failed = [e for e, m in ro["by_engine"].items()
                             if m["failed"] > 0 or m["blocked"] > 0]
        for e in blocked_or_failed:
            gaps.append({"engine": e, "issue": "failed_or_blocked",
                         "ran": ro["by_engine"][e]["ran"]})
        if engine_fullset:
            ran_set = {e for e, m in ro["by_engine"].items() if m["ran"] > 0}
            for e in engine_fullset:
                if e not in ran_set:
                    gaps.append({"engine": e, "issue": "never_ran", "ran": 0})
        return gaps

    # ---------- 输出 ----------
    def snapshot(self, engine_fullset: Optional[List[str]] = None,
                 complete: bool = False) -> Dict[str, Any]:
        if complete is not None:
            self.scan_complete = bool(complete)
        rollup = self._rollup(self._rows)
        total_ok = sum(m["ran"] for m in rollup["by_engine"].values())
        return {
            "schema_version": COVERAGE_SCHEMA_VERSION,
            "target": self.target,
            "started_at": datetime.fromtimestamp(self.started_at).strftime("%Y-%m-%d %H:%M:%S"),
            "completed_at": (datetime.fromtimestamp(self.completed_at or time.time())
                             .strftime("%Y-%m-%d %H:%M:%S")),
            "complete": self.scan_complete,
            "source": "machine_observed",
            "rows": self._rows,
            "rollup": rollup,
            "gaps": self.gaps(engine_fullset),
            "stats": {
                "assets_covered": len(rollup["by_asset"]),
                "engine_runs": len(self._rows),
                "successful_runs": total_ok,
                "findings_total": sum(r.get("findings") or 0 for r in self._rows),
            },
        }

    def write(self, out_path: Optional[str] = None, engine_fullset: Optional[List[str]] = None,
              complete: bool = False) -> str:
        obj = self.snapshot(engine_fullset=engine_fullset, complete=complete)
        path = out_path or os.path.join("_runtime_cache", "metrics", COVERAGE_FILENAME)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        logger.info("coverage 账本已落盘: %s (rows=%d, complete=%s)",
                    path, len(obj["rows"]), obj["complete"])
        return path


# ---------- P4-2: 进程级账本单例（扫描全程共用；记录仅 append，协程安全） ----------
_LEDGER: Optional[CoverageLedger] = None


def get_coverage_ledger(target: str = "") -> CoverageLedger:
    """进程级账本单例：引擎调用路径自动记账，收尾由报告层 write 落盘。"""
    global _LEDGER
    if _LEDGER is None:
        _LEDGER = CoverageLedger(target=target)
    return _LEDGER


def reset_coverage_ledger(target: str = "") -> CoverageLedger:
    """显式重置（新扫描开始时调用，避免跨扫描串账）。"""
    global _LEDGER
    _LEDGER = CoverageLedger(target=target)
    return _LEDGER


class _TrackGuard:
    """with ledger.track(asset, engine) as row: ... —— 异常自动记为 failed。"""

    def __init__(self, ledger: CoverageLedger, asset: str, engine: str):
        self._ledger = ledger
        self._asset = asset
        self._engine = engine
        self._start = time.time()

    def __enter__(self) -> dict:
        return {"asset": self._asset, "engine": self._engine}

    def __exit__(self, exc_type, exc, tb) -> bool:
        dur = round(time.time() - self._start, 3)
        if exc_type is not None:
            self._ledger.record_failed(self._asset, self._engine, "exeception: %s" % (exc or exc_type))
            return False  # 不吞异常
        self._ledger.record_run(self._asset, self._engine, duration=dur)
        return True


async def run_engine_tracked(
    engine_name: str,
    ledger: Optional[CoverageLedger],
    target: str = None,
    url: str = None,
    param: str = None,
    session=None,
    **kwargs,
) -> List[Dict[str, Any]]:
    """scanner.run_engine 的覆盖账本包装（SP3 接线点，供 MCP/协调器/编排器复用）。

    任一调用都会在 ledger 上落一行；无 ledger 时等价于直接调用 scanner.run_engine。
    """
    from vulnclaw.core.scanner import run_engine
    asset = target or url or ""
    if ledger is None:
        return await run_engine(engine_name, target=target, url=url, param=param,
                                session=session, **kwargs) or []
    _t0 = time.time()
    try:
        findings = await run_engine(engine_name, target=target, url=url, param=param,
                                    session=session, **kwargs) or []
    except Exception as exc:  # noqa: BLE001
        ledger.record_failed(asset, engine_name, str(exc))
        raise
    ledger.record_run(asset, engine_name, findings=len(findings),
                      duration=round(time.time() - _t0, 3))
    return findings


__all__ = [
    "CoverageLedger", "run_engine_tracked",
    "COVERAGE_FILENAME", "COVERAGE_SCHEMA_VERSION",
    "STATUS_RAN", "STATUS_SKIPPED", "STATUS_FAILED", "STATUS_BLOCKED",
]