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


def draft_component_cves(eco: str, pkg: str, version: str = "") -> Dict[str, Any]:
    """方向3（P2-③，2026-09-15）：组件 KB 命中 → CVE 声明草稿。

    供 recon/依赖审计侧调用：发现目标用了 (pkg, version) → 查 OSV KB
    自动生成组件声明草稿（人审后并入 builtin）。开关复用 enable_growth_ingest。
    """
    if not _flag(GROWTH_INGEST_KEY):
        return {"skipped": True}
    try:
        from vulnclaw.growth.component_osv_ingest import ComponentOsvIngest
        d = ComponentOsvIngest().ingest(eco, pkg, version)
        return d or {"no_kb_hit": True, "eco": eco, "pkg": pkg, "version": version}
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"growth: 组件 CVE 草稿失败（忽略）: {exc}")
        return {"error": str(exc)}


def adaptive_payloads(
    vuln_type: str,
    tech_stack: Optional[List[str]] = None,
    k: int = 3,
) -> List[str]:
    """方向2 供给端：按 漏洞类型 x 技术栈 返回历史有效载荷（默认关返回空）。

    供 exploit_chain / taskgen 复用；返回的 payload 均未被误报污染。

    T11 影子模式：主开关未开时**仍照常计算**，把命中情况计入影子统计，
    但**返回空**（不注入、不改变任何行为）——用真实流量积累"该不该翻转
    主开关"的数据，而不是拍脑袋裸开主链路。
    """
    live = _flag(GROWTH_FEEDBACK_KEY)
    if not live and not _shadow_enabled():
        return []
    try:
        from vulnclaw.growth.feedback_ledger import get_feedback_ledger
        rec = get_feedback_ledger().recommend_payloads(vuln_type, tech_stack, k)
    except Exception:  # noqa: BLE001
        return []
    _SHADOW_STATS["recommend_calls"] += 1
    if rec:
        _SHADOW_STATS["recommend_hits"] += 1
        _SHADOW_STATS["recommend_payloads"] += len(rec)
    return rec if live else []


# ---------------- 读取端：强误报抑制（2026-09-15 方案3） ----------------
# 幂等成本控制：账本为追加式 JSONL，按文件 mtime 缓存签名，引擎高频调用不重扫。
_SIG_CACHE: Dict[str, Any] = {}

# ---------------- T11 影子模式统计（2026-09-16） ----------------
# 目的：把"写账本"推进到"改行为"之前，先用真实流量回答两个问题——
#   ① 推荐到底有没有货？（推荐命中率 = 有推荐次数 / 调用次数）
#   ② 抑制会不会误杀？（抑制命中率 = 被判误报条目 / 判定条目）
# 影子期只统计不干预，两个率稳定后再决定翻转 enable_growth_feedback。
_SHADOW_STATS: Dict[str, Any] = {
    "recommend_calls": 0,     # 推荐被调用次数
    "recommend_hits": 0,      # 实际有推荐的次数（账本有货且未被污染）
    "recommend_payloads": 0,  # 累计推荐出的 payload 条数
    "suppress_calls": 0,      # 抑制判定条目数
    "suppress_hits": 0,       # 命中抑制签名的条目数（若开主开关会被拦下）
}


def _shadow_enabled() -> bool:
    """影子模式开关（默认开）：主开关关闭时是否仍"跑判定但只统计"。"""
    try:
        from vulnclaw.config.settings import settings
        return bool(getattr(settings, "growth_shadow_mode", True))
    except Exception:  # noqa: BLE001 - settings 不可用时保守开启
        return True


def shadow_stats() -> Dict[str, Any]:
    """影子期统计快照（含两个命中率）。"""
    s = dict(_SHADOW_STATS)
    rc = s.get("recommend_calls", 0)
    sc = s.get("suppress_calls", 0)
    s["recommend_hit_rate"] = round(s["recommend_hits"] / rc, 4) if rc else 0.0
    s["suppress_hit_rate"] = round(s["suppress_hits"] / sc, 4) if sc else 0.0
    return s


def shadow_report(path: str = "") -> Dict[str, Any]:
    """T11 验收物：产出"推荐命中率 / 抑制命中率"报表并落盘。

    报表同时记录当前两个开关的取值，避免"脱离配置读报表"导致误判
    （例如影子率很高但主开关早已打开，那不是影子数据）。
    """
    stats = shadow_stats()
    stats["live_enabled"] = bool(_flag(GROWTH_FEEDBACK_KEY))
    stats["shadow_enabled"] = bool(_shadow_enabled())
    try:
        import json as _json
        import os as _os
        out = path or "_runtime_cache/growth_shadow_report.json"
        _os.makedirs(_os.path.dirname(out) or ".", exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            _json.dump(stats, fh, ensure_ascii=False, indent=2)
        stats["report_path"] = out
    except Exception:  # noqa: BLE001 - 报表落盘失败不影响主流程
        pass
    return stats


def _active_signatures(min_shadow: int = 2) -> List[str]:
    """读取账本强误报签名（mtime 缓存；失败静默返回空）。

    签名形如 "<vuln_type>|<归一化参数>"，来自 feedback_ledger.suppressed_signatures。
    """
    try:
        import os as _os
        from vulnclaw.growth.feedback_ledger import get_feedback_ledger
        ledger = get_feedback_ledger()
        path = getattr(ledger, "_path", "") or ""
        mtime = _os.path.getmtime(path) if path and _os.path.exists(path) else 0.0
        cached = _SIG_CACHE.get("sigs")
        if cached and cached.get("mtime") == mtime and cached.get("path") == path \
                and cached.get("min_shadow") == min_shadow:
            return cached["sigs"]
        sigs = ledger.suppressed_signatures(min_shadow=min_shadow)
        _SIG_CACHE["sigs"] = {"mtime": mtime, "path": path,
                              "min_shadow": min_shadow, "sigs": sigs}
        return sigs
    except Exception:  # noqa: BLE001
        return []


def maybe_suppressed_signatures(min_shadow: int = 2) -> List[str]:
    """方向2 读取端（查询通道）：当前账本强误报抑制名单（默认关返回空）。

    供 SOC/扫描侧审计展示；命中这些签名的 (漏洞类型, 参数) 将不进报告。
    """
    if not _flag(GROWTH_FEEDBACK_KEY):
        return []
    return _active_signatures(min_shadow=min_shadow)


def _suppression_key(vuln_type: str, param: str) -> str:
    """与账本签名同口径生成匹配键（必须与 suppressed_signatures 完全一致）。"""
    try:
        from vulnclaw.growth.feedback_ledger import _norm_param
    except Exception:  # noqa: BLE001
        _norm_param = lambda s: str(s or "").strip().lower()[:64]  # noqa: E731
    vt = str(vuln_type or "").strip().lower()
    np_ = _norm_param(param)
    return f"{vt}|{np_}" if np_ else f"{vt}|*"


def suppress_findings(
    findings: Any,
    min_shadow: int = 2,
) -> tuple:
    """方向2 读取端（过滤通道）：按账本强误报指纹过滤 findings。

    - findings：单条 dict 或 list[dict]；
    - 默认关（enable_growth_feedback=False）原样返回 (findings, [])；
    - 返回 (kept, suppressed)：kept 为放行集合，suppressed 为命中抑制条目
      （移出主链路但不丢弃，供统计/审计）。失败静默不改动输入。
    """
    live = _flag(GROWTH_FEEDBACK_KEY)
    if not live and not _shadow_enabled():
        return (findings, [])
    single = isinstance(findings, dict)
    items = [findings] if single else [f for f in (findings or []) if isinstance(f, dict)]
    if not items:
        return (findings, [])
    sigs = set(_active_signatures(min_shadow=min_shadow))
    if not sigs:
        return (findings, [])
    kept: List[Dict[str, Any]] = []
    suppressed: List[Dict[str, Any]] = []
    for f in items:
        vt = str(f.get("type") or f.get("vuln_type") or "")
        pm = str(f.get("parameter") or f.get("param") or "")
        if _suppression_key(vt, pm) in sigs:
            suppressed.append(f)
        else:
            kept.append(f)
    # T11 影子统计：按条目计（命中率 = 被判误报条目 / 判定条目）
    _SHADOW_STATS["suppress_calls"] += len(items)
    _SHADOW_STATS["suppress_hits"] += len(suppressed)
    # 影子模式（主开关未开）→ 全放行，仅统计不拦截
    if not live:
        return (findings, [])
    if single:
        return (kept[0] if kept else None, suppressed)
    return (kept, suppressed)


def absorb_reports_dir(
    reports_dir: str = "_runtime_cache/reports",
    limit: int = 0,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """存量报告批量回灌（飞轮点火）：把历史扫描报告灌入经验账本。

    - 幂等：按 (vuln_type|param|payload|target) 指纹跳过已导入条目，
      重复执行不产生重复经验；
    - 不依赖开关（仅显式调用时才执行），fail-silent 保持主流程零影响；
    - limit：最多处理多少份报告（0=全部）；dry_run：只统计不落盘。
    """
    import glob as _glob
    import json as _json
    import os as _os

    stats: Dict[str, Any] = {"reports_found": 0, "reports_used": 0,
                             "findings": 0, "absorbed": 0,
                             "skipped_dupes": 0, "errors": 0}
    try:
        from vulnclaw.growth.feedback_ledger import get_feedback_ledger
        ledger = get_feedback_ledger()
        # 幂等基准：账本里已有指纹集合
        seen = set()
        for row in ledger.rows():
            if str(row.get("kind")) != "finding":
                continue
            seen.add((
                str(row.get("vuln_type") or ""),
                str(row.get("param") or ""),
                str(row.get("payload") or ""),
                str(row.get("target_host") or ""),
            ))
        paths = sorted(_glob.glob(_os.path.join(reports_dir, "*.json")))
        if limit and limit > 0:
            paths = paths[:limit]
        stats["reports_found"] = len(paths)
        for p in paths:
            try:
                with open(p, "r", encoding="utf-8") as fh:
                    report = _json.load(fh)
            except Exception:  # noqa: BLE001 - 单份损坏不阻断整批
                stats["errors"] += 1
                continue
            if not isinstance(report, dict):
                stats["errors"] += 1
                continue
            vulns = report.get("vulnerabilities") or report.get("findings") or []
            if not vulns:
                continue
            target = str(report.get("target") or "")
            # host 口径必须与 feedback_ledger 写入的 target_host 完全一致
            # （_host_of：只取 hostname，去 scheme/端口/path），否则幂等指纹永不匹配。
            host = str(report.get("target_host") or "")
            if not host:
                from urllib.parse import urlparse as _urlparse
                try:
                    host = _urlparse(target).hostname or target.split("/")[0]
                except Exception:  # noqa: BLE001
                    host = target
            fresh = []
            for v in vulns:
                if not isinstance(v, dict):
                    continue
                fp = (
                    str(v.get("type") or v.get("vuln_type") or ""),
                    str(v.get("parameter") or v.get("param") or ""),
                    str(v.get("payload") or ""),
                    host,
                )
                if fp in seen:
                    stats["skipped_dupes"] += 1
                    continue
                seen.add(fp)
                fresh.append(v)
            stats["findings"] += len(vulns)
            stats["reports_used"] += 1
            if fresh and not dry_run:
                stats["absorbed"] += ledger.absorb_scan(fresh, target=target)
        logger.info(
            f"growth: 存量报告回灌 {stats['reports_used']}/{stats['reports_found']} 份，"
            f"吸收 {stats['absorbed']} 条（跳过重复 {stats['skipped_dupes']}，"
            f"解析失败 {stats['errors']}）")
    except Exception as exc:  # noqa: BLE001
        stats["error"] = str(exc)
        logger.debug(f"growth: 存量报告回灌失败: {exc}")
    return stats