#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""组件维度 CVE→声明流水线（P2-③，2026-09-15）。

数据腿零改动：OSV 离线 KB（thirdparty/osv/component_kb.json，由
scripts/build_component_kb.py 生成）+ vulnspec.model._kb_lookup 已内建
"生态+包名 → 影响区间/OSV 漏洞 id"查询（区间字段 i/f/la/id）。
本模块补齐生产腿：

    (eco, pkg[, version]) → KB 命中 → 组件声明草稿（vulnspec 签名格式）
    → 确定性验证 → 草稿台账（JSONL）→ 人工 review

为什么独立于 cve_ingest.py：cve_ingest 消费 NVD records（正文关键词型
nuclei 规则草稿）；本模块消费 OSV KB（版本区间型组件声明）——数据源、
草稿形态、验证判据都不同。共享"drafted→validated"状态机语义。

约定：
- KB 缺失/损坏 → 一律返回 None（绝不因数据问题产出草稿）；
- 幂等：同 rule_id 已有 validated 草稿 → skipped_existing，不重复落盘；
- fail-silent：由 bridges 层调用时兜底，异常不进主流程；
- vulnerable_below 取 KB 的 fixed 或 last_affected（单区间近似，
  原始区间保留在 kb_intro/kb_fixed/kb_last_affected 供人审）。
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from vulnclaw.core.logger import logger

try:
    from vulnclaw.core.settings import PROJECT_CACHE_DIR
except Exception:  # pragma: no cover
    PROJECT_CACHE_DIR = os.path.join("_runtime_cache")

_DEFAULT_DRAFTS = os.path.join(PROJECT_CACHE_DIR, "growth", "component_osv_drafts.jsonl")
_DEFAULT_PROMOTED = os.path.join(PROJECT_CACHE_DIR, "growth", "promoted_component_sigs.json")


def _pkg_pattern(pkg: str) -> str:
    """生成依赖清单型版本捕获正则（对齐 builtin dependency_manifest 风格）。

    覆盖 requirements.txt（pkg==1.2.3）、package.json（"pkg": "1.2.3"）
    与 pom.xml/go.mod 的常见形态；版本捕获组 = group(1)。
    """
    esc = re.escape(pkg)
    return rf'"?{esc}"?\s*[:=]+\s*"?[\^~>=< ]*(\d+(?:\.\d+)*)'


class ComponentOsvIngest:
    """OSV KB → 组件声明草稿（确定性骨架，人审后并入 builtin 声明）。"""

    def __init__(self, drafts_path: Optional[str] = None,
                 promoted_path: Optional[str] = None):
        self._drafts_path = drafts_path or _DEFAULT_DRAFTS
        self._promoted_path = promoted_path or _DEFAULT_PROMOTED
        try:
            os.makedirs(os.path.dirname(self._drafts_path), exist_ok=True)
        except Exception:
            logger.debug("growth: component drafts 目录创建失败（忽略）")

    # ---------------- 数据腿 ----------------
    def kb_hits(self, eco: str, pkg: str) -> List[Dict[str, str]]:
        """KB 查询（缺失/损坏 → 空，绝不抛错）。"""
        try:
            from vulnclaw.core.vulnspec.model import _kb_lookup
            return _kb_lookup(eco, pkg) or []
        except Exception:
            return []

    # ---------------- 草稿生成 ----------------
    def draft(self, eco: str, pkg: str, version: str = "") -> Optional[Dict[str, Any]]:
        """(生态, 包[, 已知版本]) → 草稿；KB 未命中/版本已修复 → None。"""
        hits = self.kb_hits(eco, pkg)
        if not hits:
            return None
        affected = hits
        if version:
            try:
                from vulnclaw.core.vulnspec.model import _version_in_range
                affected = [
                    h for h in hits
                    if _version_in_range(
                        version,
                        str(h.get("i") or ""),
                        str(h.get("f") or ""),
                        str(h.get("la") or ""),
                    )
                ]
            except Exception:
                affected = hits  # 区间判定异常 → 保守保留全部区间交人审
            if not affected:
                return None  # 版本落在所有区间之外（已修复/未引入）→ 无声明可产
        cves = sorted({str(h.get("id") or "").strip() for h in affected if h.get("id")})
        if not cves:
            return None
        lib = f"{eco}:{pkg}"
        rid = "growth-comp-" + re.sub(r"[^a-z0-9-]+", "-", f"{eco}-{pkg}".lower())[:40]
        rid += "-" + cves[0].lower()
        sigs = []
        for h in affected[:20]:
            cve = str(h.get("id") or "").strip()
            if not cve:
                continue
            sigs.append({
                "lib": lib,
                "pattern": _pkg_pattern(pkg),
                "vulnerable_below": str(h.get("f") or h.get("la") or ""),
                "cve": cve,
                "kb_intro": str(h.get("i") or ""),
                "kb_fixed": str(h.get("f") or ""),
                "kb_last_affected": str(h.get("la") or ""),
            })
        return {
            "kind": "component_osv",
            "rule_id": rid,
            "eco": eco,
            "pkg": pkg,
            "version_queried": version or "",
            "lib": lib,
            "cves": cves,
            "signatures": sigs,
            "status": "drafted",
            "draft_ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }

    # ---------------- 验证 ----------------
    def validate(self, draft: Dict[str, Any]) -> Dict[str, Any]:
        """确定性校验：签名非空 + pattern 可编译 + CVE id 存在。"""
        problems: List[str] = []
        sigs = draft.get("signatures") or []
        if not sigs:
            problems.append("signatures 为空")
        for s in sigs:
            if not s.get("cve"):
                problems.append("存在无 CVE id 的签名")
                break
            pat = str(s.get("pattern") or "")
            try:
                re.compile(pat)
            except re.error:
                problems.append(f"pattern 非法: {pat}")
                break
            if not s.get("vulnerable_below"):
                problems.append(f"缺脆弱上界: {s.get('cve')}")
                break
        if problems:
            draft["status"] = "invalid"
            draft["invalid_reason"] = "; ".join(problems)
        else:
            draft["status"] = "validated"
            draft["validated_ts"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        return draft

    # ---------------- 台账 ----------------
    def drafts(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self._drafts_path):
            return []
        out: List[Dict[str, Any]] = []
        try:
            with open(self._drafts_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except Exception:
            logger.debug("growth: component drafts 读取失败（忽略）")
        return out

    def _append(self, draft: Dict[str, Any]) -> None:
        with open(self._drafts_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(draft, ensure_ascii=False) + "\n")

    # ---------------- 主流程 ----------------
    def ingest(self, eco: str, pkg: str, version: str = "") -> Optional[Dict[str, Any]]:
        """单组件摄入：draft → 幂等检查 → validate → 落台账。"""
        d = self.draft(eco, pkg, version)
        if d is None:
            return None
        for existing in self.drafts():
            if (existing.get("rule_id") == d["rule_id"]
                    and existing.get("status") in ("validated", "drafted")):
                d["status"] = "skipped_existing"
                return d
        d = self.validate(d)
        self._append(d)
        return d

    def ingest_batch(self, libs: Iterable[Tuple[str, ...]]) -> Dict[str, int]:
        """批量摄入 [(eco, pkg, version?), ...]。"""
        stats = {"total": 0, "validated": 0, "drafted": 0, "invalid": 0,
                 "skipped_existing": 0, "no_kb": 0}
        for item in libs:
            eco, pkg = str(item[0]), str(item[1])
            version = str(item[2]) if len(item) > 2 else ""
            stats["total"] += 1
            try:
                d = self.ingest(eco, pkg, version)
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"growth: 组件摄入异常 {eco}/{pkg}: {exc}")
                stats["no_kb"] += 1
                continue
            if d is None:
                stats["no_kb"] += 1
            elif d.get("status") == "validated":
                stats["validated"] += 1
            elif d.get("status") == "invalid":
                stats["invalid"] += 1
            elif d.get("status") == "skipped_existing":
                stats["skipped_existing"] += 1
            else:
                stats["drafted"] += 1
        return stats

    # ---------------- 晋升（人审后）----------------
    def promoted(self) -> Dict[str, Any]:
        """已晋升台账（rule_id → 条目）。缺失/损坏 → 空。"""
        if not os.path.exists(self._promoted_path):
            return {}
        try:
            with open(self._promoted_path, "r", encoding="utf-8") as fh:
                return json.load(fh) or {}
        except Exception:  # noqa: BLE001
            logger.debug("growth: promoted component sigs 读取失败（视为空）")
            return {}

    def promote(self, rule_id: str, note: str = "") -> bool:
        """晋升一条已 validated 草稿 → promoted 台账（builtin 构建时注入生效）。

        复用 CveIngest.promote 语义（2026-09-15 P1-6 闭环）：幂等（同 rule_id
        只晋升一次）；仅 validated 可晋升；签名只保留检测所需四键
        （lib/pattern/vulnerable_below/cve），kb_* 区间元数据不进检测面。
        """
        draft = next(
            (d for d in self.drafts() if d.get("rule_id") == rule_id), None)
        if not draft:
            return False
        if draft.get("status") != "validated":
            logger.warning(
                f"growth: {rule_id} 状态 {draft.get('status')}，仅 validated 可晋升")
            return False
        promoted = self.promoted()
        if rule_id in promoted:
            return False
        promoted[rule_id] = {
            "kind": draft.get("kind"),
            "eco": draft.get("eco"),
            "pkg": draft.get("pkg"),
            "lib": draft.get("lib"),
            "cves": draft.get("cves") or [],
            "signatures": [
                {k: s.get(k) for k in ("lib", "pattern", "vulnerable_below", "cve")}
                for s in (draft.get("signatures") or [])
            ],
            "promoted_ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "note": str(note)[:200],
        }
        try:
            with open(self._promoted_path, "w", encoding="utf-8") as fh:
                json.dump(promoted, fh, ensure_ascii=False, indent=2)
        except OSError as exc:
            logger.debug(f"growth: promoted sigs 写盘失败: {exc}")
            return False
        return True
