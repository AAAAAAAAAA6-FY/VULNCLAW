# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""方向5 本地规则集市 (rule_bazaar.py)

让平台"靠采用量长大"的本地可行版：导入外部/社区 nuclei YAML 规则 ->
确定性校验（必需段/severity 合法性）-> 去重指纹 -> 按 来源信誉 x 成长命中率
打分排名 -> 落入可复用规则池，供引擎/任务"采用"。

生态发布（真实社区上传/分发/信任治理）依赖用户基数，个人项目转不起来，
只留 community_publish 接口文档占位，不实现网络侧。

设计约束：
- 全部本地确定性：校验/去重/评分不调用模型，零成本。
- 失败隔离：单条规则坏 YAML 只跳过并记录，不中断导入。
- 复用池由 nuclei -t 目录加载，天然兼容现有三腿机制。
"""
import glob
import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List, Optional

import yaml

from vulnclaw.core.logger import logger

_RULES_POOL = os.path.join("_runtime_cache", "growth", "rules_pool")
_POOL_INDEX = os.path.join(_RULES_POOL, "index.jsonl")
_REQUIRED_SEG = ("id:", "info:", "http:", "matchers:")
_VALID_SEVERITY = {"info", "low", "medium", "high", "critical"}
_SOURCE_REPUTATION = {"github_verified": 3, "community": 2, "local": 1}


def _rule_fingerprint(rule: Dict[str, Any]) -> str:
    raw = json.dumps(rule, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _looks_like_yaml_text(text: str) -> bool:
    first_lines = [ln for ln in text.splitlines() if ln.strip()][:8]
    return any(ln.startswith(("id:", "info:", "requests:", "http:")) for ln in first_lines)


def _parse_or_skip(path: str) -> Optional[Dict[str, Any]]:
    """解析单个规则文件：非 YAML/坏 YAML/缺段 返回 None 并记录跳过原因。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except Exception as exc:  # noqa: BLE001
        return {"skip": str(exc), "path": path}
    if not _looks_like_yaml_text(text):
        return {"skip": "非规则 YAML 文本", "path": path}
    try:
        data = yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001
        return {"skip": f"YAML 解析失败: {exc}", "path": path}
    if not isinstance(data, dict):
        return {"skip": "顶层非映射", "path": path}
    block = {k.lower() + ":" for k in data}
    missing = [seg for seg in _REQUIRED_SEG if seg not in block]
    if missing:
        return {"skip": f"缺必需段 {missing}", "path": path}
    severity = str((data.get("info") or {}).get("severity", "")).lower()
    if severity and severity not in _VALID_SEVERITY:
        return {"skip": f"severity 非法: {severity}", "path": path}
    rule_id = str(data.get("id", "")).strip()
    if not rule_id:
        return {"skip": "id 缺失", "path": path}
    return {
        "path": path, "rule_id": rule_id,
        "name": str((data.get("info") or {}).get("name", rule_id)),
        "severity": severity or "info",
        "tags": str((data.get("info") or {}).get("tags", "")),
        "raw_yaml": text[:4000],
        "payload": _first_attack_payload(data),
    }


def _first_attack_payload(data: Dict[str, Any]) -> str:
    """从 http 段的 payload/body 里提取第一个攻击载荷（用于成长命中统计的关联）。"""
    http = data.get("http") or data.get("requests")
    if isinstance(http, list) and http and isinstance(http[0], dict):
        req = http[0]
        for k in ("payload", "body"):
            val = req.get(k)
            if isinstance(val, str) and val.strip():
                return val.strip()[:120]
        headers = req.get("headers")
        if isinstance(headers, dict):
            for _k, v in headers.items():
                if isinstance(v, str) and ("'" in v or "<" in v or ".." in v):
                    return v[:120]
    return ""


class RuleBazaar:
    """本地规则集市：导入 -> 校验 -> 去重 -> 评分排名 -> 复用池。"""

    def __init__(self, pool_dir: Optional[str] = None):
        self.pool_dir = os.path.abspath(pool_dir or _RULES_POOL)
        os.makedirs(self.pool_dir, exist_ok=True)
        self.index_path = os.path.join(self.pool_dir, "pool_index.jsonl")

    # ---------------- 导入 ----------------
    def import_rules(self, pattern: str, source: str = "local") -> Dict[str, Any]:
        """导入匹配 glob 的规则文件入池（校验 + 去重指纹）。"""
        files = sorted(glob.glob(pattern, recursive=True))
        imported = skipped = dup = 0
        skip_reasons: Dict[str, int] = {}
        for path in files:
            parsed = _parse_or_skip(path)
            if not isinstance(parsed, dict) or "skip" in parsed:
                if isinstance(parsed, dict):
                    reason = str(parsed["skip"])
                    skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
                skipped += 1
                continue
            rule = {
                "source": source,
                "reputation": _SOURCE_REPUTATION.get(source, 1),
                "success_hits": 0,
                "fp_hits": 0,
                "added_ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                **{k: parsed[k] for k in ("path", "rule_id", "name", "severity", "tags", "payload", "raw_yaml")},
            }
            fp = _rule_fingerprint(rule)
            rule["fingerprint"] = fp
            if self._exists(fp):
                dup += 1
                continue
            with open(self.index_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rule, ensure_ascii=False) + "\n")
            imported += 1
        logger.info(f"rule_bazaar: 导入 {imported}（重复 {dup}，跳过 {skipped}）")
        return {
            "scanned": len(files), "imported": imported,
            "duplicates": dup, "skipped": skipped, "skip_reasons": skip_reasons,
        }

    def _exists(self, fingerprint: str) -> bool:
        if not os.path.exists(self.index_path):
            return False
        with open(self.index_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    if json.loads(line).get("fingerprint") == fingerprint:
                        return True
                except json.JSONDecodeError:
                    continue
        return False

    # ---------------- 读取 ----------------
    def rows(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not os.path.exists(self.index_path):
            return out
        with open(self.index_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    def rank_rules(self, k: int = 20) -> List[Dict[str, Any]]:
        """评分排名：来源信誉 + 成长命中(成功/误报) 加权。"""
        scored = []
        for r in self.rows():
            hits = int(r.get("success_hits", 0) or 0)
            fps = int(r.get("fp_hits", 0) or 0)
            rep = int(r.get("reputation", 1) or 1)
            hit_rate = hits / (hits + fps) if (hits + fps) > 0 else 0.0
            score = rep * (0.5 + 0.5 * hit_rate) + min(hits, 5) * 0.1
            scored.append({**r, "score": round(score, 3), "hit_rate": round(hit_rate, 3)})
        return sorted(scored, key=lambda x: (-x["score"], x["rule_id"]))[:k]

    def record_outcome(self, fingerprint: str, verdict: str) -> bool:
        """成长回灌：按指纹累计某条池内规则的成功/误报次数（追加式更新索引）。"""
        verdict = str(verdict or "").strip().lower()
        if verdict not in ("confirm", "fp"):
            return False
        rows = self.rows()
        replaced = False
        for r in rows:
            if r.get("fingerprint") != fingerprint:
                continue
            if verdict == "confirm":
                r["success_hits"] = int(r.get("success_hits", 0) or 0) + 1
            else:
                r["fp_hits"] = int(r.get("fp_hits", 0) or 0) + 1
            replaced = True
        if not replaced:
            return False
        with open(self.index_path, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        return True

    # ---------------- 复用池 ----------------
    def export_pool(self, out_dir: Optional[str] = None, top_k: int = 50) -> Dict[str, Any]:
        """把排名靠前的规则落为 nuclei 可加载的 YAML 文件（供 -t 目录复用）。"""
        out_dir = os.path.abspath(out_dir or os.path.join(self.pool_dir, "export"))
        os.makedirs(out_dir, exist_ok=True)
        written = 0
        for rule in self.rank_rules(k=top_k):
            raw = rule.get("raw_yaml")
            if not raw:
                continue
            safe_id = re.sub(r"[^0-9A-Za-z_-]", "_", rule["rule_id"])
            target = os.path.join(out_dir, f"{safe_id}.yaml")
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(raw if raw.endswith("\n") else raw + "\n")
            written += 1
        return {"export_dir": out_dir, "written": written}


__all__ = ["RuleBazaar", "rule_bazaar_stats", "community_publish"]


def rule_bazaar_stats() -> Dict[str, Any]:
    """集市规模一眼看全。"""
    bz = RuleBazaar()
    rows = bz.rows()
    return {"rules": len(rows), "sources": sorted({r.get("source", "?") for r in rows})}


def community_publish() -> Dict[str, Any]:
    """社区发布占位：生态侧（上传/分发/信任治理）依赖用户基数，
    个人项目现阶段不可行；本地复用池已由 RuleBazaar.export_pool 承接。"""
    return {
        "supported": False,
        "reason": "规则市场的网络侧依赖用户生态与信任治理，暂不实现；"
                  "已落地本地版：导入/校验/去重/评分/复用池。",
    }