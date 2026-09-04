# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""方向1：威胁情报自喂养——CVE 增量摄入 -> 规则草稿 -> 验证 -> 晋升（自动成长第二腿）。

数据腿：复用现成 cve_index 索引（thirdparty/nuclei-templates/cve_index/records.jsonl，
含 cve_id/name/severity/cvss/file_path/description/components/versions 4327+ 条）。
游标：本地 {growth_dir}/ingest_cursor.json 记录已摄入条数 -> 纯增量，二次运行不重复。
草稿：确定性 nuclei YAML 骨架；enable_growth_llm 时用 LLM 增强 matcher 描述（失败静默回退）。
验证：确定性校验（severity/components/cve_id/yaml 骨架完整性），真靶机验证留待对接
      （local_lab 回归）——status 语义：drafted -> validated(结构过) -> promoted(晋升待消费)。
落盘：drafts 追加 {growth_dir}/cve_drafts.jsonl；promoted 聚合 {growth_dir}/promoted_rules.json。

设计约束：纯增量、确定性优先、LLM 仅增强不阻塞、无审计依赖外部网络拉取（数据腿已在库）。
"""
import json
import os
import time
from typing import Any, Dict, List, Optional

from vulnclaw.core.logger import logger

ALLOWED_SEVERITY = ("critical", "high", "medium", "low", "info")


def _default_cve_index() -> str:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # growth/
    return os.path.join(
        os.path.dirname(here),  # vulnclaw/
        "..", "thirdparty", "nuclei-templates", "cve_index",
    )


_YAML_TEMPLATE = """id: {rule_id}

info:
  name: {name}
  author: vulnclaw-growth
  severity: {severity}
  description: |
    {description}
  tags: {tags}

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}"
    matchers:
      - type: word
        words:
          - "{keyword}"
        part: body
"""


def _first_keyword(cve: Dict[str, Any]) -> str:
    """确定性关键词：优先 components 首项，其次 CVE ID 中的组名。"""
    comps = cve.get("components") or []
    if comps:
        return str(comps[0]).strip()
    name = str(cve.get("name") or "")
    return name.split("-")[0].strip() if name else "template"


def _yaml_quote(value: str) -> str:
    return str(value or "n/a").replace("\n", " ")[:400]


class CveIngest:
    """CVE 情报摄入与规则晋升状态机。"""

    def __init__(
        self,
        cve_index_dir: Optional[str] = None,
        growth_dir: Optional[str] = None,
    ):
        self.cve_index_dir = os.path.abspath(cve_index_dir or _default_cve_index())
        self.growth_dir = os.path.abspath(growth_dir or os.path.join("_runtime_cache", "growth"))
        os.makedirs(self.growth_dir, exist_ok=True)
        self._records_path = os.path.join(self.cve_index_dir, "records.jsonl")
        self._meta_path = os.path.join(self.cve_index_dir, "index_meta.json")
        self._cursor_path = os.path.join(self.growth_dir, "ingest_cursor.json")
        self._drafts_path = os.path.join(self.growth_dir, "cve_drafts.jsonl")
        self._promoted_path = os.path.join(self.growth_dir, "promoted_rules.json")

    # ---------------- 数据腿读取 ----------------
    def total_count(self) -> int:
        if os.path.exists(self._meta_path):
            try:
                meta = json.load(open(self._meta_path, encoding="utf-8"))
                return int(meta.get("count", 0))
            except Exception:  # noqa: BLE001
                logger.debug("cve_index meta 读取失败（忽略）")
        if os.path.exists(self._records_path):
            return _count_lines(self._records_path)
        return 0

    def cursor(self) -> int:
        if os.path.exists(self._cursor_path):
            try:
                return int(json.load(open(self._cursor_path, encoding="utf-8")).get("ingested", 0))
            except Exception:  # noqa: BLE001
                logger.debug("growth 游标读取失败，归零（忽略）")
        return 0

    def _new_records(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """按游标增量取新 CVE 条目（纯增量，不重复摄入）。"""
        start = self.cursor()
        if not os.path.exists(self._records_path):
            return []
        out: List[Dict[str, Any]] = []
        with open(self._records_path, "r", encoding="utf-8", errors="replace") as fh:
            for idx, line in enumerate(fh):
                if idx < start:
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
                if limit is not None and len(out) >= limit:
                    break
        return out

    # ---------------- 草稿生成 ----------------
    def draft(self, cve: Dict[str, Any], enable_llm: bool = False) -> Dict[str, Any]:
        """CVE 条目 -> 规则草稿（确定性 YAML 骨架 + 可选 LLM 增强描述）。"""
        cve_id = str(cve.get("cve_id") or "").strip()
        name = _yaml_quote(cve.get("name") or cve_id or "untitled")
        severity = str(cve.get("severity") or "info").strip().lower()
        description = _yaml_quote(cve.get("description") or "")
        components = [str(c) for c in (cve.get("components") or [])]
        keyword = _first_keyword(cve)
        rule_id = "growth-" + cve_id.lower().replace(" - ", "-").replace(" ", "-")
        yaml_draft = _YAML_TEMPLATE.format(
            rule_id=rule_id, name=name, severity=severity,
            description=description or "automatic draft rule", tags=",".join(components or ["cve"]),
            keyword=keyword,
        )
        return {
            "cve_id": cve_id,
            "rule_id": rule_id,
            "name": name,
            "severity": severity,
            "cvss": cve.get("cvss"),
            "components": components,
            "versions": [str(v) for v in (cve.get("versions") or [])],
            "source_file": str(cve.get("file_path") or ""),
            "yaml_draft": yaml_draft,
            "status": "drafted",
            "draft_ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "llm_enhanced": False,
        }

    def _llm_enhance(self, draft: Dict[str, Any]) -> Dict[str, Any]:
        """LLM 增强：根据漏洞描述补一个更精准的 matcher 关键词（失败静默回退）。"""
        try:
            from vulnclaw.ai.core import get_llm_client
            prompt = (
                f"CVE {draft['cve_id']}: {draft['name']}。"
                f"描述: {draft.get('source_file') and draft['cve_id']} "
            )
            # 轻量：只要求返回一个用于 HTTP 响应匹配的关键词/正则短语
            result = None
            client = get_llm_client()
            if client is not None and hasattr(client, "ask"):
                result = client.ask(
                    prompt + "从这条漏洞描述提炼 1 个可在 HTTP 响应 body 中匹配的关键词，只输出该关键词。",
                    system="你是漏洞规则优化助手，输出尽量短。",
                    temperature=0.1,
                    max_tokens=64,
                    retries=1,
                    usage_site="growth-cve",
                )
            if isinstance(result, dict):
                result = result.get("text") or result.get("content") or result.get("answer")
            kw = str(result or "").strip().splitlines()[0].strip() if result else ""
            if kw and not kw.lower().startswith(("http", "n/a", "无", "无法")):
                draft["yaml_draft"] = draft["yaml_draft"].replace(
                    '          - "{keyword}"',
                    f'          - "{_yaml_quote(kw)[:120]}"',
                    1,
                )
                draft["llm_enhanced"] = True
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"growth: CVE 规则 LLM 增强失败（保留骨架）: {exc}")
        return draft

    # ---------------- 验证 / 晋升 ----------------
    def validate(self, draft: Dict[str, Any]) -> Dict[str, Any]:
        """确定性校验：字段完整 + severity 合法 + YAML 骨架含必需段。"""
        problems = []
        if not draft.get("cve_id"):
            problems.append("cve_id 缺失")
        if draft.get("severity") not in ALLOWED_SEVERITY:
            problems.append(f"severity 非法: {draft.get('severity')}")
        if not draft.get("yaml_draft"):
            problems.append("yaml_draft 为空")
        else:
            y = draft["yaml_draft"]
            for seg in ("id:", "info:", "severity:", "http:", "matchers:"):
                if seg not in y:
                    problems.append(f"yaml 缺段 {seg}")
        if problems:
            draft["status"] = "invalid"
            draft["invalid_reason"] = "; ".join(problems)
        else:
            draft["status"] = "validated"
            draft["validated_ts"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        return draft

    def _append_draft(self, draft: Dict[str, Any]) -> None:
        with open(self._drafts_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(draft, ensure_ascii=False) + "\n")

    # ---------------- 主流程 ----------------
    def ingest_batch(self, limit: int = 50, enable_llm: bool = False) -> Dict[str, Any]:
        """增量摄入一批：新条目 -> 草稿(骨架/LLM 增强) -> 确定性验证 -> 追加台账。

        Returns:
            {"ingested": N, "drafted": N, "validated": N, "invalid": M, "errors": [...]}
        """
        records = self._new_records(limit=limit)
        if not records:
            return {"ingested": 0, "drafted": 0, "validated": 0, "invalid": 0, "errors": []}
        drafted = validated = invalid = 0
        last = self.cursor()
        errors: List[str] = []
        for cve in records:
            try:
                d = self.draft(cve, enable_llm=enable_llm)
                if enable_llm:
                    d = self._llm_enhance(d)
                d = self.validate(d)
                self._append_draft(d)
                drafted += 1
                if d["status"] == "validated":
                    validated += 1
                else:
                    invalid += 1
                last += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{cve.get('cve_id', '?')}: {exc}")
        with open(self._cursor_path, "w", encoding="utf-8") as fh:
            json.dump({"ingested": last}, fh, ensure_ascii=False)
        return {
            "ingested": len(records), "drafted": drafted,
            "validated": validated, "invalid": invalid, "errors": errors,
        }

    def promote(self, rule_id: str, note: str = "") -> bool:
        """晋升一条已 validated 草稿 -> promoted（写入 adopted 账本，供扫描侧消费）。

        幂等 key：rule_id；同一 rule_id 只晋升一次（已存在则提示）。
        """
        draft = self._find_draft(rule_id)
        if not draft:
            return False
        if draft.get("status") != "validated":
            logger.warning(f"growth: {rule_id} 状态 {draft.get('status')}，仅 validated 可晋升")
            return False
        promoted = self.promoted_rules()
        if rule_id in promoted:
            return False
        promoted[rule_id] = {
            "cve_id": draft.get("cve_id"),
            "name": draft.get("name"),
            "severity": draft.get("severity"),
            "source_file": draft.get("source_file"),
            "yaml_draft": draft.get("yaml_draft"),
            "promoted_ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "note": str(note)[:200],
        }
        with open(self._promoted_path, "w", encoding="utf-8") as fh:
            json.dump(promoted, fh, ensure_ascii=False, indent=2)
        return True

    # ---------------- 查询 ----------------
    def _find_draft(self, rule_id: str) -> Optional[Dict[str, Any]]:
        if not os.path.exists(self._drafts_path):
            return None
        with open(self._drafts_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if d.get("rule_id") == rule_id:
                    return d
        return None

    def drafts(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self._drafts_path):
            return []
        out = []
        with open(self._drafts_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    def promoted_rules(self) -> Dict[str, Any]:
        if not os.path.exists(self._promoted_path):
            return {}
        try:
            return json.load(open(self._promoted_path, encoding="utf-8")) or {}
        except Exception:  # noqa: BLE001
            logger.debug("promoted_rules 读取失败（视为空）")
            return {}

    def stats(self) -> Dict[str, Any]:
        drafts = self.drafts()
        status_counts: Dict[str, int] = {}
        for d in drafts:
            s = str(d.get("status") or "?")
            status_counts[s] = status_counts.get(s, 0) + 1
        return {
            "total_cve": self.total_count(),
            "cursor": self.cursor(),
            "drafts": len(drafts),
            "by_status": status_counts,
            "promoted": len(self.promoted_rules()),
        }


def _count_lines(path: str) -> int:
    n = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for _ in fh:
            n += 1
    return n