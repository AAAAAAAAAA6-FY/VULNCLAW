# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""E 方案：交叉验证层（开源工具对照，2026-09-08）

对引擎候选，用独立实现的开源工具做二次判定（对照），结论写入 finding：
  - cross_tool_confirmed  双杀：自研 + 开源工具都判定 → 交叉实锤（审核门 hard proof）
  - cross_tool_pending    自研单点且无差分/交叉证据（业务逻辑类）→ 审核门降档复核
  - cross_tool_checked    本次已尝试对照（成败皆记，供审计）

fail-open 原则：工具缺失 / 超时 / 异常一律保留引擎原判定，绝不影响主流程。
对照覆盖：CMDi→Commix；SSTI/走私/Cache Poison/配置类→Nuclei 定向模板；
SSRF/XXE/LFI-RFI/反序列化/JWT/已知CVE→Nuclei 大类 tag；
业务逻辑（IDOR/竞态/越权）无开源替代 → 规则化（强制差分/双源证据）。
原则：大类级判据 + 硬证据 + 审核门兜底，不逐类枚举。
"""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import vuln_category

# ============================================================
# 对照规格表：(匹配关键字, 规格)
#   kind=commix → Commix 命令注入确认；kind=nuclei → Nuclei 定向 tags/severity
# ============================================================
_CROSS_SPEC = [
    # 大类级判据（非逐类枚举）：命中即交开源工具对照；未命中走硬证据/审核门兜底。
    (("cmdi", "command", "rce", "命令"),
     {"kind": "commix", "timeout": 90}),
    (("ssti", "el_injection", "模板"),
     {"kind": "nuclei", "nuclei_tags": "ssti,template-injection,el-injection", "severity": "critical,high"}),
    (("smuggl", "走私", "te-cl", "transfer-encoding"),
     {"kind": "nuclei", "nuclei_tags": "http-request-smuggling,request-smuggling", "severity": "critical"}),
    (("cache", "poison", "缓存投毒"),
     {"kind": "nuclei", "nuclei_tags": "cache-poison,cache-key", "severity": "critical,high"}),
    (("hsts", "csp", "security-header", "安全头", "dnssec", "misconfig", "ssl", "配置"),
     {"kind": "nuclei", "nuclei_tags": "misconfiguration,security-headers", "severity": "critical,high,medium"}),
    (("ssrf",),
     {"kind": "nuclei", "nuclei_tags": "ssrf", "severity": "critical,high"}),
    (("xxe",),
     {"kind": "nuclei", "nuclei_tags": "xxe", "severity": "critical,high"}),
    (("lfi", "rfi", "path_traversal", "path-traversal", "路径穿越", "目录穿越", "文件包含"),
     {"kind": "nuclei", "nuclei_tags": "lfi,path-traversal,rfi", "severity": "critical,high,medium"}),
    (("deserialization", "反序列化"),
     {"kind": "nuclei", "nuclei_tags": "java-deserialization,deserialization,php-deserialization", "severity": "critical,high"}),
    (("jwt", "oauth"),
     {"kind": "nuclei", "nuclei_tags": "jwt,oauth", "severity": "high,medium"}),
    # 已知漏洞组件：cve 模板匹配面大，severity 收敛在高危段；超时/缺失由 fail-open 兜底。
    (("cve", "middleware", "中间件", "framework", "框架", "组件", "已知漏洞"),
     {"kind": "nuclei", "nuclei_tags": "cve", "severity": "critical,high"}),
]

# E3 业务逻辑类：开源无对照 → 规则化（强制差分/双源证据）
_BIZ_HINTS = ("idor", "bola", "bopla", "race", "竞态", "越权", "水平越权",
              "垂直越权", "brute", "撞库", "unauth", "越权访问")


def _find_spec(vuln: Dict) -> Optional[Dict]:
    """按 type/分类匹配对照规格；未命中返回 None。"""
    typ = str(vuln.get("type", ""))
    cat = vuln_category(typ)
    hay = (typ + " " + cat).lower()
    for kws, spec in _CROSS_SPEC:
        for kw in kws:
            if kw in hay:
                return dict(spec)
    return None


def _is_biz(vuln: Dict) -> bool:
    typ = str(vuln.get("type", "")).lower()
    return any(h in typ for h in _BIZ_HINTS)


def _apply_biz_rule(vuln: Dict) -> None:
    """E3：业务逻辑候选必须有差分/双源证据，否则标记 cross_tool_pending（审核门降档）。"""
    ev = str(vuln.get("evidence", ""))
    ev_l = (ev + " " + str(vuln.get("ai_verdict", ""))).lower()
    has_diff = (
        ("差分" in ev) or ("双会话" in ev) or ("oracle" in ev_l)
        or vuln.get("oracle_observation") or vuln.get("differential")
    )
    if has_diff:
        return
    if any(vuln.get(k) for k in ("burp_verified", "burp_confirmed", "oob_confirmed", "oob_callback", "cross_confirmed")):
        return
    vuln["cross_tool_pending"] = True


def _mark_confirmed(vuln: Dict, tool: str, out: str) -> None:
    """双杀命中：写入交叉实锤与证据。"""
    vuln["cross_tool_confirmed"] = True
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    snippet = "；".join(lines[:3])[:400]
    vuln["cross_tool_evidence"] = f"[{tool} 独立判定命中] {snippet}"
    logger.info(f"🧬 [交叉验证层] 双杀: {vuln.get('type', '')} → {tool}")


async def _run_commix(vuln: Dict, spec: Dict) -> Optional[bool]:
    """Commix 独立确认命令注入。工具缺失/失败 → None（保留引擎判定）。"""
    from vulnclaw.core.tool_registry import run_tool, tool_available
    if not tool_available("commix"):
        logger.debug("[交叉验证层] commix 未安装，跳过 CMDi 对照")
        return None
    url = str(vuln.get("url", vuln.get("target", "")) or "")
    param = str(vuln.get("parameter", vuln.get("param", "")) or "")
    if not url or not param:
        return None
    timeout = int(spec.get("timeout", 90))
    with tempfile.TemporaryDirectory(prefix="cross_commix_") as td:
        result = await run_tool(
            "commix",
            args=["--url", url, "-p", param, "--batch", "--level", "1",
                  "--output-dir", td],
            timeout=timeout,
        )
    if not result.get("success"):
        return None
    out = (result.get("stdout") or "") + "\n" + (result.get("stderr") or "")
    if any(m in out for m in ("is vulnerable", "identified the following", "Injection Point", "Vulnerable")):
        _mark_confirmed(vuln, "Commix", out)
        return True
    return False


def _collect_nuclei_hits(out_file: Optional[Path], result: Dict) -> List[dict]:
    hits: List[dict] = []
    if out_file is not None and out_file.exists():
        for raw in out_file.read_text(encoding="utf-8", errors="replace").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                hits.append(json.loads(raw))
            except BaseException:
                hits.append({"raw": raw})
    if not hits:
        for raw in (result.get("stdout") or "").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                hits.append(json.loads(raw))
            except BaseException:
                if raw and not raw.startswith("["):
                    hits.append({"raw": raw})
    return hits


async def _run_nuclei(vuln: Dict, spec: Dict) -> Optional[bool]:
    """Nuclei 定向 tags 独立确认。无命中/失败 → False/None（保留引擎判定）。"""
    url = str(vuln.get("url", vuln.get("target", "")) or "")
    if not url:
        return None
    from vulnclaw.core.tool_registry import run_tool
    timeout = int(getattr(settings, "cross_check_timeout", 120))
    out_file: Optional[Path] = None
    with tempfile.TemporaryDirectory(prefix="cross_nuclei_") as td:
        out_file = Path(td) / "nuclei_out.jsonl"
        args = [
            "-u", url,
            "-severity", spec["severity"],
            "-o", str(out_file),
            "-jsonl", "-silent",
            "-timeout", str(min(timeout, 40)),
            "-tags", spec["nuclei_tags"],
        ]
        result = await run_tool("nuclei", args=args, timeout=timeout)
        in_file = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else ""
        if not result.get("success") and not in_file:
            return None
        hits = _collect_nuclei_hits(out_file, result)
        if hits:
            first = hits[0]
            tid = first.get("template-id") or (first.get("info") or {}).get("name") or "nuclei 模板"
            matched = first.get("matched-at", first.get("host", url))
            out = f"模板 {tid} @ {matched}"
            _mark_confirmed(vuln, f"Nuclei({spec['nuclei_tags']})", out)
            return True
    return False


async def _run_spec(vuln: Dict, spec: Dict) -> Optional[bool]:
    kind = spec.get("kind")
    if kind == "commix":
        return await _run_commix(vuln, spec)
    if kind == "nuclei":
        return await _run_nuclei(vuln, spec)
    return None


async def cross_check_findings(findings: List[dict]) -> int:
    """对候选做开源工具对照，返回实际执行对照的条数。fail-open。"""
    if not getattr(settings, "cross_check_enabled", True):
        return 0
    if not findings:
        return 0
    batch = int(getattr(settings, "cross_check_batch", 3))
    sem = asyncio.Semaphore(max(1, batch))
    checked = 0

    async def _one(vuln: Dict) -> None:
        nonlocal checked
        vuln["cross_tool_checked"] = True
        spec = _find_spec(vuln)
        if spec is None:
            if getattr(settings, "cross_check_biz_rule", True) and _is_biz(vuln):
                _apply_biz_rule(vuln)
            return
        async with sem:
            try:
                changed = await _run_spec(vuln, spec)
                if changed is not None:
                    checked += 1
            except BaseException as exc:  # 对照失败绝不影响原判定
                logger.debug(f"[交叉验证层] 对照异常（忽略）: {exc}")

    await asyncio.gather(*(_one(v) for v in findings))
    n_confirm = sum(1 for v in findings if v.get("cross_tool_confirmed"))
    n_pending = sum(1 for v in findings if v.get("cross_tool_pending"))
    if n_confirm or n_pending:
        logger.info(f"🧬 [交叉验证层] 对照 {checked} 条：双杀实锤 {n_confirm} / 规则待核 {n_pending}")
    return checked


__all__ = ["cross_check_findings", "_find_spec", "_apply_biz_rule", "_is_biz"]
