#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""原生 Nuclei YAML 模板解释器（P3-11，2026-09-15）。

动机：外部模板（Nuclei 语法）此前只能靠 subprocess 调 nuclei 二进制
（进程启动开销大）。本模块提供**纯 Python 单请求模板子集**解释器：
requests(method/path/headers/body) + matchers(status/word/regex, condition
and/or) —— 与现有引擎同结构输出，可单测、零二进制依赖。

刻意划定的 MVP 边界（其余仍走 nuclei 二进制兜底，零行为回归）：
- 支持：单 http 请求块、status/word/regex matcher、matchers-condition and/or、
  negative matcher、part=body/header/all。
- 不支持：flow/workflows（多步）、raw/race/headless 类型、payloads/attack
  变形、dsl matcher —— 遇到即返回 None（跳过，不误报）。
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from vulnclaw.core.logger import logger

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

_TIMEOUT = 15


def load_template(path: str) -> Optional[Dict[str, Any]]:
    """读单个 YAML 模板（失败 → None）。"""
    if yaml is None:
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001
        logger.debug("native_templates: 模板读取失败（忽略）")
        return None


def list_templates(directory: str, limit: int = 0) -> List[str]:
    """列出目录下 .yaml/.yml 模板路径（排序稳定）。"""
    out: List[str] = []
    try:
        for name in sorted(os.listdir(directory)):
            if name.lower().endswith((".yaml", ".yml")):
                out.append(os.path.join(directory, name))
                if limit and len(out) >= limit:
                    break
    except Exception:  # noqa: BLE001
        logger.debug("native_templates: 目录列举失败（忽略）")
    return out


def _safe_search(pattern: str, text: str, flags: int) -> bool:
    try:
        return re.search(pattern, text, flags) is not None
    except re.error:
        return False


def _match_one(m: Dict[str, Any], status: int, text: str, headers: str = "") -> bool:
    """单 matcher 判定（status/word/regex；negative 反转）。不支持的类型 → False。"""
    mtype = str(m.get("type") or "").lower()
    neg = str(m.get("negative") or "").lower() in ("true", "1")
    part = str(m.get("part") or "body").lower()
    if part == "all":
        subject = (text or "") + "\n" + (headers or "")
    elif part == "header":
        subject = headers or ""
    else:
        subject = text or ""
    if mtype == "status":
        try:
            want = [int(x) for x in (m.get("status") or [])]
        except (TypeError, ValueError):
            return False
        found = int(status) in want
    elif mtype == "word":
        words = [str(w) for w in (m.get("words") or [])]
        case_ins = "i" in str(m.get("condition") or "").lower()
        hay = subject.lower() if case_ins else subject
        found = any((w.lower() if case_ins else w) in hay for w in words)
    elif mtype == "regex":
        rxs = [str(r) for r in (m.get("regex") or [])]
        flags = re.IGNORECASE if "i" in str(m.get("condition") or "").lower() else 0
        found = any(_safe_search(r, subject, flags) for r in rxs)
    else:
        return False  # dsl/其他类型：MVP 不解释（交 nuclei 二进制兜底）
    return (not found) if neg else found


async def run_template(
    tmpl: Dict[str, Any], base_url: str, session,
    timeout: int = _TIMEOUT,
) -> Optional[Dict[str, Any]]:
    """执行单请求模板：命中返回 finding dict（与引擎同结构），否则 None。"""
    try:
        if not isinstance(tmpl, dict) or tmpl.get("flow") or tmpl.get("workflows"):
            return None  # MVP 边界：多步 flow 不解释
        requests = tmpl.get("http") or tmpl.get("requests") or []
        if not requests or not isinstance(requests[0], dict):
            return None
        req = requests[0]
        matchers = req.get("matchers") or []
        if not matchers:
            return None
        condition = str(
            req.get("matchers-condition") or req.get("matchers_condition") or "or"
        ).lower()
        method = str(req.get("method") or "GET").upper()
        paths = req.get("path") or req.get("paths") or ["/"]
        if isinstance(paths, str):
            paths = [paths]
        headers = {str(k): str(v) for k, v in (req.get("headers") or {}).items()}
        body = req.get("body")
        info = tmpl.get("info") or {}
        for p in list(paths)[:3]:
            url = base_url.rstrip("/") + "/" + str(p).lstrip("/")
            try:
                import aiohttp
                to = aiohttp.ClientTimeout(total=int(timeout))
                if method == "POST":
                    async with session.post(url, headers=headers or None,
                                            data=body, timeout=to) as resp:
                        status = resp.status
                        raw = await resp.text(errors="replace")
                        hdrs = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                else:
                    async with session.get(url, headers=headers or None,
                                           timeout=to) as resp:
                        status = resp.status
                        raw = await resp.text(errors="replace")
                        hdrs = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            except Exception:  # noqa: BLE001 - 单路径失败继续下一路径
                continue
            verdicts = [_match_one(m, int(status), raw or "", hdrs) for m in matchers]
            hit = all(verdicts) if condition == "and" else any(verdicts)
            if hit:
                return {
                    "type": str(info.get("name") or tmpl.get("id") or "template"),
                    "severity": str(info.get("severity") or "info").title(),
                    "url": url,
                    "parameter": "",
                    "payload": "",
                    "evidence": (
                        f"原生模板命中: {tmpl.get('id', '?')} "
                        f"(matcher[{condition}] × {len(matchers)}, status={status})"
                    ),
                    "template_id": str(tmpl.get("id") or ""),
                    "source": "native_template",
                    "confidence": "high",
                }
        return None
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"native_templates: 模板执行异常（忽略）: {exc}")
        return None


__all__ = ["load_template", "list_templates", "run_template"]
