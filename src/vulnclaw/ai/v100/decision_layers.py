#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""三层 AI 决策架构（P3-8，2026-09-15）。

Strategic（战略层）→ Tactical（战术层）→ Operational（执行层＝现有任务系统）：

- **Strategic**：扫描初期一次性规划——从 recon brief（tech_stack/端口/API/端点）
  与已有 findings 出发，产出"高价值路径 Top-N + 资源分配建议"。LLM 可用时增强
  （给理由与置信度）；不可用/失败回退**确定性启发式**（tech→已知高危路径表）。
- **Tactical**：对单个端点产出"引擎组合建议"（按路径语义 + tech_stack 匹配）。
- **Operational**：不改变——现有 SmartTaskQueue / taskgen 执行。

接入方式（零回归）：规划结果以**任务字段注入**形式进入系统
（`strategic_priority` / `suggested_engines`），与既有 `memory_boost` 注入机制
同构 —— 不触碰任何调度/执行逻辑，消费端可渐进接入。开关
`settings.ai_three_layer=False` 默认关，关闭时不产生任何副作用。

纪律：任何 LLM 失败/超时 → 回退确定性启发式；启发式亦空 → 返回空计划；
本模块所有函数**永不抛异常**。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from vulnclaw.core.logger import logger

# tech_stack 关键词 → 已知高价值路径（确定性知识，来自实战总结）
_HIGH_VALUE_PATHS: Dict[str, tuple] = {
    "php": ("/admin", "/api", "/upload", "/.env", "/config.php", "/phpinfo.php"),
    "java": ("/actuator", "/actuator/env", "/jolokia", "/api", "/admin", "/.git/config"),
    "spring": ("/actuator/env", "/actuator/health", "/jolokia", "/env"),
    "python": ("/api", "/admin", "/docs", "/debug", "/.env"),
    "django": ("/admin", "/api", "/static/../", "/.env"),
    "flask": ("/admin", "/api", "/debug", "/console"),
    "node": ("/api", "/graphql", "/admin", "/.env"),
    "express": ("/api", "/admin", "/.env"),
    "wordpress": ("/wp-admin", "/wp-json/wp/v2/users", "/xmlrpc.php", "/wp-config.php"),
    "nginx": ("/nginx_status", "/.git/config", "/.env"),
    "apache": ("/server-status", "/.git/config", "/.env"),
    "tomcat": ("/manager/html", "/host-manager/html", "/examples/"),
}

_GENERIC_PATHS = ("/admin", "/api", "/.env", "/config", "/login")


def strategic_plan(brief: Optional[Dict], findings: Optional[List[Dict]] = None,
                   max_endpoints: int = 10) -> Dict[str, Any]:
    """战略层（确定性启发式）：brief/findings → 高价值路径计划。

    返回 {"targets": [{"path", "reason"}...], "source": "heuristic"}；
    输入为空亦有通用兜底（不返回空计划）。
    """
    try:
        tech = [str(t).lower() for t in ((brief or {}).get("tech_stack") or [])]
        targets: List[Dict[str, str]] = []
        seen = set()
        for t in tech:
            for key, paths in _HIGH_VALUE_PATHS.items():
                if key in t:
                    for p in paths:
                        if p not in seen:
                            seen.add(p)
                            targets.append({"path": p, "reason": f"tech={key}"})
        # 已确认漏洞的类型 → 同类路径优先（数据库/管理面 → 深挖）
        for f in (findings or [])[:10]:
            ft = str((f or {}).get("type") or "").lower()
            if "sql" in ft and "/api" not in seen:
                seen.add("/api")
                targets.append({"path": "/api", "reason": "existing_sqli"})
        if not targets:
            for p in _GENERIC_PATHS:
                targets.append({"path": p, "reason": "generic"})
        return {"targets": targets[:max(1, int(max_endpoints))], "source": "heuristic"}
    except Exception:  # noqa: BLE001
        return {"targets": [], "source": "error"}


async def strategic_plan_llm(brief: Optional[Dict], findings: Optional[List[Dict]] = None,
                             max_endpoints: int = 10) -> Dict[str, Any]:
    """战略层（LLM 增强）：在启发式基础上让 LLM 排序/补充；失败回退启发式结果。"""
    base = strategic_plan(brief, findings, max_endpoints)
    try:
        from vulnclaw.ai.core import get_llm_client
        client = get_llm_client()
        if client is None or not hasattr(client, "ask"):
            return base
        tech = ", ".join(str(t) for t in ((brief or {}).get("tech_stack") or [])[:8])
        ports = ", ".join(str(p) for p in ((brief or {}).get("ports") or [])[:12])
        vulns = ", ".join(
            f"{f.get('type')}@{f.get('url', '')}" for f in (findings or [])[:5]
        )
        prompt = (
            "你是渗透测试战略规划器。根据侦察信息，给出下一步最值得优先测试的"
            "路径列表（最多 10 条，按价值排序）。\n"
            f"技术栈: {tech or '未知'}\n端口: {ports or '未知'}\n已发现漏洞: {vulns or '无'}\n"
            "只输出 JSON：{\"targets\": [{\"path\": \"/xxx\", \"reason\": \"...\"}]}"
        )
        import re as _re
        import json as _json

        raw = await client.ask(prompt, system="只输出 JSON。", temperature=0.1,
                               max_tokens=500, task_type="filter",
                               usage_site="three-layer:strategic")
        if isinstance(raw, dict):
            raw = raw.get("text") or raw.get("content") or raw.get("answer") or ""
        m = _re.search(r"\{.*\}", str(raw or ""), _re.S)
        if not m:
            return base
        data = _json.loads(m.group(0))
        targets = [
            {"path": str(t.get("path")), "reason": str(t.get("reason") or "llm")}
            for t in (data.get("targets") or [])
            if isinstance(t, dict) and t.get("path")
        ]
        if targets:
            return {"targets": targets[:max(1, int(max_endpoints))], "source": "llm"}
        return base
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[ThreeLayer] 战略层 LLM 增强失败（回退启发式）: {exc}")
        return base


def tactical_plan(endpoint: str, brief: Optional[Dict] = None,
                  engine_names: Optional[List[str]] = None) -> Dict[str, Any]:
    """战术层：端点 → 引擎组合建议（确定性规则，按路径语义 + tech_stack）。"""
    try:
        ep = str(endpoint or "").lower()
        engines: List[str] = []
        if "?" in ep or "=" in ep:
            engines += ["sqli", "xss"]
        if any(k in ep for k in ("upload", "file", "download", "attach")):
            engines += ["upload", "lfi"]
        if any(k in ep for k in ("redirect", "url", "next", "return", "callback")):
            engines += ["open_redirect", "ssrf"]
        if any(k in ep for k in ("api", "json", "graphql", "rest")):
            engines += ["idor", "api_version"]
        if any(k in ep for k in ("admin", "manage", "console")):
            engines += ["auth", "idor"]
        tech = [str(t).lower() for t in ((brief or {}).get("tech_stack") or [])]
        if any(("java" in t or "spring" in t) for t in tech):
            engines += ["deserialization"]
        if any("wordpress" in t for t in tech):
            engines += ["component"]
        if not engines:
            engines = ["xss", "sqli"]
        # 与引擎注册表求交集（只建议真实存在的引擎）
        if engine_names:
            known = set(str(e) for e in engine_names)
            engines = [e for e in engines if e in known] or engines
        seen, out = set(), []
        for e in engines:
            if e not in seen:
                seen.add(e)
                out.append(e)
        return {"endpoint": endpoint, "engines": out[:6], "source": "heuristic"}
    except Exception:  # noqa: BLE001
        return {"endpoint": endpoint, "engines": [], "source": "error"}


def inject_strategic_fields(tasks: List[Any], plan: Dict[str, Any]) -> int:
    """把战略计划以字段注入任务（与 memory_boost 同构；消费端可渐进接入）。

    只新增 `strategic_priority`（数值，越大越优先），不改任何既有字段。
    返回注入数；任何异常返回 0（绝不抛）。
    """
    try:
        targets = (plan or {}).get("targets") or []
        if not tasks or not targets:
            return 0
        priority_map = {
            str(t.get("path")): (len(targets) - i)
            for i, t in enumerate(targets) if t.get("path")
        }
        n = 0
        for task in tasks:
            td = getattr(task, "task_data", None)
            if not isinstance(td, dict):
                continue
            url = str(td.get("url") or td.get("target") or "")
            if not url:
                continue
            for path, pri in priority_map.items():
                if path in url:
                    td["strategic_priority"] = int(pri)
                    n += 1
                    break
        return n
    except Exception:  # noqa: BLE001
        return 0


def three_layer_enabled() -> bool:
    """开关读取（默认关；任何异常视为关）。"""
    try:
        from vulnclaw.core.settings import settings
        return bool(getattr(settings, "ai_three_layer", False))
    except Exception:  # noqa: BLE001
        return False


__all__ = [
    "strategic_plan", "strategic_plan_llm", "tactical_plan",
    "inject_strategic_fields", "three_layer_enabled",
]
