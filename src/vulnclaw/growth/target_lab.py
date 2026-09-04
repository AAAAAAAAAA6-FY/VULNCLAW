# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""方向3 自举靶机验证 (target_lab.py)

用最小漏洞靶机自测引擎覆盖：本地起 aiohttp 靶机 -> 调用真实引擎 scan ->
记录命中/漏检 -> 产出覆盖缺口报告并按优先级排序。

设计约束（零成本 + 零回归 + 确定性）：
- 靶机绑定 127.0.0.1 随机端口，扫描完即停，无任何外部流量。
- 靶机模板内置代码，无外部依赖、无 OOB、无真实攻击行为。
- 只测映射表内的"正主引擎"，防止其他引擎误报污染覆盖判定。
- 失败隔离：单个模板/引擎异常只记入 items，不中断整体报告。
"""
import asyncio
import os
import re
import time
from typing import Any, Dict, List, Optional

from aiohttp import web

from vulnclaw.core.logger import logger

# ---------------------------------------------------------------------------
# 最小漏洞靶机模板（v1：确定性、无 OOB、Windows 可跑）
# ---------------------------------------------------------------------------


async def _sqli_handler(request: web.Request) -> web.Response:
    """布尔盲注靶机：id 正常回显 1 行；注入恒假条件回显 0 行。"""
    q = str(request.query.get("id", "1"))
    if re.search(r"'\s*(and|or)\s*'1'='2|'\s*and\s*'0'='1", q, re.I) or "1=2" in q or "2=1" in q:
        return web.Response(text="0 rows", content_type="text/plain")
    return web.Response(text=f"1 row: id={q}", content_type="text/plain")


async def _xss_handler(request: web.Request) -> web.Response:
    """反射 XSS 靶机：name 参数未经转义拼入 HTML。"""
    name = str(request.query.get("name", "guest"))
    return web.Response(text=f"<html><body>Hello {name}</body></html>", content_type="text/html")


async def _redirect_handler(request: web.Request) -> web.Response:
    """开放重定向靶机：next 参数直接作为 302 Location。"""
    next_url = str(request.query.get("next", "/"))
    return web.HTTPFound(next_url)


async def _ssrf_handler(request: web.Request) -> web.Response:
    """SSRF 探测靶机（实验）：url 参数回显抓取内容，模拟内网可达回显。"""
    target_url = str(request.query.get("url", "")).strip()
    if not target_url:
        return web.Response(text="url required", status=400)
    if not target_url.lower().startswith(("http://", "https://")):
        target_url = "http://" + target_url
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                target_url, timeout=aiohttp.ClientTimeout(total=3), allow_redirects=False
            ) as resp:
                body = await resp.text()
                return web.Response(
                    text=f"[fetch:{target_url}] status={resp.status} body={body[:500]}",
                    content_type="text/plain",
                )
    except Exception as exc:  # noqa: BLE001
        return web.Response(text=f"[fetch:{target_url}] error: {exc}", status=400)


# 靶机 -> handler 工厂与说明
_LAB_FACTORIES = {
    "reflect_sqli": (_sqli_handler, "布尔盲注/报错型 SQL 注入回显靶机"),
    "reflect_xss": (_xss_handler, "反射型 XSS 未转义回显靶机"),
    "open_redirect": (_redirect_handler, "开放重定向 302 靶机"),
    "ssrf_fetch": (_ssrf_handler, "SSRF 内网回显靶机（实验，探测引擎读取响应差异）"),
}

# 引擎类名 -> 正主靶机。未映射的引擎在报告中标记 no_lab（未知，不判缺覆盖）。
ENGINE_LAB_MAP: Dict[str, str] = {
    "SQLiEngine": "reflect_sqli",
    "XSSEngine": "reflect_xss",
    "OpenRedirectEngine": "open_redirect",
    "SSRFEngine": "ssrf_fetch",
}

# v1 暂挂（Windows 靶机模板难确定性命中，待二期补确定性复现）：
#   LFIEngine  -> 路径穿越模板在 Windows 上引擎 payload(../../etc/passwd) 大概率不命中，
#                 需二期用独立标记文件 + 归一化才稳定。


# ---------------------------------------------------------------------------
# TargetLab：本地靶机生命周期管理
# ---------------------------------------------------------------------------

class TargetLab:
    """一次性本地靶机：start 起服务并返回 base_url，stop 关闭。"""

    def __init__(self, lab_name: str, bind_host: str = "127.0.0.1"):
        if lab_name not in _LAB_FACTORIES:
            raise ValueError(f"未知靶机模板: {lab_name}，可用: {sorted(_LAB_FACTORIES)}")
        self.lab_name = lab_name
        self.bind_host = bind_host
        self._runner: Optional[Any] = None
        self._site: Optional[Any] = None
        self.base_url: str = ""

    async def start(self) -> str:
        handler, _desc = _LAB_FACTORIES[self.lab_name]
        app = web.Application()
        app.router.add_get("/", handler)
        app.router.add_get("/vuln", handler)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self.bind_host, 0)  # 随机端口
        await self._site.start()
        port = self._site._server.sockets[0].getsockname()[1]  # noqa: W0212
        self.base_url = f"http://{self.bind_host}:{port}"
        logger.debug(f"target_lab: 靶机 {self.lab_name} 已就绪 {self.base_url}")
        return self.base_url

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        self.base_url = ""

    async def __aenter__(self) -> "TargetLab":
        await self.start()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.stop()


# ---------------------------------------------------------------------------
# 覆盖度量：调用真实引擎 scan，判定命中/漏检
# ---------------------------------------------------------------------------

async def _run_engine_scan(engine_cls, base_url: str) -> List[Dict]:
    """实例化引擎并 scan 靶机，容忍引擎 scan 签名差异。"""
    import aiohttp
    from vulnclaw.core.scanner import safe_request  # noqa: F401  # 与主流程相同请求栈

    engine = engine_cls()
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
        url = base_url + "/vuln"
        # 正常响应预热（部分引擎依赖 normal_resp 基线）
        try:
            resp = await safe_request(url, session, method="GET", timeout=10)
        except Exception:  # noqa: BLE001
            resp = None
        normal_resp = resp or (200, "1 row: id=1", {})
        try:
            findings = await engine.scan(url, session, normal_resp=normal_resp)
        except TypeError:
            findings = await engine.scan(url, session)
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"target_lab: {engine_cls.__name__} scan 异常: {exc}")
            findings = []
    return findings or []


async def run_coverage(
    engine_names: Optional[List[str]] = None,
    concurrency: int = 1,
    max_findings: int = 5,
) -> Dict[str, Any]:
    """自举覆盖度量：对映射靶机逐一验证正主引擎命中率。

    返回报告结构：
    {
      "ran_at": .., "total": n, "hit": n, "miss": n, "no_lab": n,
      "items": [ {lab, engine, expected_hit, hit, findings, error?} ],
      "priority_gap": [ {engine, lab, severity_hint} ... ],   # 漏检 -> 建议补测/补引擎
      "unmapped_engines": [ ... ]                             # 无对应靶机，未测
    }
    """
    import json

    start = time.time()
    if engine_names is None:
        engine_names = list(ENGINE_LAB_MAP)  # 默认只测映射表内正主引擎

    unmapped: List[str] = []
    plan: List = []
    for name in engine_names:
        lab = ENGINE_LAB_MAP.get(name)
        if lab is None:
            unmapped.append(name)
            continue
        plan.append((name, lab))

    sem = asyncio.Semaphore(max(1, concurrency))

    async def _probe(engine_name: str, lab: str) -> Dict[str, Any]:
        async with sem:
            item: Dict[str, Any] = {
                "lab": lab, "engine": engine_name, "expected_hit": True,
                "hit": False, "findings": 0, "error": None,
            }
            try:
                mod = __import__("vulnclaw.engines", fromlist=[engine_name])
                engine_cls = getattr(mod, engine_name)
                async with TargetLab(lab) as lab_inst:
                    findings = await _run_engine_scan(engine_cls, lab_inst.base_url)
                item["findings"] = len(findings[:max_findings])
                item["hit"] = len(findings) > 0
            except Exception as exc:  # noqa: BLE001
                item["error"] = str(exc)[:200]
            return item

    items = await asyncio.gather(*(_probe(n, lab) for n, lab in plan), return_exceptions=True)
    items = [
        it if isinstance(it, dict) else {
            "lab": plan[i][1], "engine": plan[i][0], "expected_hit": True,
            "hit": False, "findings": 0, "error": str(it)[:200],
        }
        for i, it in enumerate(items)
    ]

    hit = sum(1 for it in items if it["expected_hit"] and it["hit"])
    miss = sum(1 for it in items if it["expected_hit"] and not it["hit"])
    report = {
        "ran_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "elapsed_ms": int((time.time() - start) * 1000),
        "total": len(items),
        "hit": hit,
        "miss": miss,
        "no_lab": len(unmapped),
        "items": items,
        "priority_gap": [
            {"engine": it["engine"], "lab": it["lab"], "hint": "目标引擎未命中正主靶机，需补测或补强"}
            for it in items if it["expected_hit"] and not it["hit"]
        ],
        "unmapped_engines": unmapped,
    }
    os.makedirs(os.path.dirname(_report_path()), exist_ok=True)
    with open(_report_path(), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(report, ensure_ascii=False) + "\n")
    logger.info(f"target_lab: 覆盖自测 命中 {hit}/{len(items)}，漏检 {miss}，未映射 {len(unmapped)}")
    return report


def _report_path() -> str:
    return os.path.join("_runtime_cache", "growth", "coverage_gaps.jsonl")


def summarize_gap_priorities(report: Dict[str, Any]) -> List[str]:
    """把覆盖缺口转成人类可读的开发优先级建议（最高优先：漏检最多）。"""
    out: List[str] = []
    for gap in report.get("priority_gap", []):
        out.append(f"引擎 {gap['engine']} 漏检靶机 {gap['lab']} —— {gap['hint']}")
    for name in report.get("unmapped_engines", []):
        out.append(f"引擎 {name} 暂无对应靶机模板（未测，二期补靶机后再判）")
    return out or ["当前映射靶机全部命中，无覆盖缺口"]


__all__ = [
    "TargetLab", "run_coverage", "summarize_gap_priorities",
    "ENGINE_LAB_MAP", "_LAB_FACTORIES",
]