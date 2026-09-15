# -*- coding: utf-8 -*-
"""DOM Clobbering 攻击面检测引擎。

Clobbering 利用：HTML 元素的 id/name 属性会创建同名的 document.X / window.X 引用。
攻击者通过 XSS/HTML 注入点植入精心构造的元素，覆盖框架信任的全局对象，可：
  1) 覆盖危险全局名（top/self/parent/location/document 等）劫持跳转/导航
  2) 配合 javascript: URL 绕过 CSP 触发 XSS
  3) 表单劫持（<form name="x"> 后 JS 用 document.x 取表单 → CSRF/状态污染）

为何单独立引擎：clobbering 是 XSS 利用链的中间步骤，纯反射 XSS 引擎（仅看响应回显）
会漏掉这类「前置条件+利用向量」组合威胁，是 bug bounty 高频漏洞。
"""
import re
from typing import Dict, List

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get
from vulnclaw.engines.base import BaseEngine


class DOMClobberingEngine(BaseEngine):
    """DOM Clobbering 攻击面检测引擎（scan 型）。

    通过 fetch URL + 正则分析 HTML，检测两类危险模式：
      A) 元素 id/name 与 JS 全局变量名同名（覆盖 window.X / document.X）
      B) href/action/src 等属性含 javascript: URL（配合 clobbering 可触发 XSS）
    """

    name = "dom_clobbering"
    description = "DOM Clobbering 攻击面检测引擎（HTML 属性覆盖 window.* / document.* + javascript: URL 注入）"

    # 覆盖后会污染 JS 执行上下文的危险全局名
    DANGEROUS_NAMES = frozenset({
        "top", "self", "parent", "frames", "length", "opener", "closed",
        "location", "document", "window", "name", "status",
        "defaultStatus", "origin", "event",
    })

    # 匹配有 id/name/href/action/src 等属性的关键标签
    FULL_ELEM_RE = re.compile(
        r"<\s*(?P<tag>a|form|img|embed|object|iframe|input|button|svg|details|textarea|select|link|area|base)\b"
        r"(?P<attrs>[^>]*?)>\s*",
        re.IGNORECASE | re.DOTALL,
    )

    ATTR_RE = re.compile(
        r"\b(?P<key>id|name|href|action|formaction|data|src|xlink:href)\s*=\s*[\"\'](?P<val>[^\"\']+)[\"\']",
        re.IGNORECASE,
    )

    MAX_BODY = 200_000

    async def check(
        self,
        url: str,
        param: str,
        normal_resp,
        parsed_query: str,
        session,
        **kwargs
    ):
        # DOM Clobbering 是 scan 型（全局分析整页 HTML），无 param 驱动；
        # check 入口留空桩，由 scanner 走 scan()。
        return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        try:
            resp = await async_get(target, session=session, timeout=settings.timeout, no_retry=True)
            if not resp or not isinstance(resp, tuple):
                return findings
            status, text = resp[0], resp[1] or ""
            if status != 200 or not isinstance(text, str):
                return findings

            body = text[: self.MAX_BODY]

            dangerous_hits: List = []
            href_hits: List = []

            for m in self.FULL_ELEM_RE.finditer(body):
                tag = m.group("tag").lower()
                attrs_str = m.group("attrs") or ""
                id_name_val: str = ""
                js_url_val: str = ""
                for am in self.ATTR_RE.finditer(attrs_str):
                    key = am.group("key").lower()
                    val = am.group("val").strip()
                    if key in ("id", "name") and not id_name_val:
                        id_name_val = val
                    elif key in ("href", "action", "formaction", "data", "src", "xlink:href"):
                        if val.lower().startswith("javascript:"):
                            js_url_val = val
                if id_name_val and id_name_val.lower() in self.DANGEROUS_NAMES:
                    dangerous_hits.append((tag, id_name_val))
                if js_url_val:
                    href_hits.append((tag, js_url_val))

            if dangerous_hits:
                sample = ", ".join(f"<{t} id/name='{v}'>" for t, v in dangerous_hits[:5])
                findings.append({
                    "url": target,
                    "type": "DOM Clobbering(危险名覆盖)",
                    "severity": "Medium",
                    "ai_verdict": "中",
                    "confidence": "medium",
                    "evidence": (
                        f"DOM Clobbering(危险名覆盖) — 检测到 {len(dangerous_hits)} 个元素 id/name 与 JS 全局变量同名，"
                        f"可覆盖 window/document 同名属性（典型 clobbering 利用前置条件）；示例：{sample}"
                    ),
                    "recommendation": (
                        "避免使用 id/name 属性覆盖 JS 全局变量名（top/self/parent/location 等），"
                        "或对用户输入的 HTML 做白名单过滤"
                    ),
                    "hits": dangerous_hits,
                })

            if href_hits:
                sample = ", ".join(f"<{t} ...='{v[:40]}'>" for t, v in href_hits[:3])
                findings.append({
                    "url": target,
                    "type": "DOM Clobbering(javascript: URL 注入)",
                    "severity": "High",
                    "ai_verdict": "高",
                    "confidence": "high",
                    "evidence": (
                        f"检测到 {len(href_hits)} 个元素 href/action 含 javascript: URL；"
                        f"如攻击者可控制这些属性，结合 clobbering 可绕过 CSP 触发 XSS；示例：{sample}"
                    ),
                    "recommendation": "禁止 javascript: URL（href/action/src/formaction），使用 CSP 严格策略",
                    "hits": href_hits,
                })
        except Exception as e:
            logger.debug(f"[{self.name}] DOM Clobbering 检测异常: {e}")
        return findings