# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/tools.py
"""
AI 工具注册表 - 动态注册所有引擎
每个引擎作为一个工具，Agent 根据情况传入 url 和可选的 param
如果传了 param -> 调用引擎的 check() 方法
如果没传 param -> 调用引擎的 scan() 方法（全局检测，仅当引擎支持时）
修复：从合并文件导入所有引擎
"""

import re
import shlex

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get, get_shared_session
from typing import Dict, List, Optional
from vulnclaw.dashboard.server import ScanEvent, emit_event

# ===== 修复：从合并文件导入引擎（而非单文件） =====
from vulnclaw.engines.web_engines import (
    SQLiEngine, XSSEngine, LFIEngine,
    CMDIEngine, NoSQLEngine, SSTIEngine
)
from vulnclaw.engines.auth_engines import IDOREngine, JWTEngine, OAuthEngine, SessionEngine
from vulnclaw.engines.net_engines import SSRFEngine, XXEEngine, GraphQLEngine
from vulnclaw.engines.input_engines import (
    ELInjectionEngine, FileUploadEngine, CORSEngine,
    CRLFEngine, LDAPEngine
)
from vulnclaw.engines.http_engines import (
    SecurityHeadersEngine, HostHeaderEngine,
    OpenRedirectEngine, RaceConditionEngine, CachePoisonEngine
)
from vulnclaw.engines.input_engines import BusinessLogicEngine, InfoLeakEngine
from vulnclaw.engines.auxiliary_engines import (
    APIVersionDiffEngine, RequestSmugglingEngine, HTTP2WebSocketEngine
)
from vulnclaw.engines.deserialization import DeserializationEngine
from vulnclaw.engines.dotnet_deserialization import DotNetDeserializationEngine


class BaseTool:
    """工具基类（A5.1 统一 Tool Schema）"""
    name: str = ""
    description: str = ""
    parameters: List[Dict] = [
        {"name": "url", "type": "string", "required": True, "description": "目标URL"},
        {"name": "param", "type": "string", "required": False, "description": "要测试的参数名（可选，不提供则执行全局检测）"},
    ]
    # A5.1: 统一 Tool Schema 元数据——参数/危险级/超时/输出裁剪规则/类别
    #   safe=常规检测 / guarded=主动侦察或注入验证 / dangerous=真实利用（需 DangerGuard）
    danger_level: str = "safe"
    timeout: int = 60                  # 执行超时（秒）
    category: str = "engine"           # engine=内置检测引擎 / cli=外部工具
    clip_fields: tuple = ("stdout", "stderr", "summary")  # 喂 LLM 前需裁剪的字段

    def get_schema(self) -> Dict:
        """A5.1: 声明式统一 Schema——注册即入 Agent 可用清单，新增工具零改 dispatcher。"""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "danger_level": self.danger_level,
            "timeout": self.timeout,
            "category": self.category,
            "clip_fields": list(self.clip_fields),
        }

    async def execute(self, **kwargs) -> Dict:
        raise NotImplementedError


def create_tool(engine_class, custom_name: str = None, custom_desc: str = None):
    """
    为给定的引擎类动态创建一个 Tool 子类
    """
    tool_name = custom_name or getattr(engine_class, 'name', engine_class.__name__.replace('Engine', '').lower())
    tool_desc = custom_desc or getattr(engine_class, 'description', f'{tool_name} 漏洞检测')

    class DynamicTool(BaseTool):
        # 注意：Python 类体作用域里不能直接读取同名闭包变量 (name=name / desc=desc 会 NameError)，
        # 因此用不同名字的外层变量显式赋值，避免创建 TOOL_REGISTRY 时模块级导入失败。
        name = tool_name
        description = tool_desc
        _engine_instance = None

        async def execute(self, url: str, param: str = None, **kwargs) -> Dict:
            # 延迟初始化引擎
            if self._engine_instance is None:
                self._engine_instance = engine_class()
                if hasattr(self._engine_instance, 'max_payloads'):
                    self._engine_instance.max_payloads = 8
            engine = self._engine_instance

            session = await get_shared_session()

            try:
                if param is not None:
                    try:
                        normal_resp = await async_get(url, session=session, timeout=settings.request_timeout)
                    except Exception as e:
                        return {"error": f"获取正常响应失败: {e}"}

                    parsed_query = url.split('?')[1] if '?' in url else ''
                    result = await engine.check(
                        url=url,
                        param=param,
                        normal_resp=normal_resp,
                        parsed_query=parsed_query,
                        session=session
                    )
                    if result:
                        return {"type": "漏洞", "subtype": self.name, "data": result}
                    return {"type": "info", "message": f"参数 {param} 未发现 {self.name} 漏洞"}

                else:
                    if not hasattr(engine, 'scan') or not callable(engine.scan):
                        return {"error": f"引擎 {self.name} 不支持全局扫描（缺少 scan 方法）"}
                    result = await engine.scan(url, session)
                    if isinstance(result, list) and result:
                        return {"type": "漏洞", "subtype": self.name, "data": result}
                    elif result:
                        return {"type": "漏洞", "subtype": self.name, "data": result}
                    return {"type": "info", "message": f"全局检测未发现 {self.name} 漏洞"}

            except Exception as e:
                logger.error(f"工具 {self.name} 执行异常: {e}")
                return {"error": str(e)}

    return DynamicTool


# ===== 注册所有引擎（使用合并后的类） =====
ENGINE_CONFIGS = [
    (SQLiEngine, None, None),
    (XSSEngine, None, None),
    (LFIEngine, None, None),
    (CMDIEngine, None, None),
    (NoSQLEngine, None, None),
    (SSTIEngine, None, None),
    (SSRFEngine, None, None),
    (XXEEngine, None, None),
    (IDOREngine, None, None),
    (JWTEngine, None, None),
    (OAuthEngine, None, None),
    (GraphQLEngine, None, None),
    (FileUploadEngine, None, None),
    (ELInjectionEngine, None, None),
    (CORSEngine, None, None),
    (SecurityHeadersEngine, None, None),
    (RaceConditionEngine, None, None),
    (OpenRedirectEngine, None, None),
    (CRLFEngine, None, None),
    (LDAPEngine, None, None),
    (HostHeaderEngine, None, None),
    (InfoLeakEngine, None, None),
    (BusinessLogicEngine, None, None),
    (CachePoisonEngine, None, None),
    (SessionEngine, None, None),
    (APIVersionDiffEngine, None, None),
    (RequestSmugglingEngine, None, None),
    (HTTP2WebSocketEngine, None, None),
    (DeserializationEngine, None, None),
    (DotNetDeserializationEngine, None, None),
]

TOOL_REGISTRY = {}

for engine_class, custom_name, custom_desc in ENGINE_CONFIGS:
    ToolClass = create_tool(engine_class, custom_name, custom_desc)
    tool_instance = ToolClass()
    TOOL_REGISTRY[tool_instance.name] = tool_instance

# ==================================================================
# A5.2: 安全工具全集入册——外部 CLI 工具包装为 Agent 可运行时点选（非固定阶段）
# ==================================================================
def _host_of(url: str) -> str:
    """从 URL 提取主机名（供 nmap/naabu/subfinder 等主机级工具）。"""
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", str(url or ""))
    return u.split("/")[0].split(":")[0]


def _split_extra(extra: str) -> List[str]:
    """把 Agent 传的附加参数字符串安全拆分为 argv 列表（shlex，支持引号）。"""
    extra = str(extra or "").strip()
    return shlex.split(extra) if extra else []


class CLITool(BaseTool):
    """A5.2: 外部 CLI 工具——经 core.tool_registry.run_tool 执行。

    参数为"tools.yaml default_args + 传入 args"追加模式；Agent 可传 extra_args 微调。
    危险参数黑名单（A5.4 参数级门禁雏形）在执行前拒绝并有审计日志。
    """

    def __init__(self, tool_name, description, arg_builder,
                 danger_level="safe", timeout=120, blocked_patterns=()):
        self.name = tool_name
        self.description = description
        self.parameters = [
            {"name": "url", "type": "string", "required": True, "description": "目标URL"},
            {"name": "extra_args", "type": "string", "required": False,
             "description": "附加命令行参数（如 '-p 80,443'）"},
        ]
        self.danger_level = danger_level
        self.timeout = timeout
        self.category = "cli"
        self._arg_builder = arg_builder
        self._blocked_patterns = tuple(blocked_patterns or ())

    async def execute(self, url: str, extra_args: str = None, **kwargs) -> Dict:
        from vulnclaw.core.tool_registry import run_tool

        extra = str(extra_args or "")
        # A5.4: 工具+参数级 DangerGuard 审批（deny 拒绝 / prompt 交互确认 / allow 放行）。
        # 黑名单（_blocked_patterns）是绝对禁止，优先于 guard（guard 可被 DANGEROUS_ALLOW 放行）。
        for pat in self._blocked_patterns:
            if pat in extra:
                logger.warning(f"🚫 [CLITool] {self.name} 拒绝危险参数: {pat}")
                return {"error": f"参数 {pat} 被拒绝（危险参数黑名单）", "guard_denied": True}

        try:
            args = self._arg_builder(url, extra)
        except Exception as e:
            return {"error": f"构造命令参数失败: {e}"}

        try:
            from vulnclaw.core.danger_guard import guard
            if not guard.require_tool_approval(self.name, " ".join(args), f"{self.name} @ {url}"):
                logger.warning(f"🚫 [DangerGuard] 工具 {self.name} 未获审批（工具级门禁）")
                return {"error": f"工具 {self.name} 未获审批（DangerGuard 工具级门禁）", "guard_denied": True}
        except Exception as _ge:  # noqa: BLE001
            logger.debug(f"[DangerGuard] 工具级检查失败（放行兜底）: {_ge}")

        result = await run_tool(self.name, args=args, timeout=self.timeout)
        ok = bool(result.get("success"))
        stdout = str(result.get("stdout", "") or "")
        stderr = str(result.get("stderr", "") or "")
        return {
            "tool": self.name,
            "type": "cli_result",
            "success": ok,
            "returncode": result.get("returncode"),
            "summary": stdout[:500] if ok else stderr[:300],
            "error": None if ok else f"工具 {self.name} 执行失败 rc={result.get('returncode')}",
        }


def _register_cli_tools() -> int:
    """A5.2: 注册本机可用的安全工具（仅探测命中才入册，避免 Agent 选到必然失败的工具）。

    危险级：nmap/naabu=guarded（主动网络扫描）；sqlmap=guarded（注入利用，危险参数黑名单）。
    """
    from vulnclaw.core.utils import get_tool_path

    specs = [
        ("nuclei", "Nuclei 模板漏洞扫描（thirdparty/nuclei-templates 模板库）",
         lambda url, extra: ["-u", url] + _split_extra(extra), "safe", 180, ()),
        ("httpx", "HTTP 存活探测与标题/技术栈指纹",
         lambda url, extra: ["-u", url] + _split_extra(extra), "safe", 60, ()),
        ("katana", "主动爬虫发现端点与参数",
         lambda url, extra: ["-u", url] + _split_extra(extra), "safe", 120, ()),
        ("ffuf", "目录/路径模糊枚举（Fuzz）",
         lambda url, extra: ["-u", url.rstrip("/") + "/FUZZ"] + _split_extra(extra), "safe", 120, ()),
        ("dalfox", "XSS 参数扫描与 Payload 验证",
         lambda url, extra: ["url", url] + _split_extra(extra), "safe", 120, ()),
        ("gau", "从公开数据集（Wayback/CommonCrawl）拉取已知 URL",
         lambda url, extra: [_host_of(url)] + _split_extra(extra), "safe", 90, ()),
        ("waybackurls", "Wayback Machine 历史 URL 收集",
         lambda url, extra: [_host_of(url)] + _split_extra(extra), "safe", 90, ()),
        ("subfinder", "子域名被动枚举",
         lambda url, extra: ["-d", _host_of(url)] + _split_extra(extra), "safe", 120, ()),
        ("naabu", "端口快速扫描",
         lambda url, extra: ["-host", _host_of(url)] + _split_extra(extra), "guarded", 180, ()),
        ("nmap", "端口与服务版本扫描（网络侦察）",
         lambda url, extra: ["-Pn", _host_of(url)] + _split_extra(extra or "-sV --top-ports 100"),
         "guarded", 300, ()),
        ("sqlmap", "SQL 注入深度验证（注入利用工具）",
         lambda url, extra: ["-u", url, "--batch"] + _split_extra(extra), "guarded", 300,
         ("--os-shell", "--os-pwn", "--priv-esc", "--file-write", "--file-dest")),
        ("curl", "原始 HTTP 请求工具",
         lambda url, extra: ["-sS", "-i", url] + _split_extra(extra), "safe", 30, ()),
    ]
    registered = 0
    for name, desc, builder, level, timeout, blocked in specs:
        try:
            if not get_tool_path(name):
                continue
        except Exception:
            continue
        TOOL_REGISTRY[name] = CLITool(name, desc, builder, level, timeout, blocked)
        registered += 1
    return registered


_cli_registered = _register_cli_tools()


# ==================================================================
# Burp 集成工具——把 agent metadata 里的幽灵名 fetch_burp_issues 变成
# 可执行工具（Burp Pro Scanner 提交 + 三级收割）。Burp 未运行时返回
# 明确的可用性说明而非崩溃；注册无条件（Burp 可能稍后才启动）。
# ==================================================================
class BurpIssuesTool(BaseTool):
    """把 URL 提交给 Burp Pro Scanner 深度扫描并收割 issues。

    复用 BurpClient.scan_and_collect（提交 → 轮询终态 → 扩展桥/REST 三级收割），
    与 phases_executor._run_burp_scan 同源。danger_level=guarded：触发的是
    Burp 主动扫描，属主动行为。
    """

    def __init__(self):
        self.name = "fetch_burp_issues"
        self.description = (
            "把 URL 提交给本机 Burp Pro Scanner 深度扫描并收割 issues"
            "（需要 Burp 运行且 REST API 已开启；未运行时返回可用性说明）"
        )
        self.parameters = [
            {"name": "url", "type": "string", "required": True, "description": "目标URL"},
            {"name": "wait_timeout", "type": "number", "required": False,
             "description": "等待扫描终态的秒数（默认 120）"},
        ]
        self.category = "burp"
        self.danger_level = "guarded"

    async def execute(self, url: str = "", wait_timeout: int = 120, **kwargs) -> Dict:
        from vulnclaw.ai.burp import get_burp_client

        url = str(url or "").strip()
        if not url:
            return {"tool": self.name, "success": False, "error": "url 参数不能为空"}
        client = get_burp_client()
        if client is None:
            return {"tool": self.name, "success": False, "burp_available": False,
                    "error": "Burp 客户端未配置（检查 BURP_API_URL / BURP_API_KEY）"}
        try:
            if not await client.get_status():
                return {"tool": self.name, "success": False, "burp_available": False,
                        "error": "Burp 未运行或 REST API 未开启（Burp → Settings → Suite → REST API）"}
            issues = await client.scan_and_collect(urls=[url], wait_timeout=int(wait_timeout))
            return {
                "tool": self.name,
                "type": "burp_issues",
                "success": bool(issues),
                "count": len(issues),
                "issues": issues[:50],
                "summary": (f"Burp Scanner 返回 {len(issues)} 个 issue"
                            if issues else "Burp 扫描完成：无 issue"),
            }
        except Exception as e:  # noqa: BLE001
            return {"tool": self.name, "success": False, "error": f"Burp 扫描失败: {e}"}


class BurpIntruderTool(BaseTool):
    """真 Intruder：经 Burp 扩展桥（1.1.0+）对标记位逐 payload 模糊测试。

    替代 FALLBACK_MAP 里 burp_intruder→ffuf 的旧兜底语义：走 Burp 自身 HTTP
    栈（会话/Cookie/上游代理与手工测试一致），收集 status/length/耗时差异表。
    danger_level=guarded：主动模糊测试，经工具级 DangerGuard 审批。
    """

    def __init__(self):
        self.name = "burp_intruder"
        self.description = (
            "Burp Intruder 模糊测试：对 URL 中标记位（默认 FUZZ）逐 payload 发送，"
            "收集 status/length/耗时差异表（需要 Burp 运行且已加载 "
            "vulnclaw-bridge.jar 1.1.0+；不可用时返回明确说明而非崩溃）"
        )
        self.parameters = [
            {"name": "url", "type": "string", "required": True,
             "description": "目标 URL，含标记位（如 http://x/?q=FUZZ）"},
            {"name": "payloads", "type": "string", "required": True,
             "description": "逗号分隔的 payload 列表（含逗号的 payload 请改用多标记位）"},
            {"name": "marker", "type": "string", "required": False,
             "description": "标记占位符（默认 FUZZ）"},
            {"name": "concurrency", "type": "number", "required": False,
             "description": "并发数（默认 4，上限 16）"},
        ]
        self.category = "burp"
        self.danger_level = "guarded"

    async def execute(self, url: str = "", payloads: str = "", marker: str = "FUZZ",
                      concurrency: int = 4, **kwargs) -> Dict:
        from vulnclaw.ai.burp import get_burp_client

        url = str(url or "").strip()
        plist = [p.strip() for p in str(payloads or "").split(",") if p.strip()]
        if not url or not plist:
            return {"tool": self.name, "success": False,
                    "error": "url 与 payloads 均不能为空（payloads 逗号分隔）"}
        # 工具级门禁：主动模糊测试需 DangerGuard 审批
        try:
            from vulnclaw.core.danger_guard import guard
            if not guard.require_tool_approval(
                    self.name, f"intruder x{len(plist)} payloads", f"{self.name} @ {url}"):
                logger.warning(f"🚫 [DangerGuard] {self.name} 未获审批（工具级门禁）")
                return {"tool": self.name, "success": False, "guard_denied": True,
                        "error": "工具未获审批（DangerGuard 工具级门禁）"}
        except Exception as _ge:  # noqa: BLE001
            logger.debug(f"[DangerGuard] 工具级检查失败（放行兜底）: {_ge}")

        client = get_burp_client()
        if client is None:
            return {"tool": self.name, "success": False, "burp_available": False,
                    "error": "Burp 客户端未配置（检查 BURP_API_URL / BURP_API_KEY）"}
        try:
            result = await client.run_intruder(
                url, plist, marker=marker or "FUZZ",
                concurrency=concurrency if isinstance(concurrency, int) else 4)
        except Exception as e:  # noqa: BLE001
            return {"tool": self.name, "success": False, "error": f"Intruder 调用失败: {e}"}
        if result is None:
            return {"tool": self.name, "success": False, "burp_available": False,
                    "error": "扩展桥不可用（Burp 未运行或未加载 vulnclaw-bridge.jar 1.1.0+）",
                    "fallback_hint": "可改用 ffuf 做目录模糊枚举"}
        results = result.get("results") or []
        return {
            "tool": self.name,
            "type": "burp_intruder",
            "success": bool(results),
            "count": int(result.get("count", 0)),
            "ok": int(result.get("ok", 0)),
            "results": results[:100],
            "summary": (f"Intruder 完成 {result.get('ok', 0)}/{result.get('count', 0)} 个 payload"),
        }


def _register_burp_tools() -> int:
    registered = 0
    try:
        TOOL_REGISTRY["fetch_burp_issues"] = BurpIssuesTool()
        registered += 1
    except Exception as e:  # noqa: BLE001
        logger.warning(f"⚠️ Burp 工具注册失败: {e}")
    try:
        TOOL_REGISTRY["burp_intruder"] = BurpIntruderTool()
        registered += 1
    except Exception as e:  # noqa: BLE001
        logger.warning(f"⚠️ Burp Intruder 工具注册失败: {e}")
    return registered


_register_burp_tools()
logger.info(
    f"✅ 已注册 {len(TOOL_REGISTRY) - _cli_registered} 个检测工具"
    f" + {_cli_registered} 个 CLI 工具（A5.2 安全工具全集入册）"
)


# ==================================================================
# A6.1 / A6.2 / A5.3: 原生 Agent 工具（浏览器 / 登录 / 受控沙箱）
# 注：playwright 相关工具延迟导入，缺依赖时注册不报错，execute 时优雅降级。
# ==================================================================
class BrowserAgentTool(BaseTool):
    """A6.1: BrowserAIAgent 注册为 Agent 工具——点击/填表/翻页由 LLM 逐步指令驱动。"""

    name = "browser_explore"
    description = "AI 驱动的浏览器交互探索：自动点击/填表/翻页，捕获页面与 API 请求。用于 SPA/JS 渲染站点或需交互才能触达的端点。"
    category = "native"
    danger_level = "safe"
    timeout = 120  # 工具长执行超时（浏览器交互，非子进程），保持原值不接入 subprocess_timeout
    parameters = [
        {"name": "url", "type": "string", "required": True, "description": "起始 URL"},
        {"name": "use_profile_b", "type": "string", "required": False,
         "description": "是否用第二浏览器档案(admin 角色)，true/false"},
    ]

    async def execute(self, url: str, use_profile_b: str = "false", **kwargs) -> Dict:
        try:
            from vulnclaw.core.browser_ai_agent import BrowserAIAgent, HAS_PLAYWRIGHT
            if not HAS_PLAYWRIGHT:
                return {"type": "browser_result", "success": False,
                        "error": "Playwright 未安装（pip install playwright && playwright install chromium）"}
            agent = BrowserAIAgent()
            res = await agent.explore(url, use_profile_b=(str(use_profile_b).lower() == "true"))
            return {"type": "browser_result", "success": True, "data": res}
        except Exception as e:  # noqa: BLE001
            return {"type": "browser_result", "success": False, "error": str(e)}


class LoginAgentTool(BaseTool):
    """A6.2: 登录流自动拆解——登录表单识别→账号试填→提交→cookie 回传会话管理。"""

    name = "auto_login"
    description = "自动登录目标站点并提取 Cookie 回写会话管理（供后续引擎带认证态探测）。需提供账号密码与登录页选择器。"
    category = "native"
    danger_level = "guarded"
    timeout = 120  # 工具长执行超时（登录流，非子进程），保持原值不接入 subprocess_timeout
    parameters = [
        {"name": "login_url", "type": "string", "required": True, "description": "登录页 URL"},
        {"name": "username", "type": "string", "required": True, "description": "账号"},
        {"name": "password", "type": "string", "required": True, "description": "密码"},
        {"name": "username_selector", "type": "string", "required": False, "description": "用户名输入框 CSS 选择器"},
        {"name": "password_selector", "type": "string", "required": False, "description": "密码输入框 CSS 选择器"},
        {"name": "submit_selector", "type": "string", "required": False, "description": "提交按钮 CSS 选择器"},
        {"name": "success_indicator", "type": "string", "required": False, "description": "登录成功标识（URL 或页面内容包含）"},
    ]

    async def execute(self, login_url: str, username: str, password: str,
                     username_selector: str = "#username", password_selector: str = "#password",
                     submit_selector: str = "#login-btn", success_indicator: str = "dashboard",
                     **kwargs) -> Dict:
        try:
            from vulnclaw.core.auth.auto_login import auto_login_and_get_cookie, HAS_PLAYWRIGHT
            if not HAS_PLAYWRIGHT:
                return {"success": False,
                        "error": "Playwright 未安装（pip install playwright && playwright install chromium）"}
            cookies = await auto_login_and_get_cookie(
                login_url, username, password, username_selector,
                password_selector, submit_selector, success_indicator,
            )
            if not cookies:
                return {"success": False, "error": "自动登录失败（未检测到成功标识）"}
            domain = login_url.split("/")[2] if "://" in login_url else login_url
            try:
                from vulnclaw.core.auth.session_manager import get_session_manager
                get_session_manager().add_cookies(domain=domain, cookies=cookies)
            except Exception as se:  # noqa: BLE001
                logger.warning(f"[auto_login] cookie 回写会话管理失败: {se}")
            return {"success": True, "type": "login_result",
                    "domain": domain, "cookies": list(cookies.keys())}
        except Exception as e:  # noqa: BLE001
            return {"success": False, "error": str(e)}


class SandboxTool(BaseTool):
    """A5.3: 受控 shell 沙箱——白名单命令 + 参数校验 + 超时 + 输出截断 + 工作目录隔离。"""

    name = "shell"
    description = "受控 shell 沙箱：仅允许白名单命令（echo/cat/grep/curl 等），禁止组合/重定向/危险参数，带超时与输出截断。安全辅助命令执行。"
    category = "native"
    danger_level = "guarded"
    timeout = settings.subprocess_timeout
    parameters = [
        {"name": "command", "type": "string", "required": True, "description": "白名单命令（如 curl）"},
        {"name": "args", "type": "string", "required": False, "description": "命令参数，空格分隔"},
    ]

    async def execute(self, command: str, args: str = "", **kwargs) -> Dict:
        from vulnclaw.core.sandbox import run_sandboxed
        arg_list = shlex.split(args) if args else []
        return await run_sandboxed(command, arg_list, timeout=self.timeout)


def _register_native_tools() -> int:
    registered = 0
    for ToolClass in (BrowserAgentTool, LoginAgentTool, SandboxTool):
        try:
            inst = ToolClass()
            TOOL_REGISTRY[inst.name] = inst
            registered += 1
        except Exception as e:  # noqa: BLE001
            logger.warning(f"⚠️ 原生工具 {ToolClass.__name__} 注册失败: {e}")
    return registered


_register_native_tools()


def _fix_tool_args(tool, kwargs: Dict, err: str) -> Optional[Dict]:
    """PGEN-TCF: ToolCallFixer——按工具 schema（parameters: [{name,...}]）修复参数。

    1) 剔除 schema 外的未知参数（unexpected keyword argument）
    2) missing/required 类错误补齐缺失 schema 参数为安全空值（交工具内部校验兜底）
    发生实际修复（fixed != kwargs）才返回修复结果；否则 None 不重试。
    """
    try:
        schema = [
            p.get("name") for p in (getattr(tool, "parameters", None) or [])
            if isinstance(p, dict) and p.get("name")
        ]
    except Exception:  # noqa: BLE001
        return None
    if not schema:
        return None
    fixed = {k: v for k, v in kwargs.items() if k in schema}
    err_lower = str(err).lower()
    if "missing" in err_lower or "required" in err_lower:
        for s in schema:
            fixed.setdefault(s, "")
    if fixed == kwargs:
        return None
    return fixed


async def execute_tool(name: str, **kwargs) -> Dict:
    if name not in TOOL_REGISTRY:
        return {"error": f"未知工具: {name}"}
    tool = TOOL_REGISTRY[name]
    # PGEN-EVENT: 工具调用前广播（覆盖最广——所有引擎/工具调用都过此入口）
    await emit_event(ScanEvent.TOOL_CALL_LOG, {"phase": "call", "tool": name})
    try:
        result = await tool.execute(**kwargs)
        await emit_event(ScanEvent.TOOL_CALL_LOG, {"phase": "done", "tool": name, "ok": True})
        return result
    except TypeError as e:
        # PGEN-TCF: 参数类错误 → 按 schema 修复后重试一次（对齐 PentAGI tool_call_fixer）
        fixed = _fix_tool_args(tool, kwargs, str(e))
        if fixed is None:
            logger.error(f"工具 {name} 参数错误（修复失败）: {e}")
            await emit_event(ScanEvent.TOOL_CALL_LOG, {"phase": "error", "tool": name, "fixed": False})
            return {"error": str(e)}
        logger.warning(
            f"[ToolCallFixer] 工具 {name} 参数已修复重试: 原始{len(kwargs)}项 -> 修复{len(fixed)}项"
        )
        try:
            result = await tool.execute(**fixed)
            await emit_event(ScanEvent.TOOL_CALL_LOG, {"phase": "done", "tool": name, "ok": True, "fixed": True})
            return result
        except Exception as e2:  # noqa: BLE001
            logger.error(f"工具 {name} 修复后仍失败: {e2}")
            await emit_event(ScanEvent.TOOL_CALL_LOG, {"phase": "error", "tool": name, "fixed": True})
            return {"error": str(e2)}
    except Exception as e:
        logger.error(f"工具 {name} 执行异常: {e}")
        await emit_event(ScanEvent.TOOL_CALL_LOG, {"phase": "error", "tool": name})
        return {"error": str(e)}


__all__ = ['TOOL_REGISTRY', 'execute_tool']
