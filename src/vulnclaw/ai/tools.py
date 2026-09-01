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
from vulnclaw.core.utils import async_get, get_shared_session
from typing import Dict, List

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
                        normal_resp = await async_get(url, session=session, timeout=10)
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
logger.info(
    f"✅ 已注册 {len(TOOL_REGISTRY) - _cli_registered} 个检测工具"
    f" + {_cli_registered} 个 CLI 工具（A5.2 安全工具全集入册）"
)


async def execute_tool(name: str, **kwargs) -> Dict:
    if name not in TOOL_REGISTRY:
        return {"error": f"未知工具: {name}"}
    tool = TOOL_REGISTRY[name]
    try:
        return await tool.execute(**kwargs)
    except Exception as e:
        logger.error(f"工具 {name} 执行异常: {e}")
        return {"error": str(e)}


__all__ = ['TOOL_REGISTRY', 'execute_tool']
