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
    """工具基类"""
    name: str = ""
    description: str = ""
    parameters: List[Dict] = [
        {"name": "url", "type": "string", "required": True, "description": "目标URL"},
        {"name": "param", "type": "string", "required": False, "description": "要测试的参数名（可选，不提供则执行全局检测）"},
    ]

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

logger.info(f"✅ 已注册 {len(TOOL_REGISTRY)} 个检测工具")


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
