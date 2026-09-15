# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Engine facade for vulnclaw.

Import engine classes directly from the package root, e.g.:
    from vulnclaw.engines import SQLiEngine, XSSEngine
"""

from .auth_engines import IDOREngine, JWTEngine, OAuthEngine, SessionEngine, WeakCredentialEngine, PasswordResetEngine
from .auxiliary_engines import APIVersionDiffEngine, HTTP2WebSocketEngine, RequestSmugglingEngine
from .api_security_engines import APISecurityEngine, MassAssignmentEngine
from .api_version import APIVersionEngine
from .base import BaseEngine, CaseInsensitiveDict
from .container_engines import ContainerSecurityEngine
from .deserialization import DeserializationEngine
from .dotnet_deserialization import DotNetDeserializationEngine
from .framework_zero_day_engines_2 import (
    AdminConsoleExposureEngine,
    CloudAndContainerExposureEngine,
    ContainerPlatformExposureEngine,
    ShiroRememberMeEngine,
    SpringCloudGatewayEngine,
)
from .http_engines import (
    CachePoisonEngine,
    HostHeaderEngine,
    OpenRedirectEngine,
    RaceConditionEngine,
    SecurityHeadersEngine,
)
from .input_engines import (
    BusinessLogicEngine,
    CORSEngine,
    CRLFEngine,
    ELInjectionEngine,
    FileUploadEngine,
    HPPEngine,
    InfoLeakEngine,
    LDAPEngine,
)
from .logic_leak_engines_2 import (
    BackendComponentFingerprintEngine,
    BackupFileLeakEngine,
    GraphQLIntrospectionEngine,
    JsLibraryCveEngine,
    PrometheusMetricsExposureEngine,
    RateLimitEngine,
    SwaggerApiDocEngine,
    VerbTamperingEngine,
)
from .mobile_engines import MobileAPIEngine
from .net_engines import DnsRebindingEngine, DnsSecurityEngine, GraphQLEngine, SSRFEngine, TlsSecurityEngine, XXEEngine
from .web_engines import CMDIEngine, LFIEngine, NoSQLEngine, RFIEngine, SQLiEngine, SSTIEngine, XSSEngine
from .http_advanced_engines import CSRFEngine, WebCacheDeceptionEngine
from .middleware_exposure_engines import (
    ConfluenceExposureEngine,
    NacosExposureEngine,
    SolrExposureEngine,
)
from .framework_zero_day_engines import FastjsonDeserializationEngine, Log4ShellEngine, Spring4ShellEngine, Struts2OGNLEngine, ViewStateEngine
from .leak_logic_engines import AuthEnumerationEngine, SourceCodeLeakEngine, SpringActuatorEngine
from .web_advanced_engines import CssExfiltrationEngine, JSONPHijackingEngine, PrototypePollutionEngine, SSIInjectionEngine, XPathInjectionEngine
from .websocket_security import WebSocketSecurityEngine
from .dom_clobbering import DOMClobberingEngine
from .deep_chimera import DeepChimeraEngine
from .biz_oracle_engines import DualSessionOracleEngine
from .state_chain import StateChainEngine
from .parsing_shadow import ParsingShadowEngine
from .symbolic_engine import SymbolicLogicEngine

__all__ = [
    "BaseEngine",
    "CaseInsensitiveDict",
    "SymbolicLogicEngine",
    "IDOREngine",
    "JWTEngine",
    "OAuthEngine",
    "SessionEngine",
    "APIVersionDiffEngine",
    "HTTP2WebSocketEngine",
    "RequestSmugglingEngine",
    "DeserializationEngine",
    "DotNetDeserializationEngine",
    "SecurityHeadersEngine",
    "HostHeaderEngine",
    "OpenRedirectEngine",
    "RaceConditionEngine",
    "CachePoisonEngine",
    "ELInjectionEngine",
    "FileUploadEngine",
    "CORSEngine",
    "CRLFEngine",
    "LDAPEngine",
    "BusinessLogicEngine",
    "InfoLeakEngine",
    "MobileAPIEngine",
    "SSRFEngine",
    "XXEEngine",
    "GraphQLEngine",
    "XSSEngine",
    "SQLiEngine",
    "LFIEngine",
    "CMDIEngine",
    "SSTIEngine",
    "NoSQLEngine",
    "ContainerSecurityEngine",
    "WebSocketSecurityEngine",
    "APISecurityEngine",
    "APIVersionEngine",
    "RFIEngine",
    "HPPEngine",
    "XPathInjectionEngine",
    "SSIInjectionEngine",
    "PrototypePollutionEngine",
    "JSONPHijackingEngine",
    "CssExfiltrationEngine",
    "DOMClobberingEngine",
    "CSRFEngine",
    "WebCacheDeceptionEngine",
    "Log4ShellEngine",
    "FastjsonDeserializationEngine",
    "Struts2OGNLEngine",
    "Spring4ShellEngine",
    "ViewStateEngine",
    "SpringActuatorEngine",
    "SourceCodeLeakEngine",
    "AuthEnumerationEngine",
    "ShiroRememberMeEngine",
    "SpringCloudGatewayEngine",
    "ContainerPlatformExposureEngine",
    "AdminConsoleExposureEngine",
    "BackupFileLeakEngine",
    "SwaggerApiDocEngine",
    "GraphQLIntrospectionEngine",
    "RateLimitEngine",
    "VerbTamperingEngine",
    "PrometheusMetricsExposureEngine",
    "TlsSecurityEngine",
    "DnsSecurityEngine",
    "DnsRebindingEngine",
    "MassAssignmentEngine",
    "WeakCredentialEngine",
    "JsLibraryCveEngine",
    "PasswordResetEngine",
    "CloudAndContainerExposureEngine",
    "BackendComponentFingerprintEngine",
    "ConfluenceExposureEngine",
    "NacosExposureEngine",
    "SolrExposureEngine",
    "ParsingShadowEngine",
    "StateChainEngine",
    "DeepChimeraEngine",
    "DualSessionOracleEngine",
]

from vulnclaw.engines.llm_security_engines import LLMInjectionEngine


# ============ P0-3：统一引擎注册表（自动汇总 + 可达性自检辅助） ============
# 设计背景：core/scanner._do_load_engines 用 inspect.getmembers 自动发现所有
# BaseEngine 子类（不依赖本文件 import），但引擎"是否被调度"取决于 phases_taskgen
# 的 engine_priority / global_engines 两调度池。新增引擎若忘了进池，会"注册但不跑"。
# 这里在包加载时自动汇总所有引擎类为注册表，供调度层与可达性自检统一查询，
# 并让 phased_taskgen 在启动时自动兜底未入池引擎（消除漏调度隐患）。
ENGINE_REGISTRY = {}
for _n, _obj in list(globals().items()):
    if (isinstance(_obj, type) and issubclass(_obj, BaseEngine) and _obj is not BaseEngine):
        # key 统一用引擎的 name 属性（如 "sqli"），与调度池 / scanner._ENGINE_MAP 一致；
        # name 缺失时退回类名，避免漏注册。
        _ename = getattr(_obj, "name", None)
        ENGINE_REGISTRY[_ename if _ename else _n] = _obj


def get_engine_class(name: str):
    """按 name 取引擎类；找不到返回 None。调度层统一入口，替代散落的 getattrs。"""
    return ENGINE_REGISTRY.get(name)


def engine_names() -> list:
    """返回所有已注册引擎名（用于可达性自检与覆盖统计）。"""
    return list(ENGINE_REGISTRY.keys())