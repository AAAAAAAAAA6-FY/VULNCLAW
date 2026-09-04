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
from .net_engines import DnsSecurityEngine, GraphQLEngine, SSRFEngine, TlsSecurityEngine, XXEEngine
from .web_engines import CMDIEngine, LFIEngine, NoSQLEngine, RFIEngine, SQLiEngine, SSTIEngine, XSSEngine
from .http_advanced_engines import CSRFEngine, WebCacheDeceptionEngine
from .middleware_exposure_engines import (
    ConfluenceExposureEngine,
    NacosExposureEngine,
    SolrExposureEngine,
)
from .framework_zero_day_engines import FastjsonDeserializationEngine, Log4ShellEngine, Spring4ShellEngine, Struts2OGNLEngine, ViewStateEngine
from .leak_logic_engines import AuthEnumerationEngine, SourceCodeLeakEngine, SpringActuatorEngine
from .web_advanced_engines import JSONPHijackingEngine, PrototypePollutionEngine, SSIInjectionEngine, XPathInjectionEngine
from .websocket_security import WebSocketSecurityEngine

__all__ = [
    "BaseEngine",
    "CaseInsensitiveDict",
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
    "MassAssignmentEngine",
    "WeakCredentialEngine",
    "JsLibraryCveEngine",
    "PasswordResetEngine",
    "CloudAndContainerExposureEngine",
    "BackendComponentFingerprintEngine",
    "ConfluenceExposureEngine",
    "NacosExposureEngine",
    "SolrExposureEngine",
]