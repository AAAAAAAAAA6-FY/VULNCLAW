# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Engine facade for vulnclaw.

Import engine classes directly from the package root, e.g.:
    from vulnclaw.engines import SQLiEngine, XSSEngine
"""

from .auth_engines import IDOREngine, JWTEngine, OAuthEngine, SessionEngine
from .auxiliary_engines import APIVersionDiffEngine, HTTP2WebSocketEngine, RequestSmugglingEngine
from .api_security_engines import APISecurityEngine
from .api_version import APIVersionEngine
from .base import BaseEngine, CaseInsensitiveDict
from .container_engines import ContainerSecurityEngine
from .deserialization import DeserializationEngine
from .dotnet_deserialization import DotNetDeserializationEngine
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
from .mobile_engines import MobileAPIEngine
from .net_engines import GraphQLEngine, SSRFEngine, XXEEngine
from .web_engines import CMDIEngine, LFIEngine, NoSQLEngine, RFIEngine, SQLiEngine, SSTIEngine, XSSEngine
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
]
