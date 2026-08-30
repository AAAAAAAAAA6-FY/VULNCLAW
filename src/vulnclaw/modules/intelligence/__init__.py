# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# modules/intelligence/__init__.py
"""P4-1: 外部情报源自动补全（Shodan / Censys）。

在 Recon 阶段对目标 IP 拉取开放端口、历史漏洞（CVE）、服务指纹（product），
注入 recon_brief["intel"]，供引擎与 AI 决策 payload 时优先尝试对应服务类型。

未配置 API Key 时静默降级（info 级日志），不阻塞扫描主流程。
"""

from vulnclaw.modules.intelligence.shodan_client import (
    CensysClient,
    ShodanClient,
    enrich_brief_with_intel,
    lookup_ip,
    resolve_ip,
)

__all__ = [
    "ShodanClient",
    "CensysClient",
    "lookup_ip",
    "resolve_ip",
    "enrich_brief_with_intel",
]
