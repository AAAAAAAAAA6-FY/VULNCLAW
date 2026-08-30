# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# 合并后新增导出
from .recon import alive_scan, port_scan, get_subdomains, get_subdomains_async, EndpointCollector
from .collectors import (
    JSDeepAnalyzer, analyze_js_deep,
    run_all_burp_plugins_checks,
    BrowserAIAgent, create_browser_agent, HAS_PLAYWRIGHT,
    APISpecParser,
    scan_session_security,
)
from .vuln_scanner import (
    verify_with_ai, batch_verify_with_ai, verify_nuclei_with_ai_async,
    is_waf_block, extract_params_from_html, test_post_json,
    get_vuln_llm_client, safe_extract_json, normalize_response,
    run_arjun, run_nuclei_async, run_ffuf_async,
    get_interactsh_domain_async, get_interactsh_poll,
    IDORScanner, scan_idor, scan_vertical_privilege,
    check_default_credentials,
    scan_llm_injection, scan_spring_actuator, scan_oauth_hijack,
    scan_graphql_introspection, scan_dns_rebinding,
    run_all_advanced_ai_checks,
)

__all__ = [
    "alive_scan", "port_scan", "get_subdomains", "get_subdomains_async", "EndpointCollector",
    "JSDeepAnalyzer", "analyze_js_deep", "run_all_burp_plugins_checks",
    "BrowserAIAgent", "create_browser_agent", "HAS_PLAYWRIGHT",
    "APISpecParser", "scan_session_security",
    "verify_with_ai", "batch_verify_with_ai", "verify_nuclei_with_ai_async",
    "is_waf_block", "extract_params_from_html", "test_post_json",
    "get_vuln_llm_client", "safe_extract_json", "normalize_response",
    "run_arjun", "run_nuclei_async", "run_ffuf_async",
    "get_interactsh_domain_async", "get_interactsh_poll",
    "IDORScanner", "scan_idor", "scan_vertical_privilege",
    "check_default_credentials",
    "scan_llm_injection", "scan_spring_actuator", "scan_oauth_hijack",
    "scan_graphql_introspection", "scan_dns_rebinding",
    "run_all_advanced_ai_checks",
]
