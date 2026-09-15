# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Vulnerability scanning helpers, split by scanning capability."""

from .verify_ai import (
    VulnAIRateLimiter,
    verify_with_ai,
    batch_verify_with_ai,
    verify_nuclei_with_ai_async,
    is_waf_block,
    extract_params_from_html,
    test_post_json,
    get_vuln_llm_client,
    safe_extract_json,
    normalize_response,
    get_pending_retry_count,
    clear_pending_retry,
)
from .cve_nuclei import (
    run_arjun,
    run_nuclei_async,
    run_nikto,
    nuclei_template_health,
    collect_line_targets,
    run_nuclei_community_line,
)
from .directory_ffuf import run_ffuf_async
from .oob_interactsh import get_interactsh_domain_async, get_interactsh_poll
from .auth_privilege import IDORScanner, scan_idor, scan_vertical_privilege, check_default_credentials
from .advanced_business import (
    scan_llm_injection,
    scan_spring_actuator,
    scan_dependency_confusion,
    scan_oauth_hijack,
    scan_rtsp_default_creds,
    scan_graphql_introspection,
    scan_dns_rebinding,
    run_all_advanced_ai_checks,
    invoke_external_tool,
)

__all__ = [
    "VulnAIRateLimiter",
    "verify_with_ai",
    "batch_verify_with_ai",
    "verify_nuclei_with_ai_async",
    "is_waf_block",
    "extract_params_from_html",
    "test_post_json",
    "get_vuln_llm_client",
    "safe_extract_json",
    "normalize_response",
    "get_pending_retry_count",
    "clear_pending_retry",
    "run_arjun",
    "run_nuclei_async",
    "run_nikto",
    "nuclei_template_health",
    "collect_line_targets",
    "run_nuclei_community_line",
    "run_ffuf_async",
    "get_interactsh_domain_async",
    "get_interactsh_poll",
    "IDORScanner",
    "scan_idor",
    "scan_vertical_privilege",
    "check_default_credentials",
    "scan_llm_injection",
    "scan_spring_actuator",
    "scan_dependency_confusion",
    "scan_oauth_hijack",
    "scan_rtsp_default_creds",
    "scan_graphql_introspection",
    "scan_dns_rebinding",
    "run_all_advanced_ai_checks",
    "invoke_external_tool",
]
