# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""core/auth 子包：认证模块统一入口（v103 阶段 1 收敛）。"""

from .auth_helper import (
    parse_cookie_string,
    verify_cookie_sync,
    get_accounts_interactive,
    auto_login,
)
from .auto_login import auto_login_and_get_cookie, auto_login_multiple_accounts
from .browser_cookie import get_browser_cookies, get_all_browser_cookies
from .session_manager import CookieManager, SessionManager, get_session_manager

__all__ = [
    "parse_cookie_string",
    "verify_cookie_sync",
    "get_accounts_interactive",
    "auto_login",
    "auto_login_and_get_cookie",
    "auto_login_multiple_accounts",
    "get_browser_cookies",
    "get_all_browser_cookies",
    "CookieManager",
    "SessionManager",
    "get_session_manager",
]
