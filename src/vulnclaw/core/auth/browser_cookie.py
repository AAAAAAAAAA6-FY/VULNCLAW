# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/browser_cookie.py
"""
从 Chrome/Edge 浏览器读取 Cookie
"""

import sqlite3
import os
import shutil
import tempfile
from typing import Dict, Optional


def get_browser_cookies(domain: str) -> Optional[Dict[str, str]]:
    """
    从 Chrome 或 Edge 读取指定域名的 Cookie
    domain: 域名（如 neon.tech）
    返回: {"cookie_name": "value", ...} 或 None
    """
    cookie_paths = [
        os.path.expanduser("~/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies"),
        os.path.expanduser("~/AppData/Local/Google/Chrome/User Data/Default/Cookies"),
        os.path.expanduser("~/AppData/Local/Microsoft/Edge/User Data/Default/Network/Cookies"),
        os.path.expanduser("~/AppData/Local/Microsoft/Edge/User Data/Default/Cookies"),
        os.path.expanduser("~/AppData/Local/Google/Chrome/User Data/Profile 1/Network/Cookies"),
        os.path.expanduser("~/AppData/Local/Google/Chrome/User Data/Profile 1/Cookies"),
    ]

    cookie_path = None
    for path in cookie_paths:
        if os.path.exists(path):
            cookie_path = path
            break

    if not cookie_path:
        print("❌ 未找到 Chrome 或 Edge 的 Cookie 数据库")
        return None

    temp_path = tempfile.mktemp(suffix=".db")
    try:
        shutil.copy(cookie_path, temp_path)
    except Exception as e:
        print(f"❌ 复制 Cookie 文件失败: {e}")
        return None

    cookies = {}
    try:
        conn = sqlite3.connect(temp_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name, value FROM cookies WHERE host_key LIKE ?",
            (f"%{domain}%",)
        )
        for row in cursor.fetchall():
            cookies[row[0]] = row[1]
        conn.close()
    except Exception as e:
        print(f"❌ 读取 Cookie 失败: {e}")
        return None
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except BaseException:
                pass

    if cookies:
        print(f"🍪 从浏览器读取到 {len(cookies)} 个 Cookie (域名: {domain})")
        return cookies
    else:
        print(f"⚠️ 未从浏览器找到 {domain} 的 Cookie，请先登录")
        return None


def get_all_browser_cookies(domain: str) -> Dict[str, Dict[str, str]]:
    """
    获取浏览器中所有匹配域名的 Cookie，按精确域名分组
    返回: {"domain.com": {"cookie_name": "value", ...}, ...}
    """
    cookie_paths = [
        os.path.expanduser("~/AppData/Local/Google/Chrome/User Data/Default/Cookies"),
        os.path.expanduser("~/AppData/Local/Microsoft/Edge/User Data/Default/Cookies"),
    ]

    cookie_path = None
    for path in cookie_paths:
        if os.path.exists(path):
            cookie_path = path
            break

    if not cookie_path:
        return {}

    temp_path = tempfile.mktemp(suffix=".db")
    try:
        shutil.copy(cookie_path, temp_path)
    except BaseException:
        return {}

    result = {}
    try:
        conn = sqlite3.connect(temp_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT host_key, name, value FROM cookies WHERE host_key LIKE ?",
            (f"%{domain}%",)
        )
        for row in cursor.fetchall():
            host = row[0].lstrip('.')
            result.setdefault(host, {})[row[1]] = row[2]
        conn.close()
    except BaseException:
        pass
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except BaseException:
                pass

    return result


# ============================================================
# 导出
# ============================================================
__all__ = [
    'get_browser_cookies',
    'get_all_browser_cookies'
]
