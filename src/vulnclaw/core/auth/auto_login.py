# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/auto_login.py
"""
使用 Playwright 自动登录目标网站，提取 Cookie
"""
from typing import Dict, List, Optional


# 检查 Playwright 是否可用
try:
    from playwright.async_api import async_playwright  # noqa: F401  (可用性探测)
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


async def auto_login_and_get_cookie(
    login_url: str,
    username: str,
    password: str,
    username_selector: str = "",
    password_selector: str = "",
    submit_selector: str = "",
    success_indicator: str = "",
    headless: bool = True,
    timeout: int = 30000,
    persist_cookie: bool = True,
) -> Optional[Dict[str, str]]:
    """Playwright 自动登录并提取 Cookie（选择器/成功标识可由 settings 配置）。

    配置项（settings 动态读取，未声明时用默认值，零字段依赖）：
      login_username_selector / login_password_selector /
      login_submit_selector   / login_success_indicator
    成功后（persist_cookie=True）自动 seed 到目标域 Cookie 文件——
    后续扫描 get_shared_session 直接携带登录态（与 --cookie 同落点）。
    """
    if not HAS_PLAYWRIGHT:
        print("❌ Playwright 未安装，请运行: pip install playwright && playwright install chromium")
        return None

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print("❌ Playwright 导入失败")
        return None

    # 选择器/成功标识：显式参数 > settings 配置 > 默认值（硬编码仅作最后兜底）
    try:
        from vulnclaw.config.settings import settings as _st
    except Exception:  # noqa: BLE001
        _st = None
    username_selector = (username_selector
                         or str(getattr(_st, "login_username_selector", "") or "")
                         or "#username")
    password_selector = (password_selector
                         or str(getattr(_st, "login_password_selector", "") or "")
                         or "#password")
    submit_selector = (submit_selector
                       or str(getattr(_st, "login_submit_selector", "") or "")
                       or "#login-btn")
    success_indicator = (success_indicator
                         or str(getattr(_st, "login_success_indicator", "") or "")
                         or "dashboard")

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=headless)
            context = await browser.new_context()
            page = await context.new_page()
            try:
                await page.goto(login_url, timeout=timeout)
                await page.wait_for_load_state("networkidle")
                await page.fill(username_selector, username)
                await page.fill(password_selector, password)
                await page.click(submit_selector)
                await page.wait_for_load_state("networkidle", timeout=timeout)
                current_url = page.url
                page_content = await page.content()
                if success_indicator in current_url or success_indicator in page_content:
                    cookies = await context.cookies()
                    cookie_dict = {c["name"]: c["value"] for c in cookies}
                    print(f"✅ 自动登录成功，获取到 {len(cookie_dict)} 个 Cookie")
                    if persist_cookie and cookie_dict:
                        _persist_login_cookies(login_url, cookie_dict)
                    await browser.close()
                    return cookie_dict
                else:
                    print(f"❌ 登录失败，未检测到成功标识: {success_indicator}")
                    await browser.close()
                    return None
            except Exception as e:
                print(f"❌ 自动登录异常: {e}")
                await browser.close()
                return None
    except Exception as e:
        print(f"❌ Playwright 启动失败: {e}")
        return None


def _persist_login_cookies(login_url: str, cookie_dict: Dict[str, str]) -> None:
    """把登录态 Cookie 落盘到目标域文件（复用 --cookie 的落点与原子写）。

    落盘后 get_shared_session / extract_target_cookies 自动携带登录态，
    供认证后扫描（如 IDOR multi-session oracle）使用。
    """
    try:
        from urllib.parse import urlparse
        from vulnclaw.runners.scan_runner import seed_cookie_for_domain
        host = urlparse(login_url).hostname or ""
        if host:
            seed_cookie_for_domain(
                host, "; ".join(f"{k}={v}" for k, v in cookie_dict.items()))
    except Exception as exc:  # noqa: BLE001 - 落盘失败不影响登录结果返回
        print(f"⚠️ 登录态落盘失败（不影响返回）: {exc}")


async def auto_login_multiple_accounts(
    login_url: str,
    accounts: List[Dict[str, str]],
    headless: bool = True,
) -> List[Dict[str, str]]:
    """
    用多个账户自动登录，返回 Cookie 列表

    accounts: [{"username": "user1", "password": "pass1"}, {"username": "user2", "password": "pass2"}]
    返回: [{"domain": "xxx", "cookies": {...}, "role": "user1"}, ...]
    """
    if not accounts:
        print("❌ 账户列表为空")
        return []

    results = []
    for idx, acc in enumerate(accounts):
        username = acc.get('username', '')
        password = acc.get('password', '')
        if not username or not password:
            print(f"⚠️ 账户 {idx + 1} 缺少用户名或密码，跳过")
            continue

        print(f"🔄 正在登录账户 {idx + 1}: {username}")
        cookies = await auto_login_and_get_cookie(
            login_url=login_url,
            username=username,
            password=password,
            headless=headless,
        )
        if cookies:
            # 提取域名
            domain = login_url.split("/")[2] if "://" in login_url else login_url
            results.append({
                "domain": domain,
                "cookies": cookies,
                "role": f"user{idx + 1}",
            })
    return results


# ============================================================
# 导出
# ============================================================
__all__ = [
    'auto_login_and_get_cookie',
    'auto_login_multiple_accounts',
    'HAS_PLAYWRIGHT'
]
