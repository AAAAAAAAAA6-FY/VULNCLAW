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
    username_selector: str = "#username",
    password_selector: str = "#password",
    submit_selector: str = "#login-btn",
    success_indicator: str = "dashboard",
    headless: bool = True,
    timeout: int = 30000,
) -> Optional[Dict[str, str]]:
    if not HAS_PLAYWRIGHT:
        print("❌ Playwright 未安装，请运行: pip install playwright && playwright install chromium")
        return None

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print("❌ Playwright 导入失败")
        return None

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

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        context = await browser.new_context()
        page = await context.new_page()

        try:
            # 1. 访问登录页面
            await page.goto(login_url, timeout=timeout)
            await page.wait_for_load_state("networkidle")

            # 2. 填写表单
            await page.fill(username_selector, username)
            await page.fill(password_selector, password)

            # 3. 点击登录按钮
            await page.click(submit_selector)

            # 4. 等待登录完成（跳转或页面变化）
            await page.wait_for_load_state("networkidle", timeout=timeout)

            # 5. 检查是否登录成功
            current_url = page.url
            page_content = await page.content()

            # 检查 URL 或页面内容中是否包含成功标识
            if success_indicator in current_url or success_indicator in page_content:
                # 6. 提取所有 Cookie
                cookies = await context.cookies()
                cookie_dict = {c["name"]: c["value"] for c in cookies}
                print(f"✅ 自动登录成功，获取到 {len(cookie_dict)} 个 Cookie")
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
