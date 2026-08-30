# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/auth_helper.py
# 合并 interactive.py + login.py

import sys
import re
import os
import tempfile
import requests
from vulnclaw.core.settings import settings
from vulnclaw.core.settings import settings
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import Dict, List

LOGIN_TIMEOUT = getattr(settings, 'auth_login_timeout', 15)

# ---------- 原 interactive.py ----------


def parse_cookie_string(cookie_str: str) -> Dict[str, str]:
    cookie_str = re.sub(r'^Cookie:\s*', '', cookie_str, flags=re.IGNORECASE)
    parts = re.split(r'[;\n]', cookie_str)
    cookies = {}
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if '=' in part:
            key, value = part.split('=', 1)
            cookies[key.strip()] = value.strip()
    return cookies


def verify_cookie_sync(domain: str, cookies: Dict[str, str]) -> bool:
    if not cookies:
        return False
    cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
    headers = {"Cookie": cookie_str, "User-Agent": "Mozilla/5.0"}
    test_urls = [
        f"https://{domain}/dashboard",
        f"https://{domain}/api/me",
        f"https://{domain}/profile",
        f"https://{domain}/",
    ]
    for url in test_urls:
        try:
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
            if resp.status_code in (401, 403):
                continue
            text = resp.text.lower()
            if 'login' not in text and 'sign in' not in text and '请登录' not in text:
                return True
        except BaseException:
            continue
    return False


def get_accounts_interactive(default_domain: str) -> List[Dict]:
    print("\n" + "=" * 60)
    print("🍪 请输入两个账户的 Cookie 信息（用于越权测试）")
    print("=" * 60)
    print(f"默认域名: {default_domain}（可直接回车使用）")
    print("如果您的 Cookie 属于其他子域，请手动输入（如 console.neon.tech）")
    print("每个账户只需粘贴 Cookie 字符串即可。\n")
    sys.stdout.flush()

    accounts = []
    role_names = ["用户A", "用户B"]

    for i in range(2):
        print(f"\n--- 请输入 {role_names[i]} 的 Cookie ---")
        sys.stdout.flush()
        domain = input(f"请输入该账户对应的域名（直接回车使用 {default_domain}）: ").strip()
        if not domain:
            domain = default_domain

        print("请粘贴该账户的 Cookie 字符串（从浏览器请求头复制，可含 'Cookie:' 前缀）:")
        sys.stdout.flush()
        cookie_str = sys.stdin.readline().strip()
        if not cookie_str:
            if i == 0:
                print("❌ 至少需要第一个账户的 Cookie，请重新启动。")
                sys.exit(1)
            else:
                print("跳过第二账户。")
                break

        cookies = parse_cookie_string(cookie_str)
        if not cookies:
            print("❌ 无法解析 Cookie，请检查格式。")
            continue

        print(f"⏳ 正在验证 {domain} 的 Cookie...")
        sys.stdout.flush()
        if verify_cookie_sync(domain, cookies):
            print("✅ Cookie 验证通过！")
        else:
            print("⚠️  Cookie 验证失败（可能无法访问认证接口），但会继续使用。")

        accounts.append({
            "domain": domain,
            "cookies": cookies,
            "role": f"user{i + 1}"
        })
        print(f"✅ {role_names[i]} 的 Cookie 已保存。")

        if i == 0:
            add_second = input("\n是否添加第二个账户？(y/n，默认 n): ").strip().lower()
            if add_second != 'y':
                break

    if not accounts:
        print("❌ 未获取任何有效 Cookie，退出。")
        sys.exit(1)

    return accounts


# ---------- 原 login.py ----------
def auto_login(target, username, password, login_url=None):
    if not username or not password:
        print("❌ 用户名或密码为空")
        return None

    if login_url is None:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        possible_paths = ['/login', '/signin', '/auth/login', '/user/login', '/admin/login']
        for path in possible_paths:
            test_url = urljoin(base, path)
            try:
                r = requests.get(test_url, timeout=LOGIN_TIMEOUT, verify=False)
                if r.status_code == 200 and ('login' in r.text.lower() or 'sign in' in r.text.lower()):
                    login_url = test_url
                    print(f"[+] 发现登录页面: {login_url}")
                    break
            except BaseException:
                continue
        if login_url is None:
            print("❌ 未自动检测到登录页面，请手动指定 --login-url")
            return None
    else:
        if not login_url.startswith('http'):
            login_url = urljoin(target, login_url)

    print(f"[*] 登录目标: {login_url}")

    try:
        session = requests.Session()
        resp = session.get(login_url, timeout=LOGIN_TIMEOUT, verify=False)
        if resp.status_code != 200:
            print(f"❌ 无法访问登录页面: {resp.status_code}")
            return None

        soup = BeautifulSoup(resp.text, 'html.parser')
        form = soup.find('form')
        if not form:
            print("⚠️  未找到登录表单，尝试直接 POST（可能失败）")
            post_data = {'username': username, 'password': password}
        else:
            post_data = {}
            for inp in form.find_all('input'):
                name = inp.get('name')
                value = inp.get('value', '')
                if name:
                    if name.lower() in ('username', 'user', 'email'):
                        post_data[name] = username
                    elif name.lower() in ('password', 'pass'):
                        post_data[name] = password
                    else:
                        post_data[name] = value
            action = form.get('action')
            if action:
                if not action.startswith('http'):
                    action = urljoin(login_url, action)
                login_url = action

        print(f"[*] 提交登录请求至: {login_url}")

        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        login_resp = session.post(login_url, data=post_data, headers=headers, timeout=LOGIN_TIMEOUT, verify=False)

        if login_resp.status_code in (301, 302) and 'location' in login_resp.headers:
            print("[+] 登录成功（重定向）")
        elif login_resp.status_code == 200 and ('login' not in login_resp.text.lower() and 'sign in' not in login_resp.text.lower()):
            print("[+] 登录成功（页面内容判断）")
        else:
            print(f"⚠️  登录可能失败，状态码: {login_resp.status_code}")
            if 'error' in login_resp.text.lower() or 'invalid' in login_resp.text.lower():
                print("[-] 登录失败，请检查用户名/密码或网站结构")
                return None

        cookies = session.cookies.get_dict()
        if not cookies:
            print("❌ 未获取到任何 Cookie")
            return None

        fd, temp_path = tempfile.mkstemp(suffix='.txt', prefix='cookie_', text=True)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            for k, v in cookies.items():
                f.write(f"{k}={v}\n")
        print(f"[+] 自动登录成功，Cookie 已保存至: {temp_path}")
        print(f"    Cookie 条目数: {len(cookies)}")
        return temp_path

    except Exception as e:
        print(f"❌ 自动登录异常: {e}")
        return None


def cleanup_temp_file(filepath):
    if filepath and os.path.exists(filepath):
        try:
            os.unlink(filepath)
            print(f"[✓] 已清理临时 Cookie 文件: {filepath}")
        except Exception as e:
            print(f"⚠️  清理临时文件失败: {e}")


# ============================================================
# 导出
# ============================================================
__all__ = [
    'parse_cookie_string',
    'verify_cookie_sync',
    'get_accounts_interactive',
    'auto_login',
    'cleanup_temp_file'
]
