# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
指令凭据消费层（SP27：--instruction 账号密码自动登录）

纯增量接线：从 Instruction 对象登录目标并落盘 Cookie，失败自动回退，
不改变既有 cookie 4 步流程。

流程：
1. 无凭据 → 直接返回 False（走原有 auto_fetch_cookie 4 步）
2. 依次对每个账号尝试登录（顺序即优先级，首个成功的为主账号）：
   - 有 Playwright → 复用 auto_login_and_get_cookie()
   - 无 Playwright → HTTP 表单登录降级（html.parser 找表单 + httpx 提交）
3. 落盘（与既有格式一致 {"domain": {name: value}}）：
   - 主账号 → cookies/{domain}.json（get_shared_session 自动消费，认证爬取立即生效）
   - 角色账号 → cookies/{domain}@{role}.json（供多角色越权测试引用）
4. 多账号时注册 session_manager 角色会话（IDOR/越权引擎 get_roles()>=2 自动启用）
5. 日志一律脱敏 username:***，密码明文只存在于内存对象。
"""
from __future__ import annotations

import json
import os
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urljoin

from vulnclaw.config import PROJECT_CACHE_DIR
from vulnclaw.core.auth.auto_login import HAS_PLAYWRIGHT, auto_login_and_get_cookie
from vulnclaw.core.instructions import Acct, Instruction
from vulnclaw.core.logger import logger

COOKIE_DIR = Path(PROJECT_CACHE_DIR) / "cookies"

# 文件名非法字符（Windows \/:*?"<>| 与空格），角色名入文件名需清洗
_FILENAME_BAD = re.compile(r'[\\/:*?"<>|\s]+')

_MASKED = "***"


# ============================================================
# Cookie 落盘
# ============================================================

def _role_suffix(role: str) -> str:
    """角色转安全文件名片段（default/空 → 空后缀，即主账号文件）。"""
    role = (role or "").strip().lower()
    if not role or role in ("default", "主账号"):
        return ""
    return "@" + _FILENAME_BAD.sub("_", role)[:48]


def _cookie_file_path(domain: str, suffix: str = "") -> Path:
    COOKIE_DIR.mkdir(parents=True, exist_ok=True)
    return COOKIE_DIR / f"{domain}{suffix}.json"


def _save_cookie(domain: str, cookies: Dict[str, str], suffix: str = "", role_hint: str = "") -> Path:
    """原子写 cookie 文件（.tmp + replace），格式 {"domain": {name: value}}。"""
    path = _cookie_file_path(domain, suffix)
    tmp = path.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({domain: cookies}, fh, indent=2, ensure_ascii=False)
        fh.flush()
        os.fsync(fh.fileno())
    tmp.replace(path)
    label = role_hint or "(主账号)"
    logger.info(f"🔐 指令登录 Cookie 已落盘: {path}（{len(cookies)} 条，{label}）")
    return path


# ============================================================
# 单账号登录
# ============================================================

class _FormParser(HTMLParser):
    """抽取登录表单：action / method / 输入框(name,type,value)。"""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list = []
        self._cur = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attr = dict(attrs)
        if tag == "form":
            self._cur = {
                "action": attr.get("action", ""),
                "method": (attr.get("method") or "get").lower(),
                "inputs": [],
            }
            self.forms.append(self._cur)
        elif tag == "input" and self._cur is not None:
            itype = (attr.get("type") or "text").lower()
            if itype not in ("submit", "button", "image", "reset"):
                self._cur["inputs"].append(
                    {
                        "name": attr.get("name", ""),
                        "type": itype,
                        "value": attr.get("value", ""),
                    }
                )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._cur = None


async def _http_form_login(
    login_url: str,
    username: str,
    password: str,
    transport=None,
) -> Optional[Dict[str, str]]:
    """HTTP 表单登录降级：解析登录页表单 → 提交 → 判定成功 → 返回 cookie。"""
    try:
        import httpx
    except ImportError:  # pragma: no cover
        return None

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=15,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (VULNCLAW)"},
        transport=transport,
    ) as client:
        try:
            resp = await client.get(login_url)
        except Exception as exc:
            logger.warning(f"指令登录降级失败（加载登录页）: {exc}")
            return None

        parser = _FormParser()
        parser.feed(resp.text)

        # 只保留同时具备用户名框 + 密码框的表单；无表单则默认 post 到登录页本身
        candidates = [
            f for f in parser.forms
            if any(i["type"] in ("text", "email") for i in f["inputs"])
            and any(i["type"] == "password" for i in f["inputs"])
        ]
        form = candidates[0] if candidates else {"action": "", "method": "post", "inputs": []}

        action = urljoin(str(resp.url), form["action"] or login_url)
        data = {}
        for i in form["inputs"]:
            if not i["name"]:
                continue
            if i["type"] == "password":
                data[i["name"]] = password
            elif i["type"] in ("text", "email"):
                data[i["name"]] = username
            else:  # hidden 及其它：保留页面默认值（如 CSRF token）
                data[i["name"]] = i.get("value", "")

        try:
            if form["method"] == "get":
                resp = await client.get(action, params=data)
            else:
                resp = await client.post(action, data=data)
        except Exception as exc:
            logger.warning(f"指令登录降级失败（提交表单）: {exc}")
            return None

        # 用 client.cookies：重定向(302) 下发的 Set-Cookie 会累积进 client 级 jar，
        # 而最终 resp.cookies 只含最终响应自身，会漏掉登录会话 cookie。
        try:
            cookies = {k: v for k, v in client.cookies.items() if k and v}
        except Exception:
            cookies = {k: v for k, v in resp.cookies.items() if k and v}
        if not cookies:
            logger.warning("指令登录降级：目标未下发任何 Cookie")
            return None

        # 成功判据：提交后不再出现密码框，或正文出现用户名
        body = resp.text
        still_form = 'type="password"' in body.lower() or "type='password'" in body.lower()
        looks_logged = username.lower() in body.lower() or username.lower() in str(resp.url).lower()
        if still_form and not looks_logged:
            logger.warning(f"指令登录降级：登录疑似失败（{username}:{_MASKED}）")
            return None

        logger.info(f"✅ 指令登录（HTTP 降级）成功: {username}:{_MASKED}")
        return cookies


async def _login_one(login_url: str, acct: Acct) -> Optional[Dict[str, str]]:
    """对单个账号尝试登录：优先 Playwright，失败/无环境则 HTTP 表单降级。"""
    if HAS_PLAYWRIGHT:
        try:
            cookies = await auto_login_and_get_cookie(
                login_url=login_url,
                username=acct.username,
                password=acct.password,
            )
            if cookies:
                return cookies
        except Exception as exc:
            logger.warning(f"Playwright 登录异常，改用 HTTP 降级: {exc}")

    return await _http_form_login(login_url, acct.username, acct.password)


# ============================================================
# 多角色会话注册（供 IDOR / 越权引擎消费）
# ============================================================

async def _register_role_sessions(domain: str, role_cookies) -> None:
    """把多个角色 cookie 注册进 session_manager（ins: 前缀隔离，get_roles()>=2 时越权对比生效）。"""
    try:
        from vulnclaw.core.auth.session_manager import get_session_manager

        sm = get_session_manager()
    except Exception as exc:
        logger.warning(f"指令多角色注册跳过（session_manager 不可用）: {exc}")
        return
    for role, cookies in role_cookies:
        try:
            sm.add_session(
                role=f"ins:{role or 'user'}",
                cookie_dict=cookies,
                domain=domain,
            )
            logger.info(f"🔑 指令角色会话已注册: ins:{role or 'user'}（{len(cookies)} 条 Cookie）")
        except Exception as exc:
            logger.warning(f"指令角色会话注册失败（{role or 'user'}）: {exc}")


# ============================================================
# 对外入口
# ============================================================

async def try_instruction_login(
    target_url: str,
    domain: str,
    ins: Instruction,
) -> bool:
    """按指令登录：多账号依次尝试，主账号落 {domain}.json，角色账号落 @{role}.json。

    返回主账号是否登录成功；全部失败 → False，调用方回退既有 cookie 流程。
    """
    if not ins or not ins.accounts:
        return False

    login_url = ins.login_url
    if not login_url:
        base = target_url if target_url.startswith(("http://", "https://")) else f"https://{domain}"
        login_url = urljoin(base.rstrip("/") + "/", "login")

    n_total = len(ins.accounts)
    n_ok = 0
    _role_cookies = []  # [(role, cookies)] 成功角色，供多角色越权注册
    for idx, acct in enumerate(ins.accounts):
        try:
            cookies = await _login_one(login_url, acct)
        except Exception as exc:
            logger.warning(f"指令登录异常（{acct.username}:{_MASKED}）: {exc}")
            continue
        if not cookies:
            logger.warning(
                f"❌ 指令登录失败 ({idx + 1}/{n_total}): {acct.role or 'default'}={acct.username}:{_MASKED}"
            )
            continue

        n_ok += 1
        suffix = _role_suffix(acct.role)
        if n_ok == 1:
            _save_cookie(domain, cookies, suffix="", role_hint=acct.role or "主账号")
            logger.info(f"✅ 指令登录成功（主账号）: {acct.username}:{_MASKED}")
            _role_cookies.append(("user", cookies))
        else:
            _save_cookie(domain, cookies, suffix=suffix, role_hint=acct.role or f"role{idx + 1}")
            logger.info(f"✅ 指令登录成功（角色）: {acct.username}:{_MASKED}")
            _role_cookies.append((acct.role or f"role{idx + 1}", cookies))

    if len(_role_cookies) > 1:
        await _register_role_sessions(domain, _role_cookies)

    return n_ok > 0


__all__ = [
    "try_instruction_login",
    "_save_cookie",
    "_http_form_login",
    "_login_one",
    "_register_role_sessions",
    "COOKIE_DIR",
]
