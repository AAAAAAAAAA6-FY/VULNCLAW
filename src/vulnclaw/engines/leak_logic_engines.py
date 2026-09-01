# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/leak_logic_engines.py
"""
源码/配置泄露 + 认证逻辑引擎组（v104 新增）
SpringActuatorEngine / SourceCodeLeakEngine / AuthEnumerationEngine
设计原则：泄露类以"字节级魔数/固定指纹"判定（低误报）；认证枚举类保守，仅给出差异证据并标注复核。
"""
import random
from typing import Dict, List, Optional, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get, async_post
from vulnclaw.engines.base import BaseEngine


class _ProbeEngine(BaseEngine):
    """scan 型基类：依次请求固定路径列表，命中 200 即返回首个命中项。"""

    async def _probe(self, target: str, session):
        base = target.split("?")[0].rstrip("/")
        for path in getattr(self, "PROBE_PATHS", []):
            probe_url = f"{base}/{path.lstrip('/')}"
            try:
                resp = await async_get(probe_url, session=session, timeout=settings.timeout, no_retry=True)
                if resp is None:
                    continue
                status, text = resp[0], resp[1] or ""
                if status == 200:
                    headers = resp[2] if len(resp) > 2 else {}
                    return probe_url, text or "", headers, path
            except Exception:
                continue
        return None


# ============================================================
# SpringActuatorEngine（Spring Boot Actuator 端点暴露）
# ============================================================
class SpringActuatorEngine(_ProbeEngine):
    """Spring Boot 未授权 Actuator 端点暴露检测"""

    name = "spring_actuator"
    description = "Spring Boot Actuator 未授权端点暴露检测"

    PROBE_PATHS = [
        "actuator",
        "actuator/health",
        "actuator/env",
        "actuator/configprops",
        "actuator/beans",
        "actuator/mappings",
        "actuator/heapdump",
        "actuator/threaddump",
        "env",
        "health",
        "heapdump",
    ]

    ENV_HINT_RE = __import__("re").compile(
        r'"propertySources"|"java\.version"|"server\.port"|"spring\.'
    )

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        hit = await self._probe(target, session)
        if not hit:
            return findings
        probe_url, text, headers, path = hit
        text_lower = (text or "").lower()
        ctype = str(headers.get("content-type", "") or "").lower()

        # heapdump：二进制魔数或 octet-stream 且体积不小
        is_binary = text_lower.encode("utf-8", "ignore").startswith(b"\xca\xfe\xba\xbe") if text_lower else False
        if path in ("actuator/heapdump", "heapdump") and (is_binary or ("octet-stream" in ctype and len(text) > 1000)):
            findings.append({
                'url': probe_url, 'parameter': '',
                'payload': path,
                'type': 'Spring Actuator heapdump批量泄露',
                'severity': 'High', 'ai_verdict': '高', 'confidence': 'high',
                'evidence': f'未授权访问 {probe_url} 返回堆转储二进制（content-type={ctype}，约 {len(text)}B）',
                'recommendation': '生产禁用 Actuator 或仅内网+鉴权暴露 management.endpoints.web.exposure',
            })
            return findings

        if path in ("actuator", "actuator/env", "env") and self.ENV_HINT_RE.search(text):
            findings.append({
                'url': probe_url, 'parameter': '',
                'payload': path,
                'type': 'Spring Actuator 环境配置泄露',
                'severity': 'High', 'ai_verdict': '高', 'confidence': 'high',
                'evidence': f'未授权访问 {probe_url} 泄露环境配置（命中环境键特征）',
                'recommendation': '生产禁用 Actuator 或限制 env/configprops 端点',
            })
            return findings

        if path in ("actuator/health", "health") and '"status"' in text_lower and any(
            s in text_lower for s in ('"up"', '"down"', '"out_of_service"')
        ):
            findings.append({
                'url': probe_url, 'parameter': '',
                'payload': path,
                'type': 'Spring Actuator health端点暴露',
                'severity': 'Medium', 'ai_verdict': '高', 'confidence': 'high',
                'evidence': f'未授权访问 {probe_url} 返回健康状态 JSON（{text[:60]}...）',
                'recommendation': '生产限定 Actuator 端点访问',
            })
            return findings

        if "json" in ctype and text_lower.startswith(("{\"", "[")):
            findings.append({
                'url': probe_url, 'parameter': '',
                'payload': path,
                'type': 'Spring Actuator 端点暴露',
                'severity': 'Medium', 'ai_verdict': '中', 'confidence': 'medium',
                'evidence': f'未授权访问 {probe_url} 返回 JSON（content-type={ctype}）',
                'recommendation': '生产禁用 Actuator 或做访问控制',
            })
        return findings

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        return None


# ============================================================
# SourceCodeLeakEngine（Git/SVN/.DS_Store 源码泄露）
# ============================================================
class SourceCodeLeakEngine(_ProbeEngine):
    """Git / SVN / .DS_Store 源码泄露检测"""

    name = "source_code_leak"
    description = "Git/SVN/.DS_Store 版本控制与源码泄露检出"

    PROBE_PATHS = [
        ".git/config",
        ".git/HEAD",
        ".gitignore",
        ".svn/entries",
        ".svn/wc.db",
        ".DS_Store",
        ".idea/workspace.xml",
    ]

    GIT_CONFIG_RE = __import__("re").compile(r'\[(core|remote|branch)\]|repositoryformatversion', __import__("re").I)
    GIT_HEAD_RE = __import__("re").compile(r'ref:\s*refs/heads/', __import__("re").I)
    SVN_ENTRIES_RE = __import__("re").compile(r'^(?:dir|file)($|\t)', __import__("re").M)
    DS_STORE_MAGIC = b"\x00\x00\x00\x01Bud1"

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        base = target.split("?")[0].rstrip("/")
        for path in self.PROBE_PATHS:
            probe_url = f"{base}/{path}"
            try:
                resp = await async_get(probe_url, session=session, timeout=settings.timeout, no_retry=True)
                if resp is None:
                    continue
                status, text = resp[0], resp[1] or ""
                raw = (text or "").encode("utf-8", "ignore")
            except Exception as e:
                self.log_debug(f"源码泄露探测异常 {path}: {e}")
                continue

            evidence = None
            severity = "High"
            if path == ".git/config" and self.GIT_CONFIG_RE.search(text):
                evidence = "git config 泄露，可能暴露仓库地址/子模块/凭据"
            elif path == ".git/HEAD" and self.GIT_HEAD_RE.search(text):
                evidence = "git HEAD 泄露，可尝试 .git 对象回源下载源码"
            elif path == ".gitignore" and status == 200 and text.strip():
                evidence = "gitignore 泄露（目录结构/文件线索）"
            elif path == ".svn/entries" and self.SVN_ENTRIES_RE.search(text):
                evidence = "svn entries 泄露（文件/目录列表）"
            elif path == ".svn/wc.db" and raw.startswith(b"SQLite format 3"):
                evidence = "svn wc.db(sqlite)泄露，可导出元数据"
            elif path == ".DS_Store" and raw.startswith(self.DS_STORE_MAGIC):
                evidence = ".DS_Store 泄露（目录/文件名列表）"
            elif path == ".idea/workspace.xml" and "<module " in text:
                evidence = "JetBrains 项目配置泄露（模块/路径信息）"
                severity = "Medium"

            if evidence:
                findings.append({
                    'url': probe_url, 'parameter': '',
                    'payload': path,
                    'type': f'源码/版本控制泄露({path})',
                    'severity': severity, 'ai_verdict': '高', 'confidence': 'high',
                    'evidence': f'{probe_url} 可未授权访问：{evidence}',
                    'recommendation': '生产移除 .git/.svn/.DS_Store/.idea 等元数据目录，或在 Web 服务器/WAF 拦截点(.)开头路径',
                })
        return findings

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        return None


# ============================================================
# AuthEnumerationEngine（用户枚举 / 认证逻辑，保守证据）
# ============================================================
class AuthEnumerationEngine(BaseEngine):
    """登录/注册用户枚举检测（scan 型：存在/不存在用户响应差异，保守标注）"""

    name = "auth_enumeration"
    description = "登录/注册用户枚举检测（响应差异证据，需复核）"

    USER_EXISTS_HINT = __import__("re").compile(
        r"(incorrect password|invalid password|wrong password|bad password|"
        r"password.*incorrect|invalid credentials)", __import__("re").I,
    )
    USER_NOT_FOUND_HINT = __import__("re").compile(
        r"(user not found|account not found|invalid user|invalid username|"
        r"no account|doesn't exist|does not exist|unregistered)", __import__("re").I,
    )
    LOGIN_PATHS = [
        "/login", "/signin", "/signup", "/register", "/user/login", "/api/login",
        "/account/login", "/auth/login",
    ]

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        base = target.split("?")[0].rstrip("/")
        root = base
        candidates = [root] + [root + p for p in self.LOGIN_PATHS]

        for login_url in candidates:
            try:
                resp = await async_get(login_url, session=session, timeout=settings.timeout, no_retry=True)
            except Exception:
                continue
            if resp is None:
                continue
            body = resp[1] or ""
            if not isinstance(body, str) or ("password" not in body.lower() and "login" not in body.lower()):
                continue
            diff = await self._probe_enumeration(login_url, session)
            if diff:
                findings.append(diff)
                return findings
        return findings

    async def _probe_enumeration(self, login_url: str, session) -> Optional[Dict]:
        existing_user = "admin"
        ghost_user = "vlcgh" + "".join(random.sample("abcdefghijklmnopqrstuvwxyz", 8))
        resp_exist = await self._login_try(login_url, existing_user, session)
        resp_ghost = await self._login_try(login_url, ghost_user, session)
        if not resp_exist or not resp_ghost:
            return None
        se, te = resp_exist[0], resp_exist[1] or ""
        sg, tg = resp_ghost[0], resp_ghost[1] or ""
        if not isinstance(te, str) or not isinstance(tg, str):
            return None

        ex_name = bool(self.USER_NOT_FOUND_HINT.search(tg)) and not bool(self.USER_NOT_FOUND_HINT.search(te))
        ex_pass = bool(self.USER_EXISTS_HINT.search(te)) and not bool(self.USER_EXISTS_HINT.search(tg))
        status_diff = se != sg and se in (200, 401, 403) and sg in (200, 401, 403, 302)

        if ex_name or ex_pass or status_diff:
            bits = []
            if ex_name:
                bits.append("随机用户出现'未找到'提示而 admin 没有")
            if ex_pass:
                bits.append("admin 出现'密码错误'提示而随机用户没有")
            if status_diff:
                bits.append(f"两者响应状态码不同({se} vs {sg})")
            return {
                'url': login_url, 'parameter': 'username',
                'payload': f'{existing_user} vs {ghost_user}',
                'type': '用户枚举(响应差异)',
                'severity': 'Medium', 'ai_verdict': '中', 'confidence': 'low',
                'evidence': f"对 {login_url} 比对存在用户 `{existing_user}` 与随机用户 `{ghost_user}`：{'；'.join(bits)}。黑盒判定，建议人工复核",
                'recommendation': '统一登录失败提示（不区分用户是否存在），并加入速率限制/账户锁定',
            }
        return None

    async def _login_try(self, login_url: str, username: str, session):
        try:
            return await async_post(
                login_url,
                data={"username": username, "password": "vlc_incorrect_xyz"},
                session=session, timeout=settings.timeout, no_retry=True,
            )
        except Exception:
            return None

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        return None


__all__ = [
    'SpringActuatorEngine',
    'SourceCodeLeakEngine',
    'AuthEnumerationEngine',
]