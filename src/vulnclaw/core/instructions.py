# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
指令解析层（SP27：对标 Strix --instruction 的账号密码直写）

从自然语言指令中提取：
  - 账号密码（支持多账号/多角色）
  - 可选登录页 URL（login_url / 登录页）
  - 测试重点（Focus on / 重点）
  - 排除项（Out of scope / 排除）

纯 Python + 正则，零新依赖。密码明文只存在于返回的 Instruction 对象内，
输出摘要一律脱敏（username:***）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

# ============================================================
# 数据结构
# ============================================================

_MASKED = "***"


@dataclass
class Acct:
    """一个账号（角色 + 用户名 + 密码）"""

    role: str
    username: str
    password: str


@dataclass
class Instruction:
    """解析结果：账号列表 + 可选登录页 + 重点 + 排除项"""

    accounts: List[Acct] = None
    login_url: Optional[str] = None
    focus: List[str] = None
    exclude: List[str] = None

    def __post_init__(self) -> None:
        self.accounts = self.accounts or []
        self.focus = self.focus or []
        self.exclude = self.exclude or []

    @property
    def has_credentials(self) -> bool:
        return bool(self.accounts)

    @property
    def masked_summary(self) -> str:
        """脱敏摘要：只暴露角色与用户名，密码打码。用于打日志。"""
        if not self.accounts:
            return "(无凭据)"
        return "; ".join(
            f"{a.role or 'role'}={a.username}:{_MASKED}" for a in self.accounts
        )


# ============================================================
# 正则匹配器（按优先级顺序）
# ============================================================

# 1) Strix 风格长句：Login with email: x@x.com, password: Pass123
_RE_STRIX = re.compile(
    r"\b(?:login|log\s*in)\s+with\s+(?:email|e-?mail|username|user|账号|邮箱)"
    r"\s*[:：]\s*(?P<u>[^\s,，;；]+)\s*[,，]\s*"
    r"(?:password|passwd|pwd|密码)\s*[:：]\s*(?P<p>[^\s,，;；]+)",
    re.IGNORECASE,
)

# 2) 中文键值对：账号[:：]u 密码[:：]p（同一行内）
_RE_ZH_KV = re.compile(
    r"\b(?:账号|用户名|帐号)\s*[:：]\s*(?P<u>[^\s,，;；/]+)"
    r"[\s，,;；/]+(?:密码|口令)\s*[:：]\s*(?P<p>[^\s，,;；]+)",
)

# 3) email:pass / user:pass（冒号或斜杠分隔）
_RE_AT_PAIR = re.compile(r"\b(?P<u>[\w.+-]+@[\w.-]+\.[A-Za-z]{2,})\s*[:：/]\s*(?P<p>\S+)")

# 4) 列表项：- 角色: user / pass   或   1. Role Name  user / pass
_RE_LIST_ITEM = re.compile(
    r"^\s*(?P<bullet>[-*•]|\d+[.)、]|o)\s*(?P<role>[^:：/]{1,24}?)\s*[:：-]\s*"
    r"(?P<u>[\w.@+-]+)\s*[/|]\s*(?P<p>[^\s,，;；]+)"
    r"|^\s*(?P<bullet2>[-*•]|\d+[.)、]|o)\s*(?P<u2>[\w.@+-]+)\s*[/|]\s*(?P<p2>[^\s,，;；]+)",
    re.IGNORECASE | re.MULTILINE,
)

# 5) 登录页提示
_RE_LOGIN_URL = re.compile(
    r"\b(?:login[_\- ]?url|登录页|登陆页|login\s*page)\s*[:：]\s*(?P<u>https?://\S+)",
    re.IGNORECASE,
)

# 6) 中文自然语言连写："邮箱 admin@x.com 密码 Pass123"
_RE_ZH_FREE = re.compile(
    r"\b(邮箱|电子邮箱)\s*(?P<u>[\w.+-]+@[\w.-]+\.[A-Za-z]{2,})"
    r"[\s，,;；]*(?:密码|口令)\s*(?P<p>[^\s，,;；]+)",
)

# 4b) 英文键值对同行：Email: u Password: p
_RE_EN_KV = re.compile(
    r"\b(?:email|e-?mail|username|user)\s*[:：]\s*(?P<u>[^\s,，;；]+)[\s]{1,4}"
    r"(?:password|passwd|pwd)\s*[:：]\s*(?P<p>[^\s,，;；]+)",
    re.IGNORECASE,
)

# 7) focus/exclude 段（行级）
_RE_FOCUS = re.compile(
    r"\b(?:focus\s*(?:on)?|测试重点|重点测试|重点)\s*[:：]?\s*(?P<rest>.+?)(?=\b(?:out\s*of\s*scope|排除|exclude|$))",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)
_RE_EXCLUDE = re.compile(
    r"\b(?:out\s*of\s*scope|排除项?|exclude[d]?|不要(?:测试|扫描))\s*[:：]?\s*(?P<rest>.+)$",
    re.IGNORECASE | re.MULTILINE,
)

_SECTION_SPLIT = re.compile(r"[,，;/、\s]+")


def _clean_token(raw: str) -> str:
    """清洗单个词条：去首尾标点/空白，去引号与句号。"""
    return raw.strip().strip("`'\"。．.!！?？:：,，;；()（）[]【】{}*").strip()


def _split_items(rest: str) -> List[str]:
    items = []
    for raw in rest.splitlines():
        for piece in _SECTION_SPLIT.split(raw):
            tok = _clean_token(piece)
            if len(tok) >= 2:
                items.append(tok)
    seen, out = set(), []
    for it in items:
        key = it.lower()
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out


def _extract_accounts(text: str) -> List[Acct]:
    """提取账号。返回 (role, username, password)。"""
    accounts: List[Acct] = []
    seen = set()

    def push(role: str, u: str, p: str) -> None:
        u, p = u.strip(), p.strip()
        if not u or not p:
            return
        key = (u.lower(), p.lower())
        if key in seen:
            return
        seen.add(key)
        accounts.append(Acct(role=role or "default", username=u, password=p))

    # 1) 列表项（Role: u / p）优先：保留 role
    for m in _RE_LIST_ITEM.finditer(text):
        if m.group("u") is not None:
            role = (m.group("role") or "").strip()
            u, p = m.group("u"), m.group("p")
        else:
            role, u, p = "", m.group("u2"), m.group("p2")
        push(role, u, p)

    # 2) 英文键值对：Email: u Password: p（同行）
    for m in _RE_EN_KV.finditer(text):
        push("default", m.group("u"), m.group("p"))

    # 3) 全文匹配：Strix 长句 / 中文键值对 / 邮箱连写 / email:pass（重复项被 u+p 去重吞掉）
    for pattern in (_RE_STRIX, _RE_ZH_KV, _RE_ZH_FREE, _RE_AT_PAIR):
        for m in pattern.finditer(text):
            push("default", m.group("u"), m.group("p"))

    return accounts



# ============================================================
# 公开 API
# ============================================================


def parse_instruction_text(text: str) -> Instruction:
    """解析指令文本为 Instruction 对象。任何文本（含空串）都不抛异常。"""
    text = (text or "").strip()
    ins = Instruction()

    m = _RE_LOGIN_URL.search(text)
    if m:
        ins.login_url = m.group("u").strip().rstrip(",;。")

    ins.accounts = _extract_accounts(text)

    m = _RE_FOCUS.search(text)
    if m and m.group("rest").strip():
        ins.focus = _split_items(m.group("rest"))
    m = _RE_EXCLUDE.search(text)
    if m and m.group("rest").strip():
        ins.exclude = _split_items(m.group("rest"))

    return ins


def load_instruction(inline: Optional[str], file: Optional[str]) -> Instruction:
    """从内联文本或文件加载指令（二选一，优先 inline）。

    文件不存在时抛 FileNotFoundError（由调用方转成友好报错）。
    """
    if inline is not None and inline.strip():
        return parse_instruction_text(inline)
    if file:
        with open(file, "r", encoding="utf-8") as fh:
            return parse_instruction_text(fh.read())
    return Instruction()


__all__ = [
    "Acct",
    "Instruction",
    "parse_instruction_text",
    "load_instruction",
]