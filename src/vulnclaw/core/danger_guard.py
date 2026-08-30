# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""
危险操作权限门卫（Danger Guard）

对"会实际影响目标"的操作（利用执行 / MSF 命令 / shell 写入 / 利用链）做统一审批。

模式（settings.dangerous_mode / 环境变量 DANGEROUS_MODE）：
  - deny   （默认）：一律拒绝，返回 denied
  - prompt：交互终端（tty）逐次确认；非交互环境自动拒绝
  - allow  ：放行（CLI --dangerous 或 DANGEROUS_MODE=allow 显式开启）

允许清单（DANGEROUS_ALLOW="op1,op2"）可在 deny 模式下单独放行某些操作。
所有决策写入内存审计环，供 MCP 工具 scan.danger_guard_status 查询。
"""
import sys
from typing import Dict, List

from vulnclaw.config.settings import settings

# 危险操作注册表（op_id -> 中文说明）
DANGEROUS_OPS: Dict[str, str] = {
    "exploit_verify": "对已确认漏洞执行利用验证（发送真实攻击载荷）",
    "exploit_chain": "执行深度利用链（POC 生成 + 自动利用 + 回连确认）",
    "msf_exploit": "通过 Metasploit RPC 实际执行漏洞利用模块",
    "msf_shell_write": "向已建立的 MSF 会话 shell 写入命令",
    "remote_task_execution": "将本地工具调用委派给远程 AI Agent 执行（远程 Agent 实际发送载荷）",
    "remote_deep_penetrate": "由远程 AI Agent 自主执行单点深度渗透（远程 Agent 实际攻击目标）",
}

_AUDIT_LIMIT = 200

# 模式别名：兼容 .env 里已存在的布尔写法（DANGEROUS_MODE=false/true）
_MODE_ALIASES = {
    "deny": "deny", "denied": "deny", "false": "deny", "0": "deny",
    "no": "deny", "off": "deny", "": "deny",
    "allow": "allow", "true": "allow", "1": "allow", "yes": "allow", "on": "allow",
    "prompt": "prompt", "ask": "prompt", "interactive": "prompt",
}


def _normalize_mode(mode: str) -> str:
    """把任意写法归一化为 deny / prompt / allow；未知值一律按 deny（安全兜底）。"""
    return _MODE_ALIASES.get(str(mode or "").strip().lower(), "deny")


class DangerGuard:
    """进程级危险操作门卫（单例 guard）。"""

    def __init__(self) -> None:
        self._mode: str = _normalize_mode(settings.dangerous_mode)
        self._allow_list: set = set(settings.dangerous_allow_list or [])
        self._audit: List[dict] = []

    def set_mode(self, mode: str) -> None:
        normalized = _normalize_mode(mode)
        # 未知模式不静默生效，避免误配成 deny 之外的行为
        if str(mode or "").strip().lower() in _MODE_ALIASES:
            self._mode = normalized

    @property
    def mode(self) -> str:
        return self._mode

    def is_dangerous(self, op: str) -> bool:
        return op in DANGEROUS_OPS

    def require_approval(self, op: str, detail: str = "") -> bool:
        """是否允许执行 op。返回 True=放行，False=拒绝。非危险操作恒放行。"""
        if not self.is_dangerous(op):
            return True
        if op in self._allow_list or self._mode == "allow":
            allowed = True
        elif self._mode == "prompt":
            allowed = self._prompt(op, detail)
        else:  # deny / 其他
            allowed = False
        self._audit.append({
            "op": op,
            "detail": detail,
            "allowed": allowed,
            "mode": self._mode,
        })
        if len(self._audit) > _AUDIT_LIMIT:
            self._audit = self._audit[-_AUDIT_LIMIT:]
        return allowed

    def _prompt(self, op: str, detail: str) -> bool:
        if not sys.stdin or not sys.stdin.isatty():
            return False
        try:
            answer = input(f"[DangerGuard] 危险操作「{op}」{detail or ''} 需要确认 (y/N): ").strip().lower()
            return answer in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    def get_audit(self, limit: int = 50) -> List[dict]:
        return list(self._audit[-limit:])


guard = DangerGuard()

__all__ = ["DangerGuard", "DANGEROUS_OPS", "guard"]
