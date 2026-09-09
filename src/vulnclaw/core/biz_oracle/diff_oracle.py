# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""B 方案: 差分 oracle——并发双发同一请求给两个身份，输出机器可判定的差分信号。

信号：blocked / 私有标记 / body_sim / status_parity / resp_len_delta。
三态判定（fail-closed）：auth_enforced（安全）→ public_shell（公开壳）→ horizontal_leak（越权实锤）；
探针失败或机器无法裁决一律 'error'，绝不产出。
"""
import asyncio
import difflib
import re
from typing import Dict, Optional

from vulnclaw.core.logger import logger
from vulnclaw.engines.auth_engines import IDOREngine

_BODY_CAP = 20000   # 差分比较/私有标记扫描的正文上限（防 SPA 巨型响应烧内存）
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_LOGIN_PATH_HINTS = ("login", "signin", "logon", "auth")


def _norm_body(text: Optional[str]) -> str:
    # 延迟导入：evidence_pack 位于 ai 层，顶层导入会与 core.scanner→engines→diff_oracle 形成循环。
    from vulnclaw.ai.v100.evidence_pack import _strip_bloat
    return _strip_bloat(str(text or ""))[:_BODY_CAP]


def _private_markers(text: Optional[str]) -> Dict[str, str]:
    """提取响应中的私有数据标记（email/phone/…/uuid）。用于区分"个性化私有资源"与公开壳。"""
    t = str(text or "")[:_BODY_CAP]
    out: Dict[str, str] = {}
    for name, pat in IDOREngine.SENSITIVE_PATTERNS.items():
        m = re.search(pat, t)
        if m:
            out[name] = m.group(0)[:64]
    mu = _UUID_RE.search(t)
    if mu:
        out["uuid"] = mu.group(0)[:36]
    return out


async def dual_session_probe(
    url: str,
    method: str = "GET",
    identity_a: Optional[str] = None,
    identity_b: Optional[str] = None,
    identities=None,
    timeout: int = 10,
) -> Dict:
    """并发双发同一请求（身份 A / 身份 B），返回差分信号字典。任何异常 → {'ok': False}（fail-closed）。"""
    sig: Dict = {"ok": True, "url": url, "method": method}
    if identities is None or not identity_a or not identity_b:
        sig.update({"ok": False, "reason": "missing_identity"})
        return sig

    async def _one(ident: str):
        try:
            return await identities.request(ident, method, url, timeout=timeout)
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[oracle] {ident} 请求失败: {e}")
            return 0, "", {}

    try:
        a_resp, b_resp = await asyncio.gather(_one(identity_a), _one(identity_b))
    except Exception as e:  # noqa: BLE001
        sig.update({"ok": False, "reason": "gather_error", "error": str(e)[:120]})
        return sig

    a_status, a_text, a_headers = a_resp
    b_status, b_text, b_headers = b_resp
    if not a_status or not b_status:
        sig.update({"ok": False, "reason": "net_failure",
                    "a_status": a_status, "b_status": b_status})
        return sig

    a_norm, b_norm = _norm_body(a_text), _norm_body(b_text)
    sim = difflib.SequenceMatcher(None, a_norm, b_norm).ratio() if (a_norm or b_norm) else 1.0
    a_markers = _private_markers(a_text)
    b_markers = _private_markers(b_text)

    blocked = b_status in (401, 403)
    if not blocked and b_status == 302:
        loc = str((b_headers or {}).get("Location", "") or "").lower()
        if any(_h in loc for _h in _LOGIN_PATH_HINTS):
            blocked = True

    sig.update({
        "a_status": a_status,
        "b_status": b_status,
        "b_blocked": bool(blocked),
        "a_private": a_markers or None,
        "b_private": b_markers or None,
        "body_sim": round(sim, 4),
        "status_parity": a_status == b_status,
        "resp_len_delta": round(abs(len(a_norm) - len(b_norm)) / max(1, len(a_norm)), 4),
    })
    return sig


def oracle_verdict(sig: Dict, shell_sim: float = 0.85) -> str:
    """三态判定（fail-closed，严格私有标记门，宁漏勿误）：

    - 'auth_enforced':   身份B 被拦（401/403/登录跳转）→ 授权已强制（安全）
    - 'public_shell':    双身份同构且无私有标记 → 公开资源/SPA 壳（排除）
    - 'horizontal_leak': 身份B 未授权拿到私有数据（私有标记实锤）→ 水平越权
    - 'error':           探针失败或机器无法裁决 —— 绝不产出
    """
    if not isinstance(sig, dict) or sig.get("ok") is not True:
        return "error"
    if sig.get("b_blocked"):
        return "auth_enforced"
    if sig.get("status_parity") and sig.get("body_sim", 0) >= shell_sim and not sig.get("b_private"):
        return "public_shell"
    if sig.get("b_private"):
        return "horizontal_leak"
    return "error"


__all__ = ["dual_session_probe", "oracle_verdict", "_private_markers", "_norm_body"]
