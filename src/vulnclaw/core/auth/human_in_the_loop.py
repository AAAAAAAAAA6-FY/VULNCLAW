# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""A6.5 2FA / 验证码人工接管占位。

合规优先：检测到二次验证/验证码挑战时**暂停并等待人工干预**，不做自动破解。
提供 detect_challenge（挑战识别）与 request_human_intervention（人工接管窗口占位），
可被 A6.2 auto_login 在提交后调用。
"""
import json
import os
import time
from typing import Dict, List, Optional

try:  # 软导入：隔离环境也能独立加载
    from vulnclaw.core.logger import logger
except Exception:  # noqa: BLE001
    import logging
    logger = logging.getLogger("vulnclaw.human_in_the_loop")

CHALLENGE_DIR = os.path.join(os.path.dirname(__file__), "challenges")

_CHALLENGE_KEYWORDS = {
    "2fa": ["two-factor", "2fa", "otp", "one-time password", "authenticator", "verification code"],
    "otp": ["otp", "one-time code", "one time password"],
    "captcha": ["captcha", "i'm not a robot", "recaptcha", "hcaptcha", "verify you are human",
                "verify you're human"],
}

_PENDING: Dict[str, Dict] = {}


def detect_challenge(text: str, url: str = "") -> Optional[str]:
    """根据页面文本（及可选 URL）识别挑战类型，返回 '2fa' | 'otp' | 'captcha' | None。"""
    low = (text or "").lower()
    for ctype, kws in _CHALLENGE_KEYWORDS.items():
        if any(kw in low for kw in kws):
            return ctype
    return None


def request_human_intervention(target: str, challenge_type: str, context: str = "",
                               timeout: int = 300) -> Dict:
    """占位：记录人工接管请求并返回暂停信号。真实回填需外部人工（不自动破解）。"""
    req_id = f"{target}:{challenge_type}:{int(time.time())}"
    payload = {
        "request_id": req_id,
        "target": target,
        "challenge_type": challenge_type,
        "context": context,
        "created_at": time.time(),
        "timeout": timeout,
        "status": "awaiting_human",
    }
    try:
        os.makedirs(CHALLENGE_DIR, exist_ok=True)
        path = os.path.join(CHALLENGE_DIR, f"{req_id.replace(':', '_')}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
    except OSError as exc:
        logger.warning(f"⚠️ 人工接管请求写入失败: {exc}")
    _PENDING[req_id] = payload
    logger.info(f"🛑 [A6.5] 检测到 {challenge_type} 挑战，已暂停等待人工接管: {target}")
    return payload


def resolve_human_intervention(req_id: str, resolved_by: str = "human") -> bool:
    """外部人工回填后调用，标记已解决。"""
    if req_id in _PENDING:
        _PENDING[req_id]["status"] = "resolved"
        _PENDING[req_id]["resolved_by"] = resolved_by
        return True
    return False


def pending_requests() -> List[Dict]:
    return list(_PENDING.values())


__all__ = ["detect_challenge", "request_human_intervention",
           "resolve_human_intervention", "pending_requests"]
