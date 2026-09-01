# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""A6.5 2FA / 验证码人工接管占位单测。"""
import vulnclaw.core.auth.human_in_the_loop as hitl
from vulnclaw.core.auth.human_in_the_loop import (
    detect_challenge,
    request_human_intervention,
    resolve_human_intervention,
)


def test_detect_2fa():
    assert detect_challenge("Please enter your one-time password to verify") == "2fa"
    assert detect_challenge("Two-Factor Authentication required") == "2fa"


def test_detect_captcha():
    assert detect_challenge("Please complete the captcha to continue") == "captcha"
    assert detect_challenge("I'm not a robot") == "captcha"


def test_detect_none():
    assert detect_challenge("Welcome back, user!") is None


def test_human_intervention_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setattr(hitl, "CHALLENGE_DIR", str(tmp_path))
    req = request_human_intervention("https://x/login", "2fa", context="after submit")
    assert req["status"] == "awaiting_human"
    assert req["challenge_type"] == "2fa"
    assert resolve_human_intervention(req["request_id"]) is True
