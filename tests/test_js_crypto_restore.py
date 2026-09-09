#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""K.1-K.4 JS 加密参数还原模块测试（用静态 fixture，不发起真实请求）。"""
from pathlib import Path

from vulnclaw.modules.js_crypto_restore import JSCryptoRestorer

FIX = Path(__file__).parent / "fixtures" / "js_crypto" / "sample_login.html"


def test_restore_aes_const_propagation():
    r = JSCryptoRestorer().analyze_file(FIX)
    aes = [e for e in r if e["api"] == "CryptoJS.AES"][0]
    assert aes["restorable"] is True
    assert "hardcodedkey123" in aes["key_source"]          # K.3 常量传播
    assert aes["iv_source"] == "1234567890123456"          # K.2 显式 iv 常量传播


def test_restore_rabbit_literal_key():
    r = JSCryptoRestorer().analyze_file(FIX)
    rb = [e for e in r if e["api"] == "CryptoJS.Rabbit"][0]
    assert rb["restorable"] is True
    assert rb["key_source"] == "rabbitkey"                  # 字面量密钥


def test_obfuscator_hint_detected():
    r = JSCryptoRestorer().analyze_file(FIX)
    assert any(e["api"] == "obfuscator" for e in r)
