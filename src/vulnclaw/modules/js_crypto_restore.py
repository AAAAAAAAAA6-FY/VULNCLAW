#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""K.1-K.4 JS 加密参数还原模块（静态分析，不执行不可信 JS）。

供 scanner / web 被动分析层调用：对响应 HTML 提取前端加密参数调用点 + 密钥/IV 来源，
输出「可还原配方」，供构造等效加密请求（如登录密码加密后重放注入测试）。

能力（与 scripts/js_crypto_restore_poc.py 同源，后者为独立 PoC 验证版）：
  - K.1 提取 CryptoJS 全系 / SM4 / JSEncrypt / Base64 混淆链 / obfuscator 标识；
  - K.2 解析 opts 中 iv（字面量或变量常量传播），标准 CryptoJS.AES-CBC 逐字节等效密文；
  - K.3 增强常量流（var/let/const、裸赋值、对象属性三种字面量赋值形态）。

安全红线：只读静态分析抽取，绝不 eval/exec 目标 JS（避免运行不可信代码）。
"""
from __future__ import annotations

import re
from pathlib import Path

CRYPT_PATTERNS = [
    ("CryptoJS.AES", re.compile(
        r"CryptoJS\.AES\.encrypt\s*\(\s*(.+?)\s*,\s*(.+?)\s*(?:,\s*(\{.*?\})|\s*\))", re.S)),
    ("CryptoJS.DES", re.compile(r"CryptoJS\.DES\.encrypt\s*\(\s*(.+?)\s*,\s*(.+?)\s*\)", re.S)),
    ("CryptoJS.Rabbit", re.compile(r"CryptoJS\.Rabbit\.encrypt\s*\(\s*(.+?)\s*,\s*(.+?)\s*\)", re.S)),
    ("CryptoJS.RC4", re.compile(r"CryptoJS\.RC4\.encrypt\s*\(\s*(.+?)\s*,\s*(.+?)\s*\)", re.S)),
    ("CryptoJS.TripleDES", re.compile(r"CryptoJS\.TripleDES\.encrypt\s*\(\s*(.+?)\s*,\s*(.+?)\s*\)", re.S)),
    ("SM4", re.compile(r"(?:sm4|SM4)\.[A-Za-z]*encrypt\s*\(\s*(.+?)\s*,\s*(.+?)\s*\)", re.S)),
    ("JSEncrypt", re.compile(r"new\s+JSEncrypt\([^)]*\)\.encrypt\s*\(\s*(.+?)\s*\)", re.S)),
    ("Base64-chain", re.compile(r"(?:btoa|atob|Buffer\.from)\s*\(([^)]{0,120})\)", re.S)),
]
OBFUSCATOR_HINT = re.compile(r"(?:_0x[a-f0-9]{4,}|javascript-obfuscator|aa[a-zA-Z]{2,}\()")
_IV_PATTERN = re.compile(r"iv\s*:\s*CryptoJS\.enc\.Utf8\.parse\(\s*[\"']([^\"']+)[\"']", re.S)
_IV_VAR_PATTERN = re.compile(r"iv\s*:\s*CryptoJS\.enc\.Utf8\.parse\(\s*([A-Za-z_$][\w$]*)\s*\)", re.S)

_ASSIGN_VAR = re.compile(r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*([\"'])(.*?)\2", re.S)
_ASSIGN_BARE = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*([\"'])(.*?)\2", re.S)
_ASSIGN_PROP = re.compile(r"([A-Za-z_$][\w$.]*)\.([A-Za-z_$][\w$]*)\s*=\s*([\"'])(.*?)\3", re.S)


def _string_literal(arg: str):
    arg = arg.strip()
    if len(arg) >= 2 and arg[0] in "\"'":
        return arg[1:-1]
    return None


def _extract_js(html: str) -> str:
    parts = []
    for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.S | re.I):
        parts.append(m.group(1))
    for m in re.finditer(r'<script[^>]*\ssrc=["\']([^"\']+)["\']', html, re.I):
        parts.append(f"// [external script: {m.group(1)}] (需另行抓取)")
    return "\n".join(parts)


def _collect_const_assignments(js: str) -> dict:
    out: dict = {}
    for m in _ASSIGN_VAR.finditer(js):
        out[m.group(1)] = m.group(3)
    for m in _ASSIGN_BARE.finditer(js):
        out[m.group(1)] = m.group(3)
    for m in _ASSIGN_PROP.finditer(js):
        out[f"{m.group(1)}.{m.group(2)}"] = m.group(4)
    return out


def _parse_iv(opts: str, consts: dict | None = None) -> str:
    if not opts:
        return ""
    m = _IV_PATTERN.search(opts)
    if m:
        return m.group(1)
    m2 = _IV_VAR_PATTERN.search(opts)
    if m2 and consts and m2.group(1) in consts:
        return consts[m2.group(1)]
    return opts[:40]


def _restore_cryptojs_aes(plaintext: str, key: str, iv_literal: str | None = None) -> str | None:
    try:
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import EVP_BytesToKey
        from Crypto.Util.Padding import pad
        from Crypto.Random import get_random_bytes
    except Exception:  # noqa: BLE001
        return None
    import base64
    if iv_literal:
        iv_b = iv_literal.encode()[:16].ljust(16, b"\x00")
        key_b, _ = EVP_BytesToKey(key.encode(), b"", 32, 16, 1)
        ct = AES.new(key_b, AES.MODE_CBC, iv_b).encrypt(pad(plaintext.encode(), 16))
        return "CryptoJS.AES 精确密文(base64,显式iv)=" + base64.b64encode(ct).decode()
    salt = get_random_bytes(8)
    key_b, iv_b = EVP_BytesToKey(key.encode(), salt, 32, 16, 1)
    ct = AES.new(key_b, AES.MODE_CBC, iv_b).encrypt(pad(plaintext.encode(), 16))
    return "CryptoJS.AES 等效密文(base64)=" + base64.b64encode(b"Salted__" + salt + ct).decode()


class JSCryptoRestorer:
    """前端加密参数还原器（静态分析）。调用方：scanner 被动分析层 / web 引擎。"""

    def analyze(self, html: str) -> list:
        results: list = []
        js = _extract_js(html)
        consts = _collect_const_assignments(js)
        if OBFUSCATOR_HINT.search(js):
            results.append({"api": "obfuscator", "location": "?", "plaintext_arg": "",
                            "key_source": "混淆代码，需反混淆后分析", "iv_source": "",
                            "restorable": False,
                            "poc": "检测到 javascript-obfuscator/变量名混淆，建议先反混淆"})
        for api, pat in CRYPT_PATTERNS:
            for m in pat.finditer(js):
                groups = m.groups()
                plaintext_arg = (groups[0] or "").strip()
                key_arg = (groups[1] if len(groups) > 1 else "").strip()
                opts = (groups[2] if len(groups) > 2 else "").strip()
                key_lit = _string_literal(key_arg)
                from_const = False
                if key_lit is None and key_arg in consts:
                    key_lit = consts[key_arg]
                    from_const = True
                iv_src = _parse_iv(opts, consts) if api == "CryptoJS.AES" else (opts[:40] if opts else "")
                entry = {
                    "api": api, "location": f"char~{m.start()}",
                    "plaintext_arg": plaintext_arg[:80],
                    "key_source": (key_lit if key_lit is not None else f"动态({key_arg[:40]})")
                                 + ("(常量传播)" if from_const else ""),
                    "iv_source": iv_src, "restorable": False, "poc": "",
                }
                if api == "CryptoJS.AES" and key_lit is not None:
                    entry["restorable"] = True
                    poc = _restore_cryptojs_aes("POC_TEST_PLAINTEXT", key_lit, iv_literal=iv_src or None)
                    entry["poc"] = (poc if poc else
                        f"AES 密钥已还原(key={key_lit[:12]}...)，iv={iv_src or '派生'}，"
                        f"本机缺 PyCryptodome 时用 CryptoJS 等价算法离线生成等效密文")
                elif key_lit is not None:
                    entry["restorable"] = True
                    entry["poc"] = f"{api} 密钥硬编码 -> 可离线还原等效参数"
                results.append(entry)
        return results

    def analyze_file(self, path) -> list:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        return self.analyze(text)
