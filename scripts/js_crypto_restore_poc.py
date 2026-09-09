#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""K.1-K.3 JS 加密参数还原 PoC（静态分析，不执行不可信 JS）。

场景：前端登录/接口把敏感参数用 JS 加密后再发（如 CryptoJS.AES.encrypt(pwd, key, {iv})），
扫描器直接重放明文参数会被服务端拒绝。本 PoC 证明：可静态提取加密调用点 + 密钥/IV
来源，并对「标准 CryptoJS.AES + 硬编码密钥 + 显式 iv」离线生成等效密文，使扫描能构造
等效加密请求。

能力（v2 增强）：
  K.1 基础：提取加密调用（CryptoJS 全系 / SM4 / JSEncrypt / Base64 混淆链 / obfuscator）。
  K.2 精确还原：解析 opts 中的 iv（字面量 `parse("...")` 或变量 `parse(ivVar)` 经常量传播），
      用该 iv 逐字节生成等效密文（标准 CryptoJS.AES-CBC）。
  K.3 常量流：增强赋值收集，覆盖 `var/let/const X=`、裸赋值 `X=`、对象属性 `obj.prop=`
      等形态，把加密调用处的变量名解析回硬编码字面量（全局正则，含跨函数）。

安全红线：只读静态分析抽取，绝不 eval/exec 目标 JS（避免运行不可信代码）。

用法：
    python scripts/js_crypto_restore_poc.py --target <html或目录>
输出：JSON 列表 {api, location, plaintext_arg, key_source, iv_source, restorable, poc}
"""
from __future__ import annotations

import argparse
import glob
import json
import re
import sys
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

# K.3 增强赋值收集（3 种字面量赋值形态）
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
    """K.3 增强：覆盖 var/let/const、裸赋值、对象属性三种字面量赋值形态。"""
    out: dict = {}
    for m in _ASSIGN_VAR.finditer(js):
        out[m.group(1)] = m.group(3)
    for m in _ASSIGN_BARE.finditer(js):
        out[m.group(1)] = m.group(3)
    for m in _ASSIGN_PROP.finditer(js):
        out[f"{m.group(1)}.{m.group(2)}"] = m.group(4)
    return out


def _parse_iv(opts: str, consts: dict | None = None) -> str:
    """K.2：解析 iv。支持字面量 `parse("...")` 与变量 `parse(ivVar)`（经常量传播）。"""
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
    """K.2 精确还原：显式 iv_literal 时用该 iv 逐字节生成等效密文；否则按 CryptoJS 默认
    随机 salt 派生 iv（OpenSSL-compatible EVP_BytesToKey）。"""
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


def analyze_file(path: Path, results: list) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    js = _extract_js(text)
    consts = _collect_const_assignments(js)
    if OBFUSCATOR_HINT.search(js):
        results.append({"file": str(path), "api": "obfuscator", "location": "?",
                        "plaintext_arg": "", "key_source": "混淆代码，需反混淆后分析",
                        "iv_source": "", "restorable": False,
                        "poc": "检测到 javascript-obfuscator/变量名混淆，建议先反混淆"})
    for api, pat in CRYPT_PATTERNS:
        for m in pat.finditer(js):
            groups = m.groups()
            plaintext_arg = (groups[0] or "").strip()
            key_arg = (groups[1] if len(groups) > 1 else "").strip()
            opts = (groups[2] if len(groups) > 2 else "").strip()
            key_lit = _string_literal(key_arg)
            from_const = False
            if key_lit is None and key_arg in consts:   # K.3 常量传播
                key_lit = consts[key_arg]
                from_const = True
            iv_src = _parse_iv(opts, consts) if api == "CryptoJS.AES" else (opts[:40] if opts else "")
            entry = {
                "file": str(path), "api": api,
                "location": f"char~{m.start()}",
                "plaintext_arg": plaintext_arg[:80],
                "key_source": (key_lit if key_lit is not None else f"动态({key_arg[:40]})")
                             + ("(常量传播)" if from_const else ""),
                "iv_source": iv_src,
                "restorable": False, "poc": "",
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="HTML 文件或目录")
    args = ap.parse_args()
    root = Path(args.target)
    files = ([root] if root.is_file() else
             [Path(p) for p in glob.glob(str(root / "**" / "*.html"), recursive=True)] +
             [Path(p) for p in glob.glob(str(root / "**" / "*.js"), recursive=True)])
    if not files:
        print("NO_TARGET_FILES")
        return 0
    results: list = []
    for f in files:
        try:
            analyze_file(f, results)
        except Exception as exc:  # noqa: BLE001
            print(f"[warn] {f}: {exc}")
    print(json.dumps(results, ensure_ascii=False, indent=2))
    restorable = sum(1 for r in results if r.get("restorable"))
    print(f"\nSUMMARY files={len(files)} crypto_points={len(results)} restorable={restorable}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
