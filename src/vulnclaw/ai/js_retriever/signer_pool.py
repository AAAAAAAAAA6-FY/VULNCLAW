# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)

"""K.3 签名生成器池（SignerPool）：合法请求"前置签名"的生产与注入。

用途（任务卡 K.3）：受签名/时间戳防重放保护的端点，引擎裸扫全是 401/403，
payload 永远到不了业务参数。SignerPool 汇集 K.1 静态还原 / K.2 分诊产出的
"参数生成器"，按端点注册；taskgen 生成引擎任务时把生成的合法签名直接挂进
target URL（build_attack_url 天然保留原 query，签名随引擎每次 payload 请求
一起发出，零引擎改动）。

配方模式：
  aes_iv  静态复现（K.1 还原）：CryptoJS.AES 显式 iv，原文模板可含 {ts} 占位
  sandbox 环境执行（K.2 B 路）：node 沙箱跑前端函数取返回值（受限：无 IO）
  manual  外部注入 python 生成函数（E2E/单元测试用，最灵活）

护栏：
  - budget：settings.js_signer_max_gen_per_target（默认 20），超限返回 None 不抛
  - 原子性：线程安全（并发 taskgen/executor 读）
  - 审计：每次 generate 落盘 data/js_signer/<ts>.json（与 K.2 triage 审计并列）
"""
from __future__ import annotations

import base64
import json
import re
import threading
import time
from pathlib import Path

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings

_EVP = None


def _ensure_crypto():
    """延迟加载 pycryptodome（复用 js_crypto_restore 的 EVP_BytesToKey 参数）。"""
    global _EVP
    if _EVP is None:
        try:
            from Crypto.Cipher import AES
            from Crypto.Protocol.KDF import EVP_BytesToKey
            from Crypto.Util.Padding import pad, unpad
            _EVP = (AES, EVP_BytesToKey, pad, unpad)
        except Exception:  # noqa: BLE001
            _EVP = False
    return _EVP


def _cryptojs_aes_iv_encrypt(plain: str, key: str, iv: str) -> str | None:
    """CryptoJS.AES.encrypt(data, key, {iv}) 等效密文（含随机 salt 的 Salted__ 格式）。"""
    cr = _ensure_crypto()
    if not cr:
        return None
    AES, EVP_BytesToKey, pad, _ = cr
    iv_b = iv.encode()[:16].ljust(16, b"\x00")
    key_b, _iv = EVP_BytesToKey(key.encode(), b"", 32, 16, 1)
    salt = __import__("os").urandom(8)
    ct = AES.new(key_b, AES.MODE_CBC, iv_b).encrypt(pad(plain.encode(), 16))
    return base64.b64encode(b"Salted__" + salt + ct).decode()


def _cryptojs_aes_iv_decrypt(token: str, key: str, iv: str) -> str | None:
    """CryptoJS.AES 显式 iv 密文解密（payload 侧校验与 E2E 断言用）。"""
    cr = _ensure_crypto()
    if not cr:
        return None
    AES, EVP_BytesToKey, _pad, unpad = cr
    try:
        raw = base64.b64decode(token)
        if not raw.startswith(b"Salted__"):
            return None
        salt = raw[8:16]
        ct = raw[16:]
        key_b, iv_b = EVP_BytesToKey(key.encode(), salt, 32, 16, 1)
        pt = unpad(AES.new(key_b, AES.MODE_CBC, iv_b).decrypt(ct), 16)
        return pt.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None


class SignerPool:
    """端点 → 合法签名生成器 注册池（进程级单例，供 taskgen/executor 消费）。

    recipe 结构::

        {"param": "sign", "mode": "aes_iv",
         "key": "hardkeysign12345", "iv": "1234567890123456",
         "template": "SALT|{ts}"}                 # aes_iv

        {"param": "sign", "mode": "sandbox",
         "js": "function genSign(ts){...}", "func": "genSign"}

        {"param": "sign", "mode": "manual", "fn": callable(ts) -> str}
    """

    def __init__(self, audit_dir=None):
        self._recipes: dict[str, dict] = {}
        self._gen_count: dict[str, int] = {}
        self._lock = threading.Lock()
        if audit_dir is None:
            audit_dir = getattr(settings, "js_signer_audit_dir", "data/js_signer")
        self.audit_dir = Path(str(audit_dir))
        self._budget = int(getattr(settings, "js_signer_max_gen_per_target", 20) or 20)

    # -- 注册 ---------------------------------------------------------------
    def register(self, endpoint_pattern: str, recipe: dict) -> bool:
        """endpoint_pattern：端点子串匹配（如 '/sign/get_info'）。

        K.4 安全闸：sandbox 配方若带反爬/反调试特征（debugger/webdriver 等）
        一律拒绝注册（返回 False），防止恶意混淆样本污染探测链。
        """
        if recipe.get("mode") == "sandbox" and recipe.get("js"):
            try:
                from vulnclaw.ai.js_retriever.triage import detect_anti_bot_features

                feats = detect_anti_bot_features(recipe["js"])
            except Exception:  # noqa: BLE001
                feats = []
            if feats:
                logger.warning("[K.4] signer 拒绝注册（反调试特征 %s）: %s",
                               feats, endpoint_pattern)
                return False
        with self._lock:
            self._recipes[endpoint_pattern.strip()] = recipe
        return True

    def unregister(self, endpoint_pattern: str) -> None:
        with self._lock:
            self._recipes.pop(endpoint_pattern.strip(), None)

    # -- 查询 ---------------------------------------------------------------
    def recipe_for(self, url: str) -> dict | None:
        with self._lock:
            for pattern, recipe in self._recipes.items():
                if pattern and pattern in (url or ""):
                    return recipe
        return None

    def signed_for(self, url: str, ts: int | None = None) -> dict | None:
        """返回 {param: 值, ts} 或 None（未注册/预算耗尽/生成失败）。"""
        recipe = self.recipe_for(url)
        if not recipe:
            return None
        ts = int(ts if ts is not None else time.time())
        with self._lock:
            count = self._gen_count.get(url, 0)
            if count >= self._budget:
                logger.debug("[K.3] signer 预算耗尽(%s/%s): %s", count, self._budget, url)
                return None
            self._gen_count[url] = count + 1
        try:
            value = self._gen_value(recipe, ts)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[K.3] 签名生成失败(%s): %s", recipe.get("mode"), exc)
            return None
        if value is None:
            return None
        out = {str(recipe.get("param", "sign")): value, "ts": ts,
               "mode": recipe.get("mode")}
        self._audit(url, out)
        return out

    def augment_url(self, url: str, ts: int | None = None) -> str | None:
        """把合法签名 query 挂进 URL（追加 ?sign=...&ts=...，保留原 query）。"""
        signed = self.signed_for(url, ts)
        if signed is None:
            return None
        param = [k for k in signed if k in ("sign",) or k == signed.get("param")] or ["sign"]
        # signed 结构：{param_name: value, "ts":..., "mode":...} —— 提取实际签名参数
        sign_kv = {k: v for k, v in signed.items() if k not in ("ts", "mode")}
        pairs = []
        for key, val in sign_kv.items():
            pairs.append(f"{key}={_uquote(str(val))}")
        pairs.append(f"ts={signed['ts']}")
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{'&'.join(pairs)}"

    # -- 生成 ---------------------------------------------------------------
    def _gen_value(self, recipe: dict, ts: int) -> str | None:
        mode = recipe.get("mode")
        if mode == "aes_iv":
            key = recipe.get("key", "")
            iv = recipe.get("iv", "")
            if not key:
                return None
            template = recipe.get("template", "{ts}")
            plain = template.replace("{ts}", str(ts))
            return _cryptojs_aes_iv_encrypt(plain, key, iv)
        if mode == "sandbox":
            return self._gen_sandbox(recipe, ts)
        if mode == "manual":
            fn = recipe.get("fn")
            return fn(ts) if callable(fn) else None
        return None

    def _gen_sandbox(self, recipe: dict, ts: int) -> str | None:
        """node 沙箱黑盒调用前端函数（受限：无 IO/eval，限时 10s）。"""
        import shutil
        import subprocess

        node = shutil.which("node")
        if not node:
            return None
        js = recipe.get("js", "")
        func = recipe.get("func", "genSign")
        from vulnclaw.ai.js_retriever.triage import safe_for_sandbox

        if not safe_for_sandbox(js):
            return None
        # 包装：最小 DOM stub + 调用 func(ts) 打印纯字符串结果
        wrapper = (
            f"const __sb__={{document:{{}},window:{{}},navigator:{{userAgent:'vulnclaw'}},"
            f"location:{{href:''}},console:console}};globalThis.window=__sb__.window;"
            f"globalThis.document=__sb__.document;globalThis.navigator=__sb__.navigator;"
            f"globalThis.location=__sb__.location;globalThis.self=globalThis;\n"
            f"try{{ {js}\n;var __r__={func}('{ts}');console.log('SIGN_OUT:'+__r__);"
            f"}}catch(e){{console.log('SIGN_ERR:'+String(e&&e.message||e));}}\n"
        )
        import os
        import tempfile

        fd, tmp = tempfile.mkstemp(suffix=".js", prefix="vulnclaw_signer_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(wrapper)
            try:
                proc = subprocess.run(
                    [node, "--max-old-space-size=64", tmp],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=10.0,
                )
            except subprocess.TimeoutExpired:
                return None
            out = (proc.stdout or "")
            marker = "SIGN_OUT:"
            if marker in out:
                value = out.split(marker, 1)[1].strip().splitlines()
                return value[0] if value else None
            return None
        except Exception:  # noqa: BLE001
            return None
        finally:
            try:
                Path(tmp).unlink()
            except OSError:
                pass

    # -- 审计 ---------------------------------------------------------------
    def _audit(self, url: str, signed: dict) -> None:
        try:
            self.audit_dir.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = self.audit_dir / (f"{stamp}_{int(time.time() * 1000) % 1000000}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"url": url, "signed": signed}, fh, ensure_ascii=False, indent=2)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[K.3] signer 审计落盘失败(不影响生成): %s", exc)


def _uquote(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="")


# 进程级单例（taskgen/executor 共用注册表）
signer_pool = SignerPool()
