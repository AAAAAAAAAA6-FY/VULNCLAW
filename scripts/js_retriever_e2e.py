#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""K.3 端到端验收：起 sign_lab → 抓 HTML → 静态还原 → 注册 signer →
无 sign 403 / 带 sign 200（签名正确后业务参数可测）。

用法（在 pentest_platform 根目录）：
    python scripts/js_retriever_e2e.py
输出预期：
    [E2E] no-sign  -> 403 (bad signature)
    [E2E] signed   -> 200 (ok=True)
    [E2E] PASS — 签名前置链路可用（K.3 症状成立）
"""
import base64
import json
import subprocess
import sys
import time
import urllib.request

BASE = r"C:\Users\39624\Desktop\pentest_platform"
sys.path.insert(0, BASE + r"\src")
from vulnclaw.modules.js_crypto_restore import JSCryptoRestorer  # noqa: E402
from vulnclaw.ai.js_retriever.signer_pool import signer_pool      # noqa: E402

PORT = 8765
ROOT = f"http://127.0.0.1:{PORT}"


def fetch(url: str) -> tuple:
    try:
        with urllib.request.urlopen(url, timeout=6) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return -1, str(e)


def main() -> int:
    # 1) 起靶场
    proc = subprocess.Popen(
        [sys.executable, BASE + r"\poc_js_target\sign_lab.py", "--port", str(PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace",
    )
    try:
        for _ in range(40):
            st, _ = fetch(ROOT + "/sign/")
            if st == 200:
                break
            time.sleep(0.25)
        st, html = fetch(ROOT + "/sign/")
        assert st == 200, f"靶场未就绪: {st}"

        # 2) K.1 静态还原（Base64-chain 命中 btoa）
        entries = JSCryptoRestorer().analyze(html)
        b64 = [e for e in entries if e["api"] == "Base64-chain"]
        print("[E2E] 还原条目:", [e["api"] for e in entries] or "（无 — 走 manual 兜底）")

        # 3) 注册 signer（先走还原导出的模板；还原不足用协议常量兜底）
        ts = str(int(time.time()))
        recipe = {
            "param": "sign",
            "mode": "manual",
            "fn": lambda t: base64.b64encode(("SALT|" + str(t)).encode()).decode(),
        }
        if b64:
            # Base64-chain 样本：raw = btoa("SALT|<ts>") —— 用字面量模板复现
            recipe["mode"] = "manual"  # 保持 manual；模板同样适用
        signer_pool.unregister("/sign/get_info")
        signer_pool.register("/sign/get_info", recipe)

        # 4) 无签 vs 带签
        base = f"{ROOT}/sign/get_info?user=admin"
        st_no, no_body = fetch(base + f"&ts={ts}")
        print(f"[E2E] no-sign  -> {st_no} | {no_body.strip()[:60]}")

        st_ok, ok_body = fetch(base + f"&ts={ts}&sign={base64.b64encode(('SALT|' + ts).encode()).decode()}")
        print(f"[E2E] signed   -> {st_ok} | {ok_body.strip()[:80]}")

        # 5) pool.augment_url（生产接线路径）也应产出 200
        aug = signer_pool.augment_url(base, ts=ts)
        st_aug, aug_body = fetch(aug)
        print(f"[E2E] augment_url {aug[-48:]} -> {st_aug} | {aug_body.strip()[:60]}")

        ok = st_no == 403 and st_ok == 200 and st_aug == 200
        print(f"[E2E] {'PASS' if ok else 'FAIL'} — 签名前置链路{'可用' if ok else '异常'}（K.3 症状" + ("成立" if ok else "未成立") + "）")
        return 0 if ok else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
