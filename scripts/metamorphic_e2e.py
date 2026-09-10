#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""元orphic 不变量探针端到端验收：起 poc_meta_lab 靶场 -> 真跑探针 -> 断言能抓到漏洞。

用法（在 pentest_platform 根目录）：
    python scripts/metamorphic_e2e.py

预期：
    [E2E] price_tampering        -> 命中
    [E2E] replay_not_idempotent  -> 命中
    [E2E] idor_candidate         -> 命中
    [E2E] 安全对照 profile_safe  -> 未命中（无鉴权绕过时不误报）
    [E2E] PASS
"""
import asyncio
import subprocess
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:8791"
PY = sys.executable
ROOT = "scripts"


def fetch(url: str, timeout: float = 3.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except Exception:
        return -1, ""


async def main() -> int:
    sys.path.insert(0, "src")
    from vulnclaw.config.settings import settings
    from vulnclaw.engines.metamorphic_engines import MetamorphicEngine

    # 金额篡改/重放会改变靶场状态，本次为靶场验收，显式开启
    for attr in ("metamorphic_enabled", "metamorphic_allow_state_changing"):
        try:
            setattr(settings, attr, True)
        except Exception:
            pass
    if not getattr(settings, "metamorphic_allow_state_changing", False):
        print("[E2E] 无法开启 metamorphic_allow_state_changing，金额/重放用例将跳过")

    proc = subprocess.Popen(
        [PY, f"{ROOT}/poc_meta_lab.py", "--port", "8791"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace",
    )
    try:
        for _ in range(40):
            if fetch(BASE + "/profile?user_id=1001")[0] == 200:
                break
            time.sleep(0.25)
        else:
            print("[E2E] 靶场未就绪")
            return 1

        eng = MetamorphicEngine()

        f1 = await eng.probe_price_tampering(
            BASE + "/order/create", {"price": "100", "qty": "1"}, method="POST")
        print(f"[E2E] price_tampering       -> {'命中 ' + f1['type'] if f1 else '未命中'}")

        f2 = await eng.probe_replay_idempotency(
            BASE + "/coupon/claim", {"coupon_id": "C1"}, method="POST")
        print(f"[E2E] replay_not_idempotent -> {'命中 ' + f2['type'] if f2 else '未命中'}")

        f3 = await eng.probe_idor_candidate(
            BASE + "/profile", {"user_id": "1001"}, method="GET")
        print(f"[E2E] idor_candidate        -> {'命中 ' + f3['type'] if f3 else '未命中'}")

        f4 = await eng.probe_idor_candidate(
            BASE + "/profile_safe", {"user_id": "1001"}, method="GET")
        print(f"[E2E] 安全对照 profile_safe -> {'误报 ' + f4['type'] if f4 else '未命中（正确）'}")

        # ---- 新范式：同一批元规则，作用于 JSON body / 路径段 / header 注入点 ----
        from vulnclaw.core.attack_surface import spec_from_url

        spec_json = spec_from_url(BASE + "/api/order", "POST",
                                  json_obj={"total": 200, "items": [{"price": 50}]})
        f5 = await eng.probe_spec(spec_json)
        print(f"[E2E] json body 金额篡改 -> {'命中 ' + f5[0]['type'] if f5 else '未命中'}")

        spec_path = spec_from_url(BASE + "/api/profile/1001", "GET")
        f6 = await eng.probe_spec(spec_path)
        print(f"[E2E] path 段越权       -> {'命中 ' + f6[0]['type'] if f6 else '未命中'}")

        spec_hdr = spec_from_url(BASE + "/api/me", "GET", headers={"X-User-Id": "1001"})
        f7 = await eng.probe_spec(spec_hdr)
        print(f"[E2E] header 越权       -> {'命中 ' + f7[0]['type'] if f7 else '未命中'}")

        ok = bool(f1) and bool(f2) and bool(f3) and not f4 and bool(f5) and bool(f6) and bool(f7)
        print("[E2E] PASS — 元orphic 元规则在不注入业务知识的前提下命中逻辑漏洞"
              if ok else "[E2E] FAIL — 存在未命中或误报")
        return 0 if ok else 1
    finally:
        proc.terminate()
        try:
            from vulnclaw.core.utils import close_shared_session
            await close_shared_session()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
