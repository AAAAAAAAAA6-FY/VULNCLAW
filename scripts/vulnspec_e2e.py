#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""声明式知识库端到端验收：六条声明只靠**数据**驱动，无对应引擎代码。

用法（在 pentest_platform 根目录）：
    python scripts/vulnspec_e2e.py

验证点：
  - 六条内置声明（SQL报错 / XSS反射 / 时间盲 / 命令注入 / LFI / SSRF）各自命中靶场；
  - 安全对照端点不产生误报；
  - 全过程没有为任何一条声明写引擎代码——新增漏洞只需加声明。
"""
import asyncio
import subprocess
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:8792"
PY = sys.executable


def fetch(url: str, timeout: float = 3.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except Exception:
        return -1, ""


async def main() -> int:
    sys.path.insert(0, "src")
    from vulnclaw.core.attack_surface import spec_from_url
    from vulnclaw.core.vulnspec import SpecRunner, get_spec

    proc = subprocess.Popen(
        [PY, "scripts/poc_meta_lab.py", "--port", "8792"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace",
    )
    try:
        for _ in range(40):
            if fetch(BASE + "/search?q=test")[0] == 200:
                break
            time.sleep(0.25)
        else:
            print("[E2E] 靶场未就绪")
            return 1

        runner = SpecRunner()
        cases = [
            ("sql_error", spec_from_url(BASE + "/search?q=test", "GET")),
            ("xss_reflect", spec_from_url(BASE + "/search?q=test", "GET")),
            ("sqli_time_blind", spec_from_url(BASE + "/api/sleep?q=1", "GET")),
            ("cmd_injection", spec_from_url(BASE + "/api/cmd?c=ls", "GET")),
            ("lfi", spec_from_url(BASE + "/api/file?file=readme.txt", "GET")),
            ("ssrf_internal", spec_from_url(BASE + "/api/fetch?url=https://example.com", "GET")),
            ("xxe", spec_from_url(BASE + "/api/xml?xml=%3Cx%3Eok%3C%2Fx%3E", "GET")),
            ("ssti", spec_from_url(BASE + "/api/tpl?tpl=hello", "GET")),
            ("crlf", spec_from_url(BASE + "/api/header?v=abc", "GET")),
            ("open_redirect", spec_from_url(BASE + "/api/redirect?url=/home", "GET")),
            ("nosql_injection", spec_from_url(BASE + "/api/nosql?q=abc", "GET")),
            ("ldap_injection", spec_from_url(BASE + "/api/ldap?user=alice", "GET")),
            ("java_deserialization", spec_from_url(BASE + "/api/deser?data=hello", "GET")),
            ("dotnet_deserialization", spec_from_url(BASE + "/api/dotnet?data=hello", "GET")),
            ("php_object_injection", spec_from_url(BASE + "/api/php?data=hello", "GET")),
            ("python_pickle_injection", spec_from_url(BASE + "/api/pickle?data=hello", "GET")),
            ("graphql_introspection", spec_from_url(BASE + "/api/graphql?query=%7Bme%7D", "GET")),
            ("xpath_injection", spec_from_url(BASE + "/api/xpath?q=alice", "GET")),
            ("log4shell", spec_from_url(BASE + "/api/log?msg=hello", "GET")),
            ("cors_misconfig", spec_from_url(BASE + "/api/cors?x=1", "GET")),
            ("missing_security_headers", spec_from_url(BASE + "/api/headers?x=1", "GET")),
            ("host_header_injection", spec_from_url(BASE + "/api/host?x=1", "GET")),
            ("ssi_injection", spec_from_url(BASE + "/api/ssi?page=x", "GET")),
            ("el_injection", spec_from_url(BASE + "/api/el?el=x", "GET")),
            ("rfi", spec_from_url(BASE + "/api/rfi?url=http://evil.invalid/x.php", "GET")),
        ]

        ok = True
        for sid, spec in cases:
            decl = get_spec(sid)
            out = await runner.run(spec, specs=[decl])
            hit = bool(out)
            ok &= hit
            detail = out[0]["evidence"][:70] if out else "未命中"
            print(f"[E2E] {sid:16s} -> {'命中' if hit else '未命中'} | {detail}")

        # 安全对照：同一个命令注入声明打安全端点，不应命中
        safe = await runner.run(spec_from_url(BASE + "/api/safe?c=hello", "GET"),
                                specs=[get_spec("cmd_injection")])
        print(f"[E2E] 安全对照 /api/safe -> {'误报' if safe else '未命中（正确）'}")
        ok &= not safe

        # 全量声明的误报回归：所有声明打安全端点都不应命中
        # （header_absent 型除外——靶场确实缺安全头，命中属实而非误报）
        # 两个安全端点：echo JSON（/api/safe）与"正确转义的 HTML"（/safe/html）
        from vulnclaw.core.vulnspec import BUILTIN_SPECS
        fp_all = []
        for safe_url in (BASE + "/api/safe?c=hello", BASE + "/safe/html?q=hello"):
            for decl in BUILTIN_SPECS:
                if decl.detect.header_absent:
                    continue
                got = await runner.run(spec_from_url(safe_url, "GET"), specs=[decl])
                if got:
                    fp_all.append(f"{decl.id}@{safe_url.split('?')[0]}")
        print(f"[E2E] 全量声明误报回归 -> {fp_all if fp_all else '无（正确）'}")
        ok &= not fp_all

        print(f"[E2E] PASS — {len(cases)} 条声明零引擎代码命中对应漏洞，且无误报"
              if ok else "[E2E] FAIL — 存在未命中或误报")
        return 0 if ok else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        try:
            from vulnclaw.core.utils import close_shared_session
            await close_shared_session()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
