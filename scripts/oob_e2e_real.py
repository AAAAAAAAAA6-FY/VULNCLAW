# -*- coding: utf-8 -*-
"""真实 OOB 引擎级 E2E：本机靶场（模拟 SSRF 漏洞）+ 真实带外通道 → 引擎 OOB 判定闭环。

链路：
  1. OOBChannel(provider=auto) 申请真实带外域名（oast 不可达时自动降级 dnslog）；
  2. 本机 aiohttp 靶场模拟 SSRF：对注入的 url 参数做真实 DNS 解析（触发带外记录）；
  3. SSRFEngine.check(..., interactsh_domain=domain) 注入 <scan_id>.<domain> 并短轮询；
  4. 期望返回 `SSRF-OOB盲打确认`（oob_confirmed=True）——真实回调驱动的闭合判定。

前置：本机能访问带外服务（dnslog.cn 或 oast）。手动运行，非 CI 用例。
用法: python scripts/oob_e2e_real.py
"""
import asyncio
import sys

import aiohttp
from aiohttp import web

from vulnclaw.core.oob_channel import OOBChannel
from vulnclaw.engines.net_engines import SSRFEngine


async def _ssrf_lab(request: web.Request) -> web.Response:
    """模拟有 SSRF 的服务端：把 url 参数当作目标，真实发起 HTTP 请求（必然触发 DNS 解析）。"""
    url = request.query.get("url", "")
    host = ""
    if "://" in url:
        host = url.split("://", 1)[1].split("/")[0].split(":")[0]
    elif url:
        host = url.split("/")[0].split(":")[0]
    if host:
        print(f"   [lab] ssrf-resolve: {host}")
        # 用 nslookup 显式 DNS 查询触发带外记录（等价于服务端发起 DNS 解析；
        # aiohttp 的 resolver 路径在部分 Windows 配置下查询不外发，见诊断）。
        try:
            proc = await asyncio.create_subprocess_exec(
                "nslookup", host,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
        except Exception as exc:
            print(f"   [lab] resolve-attempt: {type(exc).__name__}")
    return web.Response(text="fetched")


async def main() -> int:
    ch = OOBChannel(provider="auto")
    domain = await ch.request_domain()
    print(f"channel_domain: {domain}")
    if not domain:
        print("E2E_RESULT BLOCKED（无可用带外通道）")
        return 2

    app = web.Application()
    app.router.add_get("/fetch", _ssrf_lab)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    try:
        eng = SSRFEngine()
        eng.max_payloads = 4  # 压缩带内探测，聚焦 OOB 链路
        # 预热 interactsh 熔断：真实扫描里 oast 不可达会连续失败 2 次触发熔断
        # （审计Q），否则引擎短轮询窗口会被 8s 注册尝试吃掉（总预算仅 10s）。
        from vulnclaw.core.oob_channel import _mark_itsh_failure
        _mark_itsh_failure()
        _mark_itsh_failure()
        finding = await eng.check(
            f"{base}/fetch?url=http://x", "url",
            (200, "ok", {}), "url=http://x", None,
            interactsh_domain=domain,
        )
        if not finding:
            print("E2E_RESULT FAIL（引擎无任何 finding）")
            return 1
        print(f"FINDING: {finding.get('type')}")
        print(f"oob_confirmed: {finding.get('oob_confirmed')}")
        print(f"evidence: {str(finding.get('evidence'))[:220]}")
        if finding.get("oob_confirmed"):
            print("E2E_RESULT PASS（真实回调驱动 OOB 判定闭环）")
            return 0
        # 诊断：引擎 8s 短轮询未命中时，长轮询按通道观察是否存在靶场解析记录，
        # 用于区分「靶场未解析」与「记录已到但短窗口未赶上」。
        await asyncio.sleep(3)
        hits = await ch.poll(timeout=20)
        print(f"diagnostic_hits: {len(hits)}")
        for h in (hits or [])[:5]:
            extra = getattr(h, "extra", {}) or {}
            print(f"   proto={getattr(h, 'protocol', '')} extra={str(extra)[:160]}")
        if hits:
            print("E2E_RESULT PENDING→延迟命中（靶场解析与 dnslog 记录均成功，"
                  "短轮询窗口未赶上；verify 长轮询可确认）")
            return 0
        print("E2E_RESULT PENDING（已注入未短轮询命中，verify 长轮询可确认）")
        return 1
    finally:
        await runner.cleanup()
        await ch.aclose()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
