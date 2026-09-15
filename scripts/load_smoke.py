# -*- coding: utf-8 -*-
"""本地并发压测冒烟：自包含内存靶场 + 引擎并发扫描（离线，无需外部服务）。

用途：验证扫描器在高并发下的吞吐与延迟（生产硬化前置检查），
不依赖 Docker/外网，可随时本地复现。

用法:
  python scripts/load_smoke.py --concurrency 20 --requests 200
输出:
  requests / concurrency / 检出数 / QPS / 延迟 p50,p95,p99 / 错误数
"""
import argparse
import asyncio
import time
from typing import List, Tuple

import aiohttp
from aiohttp import web

from vulnclaw.engines.web_engines import CMDIEngine


async def _vuln_exec(request: web.Request) -> web.Response:
    # 模拟存在命令回显的端点（引擎应检出 → 同时验证压测下判定不退化）
    return web.Response(text="uid=0(root) gid=0(root) groups=0(root)")


async def _start_lab() -> Tuple[web.AppRunner, str]:
    app = web.Application()
    app.router.add_get("/exec", _vuln_exec)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"http://127.0.0.1:{port}"


async def _one(engine, base: str, session, sem: asyncio.Semaphore,
               lat: List[float]) -> bool:
    async with sem:
        t0 = time.perf_counter()
        try:
            finding = await engine.check(
                f"{base}/exec?cmd=x", "cmd", (200, "ok", {}), "cmd=x", session
            )
        except Exception:
            finding = None
        lat.append(time.perf_counter() - t0)
        return bool(finding)


def _pct(sorted_lat: List[float], p: float) -> float:
    if not sorted_lat:
        return 0.0
    idx = min(len(sorted_lat) - 1, int(len(sorted_lat) * p))
    return sorted_lat[idx]


async def _main(concurrency: int, requests: int) -> int:
    runner, base = await _start_lab()
    try:
        lat: List[float] = []
        sem = asyncio.Semaphore(concurrency)
        engine = CMDIEngine()
        async with aiohttp.ClientSession() as session:
            t0 = time.perf_counter()
            results = await asyncio.gather(*[
                _one(engine, base, session, sem, lat) for _ in range(requests)
            ])
            elapsed = time.perf_counter() - t0
        lat_sorted = sorted(lat)
        detected = sum(results)
        qps = (requests / elapsed) if elapsed > 0 else 0.0
        print(f"requests={requests} concurrency={concurrency} detected={detected}")
        print(f"requests_total={len(lat)} errors={requests - len(lat)}")
        print(
            f"elapsed={elapsed:.3f}s qps={qps:.1f} "
            f"p50={_pct(lat_sorted, 0.50)*1000:.1f}ms "
            f"p95={_pct(lat_sorted, 0.95)*1000:.1f}ms "
            f"p99={_pct(lat_sorted, 0.99)*1000:.1f}ms"
        )
        # 压测下判定不退化：全部应检出
        if detected != requests:
            print(f"WARNING: 检出 {detected}/{requests}，并发下判定可能退化")
            return 1
        return 0
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="本地并发压测冒烟（自包含内存靶场）")
    ap.add_argument("--concurrency", type=int, default=20)
    ap.add_argument("--requests", type=int, default=200)
    args = ap.parse_args()
    raise SystemExit(asyncio.run(_main(args.concurrency, args.requests)))
