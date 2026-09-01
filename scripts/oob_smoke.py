#!/usr/bin/env python3
"""OOB 通道盲打冒烟（Z2.2 验证）。

端到端验证统一 OOB 通道：申请带外域名 → 生成 token 探测地址 → 本地自触发一次
DNS 解析（模拟目标回调）→ 轮询捕获 → 确认按 token 精确匹配。

用法（项目根）:
    PYTHONPATH=src python scripts/oob_smoke.py

不攻击任何真实目标；仅用本机 DNS 解析触发回调，验证链路可用。
"""
import asyncio
import sys

from vulnclaw.core.oob_channel import OOBChannel
from vulnclaw.core.utils import close_shared_session


async def _self_trigger_dns(host: str) -> None:
    """本地解析 host，等效于被注入目标用该域名发起 DNS 查询。"""
    try:
        from socket import getaddrinfo
        getaddrinfo(host, 80, proto=0)
        print(f"[trigger] 已对本机发起 DNS 解析: {host}")
    except Exception as exc:  # noqa: BLE001
        print(f"[trigger] DNS 解析发起失败(不影响后续轮询): {exc}")


async def main() -> int:
    rc = 0
    ch = OOBChannel()
    try:
        probe = await ch.make_probe("https")
        if not probe:
            print("FAIL: 所有 OOB 通道不可用（interactsh-client 缺失或 dnslog 失败）")
            return 1

        token, domain = probe["token"], probe["domain"]
        url, dns = probe["url"], probe["dns"]
        print(f"[probe] provider={probe['provider']} domain={domain}")
        print(f"[probe] token={token}")
        print(f"[probe] url ={url}")
        print(f"[probe] dns ={dns}")

        # 模拟目标回调：DNS 解析该子域
        await _self_trigger_dns(dns)

        hits = await ch.wait_for_interaction(token, timeout=20)
        if not hits:
            print("FAIL: 已发起回调但轮询超时未捕获（通道回调不可达）")
            return 2

        print(f"OK: 捕获 {len(hits)} 条回调，token={token} 精确匹配成立")
        for h in hits:
            print(f"  - proto={h.protocol} time={h.time} src={h.from_addr or '-'}")
    finally:
        # 关闭共享 aiohttp session，避免进程退出时的 Unclosed 警告
        await close_shared_session()
    return rc


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))