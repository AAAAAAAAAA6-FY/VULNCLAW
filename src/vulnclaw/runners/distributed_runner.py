# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""分布式扫描 runner（R2 拆分自 scan_main.py）。"""

import asyncio
import time


async def run_distributed_master(args) -> int:
    """分布式 Master 入口。

    连接 Redis 后启动 Worker 监控循环（心跳检测 + 离线故障转移），
    Ctrl+C 停止。退出码 = 正常停止 = Redis 连接失败。
    """
    from vulnclaw.distributed.master import DistributedMaster

    master = DistributedMaster(redis_url=args.redis_url)
    print("=" * 70)
    print("👑 分布式 Master 启动...")
    print(f"   Redis: {args.redis_url}")
    print("=" * 70)

    try:
        await master._connect()
    except Exception as exc:
        print(f"Master 启动失败（Redis 连接失败: {exc}")
        return 1

    print("👑 Master 已就绪，正在监控 Worker（Ctrl+C 停止）")
    try:
        await master.start_monitor()
    except asyncio.CancelledError:
        pass
    finally:
        await master.stop()
    return 0


async def run_distributed_worker(args) -> int:
    """分布式 Worker 入口。

    向 Master 注册（recon/attack/verify 能力），随后循环从 Redis Stream
    消费组拉取任务、执行、上报，并行维护心跳。退出码 = 正常停止。
    """
    from vulnclaw.distributed.worker import DistributedWorker

    worker = DistributedWorker(
        redis_url=args.redis_url,
        capabilities=['recon', 'attack', 'verify', 'report', 'deserialization'],
    )
    print("=" * 70)
    print("👷 分布式 Worker 启动...")
    print(f"   Redis: {args.redis_url}")
    print(f"   能力: {worker._capabilities}")
    print("=" * 70)

    try:
        await worker.start()
    except asyncio.CancelledError:
        pass
    finally:
        await worker.stop()
    return 0


async def run_distributed_scan(args) -> int:
    """P3-3: 分布式提交端入口（--distributed -t <target>）。

    流程：
    1. 先做子域名收集，估算目标规模；
    2. 子域名 < 50 → 自动降级单机 v100 扫描（不走分布式路径）；
    3. 子域名 >= 50 → 向 Master 的 Redis Stream 提交三类任务
       （recon_sub / recon_alive / attack_engine），并轮询汇总结果。

    退出码：0 = 成功 / 1 = 失败。
    """
    from vulnclaw.core.logger import logger
    from vulnclaw.core.utils import close_shared_session, get_shared_session

    target = args.target
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    session = await get_shared_session()
    try:
        # 1. 子域名收集（估算目标规模）
        subs = []
        try:
            from vulnclaw.modules.recon import get_subdomains_async
            subs = list(await get_subdomains_async(domain, compliant=False))
        except Exception as exc:
            logger.warning(f"⚠️ [分布式] 子域名收集失败，按小目标处理: {exc}")
        subs = list(dict.fromkeys([s for s in subs if s]))

        # 2. 小目标（<50）自动降级单机 v100
        if len(subs) < 50:
            logger.info(f"🎯 [分布式] 子域名 {len(subs)} < 50，自动降级单机 v100 扫描")
            from vulnclaw.ai.v100 import run_v100_scan
            report = await run_v100_scan(target, session)
            findings = (report or {}).get("findings") or (report or {}).get("vulnerabilities") or []
            logger.info(f"✅ [分布式] 单机扫描完成: {len(findings)} 个漏洞")
            return 0

        # 3. 大目标 → 提交三类任务
        from vulnclaw.distributed.master import DistributedMaster
        logger.info(f"🚀 [分布式] 子域名 {len(subs)} >= 50，提交分布式任务")
        master = DistributedMaster(redis_url=args.redis_url)
        prefix = domain
        context = {
            f"{prefix}_recon_subdomains": subs,
        }
        now = int(time.time())
        tasks = [
            {
                "task_id": f"recon_sub_{now}",
                "type": "recon_sub",
                "name": "子域名收集",
                "target": target,
                "params": {"prefix": prefix, "domain": domain, "target": target},
                "context": context,
            },
            {
                "task_id": f"alive_{now}",
                "type": "recon_alive",
                "name": "存活探测",
                "target": target,
                "params": {"prefix": prefix, "target": target},
                "context": context,
            },
            {
                "task_id": f"attack_{now}",
                "type": "attack_engine",
                "name": "漏洞攻击检测",
                "target": target,
                "params": {"prefix": prefix, "target": target},
                "context": context,
            },
        ]
        task_ids = await master.submit_batch(tasks)
        results = {}
        for tid in task_ids:
            try:
                r = await master.get_result(tid, timeout=1800)
            except Exception as exc:
                logger.warning(f"⚠️ [分布式] 等待任务 {tid} 结果超时: {exc}")
                r = None
            results[tid] = r

        for tid, r in results.items():
            status = (r or {}).get("status", "unknown")
            logger.info(f"📦 [分布式] 任务 {tid} → {status}")
        return 0
    finally:
        await close_shared_session()
