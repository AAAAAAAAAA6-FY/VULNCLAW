# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# dag/executor.py
import asyncio
import os
from typing import Any, Dict, List
from urllib.parse import urlparse
from vulnclaw.core.logger import logger
from .graph import DAGNode, NodeType
from .context import DAGContext


def _ctx_key(target_prefix: str, key: str) -> str:
    return f"{target_prefix}_{key}" if target_prefix else key


async def execute_recon_sub_node(node: DAGNode, context: DAGContext) -> Dict:
    """子域名收集（支持 P0-4 批量模式：subfinder -dL + 跨目标限并发）"""
    from vulnclaw.modules.recon import get_subdomains_async, get_subdomains_batch_async

    # P0-4: 批量模式 —— 单节点聚合多个目标，结果按 prefix 分发回各槽位
    targets = node.params.get('targets')
    if targets:
        domains = [d for _, d in targets]
        logger.info(f"🔍 [RECON-SUB-BATCH] 批量子域名收集: {len(domains)} 个目标")
        results = await get_subdomains_batch_async(domains)
        total = 0
        for prefix, domain in targets:
            subs = list(results.get(domain, []))
            total += len(subs)
            await context.update(_ctx_key(prefix, 'recon_subdomains'), subs)
            logger.info(f"✅ [RECON-SUB-BATCH] {domain}: {len(subs)} 个子域名")
        return {'subdomains': results, 'count': total}

    domain = node.params.get('domain', urlparse(node.target).netloc)
    logger.info(f"🔍 [RECON-SUB] 子域名收集: {domain}")

    try:
        subdomains = await get_subdomains_async(domain, compliant=False)
        await context.update(_ctx_key(node.params.get('prefix', ''), 'recon_subdomains'), subdomains)
        logger.info(f"✅ [RECON-SUB] 完成: {len(subdomains)} 个子域名")
        return {'subdomains': subdomains, 'count': len(subdomains)}
    except Exception as e:
        logger.error(f"❌ [RECON-SUB] 失败: {e}")
        raise


async def execute_recon_alive_node(node: DAGNode, context: DAGContext) -> Dict:
    """存活探测"""
    from vulnclaw.modules.recon import alive_scan

    prefix = node.params.get('prefix', '')
    subdomains = await context.get(_ctx_key(prefix, 'recon_subdomains'), [])
    logger.info(f"🔍 [RECON-ALIVE] 存活探测: {len(subdomains)} 个子域名")

    # 项目硬约束：所有"同步侦察函数"必须用 loop.run_in_executor(None, ...) 卸载到线程池，
    # 禁止直接用 asyncio.to_thread，避免子线程内部再调用需要 running event loop 的接口时
    # 触发 RuntimeError: no running event loop（和 modules/recon.py 的 alive_scan 修法对齐）。
    try:
        loop = asyncio.get_running_loop()
        alive = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: alive_scan(list(subdomains), False)),
            timeout=180,
        )
        await context.update(_ctx_key(prefix, 'recon_alive'), alive)
        logger.info(f"✅ [RECON-ALIVE] 完成: {len(alive)} 个存活")
        return {'alive': alive, 'count': len(alive)}
    except asyncio.TimeoutError:
        logger.warning("⚠️ [RECON-ALIVE] 超时 (180s)，跳过存活探测")
        alive = []
        await context.update(_ctx_key(prefix, 'recon_alive'), alive)
        return {'alive': alive, 'count': 0, 'timeout': True}
    except Exception as e:
        logger.error(f"❌ [RECON-ALIVE] 失败: {e}")
        raise


async def execute_recon_nuclei_node(node: DAGNode, context: DAGContext) -> Dict:
    """Nuclei CVE 扫描"""
    from vulnclaw.modules.vuln_scanner.cve_nuclei import run_nuclei_async

    logger.info(f"🔍 [RECON-NUCLEI] Nuclei 扫描: {node.target}")

    try:
        results = await run_nuclei_async(node.target, timeout=120)
        prefix = node.params.get('prefix', '')
        await context.update(_ctx_key(prefix, 'recon_nuclei'), results)
        logger.info(f"✅ [RECON-NUCLEI] 完成: {len(results)} 个结果")
        return {'nuclei_results': results, 'count': len(results)}
    except Exception as e:
        logger.error(f"❌ [RECON-NUCLEI] 失败: {e}")
        raise


async def execute_recon_js_node(node: DAGNode, context: DAGContext) -> Dict:
    """JS 深度分析"""
    from vulnclaw.modules.collectors import analyze_js_deep
    from vulnclaw.core.utils import async_get

    logger.info(f"🔍 [RECON-JS] JS 分析: {node.target}")

    try:
        resp = await async_get(node.target, session=None, timeout=15)
        text = resp[1] if resp and resp[0] == 200 else ""

        import re
        js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', text, re.I)
        js_endpoints = []
        for js_url in js_urls[:10]:
            try:
                if not js_url.startswith('http'):
                    parsed = urlparse(node.target)
                    js_url = f"{parsed.scheme}://{parsed.netloc}{js_url if js_url.startswith('/') else '/' + js_url}"
                js_resp = await async_get(js_url, session=None, timeout=10)
                if js_resp and js_resp[0] == 200:
                    result = await analyze_js_deep(js_resp[1], node.target, js_url)
                    js_endpoints.append(result)
            except Exception:
                pass

        prefix = node.params.get('prefix', '')
        await context.update(_ctx_key(prefix, 'recon_js'), js_endpoints)
        logger.info(f"✅ [RECON-JS] 完成: {len(js_endpoints)} 个 JS 文件分析")
        return {'js_endpoints': js_endpoints, 'count': len(js_endpoints)}
    except Exception as e:
        logger.error(f"❌ [RECON-JS] 失败: {e}")
        raise


async def execute_recon_port_node(node: DAGNode, context: DAGContext) -> Dict:
    """端口扫描"""
    from vulnclaw.modules.recon import port_scan

    domain = node.params.get('domain', urlparse(node.target).netloc)
    logger.info(f"🔍 [RECON-PORT] 端口扫描: {domain}")

    # 项目硬约束：port_scan 内部需要独立的 asyncio.run 上下文（ThreadPoolExecutor 线程提供），
    # 用 asyncio.to_thread 会在 Python 3.12+/某些嵌套场景里遇到 "no current event loop in thread"
    # 的 RuntimeError。统一改到 loop.run_in_executor(None, ...)，并加 90s 总超时，
    # 与 modules/recon.py 已经验证通过的修法保持一致。
    try:
        import socket
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            ip = domain

        loop = asyncio.get_running_loop()
        ports = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: port_scan(ip, True)),
            timeout=90,
        )
        prefix = node.params.get('prefix', '')
        await context.update(_ctx_key(prefix, 'recon_ports'), ports)
        logger.info(f"✅ [RECON-PORT] 完成: {len(ports)} 个开放端口")
        return {'ports': ports, 'count': len(ports)}
    except asyncio.TimeoutError:
        logger.warning("⚠️ [RECON-PORT] 超时 (90s)，跳过端口扫描")
        prefix = node.params.get('prefix', '')
        await context.update(_ctx_key(prefix, 'recon_ports'), [])
        return {'ports': [], 'count': 0, 'timeout': True}
    except Exception as e:
        logger.error(f"❌ [RECON-PORT] 失败: {e}")
        raise


async def execute_recon_ffuf_node(node: DAGNode, context: DAGContext) -> Dict:
    """目录爆破"""
    from vulnclaw.modules.vuln_scanner.directory_ffuf import run_ffuf_async

    logger.info(f"🔍 [RECON-FFUF] 目录爆破: {node.target}")

    try:
        dirs = await run_ffuf_async(node.target, timeout=120)
        prefix = node.params.get('prefix', '')
        await context.update(_ctx_key(prefix, 'recon_dirs'), dirs)
        logger.info(f"✅ [RECON-FFUF] 完成: {len(dirs)} 个目录")
        return {'dirs': dirs, 'count': len(dirs)}
    except Exception as e:
        logger.error(f"❌ [RECON-FFUF] 失败: {e}")
        raise


async def execute_recon_node(node: DAGNode, context: DAGContext) -> Dict:
    """执行侦察节点：调用现有 _deep_recon_internal 逻辑，返回 brief"""
    from vulnclaw.ai.v100.orchestrator import V100Orchestrator
    from vulnclaw.core.utils import get_shared_session

    prefix = node.params.get('prefix', '')
    logger.info(f"🔍 [RECON] 开始侦察: {node.target}")

    orchestrator = V100Orchestrator(
        target=node.target,
        session=await get_shared_session(target=node.target),
        max_tasks=node.params.get('max_tasks'),
        initial_qps=node.params.get('initial_qps')
    )

    brief = {}
    try:
        await orchestrator._recon()
        brief = orchestrator._recon_brief
        await context.set(_ctx_key(prefix, 'recon_brief'), brief)
        await context.set(_ctx_key(prefix, 'session'), orchestrator.session)
        await context.set(_ctx_key(prefix, 'orchestrator'), orchestrator)
        logger.info(f"✅ [RECON] 完成: {node.target}")
    except Exception as e:
        logger.error(f"❌ [RECON] 失败: {e}")
        raise
    finally:
        orchestrator.burp_client = None
        orchestrator.burp_available = False

    return brief


async def execute_attack_node(node: DAGNode, context: DAGContext) -> Dict:
    """执行攻击节点：调用现有 _generate_tasks + _execute_with_limiting。

    当 scan.py 走"6 个拆分侦察节点 → attack"路径时，没有统一的 RECON_NODE 写入
    `orchestrator / recon_brief`，这里做一次兜底装配：现场创建 V100Orchestrator，
    把 context 里 6 个拆分侦察槽位 + 入口静态侦察信息合并回填到它的 _recon_brief，
    保证下游攻击/验证/报告节点的读取行为与完整侦察模式保持一致。
    """
    prefix = node.params.get('prefix', '')
    logger.info(f"⚔️ [ATTACK] 开始攻击: {node.target}")

    orchestrator = await context.get(_ctx_key(prefix, 'orchestrator'))
    # ★★★ 关键修复：确保 orchestrator 有 rate_limiter（兜底，覆盖未装配完整路径）★★★
    if orchestrator is not None and (
        not hasattr(orchestrator, 'rate_limiter') or orchestrator.rate_limiter is None
    ):
        from vulnclaw.ai.v100.rate_limiter import get_rate_limiter
        orchestrator.rate_limiter = get_rate_limiter(getattr(orchestrator, 'initial_qps', 3))
        logger.info("[ATTACK] 兜底创建 rate_limiter (orchestrator 已存在但缺少 limiter)")
    if not orchestrator:
        from vulnclaw.ai.v100.orchestrator import V100Orchestrator
        from vulnclaw.core.utils import get_shared_session
        from vulnclaw.core.session_manager import get_session_manager
        from urllib.parse import urlparse as _urlparse

        session = await context.get(_ctx_key(prefix, 'session'))
        if session is None:
            session = await get_shared_session(target=node.target)

        logger.info(
            "🧩 [ATTACK] 未在 context 中找到 orchestrator，"
            "使用拆分侦察槽位现场装配一个 V100Orchestrator 实例。"
        )
        orchestrator = V100Orchestrator(
            target=node.target,
            session=session,
            max_tasks=node.params.get('max_tasks'),
            initial_qps=node.params.get('initial_qps'),
        )

        # run() 路径才会初始化 local_filter / task_queue；DAG 的 attack 装配路径
        # 直接跳到 _generate_tasks，需要手动补齐这两个依赖，否则 taskgen 第一行
        # `self.local_filter.should_skip(...)` 就会抛 AttributeError。
        try:
            from vulnclaw.ai.v100.local_filter import get_local_filter
            orchestrator.local_filter = get_local_filter()
        except Exception as _e:
            logger.warning(f"[ATTACK] local_filter 初始化失败，降级为 noop: {_e}")
            from vulnclaw.ai.v100.local_filter import LocalFilter
            orchestrator.local_filter = LocalFilter()
        try:
            from vulnclaw.ai.v100.smart_queue import SmartTaskQueue
            orchestrator.task_queue = SmartTaskQueue(max_size=2000)
        except Exception as _e:
            logger.warning(f"[ATTACK] task_queue 初始化失败: {_e}")
            raise
        # 补齐 run() 路径才会创建的限流/批处理/balancer 客户端资源：
        # 否则 _run_one_task 首行 self.rate_limiter.acquire 会直接抛
        # 'NoneType' object has no attribute 'acquire'。
        try:
            from vulnclaw.ai.v100.rate_limiter import get_rate_limiter
            from vulnclaw.ai.v100.batch_processor import BatchProcessor
            # DAG 模式下不跑 orchestrator.run() 的 _auto_tune()，
            # 直接读 settings 兜底。避免"llm limit=7 但 QPS=3 → acquired 长期=1"。
            # 这里把 DAG 专用 QPS floor 提到 6（建议 3：并发抢占窗口 + QPS 抬升），
            # 但仍受 ResourceGovernor llm=7 的全局上限保护，不会把第三方打爆。
            try:
                from vulnclaw.core.settings import settings as _settings
                configured_qps = int(getattr(_settings, "orchestrator_initial_qps", 0) or 0)
            except Exception:
                configured_qps = 0
            user_qps = getattr(orchestrator, "_user_initial_qps", None)
            if user_qps and int(user_qps) > 0:
                qps = int(user_qps)
            elif configured_qps > 0:
                qps = configured_qps
            else:
                qps = 6  # DAG attack 默认不低于 6；ResourceGovernor 会兜上限
            # 安全钳制：哪怕用户配置写错也不要冲到离谱值。
            qps = max(3, min(qps, 15))
            max_tasks_default = 200
            try:
                from vulnclaw.core.settings import settings as _settings2
                mt = int(getattr(_settings2, "orchestrator_max_tasks", 0) or 0)
                if mt > 0:
                    max_tasks_default = mt
            except Exception:
                pass
            user_max = getattr(orchestrator, "_user_max_tasks", None)
            orchestrator.initial_qps = qps
            orchestrator.max_tasks = int(user_max) if user_max and int(user_max) > 0 else max_tasks_default
            orchestrator.rate_limiter = get_rate_limiter(qps)
            orchestrator.batch_processor = BatchProcessor(max_batch_size=5)
            # ★★★ 关键修复：balancer.init_clients 加异常保护，失败降级为规则模式 ★★★
            try:
                orchestrator.balancer.init_clients(orchestrator.rate_limiter)
            except Exception as _be:
                logger.warning(f"[ATTACK] balancer 初始化失败，降级为规则模式: {_be}")
                orchestrator.balancer = None
            logger.info(
                "[ATTACK] DAG 装配 QPS/max_tasks 兜底: initial_qps=%s, max_tasks=%s "
                "(ResourceGovernor llm≤7 会继续在全局卡上限)",
                orchestrator.initial_qps,
                orchestrator.max_tasks,
            )
        except Exception as _e:
            logger.warning(f"[ATTACK] rate_limiter/balancer 初始化失败: {_e}")
            raise

        # 1）合并 6 个拆分侦察节点产出的 DAG 槽位
        subdomains = await context.get(_ctx_key(prefix, 'recon_subdomains'), [])
        alive = await context.get(_ctx_key(prefix, 'recon_alive'), [])
        nuclei = await context.get(_ctx_key(prefix, 'recon_nuclei'), [])
        js_endpoints = await context.get(_ctx_key(prefix, 'recon_js'), [])
        open_ports = await context.get(_ctx_key(prefix, 'recon_ports'), [])
        found_dirs = await context.get(_ctx_key(prefix, 'recon_dirs'), [])

        domain = node.params.get('domain') or _urlparse(node.target).netloc
        # 入口静态扫描信息：为 phases_taskgen._generate_tasks 提供 url_params/forms/apis/tech_stack
        status, tech_stack, url_params, forms, apis = await _probe_static_recon(
            node.target, orchestrator, session
        )

        # 2）与 phases_recon._recon 的 skeleton 保持字段名一致
        brief = {
            "target": node.target,
            "domain": domain,
            "status": status,
            "tech_stack": tech_stack,
            "url_params": url_params,
            "forms": forms,
            "has_auth": False,
            "apis": apis,
            "burp_params": list(node.params.get('burp_params') or []),
            "burp_cookies": node.params.get('burp_cookies') or {},
            "burp_tokens": node.params.get('burp_tokens') or {},
            "subdomains": list(subdomains or []),
            "alive_assets": list(alive or []),
            # Nuclei/FFUF 在外部是 severity list / [{path, status_code}] 两类，直接保留。
            "nuclei_results": (nuclei[:20] if isinstance(nuclei, list) else []),
            "js_endpoints": list(js_endpoints or [])[:30],
            "open_ports": list(open_ports or []),
            "found_dirs": (found_dirs[:50] if isinstance(found_dirs, list) else []),
        }

        # 3）同步会话鉴权状态（与 _recon 末尾逻辑一致）
        session_mgr = get_session_manager()
        if session_mgr:
            try:
                cookies = session_mgr.get_cookies_for_url(node.target)
                if cookies:
                    brief["has_auth"] = True
            except Exception as _e:
                logger.debug(f"[ATTACK] 获取会话 Cookie 失败（忽略）: {_e}")
        if brief.get("burp_cookies"):
            brief["has_auth"] = True

        # 4）绑定到 orchestrator 与 context，保持与 execute_recon_node 同等后续语义
        orchestrator._recon_brief = brief
        await context.set(_ctx_key(prefix, 'orchestrator'), orchestrator)
        await context.set(_ctx_key(prefix, 'session'), orchestrator.session)
        await context.set(_ctx_key(prefix, 'recon_brief'), brief)

    try:
        await orchestrator._generate_tasks()
        # DAG 装配路径也需要启动流水线验证，让 attack 的 finding 边出边验证。
        try:
            start_sv = getattr(orchestrator, "_start_stream_verify", None)
            if callable(start_sv):
                start_sv()
        except Exception as _sv_err:
            logger.debug("[ATTACK] 启动 stream-verify 失败（不影响攻击执行）: %s", _sv_err)
        await orchestrator._execute_with_limiting()

        findings = list(orchestrator.findings)
        await context.update(_ctx_key(prefix, 'findings'), findings)
        logger.info(f"✅ [ATTACK] 完成: {len(findings)} 个发现")
    except Exception as e:
        logger.error(f"❌ [ATTACK] 失败: {e}")
        raise

    return {'findings_count': len(findings)}


async def _probe_static_recon(target: str, orchestrator, session):
    """执行入口静态扫描（tech_stack / status / url_params / forms / apis），失败安全兜底。

    与 phases_recon._recon 的头部轻量流程对齐；攻击节点的 assembly 路径需要这份静态
    信息，否则 taskgen 会因 url_params 与 forms 为空而直接跳过"目标本身页面参数"的
    engine_bundle 生成。
    """
    import re as _re
    from vulnclaw.core.utils import async_get

    status = 0
    tech_stack = []
    url_params = []
    forms = []
    apis = []
    try:
        resp = await async_get(target, session=session, timeout=15)
        status, text, headers = resp
    except Exception as e:
        logger.warning(f"[ATTACK] 入口静态探测失败（跳过，不阻断攻击）: {e}")
        return status, tech_stack, url_params, forms, apis

    # tech_stack 直接复用 orchestrator 自身的 _detect_tech，保证特征表一致
    try:
        detect = getattr(orchestrator, '_detect_tech', None)
        if callable(detect):
            tech_stack = list(detect(headers, text) or [])[:10]
    except Exception as _e:
        logger.debug(f"[ATTACK] _detect_tech 异常: {_e}")

    if '?' in target:
        for part in target.split('?', 1)[1].split('&'):
            if '=' in part:
                name = part.split('=', 1)[0]
                if name:
                    url_params.append(name)
    if text:
        inputs = _re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', text, _re.I)
        forms = list(dict.fromkeys(inputs))[:30]
        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v[0-9]+/[^"\']+)["\']',
            r'["\'](/graphql[^"\']*)["\']',
        ]
        for pat in api_patterns:
            for m in _re.findall(pat, text):
                if len(m) > 2:
                    apis.append(m)

    try:
        # 与原 _recon 同步把缓存写进 orchestrator._normal_responses，
        # 避免 taskgen 同一页面再发 1 次重复请求。
        normal_cache = getattr(orchestrator, '_normal_responses', None)
        if isinstance(normal_cache, dict):
            normal_cache[target] = {"status": status, "text": text, "headers": headers}
    except Exception as _e:
        logger.debug(f"[ATTACK] 写入 normal_responses 缓存失败（忽略）: {_e}")

    return status, tech_stack, url_params, forms, apis


async def execute_verify_node(node: DAGNode, context: DAGContext) -> Dict:
    """执行验证节点：调用现有 _verify_all_findings"""
    prefix = node.params.get('prefix', '')
    logger.info("🔬 [VERIFY] 开始验证")

    orchestrator = await context.get(_ctx_key(prefix, 'orchestrator'))
    if not orchestrator:
        raise ValueError("Orchestrator not found in context, run ATTACK node first")

    try:
        # 先 flush 流水线 verify 剩余 pending，让 attack->verify 之间完全流水化，
        # verify 节点只等收尾而不再对已流式验过的条目重新 cross-validation。
        stop_sv = getattr(orchestrator, "_stop_stream_verify", None)
        if callable(stop_sv):
            try:
                await stop_sv(wait_pending=True)
            except Exception as _sv_err:
                logger.debug("[VERIFY] 收尾 stream-verify 失败（继续走传统 verify）: %s", _sv_err)
        await orchestrator._verify_all_findings()

        verified_findings = list(orchestrator.findings)
        await context.update(_ctx_key(prefix, 'verified_findings'), verified_findings)
        logger.info(f"✅ [VERIFY] 完成: {len(verified_findings)} 个验证后发现")
    except Exception as e:
        logger.error(f"❌ [VERIFY] 失败: {e}")
        raise

    return {'verified_count': len(verified_findings)}


async def execute_exploit_node(node: DAGNode, context: DAGContext) -> Dict:
    """执行利用节点：调用 SafeExploit.auto_exploit"""
    prefix = node.params.get('prefix', '')
    logger.info("💥 [EXPLOIT] 开始利用")

    from vulnclaw.core.exploit_verify import SafeExploit

    verified_findings = await context.get(_ctx_key(prefix, 'verified_findings'), [])
    session = await context.get(_ctx_key(prefix, 'session'))

    if not verified_findings:
        logger.info("ℹ️ [EXPLOIT] 无漏洞可利用")
        return {'exploited_count': 0}

    exploited = []
    for vuln in verified_findings[:10]:
        try:
            result = await SafeExploit.auto_exploit(vuln, session)
            if result.get('exploitable'):
                exploited.append({**vuln, 'exploit_result': result})
        except Exception as e:
            logger.debug(f"[EXPLOIT] 单个漏洞验证失败: {e}")

    await context.update(_ctx_key(prefix, 'exploited_findings'), exploited)
    logger.info(f"✅ [EXPLOIT] 完成: {len(exploited)} 个成功利用")

    return {'exploited_count': len(exploited)}


async def execute_report_node(node: DAGNode, context: DAGContext) -> Dict:
    """执行报告节点：调用 _generate_report"""
    prefix = node.params.get('prefix', '')
    logger.info("📄 [REPORT] 生成报告")

    orchestrator = await context.get(_ctx_key(prefix, 'orchestrator'))
    if not orchestrator:
        raise ValueError("Orchestrator not found in context")

    try:
        report = await orchestrator._generate_report()
        await context.set(_ctx_key(prefix, 'report'), report)
        logger.info("✅ [REPORT] 完成")
        return report
    except Exception as e:
        logger.error(f"❌ [REPORT] 失败: {e}")
        raise


async def execute_subgraph_node(node: DAGNode, context: DAGContext) -> Dict:
    """执行子图节点：动态展开子图"""
    logger.info(f"🔄 [SUBGRAPH] 动态展开: {node.node_id}")
    return {'subgraph_id': node.node_id, 'status': 'expanded'}


async def execute_code_scan_node(node: DAGNode, context: DAGContext) -> Dict:
    """Sprint 2: 代码扫描节点。

    流程：clone repo → Semgrep + CodeQL 并行扫描 → AI 审计 → 依赖扫描 → 结果写入 context。

    node.params 支持：
        - repo_url: str     Git 仓库 URL（可选，默认从 target URL 推导）
        - language: str     扫描语言（python/javascript/java/go）
        - semgrep_rules: str  自定义 Semgrep 规则集
        - enable_ai: bool   是否启用 AI 审计（默认 True）
        - enable_deps: bool 是否启用依赖扫描（默认 True）
    """
    import time as _time
    start = _time.time()
    target = node.target
    params = node.params or {}
    repo_url = params.get("repo_url", "")
    language = params.get("language", "python")
    semgrep_rules = params.get("semgrep_rules")
    enable_ai = params.get("enable_ai", True)
    enable_deps = params.get("enable_deps", True)

    logger.info(f"🔬 [CODE_SCAN] 开始代码扫描: {target} (lang={language})")

    # 1. Clone 仓库
    from vulnclaw.code.repo_manager import get_repo_manager
    repo_mgr = get_repo_manager()
    if repo_url:
        repo_path = await repo_mgr.clone_repo(repo_url)
    else:
        repo_path = target  # 假设 target 已是本地路径

    # 2. 并行执行 Semgrep + CodeQL
    from vulnclaw.code.engines.semgrep_adapter import SemgrepAdapter
    from vulnclaw.code.engines.codeql_adapter import CodeQLAdapter

    semgrep = SemgrepAdapter()
    codeql = CodeQLAdapter(language=language)

    semgrep_task = asyncio.create_task(semgrep.scan(repo_path, rules=semgrep_rules))
    codeql_task = asyncio.create_task(codeql.scan(repo_path))

    semgrep_results, codeql_results = await asyncio.gather(
        semgrep_task, codeql_task, return_exceptions=True
    )

    # 处理异常结果
    all_findings = []
    if isinstance(semgrep_results, list):
        all_findings.extend(semgrep_results)
    elif isinstance(semgrep_results, Exception):
        logger.warning(f"⚠️ [CODE_SCAN] Semgrep 异常: {semgrep_results}")
    if isinstance(codeql_results, list):
        all_findings.extend(codeql_results)
    elif isinstance(codeql_results, Exception):
        logger.warning(f"⚠️ [CODE_SCAN] CodeQL 异常: {codeql_results}")

    logger.info(f"📊 [CODE_SCAN] 原始发现: {len(all_findings)} (Semgrep + CodeQL)")

    # 3. AI 审计（过滤误报 + 生成修复建议）
    diffs = []
    if enable_ai and all_findings:
        from vulnclaw.code.ai_auditor import AIAuditor
        auditor = AIAuditor(batch_size=5)
        all_findings, diffs = await auditor.audit_findings(all_findings)
        stats = auditor.get_stats()
        logger.info(f"🤖 [CODE_SCAN] AI 审计: {stats}")

    # 4. 依赖扫描
    dep_findings = []
    if enable_deps:
        from vulnclaw.code.dependency_scanner import DependencyScanner
        dep_scanner = DependencyScanner()
        dep_findings = await dep_scanner.audit_dependencies(repo_path)

    # 5. 合并结果
    total_findings = all_findings + dep_findings
    elapsed = _time.time() - start

    result = {
        "status": "success",
        "findings": total_findings,
        "diffs": diffs,
        "stats": {
            "semgrep_count": len(semgrep_results) if isinstance(semgrep_results, list) else 0,
            "codeql_count": len(codeql_results) if isinstance(codeql_results, list) else 0,
            "dep_count": len(dep_findings),
            "ai_filtered": len(all_findings),
            "total": len(total_findings),
            "elapsed": round(elapsed, 2),
        },
    }

    # 写入 context（DAGContext.update 为协程方法，必须 await）
    await context.update("code_scan_findings", total_findings)
    await context.update("code_scan_diffs", diffs)
    await context.update("code_scan_stats", result["stats"])

    logger.info(f"✅ [CODE_SCAN] 完成: {len(total_findings)} 个漏洞, {len(diffs)} 个修复建议, {elapsed:.1f}s")
    return result


async def execute_deep_exploit_node(node: DAGNode, context: DAGContext) -> Dict:
    """Sprint 3: 深度利用节点。

    接收已确认漏洞列表，编排利用链（SQLi/LFI/RCE/XSS），
    生成 POC 或执行实际利用（--dangerous 模式）。

    node.params 支持：
        - dangerous: bool       是否实际执行利用（默认 False，仅生成 POC）
        - max_chains: int       最大利用链数量（默认 10）
        - findings_key: str     从 context 读取漏洞列表的 key（默认 "verified_findings"）
    """
    import time as _time
    start = _time.time()
    params = node.params or {}
    dangerous = params.get("dangerous", False)
    max_chains = params.get("max_chains", 10)
    findings_key = params.get("findings_key", "verified_findings")
    prefix = params.get("prefix", "")

    logger.info(f"⛓️ [EXPLOIT_DEEP] 深度利用开始: dangerous={dangerous} max={max_chains}")

    # 1. 从 context 读取已确认漏洞（DAGContext.get/update 为协程方法，必须 await）
    findings = await context.get(findings_key, [])
    if not findings:
        # 尝试从 verify 阶段结果读取
        findings = await context.get(_ctx_key(prefix, "verify_results"), [])
    if not findings:
        findings = await context.get(_ctx_key(prefix, "findings"), [])

    if not findings:
        logger.warning("⚠️ [EXPLOIT_DEEP] 无已确认漏洞，跳过")
        return {"status": "skipped", "reason": "no findings", "results": []}

    # 2. 执行利用链
    from vulnclaw.deepsec.exploit_chain import ExploitChain

    chain = ExploitChain(
        target=node.target,
        session=await context.get(_ctx_key(prefix, "session")),
        dangerous=dangerous,
        max_chains=max_chains,
    )

    results = await chain.execute(findings)
    audit_log = chain.get_audit_log()

    elapsed = _time.time() - start

    result = {
        "status": "success",
        "results": results,
        "audit_log": audit_log,
        "stats": {
            "total_findings": len(findings),
            "exploited": len([r for r in results if r.get("success")]),
            "failed": len([r for r in results if not r.get("success")]),
            "elapsed": round(elapsed, 2),
            "dangerous_mode": dangerous,
        },
    }

    # 写入 context
    await context.update(_ctx_key(prefix, "deep_exploit_results"), results)
    await context.update(_ctx_key(prefix, "deep_exploit_audit"), audit_log)
    await context.update(_ctx_key(prefix, "deep_exploit_stats"), result["stats"])

    logger.info(
        f"✅ [EXPLOIT_DEEP] 完成: {len(results)} 个利用链 "
        f"({result['stats']['exploited']} 成功), {elapsed:.1f}s"
    )
    return result


NODE_EXECUTORS = {
    NodeType.RECON: execute_recon_node,
    NodeType.RECON_SUB: execute_recon_sub_node,
    NodeType.RECON_ALIVE: execute_recon_alive_node,
    NodeType.RECON_NUCLEI: execute_recon_nuclei_node,
    NodeType.RECON_JS: execute_recon_js_node,
    NodeType.RECON_PORT: execute_recon_port_node,
    NodeType.RECON_FFUF: execute_recon_ffuf_node,
    NodeType.ATTACK: execute_attack_node,
    NodeType.VERIFY: execute_verify_node,
    NodeType.EXPLOIT: execute_exploit_node,
    NodeType.REPORT: execute_report_node,
    NodeType.SUBGRAPH: execute_subgraph_node,
    NodeType.CODE_SCAN: execute_code_scan_node,  # Sprint 2
    NodeType.EXPLOIT_DEEP: execute_deep_exploit_node,  # Sprint 3
}


async def execute_node(node: DAGNode, context: DAGContext) -> Any:
    """通用节点执行入口"""
    executor = NODE_EXECUTORS.get(node.node_type)
    if not executor:
        raise ValueError(f"Unknown node type: {node.node_type}")
    return await executor(node, context)


# ========== P1-3: 死信队列（DLQ） ==========
def dead_letter_dir() -> str:
    """死信队列目录：项目根/_runtime_cache/dag_dead_letter"""
    from vulnclaw.paths import PROJECT_ROOT
    d = os.path.join(str(PROJECT_ROOT), "_runtime_cache", "dag_dead_letter")
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass
    return d


def write_dead_letter(scan_id: str, record: Dict[str, Any]) -> str:
    """P1-3: 把重试超限的失败节点写入死信队列 jsonl；返回文件路径。"""
    import json as _json
    path = os.path.join(dead_letter_dir(), f"{scan_id or 'default'}.jsonl")
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(_json.dumps(record, ensure_ascii=False, default=str) + "\n")
        logger.error(f"💀 [DLQ] 死信已入队: {path}")
    except Exception as e:
        logger.warning(f"💀 [DLQ] 写入死信失败: {e}")
    return path


def read_dead_letter(scan_id: str) -> List[Dict[str, Any]]:
    """P1-3: 读取死信队列（resume 重放用），按写入顺序返回。"""
    import json as _json
    path = os.path.join(dead_letter_dir(), f"{scan_id or 'default'}.jsonl")
    records: List[Dict[str, Any]] = []
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            records.append(_json.loads(line))
                        except Exception:
                            continue
        except Exception as e:
            logger.warning(f"💀 [DLQ] 读取死信失败: {e}")
    return records