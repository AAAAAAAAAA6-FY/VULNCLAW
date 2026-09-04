# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""扫描主流程 runner（R2 拆分自 scan_main.py）。

包含 main_async 主扫描逻辑及其专属辅助函数：
- Cookie 获取链路（_get_cookie_file_path / _try_default_login / _try_browser_cookies /
  _try_burp_cookies / _manual_cookie_input / auto_fetch_cookie / extract_target_cookies）
- 启动前环境检查 check_environment
- 扫描入口 main_async
"""

import datetime
import json
import os
import re
import sys
import time
import traceback
from pathlib import Path
from urllib.parse import urlparse

from vulnclaw.ai.core import close_llm_client
from vulnclaw.ai.v100 import run_v100_scan
from vulnclaw.config import PROJECT_CACHE_DIR, settings
from vulnclaw.core.logger import logger
from vulnclaw.core.utils import close_shared_session, get_shared_session
from vulnclaw.runners.code_audit_runner import run_code_audit
from vulnclaw.core.detectors.spa_detector import SpaFingerprintDetector

COOKIE_DIR = Path(PROJECT_CACHE_DIR) / "cookies"
REPORT_DIR = Path(PROJECT_CACHE_DIR) / "reports"

def check_environment():



    """启动前环境检查"""



    print("🔍 检查环..")







    # 检Nuclei 模板



    try:



        template_dir = settings.nuclei_template_dir



        if os.path.exists(template_dir):



            print(f"   Nuclei 模板目录: {template_dir}")



        else:



            print(f"   ⚠️ Nuclei 模板目录不存 {template_dir}")



            print("      运行 'nuclei -update-templates' 下载")



    except Exception as e:



        print(f"   ⚠️ 无法检Nuclei 模板: {e}")







    # 检查运行时目录



    for directory in [REPORT_DIR, Path(PROJECT_CACHE_DIR) / "logs", Path(PROJECT_CACHE_DIR) / "tmp"]:



        directory.mkdir(parents=True, exist_ok=True)



    print("   目录结构已创")








    # 检AI 模型配置



    try:



        from vulnclaw.ai.core import get_llm_client



        client = get_llm_client()



        if client.models:



            print(f"   AI 模型已配 {len(client.models)} ")




        else:



            print("   ⚠️ 未配AI 模型，请检.env")



    except Exception as e:



        print(f"   ⚠️ AI 配置检查失 {e}")







    print("")

def _get_cookie_file_path(domain: str) -> Path:



    """获取目标专属Cookie 文件路径"""



    COOKIE_DIR.mkdir(parents=True, exist_ok=True)



    return COOKIE_DIR / f"{domain}.json"

async def _try_default_login(target_url: str, domain: str) -> bool:



    """尝试使用默认凭证登录目标"""



    try:



        from vulnclaw.modules.vuln_scanner import check_default_credentials



        print(f"🔐 尝试使用默认凭证登录 {target_url}...")



        session = await get_shared_session(target=target_url)



        results = await check_default_credentials(



            target_url,



            session,



            tech_stack=[],



            timeout=10,



            max_attempts=10



        )



        if results:



            print(f"默认凭证登录成功！发{len(results)} 个有效凭")



            # Cookie 写入文件



            cookie_file = _get_cookie_file_path(domain)



            try:



                cookies = session.cookie_jar.filter_cookies(urlparse(target_url))



                cookie_dict = {k: v.value for k, v in cookies.items()}



                if cookie_dict:



                    existing = {}



                    if cookie_file.exists():



                        try:



                            with open(cookie_file, 'r', encoding='utf-8') as f:



                                existing = json.load(f)



                        except BaseException:



                            pass



                    existing[domain] = cookie_dict



                    with open(cookie_file, 'w', encoding='utf-8') as f:



                        json.dump(existing, f, indent=2, ensure_ascii=False)



                    print(f"Cookie 已保存到 {cookie_file}")



                    return True



            except Exception as e:



                print(f"⚠️ 保存 Cookie 失败: {e}")



            return True



        return False



    except Exception as e:



        print(f"⚠️ 自动登录失败: {e}")



        return False

async def _try_browser_cookies(domain: str) -> bool:



    """尝试从浏览器导入 Cookie"""



    try:



        from vulnclaw.core.browser_cookie import get_browser_cookies



        print(f"🍪 尝试从浏览器读取 {domain} Cookie...")



        cookies = get_browser_cookies(domain)



        if cookies:



            cookie_file = _get_cookie_file_path(domain)



            existing = {}



            if cookie_file.exists():



                try:



                    with open(cookie_file, 'r', encoding='utf-8') as f:



                        existing = json.load(f)



                except BaseException:



                    pass



            existing[domain] = cookies



            with open(cookie_file, 'w', encoding='utf-8') as f:



                json.dump(existing, f, indent=2, ensure_ascii=False)



            print(f"从浏览器读取{len(cookies)} Cookie（已保存{cookie_file}")



            return True



        else:



            print(f"⚠️ 未从浏览器找{domain} Cookie")



            return False



    except Exception as e:



        print(f"⚠️ 读取浏览Cookie 失败: {e}")



        return False

async def _try_burp_cookies(domain: str) -> bool:



    """尝试Burp 插件文件导入 Cookie"""



    burp_file = os.path.expanduser("~/burp_cookies.json")



    if not os.path.exists(burp_file):



        return False







    try:



        with open(burp_file, 'r', encoding='utf-8') as f:



            all_cookies = json.load(f)







        filtered = {}



        for cookie_domain, cookies in all_cookies.items():



            clean_domain = cookie_domain.lstrip('.')



            if clean_domain == domain or clean_domain.endswith('.' + domain):



                filtered[cookie_domain] = cookies







        if filtered:



            cookie_file = _get_cookie_file_path(domain)



            existing = {}



            if cookie_file.exists():



                try:



                    with open(cookie_file, 'r', encoding='utf-8') as f:



                        existing = json.load(f)



                except BaseException:



                    pass



            existing.update(filtered)



            with open(cookie_file, 'w', encoding='utf-8') as f:



                json.dump(existing, f, indent=2, ensure_ascii=False)



            print(f"Burp 文件提取{len(filtered)} 个匹{domain} Cookie（已保存")



            return True



        return False



    except json.JSONDecodeError:



        print("⚠️ Burp Cookie 文件损坏，跳")



        return False



    except Exception as e:



        print(f"⚠️ 读取 Burp Cookie 失败: {e}")



        return False

async def _manual_cookie_input(domain: str) -> bool:



    """手动输入 Cookie - 修复：写入文件供 get_shared_session 读取"""



    # 非交互环境（后台运行/CI/输出重定向）下跳过手动输入，避免 EOFError



    if not sys.stdin.isatty():



        print("ℹ️ 非交互环境（stdin 非终端），跳过手Cookie 输入")



        return False







    print("\n" + "=" * 60)



    print("🍪 请手动输Cookie（从浏览器开发者工具复制）")



    print("=" * 60)



    print("格式：name1=value1; name2=value2; ...")



    print("或直接粘贴完整的 Cookie 字符")



    print("（输入空行取消）")



    print()







    # 双重保护：即使 isatty() 为真，后台/无输入流环境仍可能 EOF
    try:
        cookie_str = input("Cookie: ").strip()
    except (EOFError, OSError):
        print("ℹ️ 无可用输入流，跳过手动 Cookie 输入")
        return False



    if not cookie_str:



        print("已取")



        return False







    cookies = {}



    for part in cookie_str.split(';'):



        part = part.strip()



        if '=' in part:



            key, value = part.split('=', 1)



            cookies[key.strip()] = value.strip()







    if not cookies:



        print("无法解析 Cookie，请检查格")



        return False







    # 修复：写入文件，get_shared_session 读取



    cookie_file = _get_cookie_file_path(domain)



    try:



        existing = {}



        if cookie_file.exists():



            try:



                with open(cookie_file, 'r', encoding='utf-8') as f:



                    existing = json.load(f)



            except BaseException:



                pass







        existing[domain] = cookies



        with open(cookie_file, 'w', encoding='utf-8') as f:



            json.dump(existing, f, indent=2, ensure_ascii=False)



        print(f"已保{len(cookies)} Cookie {cookie_file}")



        return True



    except Exception as e:



        print(f"保存 Cookie 失败: {e}")



        return False

async def auto_fetch_cookie(target_url: str, domain: str) -> bool:



    """自动获取 Cookie（增强版 修复：写入文件）"""



    print(f"\n🍪 正在获取 {domain} Cookie...")







    # 1. 尝试 Burp 文件



    print("   [1/4] 尝试Burp 文件导入...")



    if await _try_burp_cookies(domain):



        return True







    # 2. 尝试浏览



    print("   [2/4] 尝试从浏览器导入...")



    if await _try_browser_cookies(domain):



        return True







    # 3. 尝试默认凭证登录



    print("   [3/4] 尝试默认凭证登录...")



    if await _try_default_login(target_url, domain):



        return True







    # 4. 提示手动输入



    print("   [4/4] 请手动输Cookie...")



    return await _manual_cookie_input(domain)

async def extract_target_cookies(target_url: str):



    """



    从各种来源提取目Cookie（修复：写入文件



    """







    parsed = urlparse(target_url)



    host = parsed.hostname



    if not host:



        return



    if host.startswith('www.'):



        host = host[4:]







    target_file = _get_cookie_file_path(host)

    # 目标专属文件不存在时回退到父域名文件（app.box.com -> box.com.json）
    if not target_file.exists():
        parts = host.split(".")
        for _i in range(1, len(parts)):
            parent = ".".join(parts[_i:])
            candidate = _get_cookie_file_path(parent)
            if candidate.exists():
                target_file = candidate
                print(f"📂 使用父域名 Cookie 文件: {candidate}")
                break


    old_file = os.path.expanduser("~/burp_cookies.json")







    # 如果已有 Cookie 文件，直接加载（不更新）



    if target_file.exists():



        try:



            mtime = target_file.stat().st_mtime



            if time.time() - mtime < 7 * 24 * 3600:



                print(f"ℹ️ Cookie 文件已存在: {target_file}")



                return



            else:



                print("ℹ️ Cookie 文件已过期（超过7天），但不重新写入，将仅使用内存中的 Cookie")



                return



        except BaseException:



            pass







    print(f"📂 Cookie 文件不存 {target_file}")







    # 如果旧文件存在，尝试加载但不分离写入



    if os.path.exists(old_file):



        try:



            with open(old_file, 'r', encoding='utf-8') as f:



                all_cookies = json.load(f)



            filtered = {}



            for domain, cookies in all_cookies.items():



                clean_domain = domain.lstrip('.')



                if clean_domain == host or clean_domain.endswith('.' + host):



                    filtered[domain] = cookies



            if filtered:



                # 写入新文



                with open(target_file, 'w', encoding='utf-8') as f:



                    json.dump(filtered, f, indent=2, ensure_ascii=False)



                print(f"🧹 已从旧文件提{host} Cookie（{len(filtered)} 个域名）")



                return



        except json.JSONDecodeError:



            print("⚠️ Cookie ")




        except Exception as e:



            print(f"⚠️ 提取Cookie 失败: {e}")







    # 尝试自动获取



    success = await auto_fetch_cookie(target_url, host)



    if success:



        print("Cookie 获取成功（已保存到文件）")



    else:



        print("⚠️ Cookie 获取失败，扫描将使用无认证模")

async def main_async(args):

    # P0-5: --metrics-port 启动 Prometheus 指标服务器
    metrics_port = getattr(args, 'metrics_port', 0) or getattr(settings, 'metrics_port', 0)
    if metrics_port:
        try:
            from vulnclaw.core_modules.metrics import start_metrics_server
            start_metrics_server(int(metrics_port))
        except Exception as e:
            logger.warning(f"⚠️ 指标服务器启动失败: {e}")

    # P0-1: --http2 启用 HTTP/2（httpx 后端，默认关闭）
    if getattr(args, 'http2', False):
        settings.http2 = True

    target = args.target

    # P3-4: 启动时代理池健康检查（探测 proxy_list 并剔除坏代理）
    try:
        from vulnclaw.core.proxy_pool import init_proxy_pool
        await init_proxy_pool()
    except Exception as exc:
        logger.warning(f"⚠️ 代理池初始化跳过: {exc}")

    # P4-4: 启动 SQLMap API 守护进程（sqlmapapi），失败则自动回退 CLI 模式
    try:
        from vulnclaw.deepsec.sqlmap_wrapper import ensure_sqlmap_api
        await ensure_sqlmap_api()
    except Exception as exc:
        logger.debug(f"SQLMap API 守护进程未启动: {exc}")







    if args.target_list and not target:



        target = "(multi-target)"







    if not target:



        print("缺少目标，请使用 -t -l 指定")



        return







    # 环境检



    check_environment()







    # 修复：Cookie 获取（写入文件）



    if args.target:

        await extract_target_cookies(target)







    print("=" * 70)



    print("🧠 v100 限流感知- 渗透测试系(完整功能")



    print("=" * 70)



    print(f"目标: {target}")



    print(f"最大任 {args.max_tasks}")



    print(f"初始QPS: {args.initial_qps}")



    print(f"认证模式: {'已认证' if not args.no_auth else '未认证'}")



    if args.auth_mode:



        print(f"认证模式: {args.auth_mode}")



    print("")



    print("组件:")



    print("   ⏱️ 自适应限流 - 避免429，动态调整QPS")



    print("   📦 智能批处理器  - 合并任务，减少API调用")



    print("   🔍 本地预筛选器  - 0成本规则检查，减少80%调用")



    print("   📋 智能任务队列  - 按优先级调度")



    print("   ⚔️ 28个检测引 - 全部保留")



    print("   🌐 完整信息收集  - 子域存活/Nuclei/JS/端口/目录爆破")



    print("")



    if args.proxy:



        print(f"代理: {args.proxy}")



    print("=" * 70)



    print()







    # 会话管理



    if args.dag and args.target_list:



        session = None



    elif args.code is not False and args.code is not None:



        return await run_code_audit(args)



    elif args.no_auth:



        print("🔒 使用未认证模式（跳过 Cookie 加载")



        session = await get_shared_session(target=target)



        session.cookie_jar.clear()



    else:



        session = await get_shared_session(target=target)







    report = None



    error_info = None







    try:



        if args.dag:



            from vulnclaw.dag.scheduler import DAGScheduler



            from vulnclaw.dag.graph import DAG, DAGNode, NodeType



            from vulnclaw.dag.context import DAGContext



            from vulnclaw.dag.executor import _ctx_key







            targets = []



            if args.target_list:



                try:



                    with open(args.target_list, 'r', encoding='utf-8') as f:



                        targets = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]



                except Exception as e:



                    print(f"读取目标列表失败: {e}")



                    return



            if args.target:



                targets.append(args.target)







            if not targets:



                print("无有效目")



                return







            logger.info(f"🔀 使用 DAG 调度模式 (Agent={args.agents}, 目标{len(targets)})")







            dag = DAG()



            context = DAGContext()







            for idx, tgt in enumerate(targets):



                prefix = f"t{idx}" if len(targets) > 1 else ""



                # (P0-4 移除的无效 re.sub 死代码行)



                domain = urlparse(tgt).netloc







                if len(targets) > 1:
                    # P0-4: 多目标 → 共享"批量子域名收集"节点（subfinder -dL + 跨目标限并发）
                    if idx == 0:
                        batch_sub_node = DAGNode(
                            node_id="batch_recon_sub",
                            node_type=NodeType.RECON_SUB,
                            name="批量子域名收集",
                            target=",".join(targets),
                            params={
                                'targets': [(f"t{i}", urlparse(t).netloc) for i, t in enumerate(targets)],
                                'prefix': '',
                            },
                        )
                        dag.add_node(batch_sub_node)
                    recon_sub_id = "batch_recon_sub"
                    recon_sub = None
                else:
                    recon_sub_id = f"{prefix}recon_sub"
                    recon_sub = DAGNode(
                        node_id=recon_sub_id,
                        node_type=NodeType.RECON_SUB,
                        name="子域名收",
                        target=tgt,
                        params={'domain': domain, 'prefix': prefix},
                    )



                recon_alive = DAGNode(



                    node_id=f"{prefix}recon_alive",



                    node_type=NodeType.RECON_ALIVE,



                    name="存活探测",



                    target=tgt,



                    params={'prefix': prefix},



                    depends_on=[recon_sub_id]



                )



                recon_nuclei = DAGNode(



                    node_id=f"{prefix}recon_nuclei",



                    node_type=NodeType.RECON_NUCLEI,



                    name="Nuclei扫描",



                    target=tgt,



                    params={'prefix': prefix}



                )



                recon_js = DAGNode(



                    node_id=f"{prefix}recon_js",



                    node_type=NodeType.RECON_JS,



                    name="JS分析",



                    target=tgt,



                    params={'prefix': prefix}



                )



                recon_port = DAGNode(



                    node_id=f"{prefix}recon_port",



                    node_type=NodeType.RECON_PORT,



                    name="端口扫描",



                    target=tgt,



                    params={'domain': domain, 'prefix': prefix}



                )



                recon_ffuf = DAGNode(



                    node_id=f"{prefix}recon_ffuf",



                    node_type=NodeType.RECON_FFUF,



                    name="目录爆破",



                    target=tgt,



                    params={'prefix': prefix}



                )



                attack_node = DAGNode(



                    node_id=f"{prefix}attack",



                    node_type=NodeType.ATTACK,



                    name="攻击",



                    target=tgt,



                    params={'prefix': prefix, 'max_tasks': args.max_tasks, 'initial_qps': args.initial_qps},



                    depends_on=[



                        recon_sub_id, f"{prefix}recon_alive",



                        f"{prefix}recon_nuclei", f"{prefix}recon_js",



                        f"{prefix}recon_port", f"{prefix}recon_ffuf"



                    ]



                )



                verify_node = DAGNode(



                    node_id=f"{prefix}verify",



                    node_type=NodeType.VERIFY,



                    name="验证",



                    target=tgt,



                    params={'prefix': prefix},



                    depends_on=[f"{prefix}attack"]



                )



                exploit_node = DAGNode(



                    node_id=f"{prefix}exploit",



                    node_type=NodeType.EXPLOIT,



                    name="利用",



                    target=tgt,



                    params={'prefix': prefix},



                    depends_on=[f"{prefix}verify"]



                )







                # Sprint 3: --deep 时在 exploit 之后追加深度利用链节



                deep_node = None



                if args.deep:



                    deep_node = DAGNode(



                        node_id=f"{prefix}exploit_deep",



                        node_type=NodeType.EXPLOIT_DEEP,



                        name="深度利用",



                        target=tgt,



                        params={



                            'prefix': prefix,



                            'dangerous': args.dangerous,



                            'findings_key': _ctx_key(prefix, 'verified_findings'),



                        },



                        depends_on=[f"{prefix}exploit"]



                    )







                report_node = DAGNode(



                    node_id=f"{prefix}report",



                    node_type=NodeType.REPORT,



                    name="报告",



                    target=tgt,



                    params={'prefix': prefix},



                    depends_on=[f"{prefix}exploit_deep" if deep_node else f"{prefix}exploit"]



                )







                if recon_sub is not None:
                    dag.add_node(recon_sub)
                for n in [recon_alive, recon_nuclei, recon_js,



                          recon_port, recon_ffuf, attack_node, verify_node,



                          exploit_node, report_node]:



                    dag.add_node(n)



                if deep_node is not None:



                    dag.add_node(deep_node)







                dag.add_edge(recon_sub_id, f"{prefix}recon_alive")



                for recon_id in [recon_sub_id, f"{prefix}recon_alive",



                                 f"{prefix}recon_nuclei", f"{prefix}recon_js",



                                 f"{prefix}recon_port", f"{prefix}recon_ffuf"]:



                    dag.add_edge(recon_id, f"{prefix}attack")



                dag.add_edge(f"{prefix}attack", f"{prefix}verify")



                dag.add_edge(f"{prefix}verify", f"{prefix}exploit")



                if deep_node is not None:



                    dag.add_edge(f"{prefix}exploit", f"{prefix}exploit_deep")



                    dag.add_edge(f"{prefix}exploit_deep", f"{prefix}report")



                else:



                    dag.add_edge(f"{prefix}exploit", f"{prefix}report")







            scheduler = DAGScheduler(
                dag, max_concurrent=args.agents, context=context,
                scan_id=f"scan_{time.strftime('%Y%m%d_%H%M%S')}",
            )







            from vulnclaw.dag.executor import NODE_EXECUTORS



            for nt, exec_fn in NODE_EXECUTORS.items():



                scheduler.register_executor(nt, exec_fn)







            results = await scheduler.run()







            if len(targets) == 1:



                prefix = ""



                report = await context.get(_ctx_key(prefix, 'report'), {})



            else:



                report = {'multi_target': True, 'targets': []}



                for idx, tgt in enumerate(targets):



                    prefix = f"t{idx}"



                    tgt_report = await context.get(_ctx_key(prefix, 'report'), {})



                    if tgt_report:



                        report['targets'].append(tgt_report)







            # DAG Scheduler 产出的画资源/并发指标合并进最终报告，便于离线复盘



            # （单JSON 报告中直接即可得最3 节点 / 并发峰/ 资源限额"）



            if isinstance(results, dict) and "dag_profile" in results:



                report["dag_profile"] = results["dag_profile"]



                # 结果摘要里同步一Top3 慢节点视图，避免扫描结束时再全量 grep 日志



                nodes = results["dag_profile"].get("nodes") or {}



                ranked = sorted(



                    (



                        (nid, info.get("duration_ms") or 0, info.get("type"), info.get("status"))



                        for nid, info in nodes.items()



                    ),



                    key=lambda x: x[1],



                    reverse=True,



                )[:3]



                report["dag_profile"]["slowest_3_nodes"] = [



                    {



                        "node_id": nid,



                        "duration_ms": dur,



                        "type": typ,



                        "status": st,



                    }



                    for nid, dur, typ, st in ranked



                ]



                # 总耗时兜底：非 dag 异常report.elapsed_seconds 取的是报告内部字段，



                # 这里DAG 级总耗时再镜像一份到根字段，保证 summary 打印一致



                if "elapsed_seconds" in results["dag_profile"] and not report.get("elapsed_seconds"):



                    report["elapsed_seconds"] = results["dag_profile"]["elapsed_seconds"]







            if not report:



                report = {"target": str(targets), "error": "DAG 执行未生成报告", "vulnerabilities": []}



        else:



            report = await run_v100_scan(



                target=target,



                session=session,



                max_tasks=args.max_tasks,



                initial_qps=args.initial_qps,

                resume=getattr(args, "resume_scan", False),



            )



            # Sprint 3: DAG 模式的深度利用链-deep 时对扫描发现执行



            if args.deep and isinstance(report, dict) and report.get('vulnerabilities'):



                try:



                    from vulnclaw.deepsec.exploit_chain import ExploitChain



                    chain = ExploitChain(



                        target=target,



                        session=session,



                        dangerous=args.dangerous,



                    )



                    deep_results = await chain.execute(report['vulnerabilities'])



                    report['deep_exploit_results'] = deep_results



                    report['deep_exploit_stats'] = {



                        'total_findings': len(report['vulnerabilities']),



                        'exploited': len([r for r in deep_results if r.get('success')]),



                        'dangerous_mode': args.dangerous,



                    }



                    logger.info(



                        f"⛓️ [EXPLOIT_DEEP] DAG 模式完成: {len(deep_results)} 条链"



                    )



                except Exception as deep_err:



                    logger.warning(f"⚠️ [EXPLOIT_DEEP] 深度利用失败（不影响扫描报告 {deep_err}")



    except KeyboardInterrupt:



        print("\n⚠️ 用户中断")



        error_info = "用户中断"



        return



    except Exception as e:



        print(f"\n扫描异常: {e}")



        traceback.print_exc()



        error_info = str(e)



        report = {



            "target": target,



            "error": error_info,



            "scan_time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),



            "vulnerabilities": [],



            "severity_stats": {},



            "elapsed_seconds": 0



        }



    finally:



        # P4-4: 停止 SQLMap API 守护进程（sqlmapapi）
        try:
            from vulnclaw.deepsec.sqlmap_wrapper import stop_sqlmap_api
            await stop_sqlmap_api()
        except Exception as exc:
            logger.debug(f"SQLMap API 守护进程停止异常: {exc}")

        if session is not None:



            await close_shared_session()



        # 关闭全局 AI 客户端，释放aiohttp 会话



        try:



            await close_llm_client()



        except Exception:



            pass







    # 保存 JSON 报告



    safe_target = re.sub(r'[^a-zA-Z0-9]', '_', target)



    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')



    REPORT_DIR.mkdir(parents=True, exist_ok=True)



    json_path = REPORT_DIR / f"report_{safe_target}_{timestamp}.json"



    with open(json_path, 'w', encoding='utf-8') as f:



        json.dump(report, f, indent=2, ensure_ascii=False, default=str)



    print(f"📄 JSON报告: {json_path}")







    # 生成 HTML 报告



    try:



        from vulnclaw.core.report_generator import generate_html_report



        html_path = json_path.with_suffix('.html')



        success = generate_html_report(report, html_path)



        if success:



            print(f"📄 HTML报告: {html_path}")



        else:



            print("⚠️ HTML报告生成失败")



    except Exception as e:



        print(f"⚠️ HTML报告生成异常: {e}")

    # P4-1: SARIF 2.1.0 输出（CI/DevSecOps 消费；异常绝不影响主报告）
    try:
        from vulnclaw.core.report_generator import generate_sarif
        sarif_path = json_path.with_suffix('.sarif')
        generate_sarif(report, str(sarif_path))
        print(f"📄 SARIF报告: {sarif_path}")
    except Exception as e:
        print(f"⚠️ SARIF报告生成异常（忽略）: {e}")

    # P4-2: 机器事实覆盖账本 coverage.json（审计口径：检查了什么/谁被跳过失败）
    try:
        from vulnclaw.core.coverage import get_coverage_ledger
        from vulnclaw.core.scanner import get_all_engines
        _fullset = [getattr(e, "name", type(e).__name__) for e in get_all_engines()]
        _ledger = get_coverage_ledger(target=str(report.get("target", "")))
        _cov_path = json_path.parent / "coverage.json"
        _ledger.write(out_path=str(_cov_path), engine_fullset=_fullset, complete=True)
        print(f"📄 覆盖账本: {_cov_path}")
    except Exception as e:
        print(f"⚠️ 覆盖账本落盘异常（忽略）: {e}")







    print("\n" + "=" * 70)



    print("📊 扫描结果")



    print("=" * 70)



    if error_info:



        print(f"⚠️ 异常: {error_info}")



    else:



        vuln_count = len(report.get('vulnerabilities', []))



        summary = report.get('summary', {})



        report.get('performance', {})







        print(f"   ⏱️ 耗时: {report.get('elapsed_seconds', 0)} ")




        print(f"   📋 任务: {report.get('processed_tasks', 0)} ")




        print(f"   🔧 引擎调用: {report.get('total_engine_calls', 0)} ")




        print(f"   🔴 漏洞: {vuln_count} ")




        print("")



        print("   严重性分")



        print(f"      Critical: {summary.get('critical', 0)}")



        print(f"      High:     {summary.get('high', 0)}")



        print(f"      Medium:   {summary.get('medium', 0)}")



        print(f"      Low:      {summary.get('low', 0)}")



        print(f"      Info:     {summary.get('info', 0)}")







        if vuln_count > 0:



            print("")



            print("   漏洞列表 (0:")



            for i, v in enumerate(report.get('vulnerabilities', [])[:10], 1):



                vtype = v.get('type', '未知')



                sev = str(v.get('severity', 'Low')).strip().capitalize()
                if sev not in ('Critical', 'High', 'Medium', 'Low', 'Info'):
                    sev = 'Low'



                param = v.get('parameter', '')



                print(f"      {i}. [{sev}] {vtype} (参数: {param})")







    print("=" * 70)



    print("完成")



    print("=" * 70)
