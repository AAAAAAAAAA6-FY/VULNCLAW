# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

#!/usr/bin/env python3
# ruff: noqa: F401
# R2 拆分后本文件为兼容存根：保留历史 import 区 + argparse + main()，
# 实际实现已迁移至 vulnclaw.runners.*_runner，未使用的 import 由转发层承担。



"""



v100 限流感知- 入口（最终修复版 v3.0



修复



1. .env 配置解析失败时捕获异常，友好提示并退



2. 增加 --auth --no-auth 模式，控制认证状



3. 启动时环境检查（Nuclei模板、关键目录）



4. 增强 Cookie 获取的错误处



5. 修复：手动输Cookie 写入文件，供 get_shared_session 读取



6. 修复：临时文件统一存于 _runtime_cache/（Cookie、调试等



"""







import os



import sys







# ============================================================



# 一、全局字节码缓存禁止（优先级最高）



# ============================================================



# 说明：必须放在任import 之前；光sys.dont_write_bytecode 不够 —



#   因为 `python -m py_compile scan.py` scan.py 被作为模import



#   CPython 在执scan.py 1 行代*之前**就会.pyc



#   关键：父进程调用 scan.py 之前必须PYTHONDONTWRITEBYTECODE=1 环境变量



#   这里是对 "scan.py 直接被外python 调用" 的场景兜底



os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")



os.environ.setdefault("PYTHONPYCACHEPREFIX", "")







# ============================================================



# 二、禁止外部工具写 HOME 目录垃圾到项目根（Nuclei / uncover



# ============================================================



# 根目录反复出现的 `.config/nuclei/`、`.config/uncover/` 来自 nuclei-cli



#   nuclei Windows 下如`%HOME%` 没设会把 `$PWD` home



#   导致$PWD/.config/...。把 nuclei/uncover 的配置和运行目录



#   全部重定向到 _runtime_cache/tools/ 下



from vulnclaw.paths import PROJECT_ROOT as _PROJECT_ROOT_DIR  # noqa: E402

_PROJECT_ROOT = str(_PROJECT_ROOT_DIR)



_RUNTIME_TOOLS = os.path.join(_PROJECT_ROOT, "_runtime_cache", "tools")



for _d in (_RUNTIME_TOOLS,



          os.path.join(_RUNTIME_TOOLS, "nuclei"),



          os.path.join(_RUNTIME_TOOLS, "uncover")):



    try:



        os.makedirs(_d, exist_ok=True)



    except Exception:



        pass



os.environ["HOME"] = _RUNTIME_TOOLS



os.environ["USERPROFILE"] = _RUNTIME_TOOLS



os.environ["NUCLEI_CONFIG_DIR"] = os.path.join(_RUNTIME_TOOLS, "nuclei")



os.environ["UNCOVER_CONFIG_DIR"] = os.path.join(_RUNTIME_TOOLS, "uncover")



os.environ["GITHUB_ACTIONS_FORCE_COLORS"] = "0"







# ============================================================



# 三、stdout/stderr UTF-8 强制（Windows PowerShell 乱码修复



# ============================================================



sys.dont_write_bytecode = True



if sys.platform.startswith("win"):



    import io as _io



    for _name in ("stdout", "stderr"):



        _stream = getattr(sys, _name)



        try:



            if hasattr(_stream, "reconfigure"):



                _stream.reconfigure(encoding="utf-8", errors="replace")



                continue



        except Exception:



            pass



        if hasattr(_stream, "buffer"):



            try:



                setattr(sys, _name,



                        _io.TextIOWrapper(_stream.buffer, encoding="utf-8",



                                          errors="replace", line_buffering=True))



            except Exception:



                pass



    os.environ.setdefault("TQDM_DISABLE", "1")



    os.environ.setdefault("FORCE_COLOR", "0")







# 释放临时变量（注意：绝不del os/sys，scan.py 后面大量 os.xxx



del _RUNTIME_TOOLS, _d, _name, _stream







import asyncio



import argparse



import datetime



import json



import re



import time



import traceback



from pathlib import Path



from urllib.parse import urlparse







from dotenv import load_dotenv



load_dotenv()







# 捕获 settings 导入异常，防.env 损坏导致启动崩溃



try:



    from vulnclaw.core.logger import logger



    from vulnclaw.config import settings, PROJECT_CACHE_DIR  # 修改：导PROJECT_CACHE_DIR



    from vulnclaw.core.utils import get_shared_session, close_shared_session



    from vulnclaw.ai.v100 import run_v100_scan



    from vulnclaw.ai.core import close_llm_client



except Exception as e:



    print("=" * 70)



    print("启动失败：配置加载异")



    print("=" * 70)



    print(f"错误信息: {e}")



    print("")



    print("可能的原")



    print("  1. .env 文件中的 JSON 配置有语法错误（如多余的逗号")



    print("  2. 缺少必要的环境变")



    print("  3. pydantic 配置验证失败")



    print("")



    print("修复建议:")



    print("  1. 检.env 文件中的 AI_MODEL_CONFIGS AI_MODELS 配置")



    print("  2. 确保 JSON 格式正确（没有尾部逗号")



    print("  3. 或删.env 文件使用默认配置")



    print("  4. 运行 tools_menu.py 重新配置")



    print("=" * 70)



    sys.exit(1)







# ============================================================



# Cookie 分离工具 - 修复：统一存于 _runtime_cache/cookies/



# ============================================================



COOKIE_DIR = Path(PROJECT_CACHE_DIR) / "cookies"



REPORT_DIR = Path(PROJECT_CACHE_DIR) / "reports"












from vulnclaw.runners.scan_runner import (  # noqa: F401
    main_async,
    check_environment,
    _get_cookie_file_path,
)
from vulnclaw.runners.health_runner import run_health_check  # noqa: F401
from vulnclaw.runners.code_audit_runner import run_code_audit  # noqa: F401
from vulnclaw.runners.distributed_runner import (  # noqa: F401
    run_distributed_master,
    run_distributed_scan,
    run_distributed_worker,
)

def run_resume(scan_id: str) -> int:
    """P1-3: 从死信队列重放失败节点（python scan.py resume --scan-id xxx）。

    读取 _runtime_cache/dag_dead_letter/{scan_id}.jsonl，逐条重建节点并调用
    dag.executor 对应执行器。依赖前序上下文的节点（attack/verify/report）
    会因 context 为空而失败，此类任务需在完整 DAG 上下文中重跑。
    """
    import asyncio as _asyncio
    from vulnclaw.core.logger import logger as _logger
    from vulnclaw.dag.context import DAGContext
    from vulnclaw.dag.executor import NODE_EXECUTORS, read_dead_letter
    from vulnclaw.dag.graph import DAGNode, NodeType

    records = read_dead_letter(scan_id)
    if not records:
        _logger.info(f"💀 [RESUME] 死信队列为空或不存在: {scan_id}")
        return 0

    _logger.info(f"💀 [RESUME] 发现 {len(records)} 条死信任务，开始重放: {scan_id}")
    context = DAGContext()
    succeeded = failed = 0
    for rec in records:
        try:
            nt = NodeType(rec.get("node_type", ""))
            node = DAGNode(
                node_id=rec.get("node_id", f"dlq_{rec.get('ts', '')}"),
                node_type=nt,
                name=rec.get("name") or rec.get("node_id", "dlq"),
                target=rec.get("target", ""),
                params=rec.get("params") or {},
            )
            executor = NODE_EXECUTORS.get(nt)
            if executor is None:
                _logger.warning(f"💀 [RESUME] 无执行器，跳过: {nt}")
                continue
            result = _asyncio.run(executor(node, context))
            succeeded += 1
            _logger.info(f"✅ [RESUME] 重放成功: {node.node_id} → {str(result)[:120]}")
        except Exception as e:
            failed += 1
            _logger.error(f"❌ [RESUME] 重放失败: {rec.get('node_id')}: {e}")
    _logger.info(f"💀 [RESUME] 完成: {succeeded} 成功 / {failed} 失败")
    return 0


def main():



    parser = argparse.ArgumentParser(description="v100 限流感知版渗透测试系")



    parser.add_argument('-t', '--target', help='目标URL')



    parser.add_argument('--health', action='store_true', help='健康检查（工具/AI配置/模板/缓存目录）并退出')



    parser.add_argument('--max-tasks', type=int, default=200, help='最大任务数')



    parser.add_argument('--initial-qps', type=int, default=3, help='初始QPS')



    parser.add_argument('--proxy', help='HTTP代理')



    parser.add_argument('--log-level', default='INFO', help='日志级别')







    # 认证模式控制



    parser.add_argument('--no-auth', action='store_true', help='使用未认证模式（不加 Cookie）')



    parser.add_argument('--auth-mode', choices=['auth', 'no-auth'], help='认证模式')



    parser.add_argument('--cookie-file', help='手动指定 Cookie 文件路径')



    parser.add_argument('--dag', action='store_true', help='使用 DAG 调度模式')



    parser.add_argument('--agents', type=int, default=3, help='并行 Agent 数量（DAG 模式）')

    parser.add_argument('--metrics-port', type=int, default=0, help='启动 Prometheus 指标服务器端口（0=禁用）')

    parser.add_argument('--http2', action='store_true', help='启用 HTTP/2（需 httpx[http2]，默认关闭）')

    parser.add_argument('--resume', action='store_true', help='从死信队列重放任务（需 --scan-id）')
    parser.add_argument('--resume-scan', dest='resume_scan', action='store_true',
                        help='P5-1: 从 SQLite 断点恢复扫描（kill -9 后续跑，跳过已完成阶段；与上者相互独立）')

    parser.add_argument('--scan-id', default='', help='扫描 ID（resume 重放死信任务时使用）')



    parser.add_argument('-l', '--list', dest='target_list', help='从文件读取目标列表（每行一个 URL）')







    # --- Sprint 1: 插件市场 CLI ---



    parser.add_argument('--update-plugins', action='store_true', help='更新插件市场列表')



    parser.add_argument('--install', help='安装指定插件，如 --install slack_notifier')



    parser.add_argument('--list-plugins', action='store_true', help='列出已安装插件')



    parser.add_argument('--auto-install', action='store_true', help='自动安装所有官方插件')







    # --- Sprint 2: 代码扫描 ---



    parser.add_argument('--code', action='store_true', help='启用代码安全扫描（Semgrep + CodeQL + AI 审计）')



    parser.add_argument('--repo', help='指定代码仓库 URL（配合 --code 使用）')



    parser.add_argument('--lang', default='python', help='代码扫描语言（python/javascript/java/go）')







    # --- Sprint 3: 深度利用 ---



    parser.add_argument('--deep', action='store_true', help='启用深度利用链（POC 生成 + 漏洞利用）')


    parser.add_argument('--agent-coordinator', action='store_true', help='启用多智能体协调器（strix 式 agent 树：recon/analysis/exploit/verify 并发 + 共享黑板知识融合）')



    parser.add_argument('--dangerous', action='store_true', help='危险模式：实际执行利用（默认仅生成 POC）')







    # --- Sprint 4: 分布式模---



    parser.add_argument('--distributed', action='store_true', help='启用分布式模式')



    parser.add_argument('--master', action='store_true', help='Master 节点运行')



    parser.add_argument('--worker', action='store_true', help='Worker 节点运行')



    parser.add_argument('--redis-url', default='redis://localhost:6379/0', help='Redis 连接 URL')







    args = parser.parse_args()

    # --- 危险操作权限门卫：--dangerous 显式放行（默认 deny） ---
    if args.dangerous:
        from vulnclaw.core.danger_guard import guard
        guard.set_mode("allow")

    # --- S1: --deep 开启 ReAct 深挖（对本地判定模糊的参数做 LLM 多轮深度渗透） ---
    if getattr(args, "deep", False):
        try:
            settings.enable_react_dive = True
        except Exception as _de:  # noqa: BLE001
            print(f"⚠️ 启用 ReAct 深挖失败（忽略，继续扫描）: {_de}")

    # --- P2: --agent-coordinator 开启多智能体协调器（strix 式 agent 树 + 共享黑板知识融合） ---
    if getattr(args, "agent_coordinator", False):
        try:
            settings.agent_coordinator_enabled = True
        except Exception as _ace:  # noqa: BLE001
            print(f"⚠️ 启用多智能体协调器失败（忽略，继续扫描）: {_ace}")







    # 健康检查子命令：不做扫描，直接输出检查结果退



    if args.health:



        sys.exit(run_health_check())







    # --- Sprint 4: 分布式模式（Master / Worker，无需 -t 目标---



    if args.master or args.worker:



        if args.master and args.worker:



            parser.error("--master --worker 不能同时使用")



        try:



            exit_code = 0



            if args.master:



                exit_code = asyncio.run(run_distributed_master(args))



            else:



                exit_code = asyncio.run(run_distributed_worker(args))



            sys.exit(exit_code)



        except KeyboardInterrupt:



            print("\n⚠️ 用户中断")



            sys.exit(1)



        except Exception as e:



            print(f"\n分布式节点启动失 {e}")



            traceback.print_exc()



            sys.exit(1)



    if args.distributed:

        if not args.master and not args.worker and getattr(args, "target", None):
            # P3-3: 分布式提交端（带 -t 目标；小目标自动降级单机）
            exit_code = asyncio.run(run_distributed_scan(args))
            sys.exit(exit_code)

        parser.error("--distributed 需配合 --master/--worker 或 -t <target> 使用")







    # P1-3: resume 重放死信队列（不要求 -t，执行完直接退出）
    if getattr(args, 'resume', False):
        sys.exit(run_resume(getattr(args, 'scan_id', '') or ''))

    if not args.target and not args.target_list and not getattr(args, 'code', False):



        parser.error("缺少 -t/--target -l/--list（或使用 --health 只做健康检查）")







    # 如果指定Cookie 文件，复制到目标目录



    if args.cookie_file:



        parsed = urlparse(args.target)



        host = parsed.hostname



        if host:



            if host.startswith('www.'):



                host = host[4:]



            try:



                with open(args.cookie_file, 'r', encoding='utf-8') as f:



                    cookies = json.load(f)



                cookie_file = _get_cookie_file_path(host)



                existing = {}



                if cookie_file.exists():



                    try:



                        with open(cookie_file, 'r', encoding='utf-8') as f:



                            existing = json.load(f)



                    except BaseException:



                        pass



                existing.update(cookies)



                with open(cookie_file, 'w', encoding='utf-8') as f:



                    json.dump(existing, f, indent=2, ensure_ascii=False)



                print(f"已从 {args.cookie_file} 导入 Cookie {cookie_file}")



            except Exception as e:



                print(f"⚠️ 读取 Cookie 文件失败: {e}")







    if args.no_auth:



        print("🔒 使用未认证模式（--no-auth")



    elif args.auth_mode == 'no-auth':



        args.no_auth = True



        print("🔒 使用未认证模")







    if args.proxy:



        settings.proxy = args.proxy







    import logging



    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO))







    try:



        # --- Sprint 1: 插件市场 CLI 分支 ---



        if getattr(args, 'list_plugins', False):



            from vulnclaw.core.plugin_market import list_installed_plugins



            plugins = list_installed_plugins()



            if not plugins:



                print("未安装任何插")



            for p in plugins:



                print(f"  {p['name']} v{p.get('version', '')} - {p.get('path', '')}")



            sys.exit(0)







        if getattr(args, 'update_plugins', False):



            from vulnclaw.core.plugin_market import list_available_plugins



            plugins = asyncio.run(list_available_plugins())



            print(f"可用插件 ({len(plugins)} :")



            for p in plugins:



                print(f"  {p['name']} v{p['version']} - {p['description'][:60]}")



            sys.exit(0)







        if getattr(args, 'install', None):



            from vulnclaw.core.plugin_market import install_plugin



            result = asyncio.run(install_plugin(args.install))



            if result['success']:



                print(f"安装成功: {result.get('path', '')}")



            else:



                print(f"安装失败: {result.get('error', '')}")



            sys.exit(0)







        if getattr(args, 'auto_install', False):



            from vulnclaw.core.plugin_market import list_available_plugins, install_plugin



            available = asyncio.run(list_available_plugins())



            for p in available:



                print(f"安装 {p['name']}...")



                asyncio.run(install_plugin(p['name']))



            print("自动安装完成")



            sys.exit(0)







        # --- Sprint 2: 代码扫描分支 ---



        if getattr(args, 'code', False):



            sys.exit(asyncio.run(run_code_audit(args)))







        asyncio.run(main_async(args))



    except KeyboardInterrupt:



        print("\n⚠️ 用户中断")



        sys.exit(1)



    except Exception as e:



        print(f"\n启动失败: {e}")



        traceback.print_exc()



        sys.exit(1)


if __name__ == "__main__":
    main()
