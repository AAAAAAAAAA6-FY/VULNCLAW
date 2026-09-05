# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""统一 CLI 入口 - VULNCLAW v103

子命令：vulnclaw scan / code / health / bandit-report / bandit-train
兼容：不带子命令时按旧 scan.py 参数风格转发（python scan.py --health 等）。
"""
from __future__ import annotations

import argparse
import sys

import vulnclaw.bootstrap  # noqa: F401  环境固化
from vulnclaw.paths import PROJECT_ROOT  # noqa: F401  确保路径锚定加载

def _run_scan_main(argv: list[str]) -> None:
    """以旧参数风格执行 scan_main（保留原 argparse 全量行为）。"""
    sys.argv = [str(PROJECT_ROOT / "scan.py")] + argv
    import vulnclaw.scan_main as _sm
    _sm.main()

def _write_client_config(client: str, config: dict) -> int:
    """把配置合并写入客户端配置文件（先备份 .bak，不覆盖已配置的其它 server）。"""
    import json
    import os
    import shutil
    from pathlib import Path

    if client == "cursor":
        path = Path.home() / ".cursor" / "mcp.json"
    elif client == "claude-desktop":
        if sys.platform == "win32":
            base = Path(os.environ.get("APPDATA") or Path.home())
            path = base / "Claude" / "claude_desktop_config.json"
        else:
            path = Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    else:
        print("# generic 客户端没有固定配置文件路径，请手动粘贴上面的片段。")
        return 0

    path.parent.mkdir(parents=True, exist_ok=True)
    merged: dict = {}
    if path.is_file():
        backup = path.with_name(path.name + ".bak")
        shutil.copyfile(path, backup)
        print(f"# 已备份原配置: {backup}")
        try:
            merged = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            print("# 原配置无法解析为 JSON，将写入全新配置（原文件已备份）")
            merged = {}

    servers = merged.get("mcpServers") or {}
    servers.update(config.get("mcpServers") or {})
    merged["mcpServers"] = servers
    path.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")

    # 收紧权限：配置里可能含明文 token，POSIX 下只允许本人读写
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
            print("# 已收紧文件权限: 600（仅本人可读写）")
        except Exception:
            pass

    print(f"# 已写入: {path}")
    return 0


def _run_mcp(args) -> int:
    """MCP 子命令分发：serve / http / token / install"""
    import asyncio
    import json

    from vulnclaw.core.mcp_server import (
        MCP_CLIENT_PROFILES,
        build_mcp_client_config,
        generate_mcp_token,
        run_mcp_http,
    )

    action = getattr(args, "mcp_command", "")

    if action == "token":
        print(generate_mcp_token())
        return 0

    if action == "serve":
        from vulnclaw.core.mcp_server import main as _mcp_main

        _mcp_main()
        return 0

    if action == "http":
        token = getattr(args, "token", None)
        if not token and getattr(args, "token_file", None):
            try:
                from pathlib import Path

                token = Path(args.token_file).read_text(encoding="utf-8").strip()
            except Exception as exc:
                print(f"读取 token 文件失败: {exc}")
                return 1

        if token and getattr(args, "token", None):
            print("# 安全提示：--token 直接传参会出现在系统进程列表里（同机其他用户 ps 可见）。")
            print("#   更安全的做法：vulnclaw mcp token > token.txt，然后用 --token-file ./token.txt")

        try:
            asyncio.run(
                run_mcp_http(
                    host=args.host,
                    port=args.port,
                    token=token,
                    allow_ips=getattr(args, "allow_ip", None),
                    trust_proxy=getattr(args, "trust_proxy", False),
                )
            )
        except ValueError as exc:
            print(f"拒绝启动: {exc}")
            return 1
        except KeyboardInterrupt:
            print("\nMCP HTTP Server 已停止")
        return 0

    if action == "banlist":
        from vulnclaw.core.mcp_server import BanList

        banlist = BanList()
        if getattr(args, "all", False):
            count = banlist.clear()
            print(f"已清空封禁表，共解除 {count} 个 IP")
            return 0
        if getattr(args, "unban", None):
            ok = banlist.unban(args.unban)
            print(f"{'已解封' if ok else '封禁表中没有这个 IP'}: {args.unban}")
            return 0
        print(json.dumps(banlist.snapshot(), ensure_ascii=False, indent=2))
        return 0

    if action == "install":
        try:
            config = build_mcp_client_config(
                client=args.client,
                mode=args.mode,
                cwd=str(PROJECT_ROOT),
                http_url=getattr(args, "http_url", None),
                token=getattr(args, "token", None),
            )
        except ValueError as exc:
            print(f"生成配置失败: {exc}")
            return 1

        # 打印时脱敏：http 模式携带真实 token 时不把它打到屏幕或重定向日志里
        printed = json.loads(json.dumps(config))
        printed_entry = printed.get("mcpServers", {}).get("vulnclaw", {})
        auth_value = (printed_entry.get("headers") or {}).get("Authorization", "")
        if auth_value.startswith("Bearer ") and getattr(args, "token", None):
            printed_entry["headers"]["Authorization"] = "Bearer ***（已隐藏，真实值来自你的 --token）"

        print(json.dumps(printed, ensure_ascii=False, indent=2))
        profile = MCP_CLIENT_PROFILES[args.client]
        print()
        print(f"# 客户端: {profile['label']}")
        print(f"# 配置文件: {profile['config_path']}")
        if getattr(args, "token", None):
            print("# ⚠️ 该配置含明文 token：别把配置文件提交进 Git，也别贴到聊天/工单里。")
        if getattr(args, "write", False):
            # 写入用原始 config（含真实 token），否则客户端连不上
            return _write_client_config(args.client, config)
        print("# （仅打印）加 --write 可自动写入：会先备份为 .bak，再合并进已有配置。")
        return 0

    return 1


def _run_tools(args) -> int:
    """tools 子命令分发：status / verify / audit"""
    import json

    from vulnclaw.core.tool_governance import get_governance

    gov = get_governance()
    action = getattr(args, "tools_command", "status")
    if action == "verify":
        results = gov.verify_all()
        print(json.dumps(results, ensure_ascii=False, indent=2))
        bad = [r for r in results
               if r.get("status") not in ("ok", "absent", "unpinned", "unavailable")]
        return 2 if bad else 0
    if action == "audit":
        print(json.dumps(gov.audit_snapshot(), ensure_ascii=False, indent=2))
        return 0
    print(json.dumps(gov.status_snapshot(), ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)

    # 无参数 / -h / --help：显示子命令帮助（直接走子命令 parser，不转发）
    if not argv or argv[0] in ("-h", "--help"):
        argv = ["--help"]
    elif argv[0] == "resume":
        # P1-3: python scan.py resume --scan-id xxx -> 转发为 --resume --scan-id xxx
        _run_scan_main(["--resume", *argv[1:]])
        return
    elif argv[0] not in ("scan", "code", "health", "mcp", "setup", "verify", "tools", "bandit-report", "bandit-train"):
        # 兼容模式：非子命令 -> 旧 scan.py 风格直接转发（保留全量旧参数行为）
        _run_scan_main(argv)
        return

    parser = argparse.ArgumentParser(
        prog="vulnclaw",
        description="VULNCLAW - AI 驱动的渗透测试平台 v103\n\n支持扫描、代码审计、健康检查、安装四大子命令。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="使用示例:\n  python scan.py setup --download-thirdparty   # 首次使用先跑这个（下载 nuclei/ffuf/...）\n  python scan.py scan -t https://example.com\n  python scan.py code --repo ./myproject\n  python scan.py health",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="启动扫描任务",
        description="启动 VULNCLAW 扫描任务，支持多种扫描模式和高级选项。",
        epilog="示例:\n  vulnclaw scan -t https://example.com\n  vulnclaw scan -t https://example.com --deep --dangerous\n  vulnclaw scan -t https://example.com --dag --agents 5",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_parser.add_argument("-t", "--target", required=True, help="目标 URL（必填）")
    scan_parser.add_argument(
        "--initial-qps",
        type=int,
        default=3,
        help="初始 QPS（每秒请求数），默认 3。扫描器会根据响应动态调整。",
    )
    scan_parser.add_argument(
        "--max-tasks",
        type=int,
        default=200,
        help="最大并发任务数，默认 200。增大可提升速度但增加目标负载。",
    )
    scan_parser.add_argument(
        "--dag",
        action="store_true",
        help="启用 DAG 调度模式：侦察→攻击→验证→利用→报告，多 Agent 并行执行。",
    )
    scan_parser.add_argument(
        "--agents",
        type=int,
        default=3,
        help="DAG 模式下的并行 Agent 数量，默认 3。建议 3~10。",
    )
    scan_parser.add_argument(
        "--deep",
        action="store_true",
        help="启用深度侦察：子域名/存活/JS/端口/目录全量收集，耗时较长但覆盖更全面。",
    )
    scan_parser.add_argument(
        "--agent-coordinator",
        action="store_true",
        help="启用多智能体协调器：recon/analysis/exploit/verify 并发深扫 + 共享黑板知识融合（Tier-1 确定性引擎）。",
    )
    scan_parser.add_argument(
        "--dangerous",
        action="store_true",
        help="危险模式：实际执行漏洞利用（默认仅生成 POC 报告，不实际攻击）。",
    )
    scan_parser.add_argument(
        "--resume-scan",
        dest="resume_scan",
        action="store_true",
        help="P5-1: 从 SQLite 断点恢复扫描（kill -9 后续跑，跳过已完成阶段）。",
    )
    scan_parser.add_argument(
        "--diff",
        action="store_true",
        help="E3.2: 增量扫描——只测相对上次目标画像的变化面（复用 A3.2 画像，无基线自动全量建立）。",
    )
    scan_parser.add_argument(
        "--proxy",
        help="HTTP/HTTPS 代理地址，例如 http://127.0.0.1:8080 （用于通过 Burp 等工具转发流量）。",
    )
    scan_parser.add_argument(
        "--metrics-port",
        type=int,
        default=0,
        help="启动 Prometheus 指标服务器端口，0=禁用（默认）。用于监控扫描性能。",
    )
    scan_parser.add_argument(
        "--http2",
        action="store_true",
        help="启用 HTTP/2 多路复用（需目标支持，默认关闭）。可减少连接开销。",
    )
    scan_parser.add_argument(
        "--download-thirdparty",
        action="store_true",
        help="扫描前自动补齐缺失的第三方二进制工具（nuclei/ffuf/subfinder/interactsh-client/...）。"
             "等价于先执行  python scan.py setup --download-thirdparty。",
    )
    scan_parser.add_argument(
        "--force-download-thirdparty",
        action="store_true",
        help="扫描前强制重新下载所有第三方工具（对齐版本），含 nuclei 模板更新。",
    )

    setup_parser = subparsers.add_parser(
        "setup",
        help="初始化 / 下载第三方工具",
        description="下载 VULNCLAW 所需的第三方二进制工具到 thirdparty/ 目录。"
                    "首次 clone 后强烈建议先跑  python scan.py setup --download-thirdparty。",
        epilog="示例:\n"
               "  python scan.py setup --download-thirdparty           只补缺失项（推荐，最快）\n"
               "  python scan.py setup --download-thirdparty --force   强制重下（版本对齐/损坏修复）\n"
               "  python scan.py setup --download-thirdparty --no-templates   不自动更新 nuclei 模板",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    setup_parser.add_argument(
        "--download-thirdparty",
        action="store_true",
        help="下载/补齐 thirdparty/ 下的二进制工具（nuclei/ffuf/subfinder/httpx/interactsh-client/assetfinder/trivy）",
    )
    setup_parser.add_argument(
        "--force",
        action="store_true",
        help="强制重新下载（即使文件已存在也重下），用于修复损坏或版本升级",
    )
    setup_parser.add_argument(
        "--no-templates",
        action="store_true",
        help="下载完成后不自动跑 nuclei -update-templates（默认自动更新）",
    )

    code_parser = subparsers.add_parser(
        "code",
        help="代码审计",
        description="对代码仓库进行安全审计，支持多种语言和扫描深度。",
        epilog="示例:\n  vulnclaw code --repo ./myproject\n  vulnclaw code --repo ./myproject --lang java",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    code_parser.add_argument("--repo", required=True, help="代码仓库路径（本地目录或 Git URL）")
    code_parser.add_argument(
        "--lang",
        default="python",
        help="代码语言，默认 python。支持: python, java, javascript, go, php, csharp, ruby。",
    )

    subparsers.add_parser(
        "health",
        help="健康检查",
        description="检查 VULNCLAW 环境健康状态：依赖、工具、配置等。",
    )

    mcp_parser = subparsers.add_parser(
        "mcp",
        help="MCP 服务器（对外 AI 接口）",
        description="启动 MCP 服务器，或生成 AI 客户端配置，让 Cursor / Claude Desktop 等直接调用扫描器。",
        epilog="示例:\n"
               "  vulnclaw mcp serve                      以 stdio 模式启动（本机 AI 客户端用这个）\n"
               "  vulnclaw mcp http                       以 HTTP 模式启动（默认只听 127.0.0.1，外网连不进来）\n"
               "  vulnclaw mcp http --host 0.0.0.0 --token-file ./token.txt   对外开放（强制 token）\n"
               "  vulnclaw mcp token                      生成一个强随机 token\n"
               "  vulnclaw mcp install --client cursor    生成 Cursor 配置\n"
               "  vulnclaw mcp install --client cursor --write   直接写入（自动备份+合并）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mcp_sub = mcp_parser.add_subparsers(dest="mcp_command", required=True)

    mcp_sub.add_parser(
        "serve",
        help="stdio 模式启动（默认方式，供本机 AI 客户端调用）",
        description="以 stdio（stdin/stdout）传输 JSON-RPC，供装在本机的 AI 客户端调用。",
    )

    http_parser = mcp_sub.add_parser(
        "http",
        help="HTTP 模式启动（默认只听 127.0.0.1）",
        description="以 HTTP 传输 JSON-RPC。默认只监听本机（外网物理不可达，无需鉴权）；\n"
                    "一旦指定非本机地址（如 0.0.0.0），必须提供 token，否则拒绝启动。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    http_parser.add_argument("--host", default="127.0.0.1", help="监听地址，默认 127.0.0.1（仅本机）")
    http_parser.add_argument("--port", type=int, default=8765, help="监听端口，默认 8765；填 0 则由系统分配随机端口")
    http_parser.add_argument("--token", help="鉴权 token；监听非本机地址时必填（会出现在进程列表，建议改用 --token-file）")
    http_parser.add_argument("--token-file", help="从文件读取 token（推荐：不进 shell 历史与进程列表）")
    http_parser.add_argument(
        "--allow-ip", action="append", default=None, metavar="CIDR",
        help="IP 白名单，可重复指定（如 --allow-ip 203.0.113.5 --allow-ip 10.0.0.0/8）；不指定则不限制",
    )
    http_parser.add_argument(
        "--trust-proxy", action="store_true",
        help="信任 X-Forwarded-For 头（仅在 HTTPS 反向代理之后才开；否则任何人都能伪造来源 IP）",
    )

    mcp_sub.add_parser(
        "token",
        help="生成一个强随机 token（32 字节 URL-safe）",
        description="生成用于 HTTP 模式鉴权的强随机 token。",
    )

    ban_parser = mcp_sub.add_parser(
        "banlist",
        help="查看/管理入侵检测封禁表",
        description="显示被入侵检测器封禁的 IP；可解封单个 IP 或清空整表（把自己锁死时的自救手段）。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n  vulnclaw mcp banlist\n  vulnclaw mcp banlist --unban 203.0.113.5\n  vulnclaw mcp banlist --all",
    )
    ban_parser.add_argument("--unban", metavar="IP", help="解封指定 IP")
    ban_parser.add_argument("--all", action="store_true", help="清空整个封禁表")

    install_parser = mcp_sub.add_parser(
        "install",
        help="生成 AI 客户端配置",
        description="生成 MCP 客户端配置。默认只打印（手动粘贴）；加 --write 才写入，且会先备份再合并。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    install_parser.add_argument(
        "--client", default="generic", choices=["cursor", "claude-desktop", "generic"],
        help="目标客户端，默认 generic",
    )
    install_parser.add_argument(
        "--mode", default="stdio", choices=["stdio", "http"],
        help="连接方式：stdio=本机进程调用（默认），http=远程连接",
    )
    install_parser.add_argument("--http-url", help="http 模式下的服务地址，如 http://127.0.0.1:8765/mcp")
    install_parser.add_argument("--token", help="http 模式下的鉴权 token")
    install_parser.add_argument("--write", action="store_true", help="直接写入客户端配置文件（先备份 .bak 再合并）")

    verify_parser = subparsers.add_parser(
        "verify",
        help="验证网关：对任意扫描器输出（SARIF/JSON）做去伪存真",
        description="Verification Gateway：消费 Strix / Burp / nuclei / xray 等任意扫描器的输出，\n"
                    "执行 去重合并 → 证据分诊 → 本地规则 → [可选]LLM 粗筛 → [可选]HTTP 重放探测 的验证链，\n"
                    "输出 verified SARIF + 防篡改审计凭证链（hash chain + 可选 HMAC）。",
        epilog="示例:\n"
               "  vulnclaw verify --input strix-output.sarif\n"
               "  vulnclaw verify --input burp.json --probe          # 附加 HTTP 重放探测\n"
               "  vulnclaw verify --input n.sarif --use-llm --receipt-key $RC_KEY\n"
               "  vulnclaw verify --input x.sarif --verify-only      # 只做收据审计校验\n"
               "  DANGEROUS_ALLOW=blind_repro vulnclaw verify --input x.sarif --blind-repro\n"
               "  DANGEROUS_ALLOW=blind_repro vulnclaw verify --input x.sarif --blind-repro"
               " --blind-sandbox  # 隔离环境复现",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verify_parser.add_argument(
        "--input", required=True,
        help="输入文件：SARIF 2.1（含 runs/results）或 findings JSON（数组或 {\"findings\": [...]}）",
    )
    verify_parser.add_argument(
        "--output", default="",
        help="verified SARIF 输出路径（默认 <input>.verified.sarif）",
    )
    verify_parser.add_argument(
        "--receipt", default="",
        help="审计凭证链输出路径（默认 <output>.receipt.json）",
    )
    verify_parser.add_argument(
        "--receipt-key", default="",
        help="可选 HMAC 密钥：给凭证链加防伪造签名（同密钥 --verify-only 可验真）",
    )
    verify_parser.add_argument(
        "--probe", action="store_true",
        help="启用 HTTP 重放探测（基线 vs 载荷；默认关：零外呼，CI 安全）",
    )
    verify_parser.add_argument(
        "--use-llm", action="store_true",
        help="启用 LLM 粗筛（filter 档；默认关；失败自动跳过不阻断）",
    )
    verify_parser.add_argument(
        "--blind-repro", action="store_true",
        help="启用盲复现闸门：不看发现者推理/载荷，独立重打目标，打不中不进 verified 台账"
             "（需 danger 放行：--dangerous 或 DANGEROUS_ALLOW=blind_repro）",
    )
    verify_parser.add_argument(
        "--blind-sandbox", action="store_true",
        help="盲复现在隔离进程/容器内执行（docker 优先、不可用降级进程隔离）",
    )
    verify_parser.add_argument(
        "--blind-max", type=int, default=40,
        help="单轮盲复现目标上限（默认 40，超出标记 skipped 不惩罚）",
    )
    verify_parser.add_argument(
        "--source", default="",
        help="标注输入来源（strix/burp/nuclei/...）；SARIF 自动读取 tool 名",
    )
    verify_parser.add_argument(
        "--verify-only", action="store_true",
        help="跳过验证，只对 --input（verified SARIF）+ 凭证链做审计校验",
    )

    tools_parser = subparsers.add_parser(
        "tools",
        help="工具治理：目录/健康/完整性/调用审计",
        description="平台第六层能力：受管工具目录（版本钉定）+ 供应链完整性（SHA256 抽检/隔离）"
                    "+ 健康降级（坏工具自动绕过）+ 全量调用审计（tool_usage.jsonl + 治理事件哈希链）。",
        epilog="示例:\n  vulnclaw tools status\n  vulnclaw tools verify\n  vulnclaw tools audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    tools_sub = tools_parser.add_subparsers(dest="tools_command", required=True)
    tools_sub.add_parser(
        "status",
        help="目录总览：每个工具的可用性/健康/完整性状态",
    )
    tools_sub.add_parser(
        "verify",
        help="强制全量 SHA256 完整性校验（不符即隔离并入审计链）",
    )
    tools_sub.add_parser(
        "audit",
        help="查看调用审计尾部 + 健康状态 + 治理事件链根",
    )

    bandit_report_parser = subparsers.add_parser(
        "bandit-report",
        help="RL 反馈飞轮：聚合 bandit_feedback.jsonl 为统计报表",
        description="读取 ContextualBandit 落盘的 JSONL 反馈样本，输出聚合报表（JSON + 文本）。",
        epilog="示例:\n  vulnclaw bandit-report --feed bandit_feedback.jsonl --out report.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    bandit_report_parser.add_argument("--feed", required=True, help="bandit_feedback.jsonl 路径")
    bandit_report_parser.add_argument("--out", default="", help="可选：JSON 报表输出路径（默认 stdout）")

    bandit_train_parser = subparsers.add_parser(
        "bandit-train",
        help="RL 反馈飞轮：用反馈样本训练轻量决策策略",
        description="基于真实 JSONL 样本训练决策策略（输出 bandit_policy.json）。",
        epilog="示例:\n  vulnclaw bandit-train --feed bandit_feedback.jsonl --out bandit_policy.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    bandit_train_parser.add_argument("--feed", required=True, help="bandit_feedback.jsonl 路径")
    bandit_train_parser.add_argument("--out", default="bandit_policy.json", help="策略输出路径（默认当前目录 bandit_policy.json）")

    args = parser.parse_args(argv)

    if args.command == "scan":
        fwd = ["-t", args.target,
               "--initial-qps", str(args.initial_qps),
               "--max-tasks", str(args.max_tasks)]
        if args.dag:
            fwd += ["--dag", "--agents", str(args.agents)]
        if args.deep:
            fwd += ["--deep"]
        if getattr(args, "agent_coordinator", False):
            fwd += ["--agent-coordinator"]
        if args.dangerous:
            fwd += ["--dangerous"]
        if getattr(args, "resume_scan", False):
            fwd += ["--resume-scan"]
        if getattr(args, "diff", False):
            fwd += ["--diff"]
        if args.proxy:
            fwd += ["--proxy", args.proxy]
        if args.metrics_port:
            fwd += ["--metrics-port", str(args.metrics_port)]
        if args.http2:
            fwd += ["--http2"]
        # 扫描前自动下载工具（按需 / 强制）
        if getattr(args, "download_thirdparty", False) or getattr(args, "force_download_thirdparty", False):
            from vulnclaw.core.utils import download_thirdparty_tools
            only_missing = not getattr(args, "force_download_thirdparty", False)
            ok, fail = download_thirdparty_tools(only_missing=only_missing, update_nuclei_templates=True)
            if fail > 0 and not only_missing:
                # 强制模式下仍有失败，阻断扫描
                print(f"❌ 强制下载仍有 {fail} 项失败，终止扫描。可单独重试  python scan.py setup --download-thirdparty --force")
                sys.exit(2)
        _run_scan_main(fwd)
    elif args.command == "setup":
        if not getattr(args, "download_thirdparty", False):
            print("# 没指定操作。用法示例：")
            print("   python scan.py setup --download-thirdparty            只补缺失项（推荐）")
            print("   python scan.py setup --download-thirdparty --force    强制重下")
            print("   python scan.py setup --download-thirdparty --no-templates   下载工具但跳过 nuclei 模板同步")
            sys.exit(1)
        from vulnclaw.core.utils import download_thirdparty_tools
        only_missing = not getattr(args, "force", False)
        update_tpl = not getattr(args, "no_templates", False)
        _ok, _fail = download_thirdparty_tools(only_missing=only_missing, update_nuclei_templates=update_tpl)
        sys.exit(0 if _fail == 0 else 3)
    elif args.command == "code":
        _run_scan_main(["--code", "--repo", args.repo, "--lang", args.lang])
    elif args.command == "health":
        _run_scan_main(["--health"])
    elif args.command == "mcp":
        sys.exit(_run_mcp(args))
    elif args.command == "verify":
        import asyncio
        import json

        from vulnclaw.core.verification_gateway import run_gateway, verify_gateway_output

        if args.verify_only:
            result = verify_gateway_output(
                output_path=args.input,
                receipt_path=args.receipt or "",
                secret=args.receipt_key or "",
            )
            print(json.dumps(result, ensure_ascii=False, indent=2))
            sys.exit(0 if result.get("ok") else 2)
        result = asyncio.run(run_gateway(
            input_path=args.input,
            output_path=args.output or "",
            receipt_path=args.receipt or "",
            probe=bool(args.probe),
            use_llm=bool(args.use_llm),
            source=args.source or "",
            receipt_key=args.receipt_key or "",
            blind_repro=bool(getattr(args, "blind_repro", False)),
            blind_sandbox=bool(getattr(args, "blind_sandbox", False)),
            blind_max=int(getattr(args, "blind_max", 40) or 40),
        ))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        sys.exit(0 if result.get("ok") else 2)
    elif args.command == "tools":
        sys.exit(_run_tools(args))
    elif args.command == "bandit-report":
        from vulnclaw.ai.v100 import bandit_report
        sys.exit(bandit_report.main(["--feed", args.feed, "--out", args.out]) or 0)
    elif args.command == "bandit-train":
        from vulnclaw.ai.v100 import bandit_train
        sys.exit(bandit_train.main(["--feed", args.feed, "--out", args.out]) or 0)
