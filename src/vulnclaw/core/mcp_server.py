# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT (sub-license of the VULNCLAW AGPL-3.0 project)
# Copyright (c) 2026 VULNCLAW Authors
# core/mcp_server.py: MCP protocol interface adapter — MIT, to allow any AI Agent
# platform (ZCode / Trae / Cursor / ChatGPT) to freely integrate this module
# without triggering AGPL copyleft on their own code. Rest of VULNCLAW = AGPL.

# core/mcp_server.py
"""
MCP (Model Context Protocol) 服务端适配器

实现 MCP 协议（JSON-RPC 2.0 over stdio），让外部工具（VS Code、Cursor）能调用扫描器核心能力。
通过事件队列（asyncio.Queue）与 scan_main.py / orchestrator.py 解耦通信。

协议参考：https://spec.modelcontextprotocol.io/
传输：stdio（stdin/stdout）
"""

import asyncio
import contextlib
import hmac
import ipaddress
import json
import secrets
import sys
import time
import traceback
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from aiohttp import web

from vulnclaw.config.settings import settings
from vulnclaw.core.logger import logger

MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "vulnclaw-mcp-server"
SERVER_VERSION = "0.1.0"


async def _run_quietly(coro):
    """执行期间把 stdout 重定向到 stderr。

    MCP 用 stdout 传输 JSON-RPC，被调度的子流程（尤其是代码审计的 print 进度）
    若往 stdout 输出会破坏协议帧，必须整体隔离到 stderr。
    """
    with contextlib.redirect_stdout(sys.stderr):
        return await coro


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanJob:
    scan_id: str
    target: str
    status: ScanStatus = ScanStatus.PENDING
    progress: int = 0
    total_urls: int = 0
    scanned_urls: int = 0
    findings: list = field(default_factory=list)
    error: str = ""
    created_at: float = 0.0
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    _task: Optional[asyncio.Task] = field(default=None, repr=False)


class ScanEventBus:
    """事件总线：MCP Server 与 Scan Worker 之间的解耦通信层。

    使用 asyncio.Queue 实现生产者-消费者模式：
    - MCP Server 发布 scan.start 事件
    - Scan Worker 消费事件并执行扫描
    - Worker 通过 update_scan_state 回调更新状态
    """

    def __init__(self, maxsize: int = 256):
        self._queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=maxsize)
        self._jobs: dict[str, ScanJob] = {}
        self._lock = asyncio.Lock()

    async def publish(self, event: dict) -> None:
        await self._queue.put(event)

    async def consume(self) -> dict:
        return await self._queue.get()

    async def register_job(self, job: ScanJob) -> None:
        async with self._lock:
            self._jobs[job.scan_id] = job

    async def get_job(self, scan_id: str) -> Optional[ScanJob]:
        async with self._lock:
            return self._jobs.get(scan_id)

    async def update_job(self, scan_id: str, **kwargs) -> None:
        async with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return
            for key, value in kwargs.items():
                if hasattr(job, key):
                    setattr(job, key, value)

    async def list_jobs(self) -> list[ScanJob]:
        async with self._lock:
            return list(self._jobs.values())


_event_bus: Optional[ScanEventBus] = None


def get_event_bus() -> ScanEventBus:
    global _event_bus
    if _event_bus is None:
        _event_bus = ScanEventBus()
    return _event_bus


class MCPJsonRpcHandler:
    """MCP JSON-RPC 2.0 协议处理器。

    处理 MCP 协议生命周期：
    - initialize → 握手
    - tools/list → 列出可用工具
    - tools/call → 调用工具
    """

    def __init__(self, event_bus: ScanEventBus):
        self._event_bus = event_bus
        self._initialized = False
        self._client_capabilities: dict = {}
        self._tools: dict[str, dict] = {}
        self._register_tools()

    def _register_tools(self) -> None:
        # annotations 遵循 MCP 2025-06-18 规范，告知客户端工具危险性
        self._tools = {
            "scan.start": {
                "name": "scan.start",
                "description": "启动一个新的安全扫描任务，对目标 URL 进行全面的漏洞检测",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "目标 URL（如 https://example.com）",
                        },
                        "max_tasks": {
                            "type": "integer",
                            "description": "最大并发任务数（可选，默认自动探测）",
                        },
                        "initial_qps": {
                            "type": "integer",
                            "description": "初始 QPS 限制（可选，默认自动探测）",
                        },
                    },
                    "required": ["target"],
                },
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": False,
                    "openWorldHint": False,
                },
            },
            "scan.status": {
                "name": "scan.status",
                "description": "查询指定扫描任务的进度和状态",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scan_id": {
                            "type": "string",
                            "description": "扫描任务 ID",
                        },
                    },
                    "required": ["scan_id"],
                },
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": False,
                },
            },
            "scan.findings": {
                "name": "scan.findings",
                "description": "获取指定扫描任务已发现的漏洞列表",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scan_id": {
                            "type": "string",
                            "description": "扫描任务 ID",
                        },
                    },
                    "required": ["scan_id"],
                },
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": False,
                },
            },
            "scan.api_audit": {
                "name": "scan.api_audit",
                "description": "执行 API 深度安全审计（GraphQL DoS、速率限制绕过、JWT 重放）",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "目标 URL",
                        },
                        "jwt_token": {
                            "type": "string",
                            "description": "可选的 JWT Token",
                        },
                    },
                    "required": ["target"],
                },
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": False,
                    "openWorldHint": False,
                },
            },
            "scan.danger_guard_status": {
                "name": "scan.danger_guard_status",
                "description": "查询危险操作权限门卫的当前模式、注册的危险操作清单与最近审批记录",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": False,
                },
            },
            "browser.explore": {
                "name": "browser.explore",
                "description": "启动 AI 浏览器代理自主探索目标站点，自动点击/填表/翻页，返回发现的 API 端点与操作轨迹（需已安装 playwright 与 chromium）",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "起始 URL（如 https://example.com）",
                        },
                        "headless": {
                            "type": "boolean",
                            "description": "是否无头模式（默认 true）",
                        },
                        "max_actions": {
                            "type": "integer",
                            "description": "最大交互步数（可选，默认取环境配置）",
                        },
                    },
                    "required": ["url"],
                },
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": False,
                    "openWorldHint": True,
                },
            },
            "exploit.verify": {
                "name": "exploit.verify",
                "description": "对单个漏洞做安全验证/利用确认（HTTP 重放 + OOB 回调 + SafeExploit 自动验证）。受危险操作门卫控制，默认拒绝——需 DANGEROUS_MODE=allow 或 DANGEROUS_ALLOW=exploit_verify。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "漏洞所在 URL（含参数）",
                        },
                        "parameter": {
                            "type": "string",
                            "description": "存在漏洞的参数名",
                        },
                        "type": {
                            "type": "string",
                            "description": "漏洞类型：sqli / xss / cmdi / ssrf / lfi 等",
                        },
                        "payload": {
                            "type": "string",
                            "description": "触发 payload（可选）",
                        },
                        "interactsh_domain": {
                            "type": "string",
                            "description": "外部 OOB 回调域名（可选）",
                        },
                    },
                    "required": ["url", "parameter", "type"],
                },
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": False,
                    "openWorldHint": False,
                },
            },
            "code.audit": {
                "name": "code.audit",
                "description": "代码安全审计：Semgrep + CodeQL + 依赖 CVE 扫描 + AI 复核，输出修复 diff 与 HTML 报告",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo": {
                            "type": "string",
                            "description": "本地仓库路径或 Git URL（如 https://github.com/org/repo.git）",
                        },
                        "lang": {
                            "type": "string",
                            "description": "主语言：python / javascript / java / go（默认 python）",
                        },
                    },
                    "required": ["repo"],
                },
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": False,
                    "idempotentHint": False,
                    "openWorldHint": False,
                },
            },
            "scan.deep": {
                "name": "scan.deep",
                "description": "单点深度渗透：ReAct 推理 Agent 对单个 URL 自主执行「侦察→思考→决策→执行→观察」循环，"
                               "动态调用 30 个检测工具，并带工具成功率学习与跨目标经验复用。"
                               "比 scan.start 更聚焦（只挖一个点）但更慢；适合对已知可疑接口深挖。"
                               "注意：① 慢——每轮约 20~35 秒（含 LLM 推理），默认 15 轮约 5~8 分钟，"
                               "建议先用 max_iterations=3 试探；② 返回的是 Agent 原始 finding，"
                               "severity/type 可能缺失（见返回值的 missing_severity_count）；"
                               "若需要完整的 CWE 映射、curl 复现命令与修复建议，请改用 scan.start（V100 全量扫描）。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "目标 URL（精确到单页/单接口，如 https://example.com/search?id=1）",
                        },
                        "max_iterations": {
                            "type": "integer",
                            "description": "最大推理轮数（默认 15；越大越深但越慢，建议先用 3~5 试探）",
                        },
                    },
                    "required": ["target"],
                },
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": False,
                    "openWorldHint": False,
                },
            },
            "scan.deep_remote": {
                "name": "scan.deep_remote",
                "description": "单点深度渗透（远程 Agent 模式）：把目标交给已配置的远程 AI Agent 自主执行深度渗透，"
                               "本地只转发请求与接收结果。默认关闭，需在 .env 中设置 REMOTE_DEEP_ENABLED=true；"
                               "危险操作 remote_deep_penetrate 默认 deny，需 DANGEROUS_MODE=allow 或 DANGEROUS_ALLOW=remote_deep_penetrate。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "目标 URL（精确到单页/单接口，如 https://example.com/search?id=1）",
                        },
                        "max_iterations": {
                            "type": "integer",
                            "description": "最大推理轮数（默认 10；由远程 Agent 决定实际轮数）",
                        },
                    },
                    "required": ["target"],
                },
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": False,
                    "openWorldHint": False,
                },
            },
            "intel.lookup": {
                "name": "intel.lookup",
                "description": "威胁情报查询（Shodan 优先、Censys 兜底）：开放端口、已知 CVE、产品指纹。未配置 API Key 时返回降级说明。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "域名或 IP（域名会自动解析为 IP）",
                        },
                    },
                    "required": ["target"],
                },
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": True,
                },
            },
            "engine.list": {
                "name": "engine.list",
                "description": "列出所有已注册的确定性检测引擎（vulnclaw 的规则/签名引擎），含名称、描述与能力入口（scan=目标级 / check=参数级）。供 agent 选定要调用的引擎。",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": False,
                },
            },
            "engine.run": {
                "name": "engine.run",
                "description": "运行指定确定性检测引擎（融合 strix 的 agent 可调工具思路）。engine 为引擎名（见 engine.list）；"
                               "scan 型引擎传 target，check 型引擎传 url+param。返回 findings 列表。受危险操作门卫约束。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "engine": {
                            "type": "string",
                            "description": "引擎名称（如 sqli / xss / ssrf / tls_security / api_security），见 engine.list",
                        },
                        "target": {
                            "type": "string",
                            "description": "目标 URL（scan 型引擎使用）",
                        },
                        "url": {
                            "type": "string",
                            "description": "带参数的完整 URL（check 型引擎使用，如 https://x/id=1）",
                        },
                        "param": {
                            "type": "string",
                            "description": "待检测参数名（check 型引擎使用）",
                        },
                        "jwt_token": {
                            "type": "string",
                            "description": "可选，传给支持 JWT 审计的引擎（如 api_security）",
                        },
                    },
                    "required": ["engine"],
                },
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": False,
                    "openWorldHint": False,
                },
            },
        }

    async def handle_request(self, request: dict) -> dict:
        method = request.get("method", "")
        req_id = request.get("id")
        params = request.get("params", {})

        try:
            if method == "initialize":
                result = await self._handle_initialize(params)
            elif method == "notifications/initialized":
                result = {}
            elif method == "tools/list":
                result = await self._handle_tools_list()
            elif method == "tools/call":
                result = await self._handle_tools_call(params)
            elif method == "ping":
                result = {}
            else:
                return self._error_response(req_id, -32601, f"Method not found: {method}")

            if req_id is not None:
                return self._success_response(req_id, result)
            return {}
        except Exception as exc:
            logger.error(f"MCP 请求处理异常: {exc}\n{traceback.format_exc()}")
            if req_id is not None:
                return self._error_response(req_id, -32603, str(exc))
            return {}

    async def _handle_initialize(self, params: dict) -> dict:
        self._client_capabilities = params.get("capabilities", {})
        self._initialized = True
        logger.info(f"MCP 客户端已连接，capabilities: {list(self._client_capabilities.keys())}")
        return {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": {},
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
            },
        }

    async def _handle_tools_list(self) -> dict:
        return {"tools": list(self._tools.values())}

    async def _handle_tools_call(self, params: dict) -> dict:
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        if tool_name not in self._tools:
            raise ValueError(f"Unknown tool: {tool_name}")

        if tool_name == "scan.start":
            return await self._tool_scan_start(arguments)
        elif tool_name == "scan.status":
            return await self._tool_scan_status(arguments)
        elif tool_name == "scan.findings":
            return await self._tool_scan_findings(arguments)
        elif tool_name == "scan.api_audit":
            return await self._tool_scan_api_audit(arguments)
        elif tool_name == "scan.danger_guard_status":
            return await self._tool_danger_guard_status(arguments)
        elif tool_name == "browser.explore":
            return await self._tool_browser_explore(arguments)
        elif tool_name == "exploit.verify":
            return await self._tool_exploit_verify(arguments)
        elif tool_name == "code.audit":
            return await self._tool_code_audit(arguments)
        elif tool_name == "scan.deep":
            return await self._tool_scan_deep(arguments)
        elif tool_name == "scan.deep_remote":
            return await self._tool_scan_deep_remote(arguments)
        elif tool_name == "intel.lookup":
            return await self._tool_intel_lookup(arguments)
        elif tool_name == "engine.list":
            return await self._tool_engine_list(arguments)
        elif tool_name == "engine.run":
            return await self._tool_engine_run(arguments)
        else:
            raise ValueError(f"Tool not implemented: {tool_name}")

    async def _tool_scan_start(self, args: dict) -> dict:
        target = args.get("target", "").strip()
        if not target:
            raise ValueError("target 参数不能为空")

        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        scan_id = str(uuid.uuid4())[:8]
        max_tasks = args.get("max_tasks")
        initial_qps = args.get("initial_qps")

        job = ScanJob(
            scan_id=scan_id,
            target=target,
            status=ScanStatus.PENDING,
            created_at=time.time(),
        )
        await self._event_bus.register_job(job)

        await self._event_bus.publish({
            "type": "scan.start",
            "scan_id": scan_id,
            "target": target,
            "max_tasks": max_tasks,
            "initial_qps": initial_qps,
        })

        logger.info(f"MCP 扫描任务已创建: {scan_id} → {target}")
        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "scan_id": scan_id,
                    "target": target,
                    "status": "pending",
                    "message": f"扫描任务已创建，ID: {scan_id}。使用 scan.status 查询进度。",
                }, ensure_ascii=False),
            }],
        }

    async def _tool_scan_status(self, args: dict) -> dict:
        scan_id = args.get("scan_id", "").strip()
        if not scan_id:
            raise ValueError("scan_id 参数不能为空")

        job = await self._event_bus.get_job(scan_id)
        if job is None:
            raise ValueError(f"扫描任务不存在: {scan_id}")

        elapsed = 0.0
        if job.started_at:
            elapsed = (job.completed_at or time.time()) - job.started_at

        status_info = {
            "scan_id": job.scan_id,
            "target": job.target,
            "status": job.status.value,
            "progress": job.progress,
            "total_urls": job.total_urls,
            "scanned_urls": job.scanned_urls,
            "findings_count": len(job.findings),
            "elapsed_seconds": round(elapsed, 1),
            "error": job.error or None,
        }

        return {
            "content": [{
                "type": "text",
                "text": json.dumps(status_info, ensure_ascii=False),
            }],
        }

    async def _tool_scan_findings(self, args: dict) -> dict:
        scan_id = args.get("scan_id", "").strip()
        if not scan_id:
            raise ValueError("scan_id 参数不能为空")

        job = await self._event_bus.get_job(scan_id)
        if job is None:
            raise ValueError(f"扫描任务不存在: {scan_id}")

        findings_data = {
            "scan_id": job.scan_id,
            "target": job.target,
            "status": job.status.value,
            "total_findings": len(job.findings),
            "findings": job.findings,
        }

        return {
            "content": [{
                "type": "text",
                "text": json.dumps(findings_data, ensure_ascii=False, default=str),
            }],
        }

    async def _tool_scan_api_audit(self, args: dict) -> dict:
        """执行 API 深度安全审计（GraphQL DoS、速率限制绕过、JWT 重放）"""
        target = args.get("target", "").strip()
        if not target:
            raise ValueError("target 参数不能为空")

        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        jwt_token = args.get("jwt_token")

        from vulnclaw.core.utils import get_shared_session, close_shared_session
        from vulnclaw.engines.api_security_engines import APISecurityEngine

        try:
            session = await get_shared_session(target=target)
            try:
                engine = APISecurityEngine()
                findings = await _run_quietly(engine.scan(target, session, jwt_token=jwt_token))
            finally:
                # 修复：审计结束后关闭共享会话，避免 Unclosed client session 警告
                await close_shared_session()
        except Exception as exc:
            logger.error(f"API 审计失败: {exc}\n{traceback.format_exc()}")
            raise ValueError(f"API 审计失败: {exc}")

        logger.info(f"MCP API 审计完成: {target}，发现 {len(findings)} 个问题")
        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "status": "success",
                    "target": target,
                    "findings_count": len(findings),
                    "findings": findings,
                }, ensure_ascii=False, default=str),
            }],
        }

    async def _tool_danger_guard_status(self, args: dict) -> dict:
        """查询危险操作权限门卫状态与最近审批记录。"""
        from vulnclaw.core.danger_guard import guard, DANGEROUS_OPS

        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "mode": guard.mode,
                    "ops": [{"op": k, "description": v} for k, v in DANGEROUS_OPS.items()],
                    "recent_audit": guard.get_audit(20),
                    "hint": "dangerous 操作默认被拒绝；放行方式：--dangerous 或 DANGEROUS_MODE=allow 或 DANGEROUS_ALLOW=op1,op2",
                }, ensure_ascii=False, indent=2),
            }],
        }

    async def _tool_browser_explore(self, args: dict) -> dict:
        """AI 浏览器代理自主探索目标站点。"""
        from vulnclaw.core.browser_ai_agent import BrowserAIAgent, HAS_PLAYWRIGHT

        url = (args.get("url") or "").strip()
        if not url:
            raise ValueError("url 参数不能为空")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        if not HAS_PLAYWRIGHT:
            raise ValueError("Playwright 未安装，无法使用浏览器探索；请执行 pip install playwright && playwright install chromium")

        agent = BrowserAIAgent(headless=bool(args.get("headless", True)))
        if args.get("max_actions"):
            agent.max_actions = int(args["max_actions"])

        logger.info(f"MCP 浏览器探索: {url}")
        result = await _run_quietly(agent.explore(url))

        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "url": url,
                    "total_actions": result.get("total_actions", 0),
                    "apis": result.get("all_apis", []),
                    "history": result.get("history", []),
                }, ensure_ascii=False, indent=2, default=str),
            }],
        }

    async def _tool_exploit_verify(self, args: dict) -> dict:
        """对单个漏洞做安全验证/利用确认（受危险操作门卫控制）。"""
        from vulnclaw.core.danger_guard import guard
        from vulnclaw.core.exploit_verify import safe_verify_vulnerability
        from vulnclaw.core.utils import close_shared_session, get_shared_session

        url = (args.get("url") or "").strip()
        parameter = (args.get("parameter") or "").strip()
        vuln_type = (args.get("type") or "").strip()
        if not url or not parameter or not vuln_type:
            raise ValueError("url / parameter / type 三个参数均为必填")

        vuln = {
            "url": url,
            "parameter": parameter,
            "type": vuln_type,
            "payload": args.get("payload", ""),
        }

        try:
            session = await get_shared_session(target=url)
            try:
                result = await _run_quietly(
                    safe_verify_vulnerability(vuln, session, args.get("interactsh_domain"))
                )
            finally:
                await close_shared_session()
        except Exception as exc:
            logger.error(f"MCP 利用验证失败: {exc}\n{traceback.format_exc()}")
            raise ValueError(f"利用验证失败: {exc}")

        payload = {
            "url": url,
            "parameter": parameter,
            "type": vuln_type,
            "result": result,
            "guard_mode": guard.mode,
        }
        if not result.get("exploitable"):
            payload["hint"] = (
                "未判定为可利用。若 reason 为 danger_denied，说明被权限门卫拒绝："
                "设置 DANGEROUS_MODE=allow 或 DANGEROUS_ALLOW=exploit_verify 后重试"
            )

        logger.info(f"MCP 利用验证完成: {url} → exploitable={result.get('exploitable')}")
        return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2, default=str)}]}

    async def _tool_scan_deep(self, args: dict) -> dict:
        """单点深度渗透：ReAct 推理 Agent 自主循环（侦察→思考→决策→执行→观察）。"""
        from vulnclaw.ai.dispatcher import ReActAgent
        from vulnclaw.core.utils import close_shared_session, get_shared_session

        target = (args.get("target") or "").strip()
        if not target:
            raise ValueError("target 参数不能为空")
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        max_iterations = args.get("max_iterations")
        if max_iterations is not None:
            try:
                max_iterations = max(1, int(max_iterations))
            except (TypeError, ValueError):
                raise ValueError("max_iterations 必须是正整数")

        logger.info(f"MCP 深度渗透: {target} (max_iterations={max_iterations or '默认'})")

        try:
            session = await get_shared_session(target=target)
            try:
                agent = ReActAgent(target, session, max_iterations=max_iterations)
                report = await _run_quietly(agent.run())
            finally:
                await close_shared_session()
        except Exception as exc:
            logger.error(f"MCP 深度渗透失败: {exc}\n{traceback.format_exc()}")
            raise ValueError(f"深度渗透失败: {exc}")

        vulnerabilities = report.get("vulnerabilities", []) or []
        # ReAct Agent 产出的是原始 finding，部分缺少 severity；如实统计而非静默补默认值
        missing_severity = sum(1 for v in vulnerabilities if not v.get("severity"))
        logger.info(f"MCP 深度渗透完成: {target} → {len(vulnerabilities)} 个漏洞（缺 severity: {missing_severity}）")

        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "status": "success",
                    "target": target,
                    "elapsed_seconds": report.get("elapsed_seconds"),
                    "iterations": report.get("iterations"),
                    "total_actions": report.get("total_actions"),
                    "findings_count": len(vulnerabilities),
                    "missing_severity_count": missing_severity,
                    "severity_stats": report.get("severity_stats", {}),
                    "tech_stack": report.get("tech_stack"),
                    "failed_params": report.get("failed_params", []),
                    "vulnerabilities": vulnerabilities,
                }, ensure_ascii=False, indent=2, default=str),
            }],
        }

    async def _tool_scan_deep_remote(self, args: dict) -> dict:
        """单点深度渗透（远程 Agent 模式）：把目标交给远程 AI Agent 自主执行。"""
        from vulnclaw.ai.remote_agents import delegate_deep
        from vulnclaw.core.danger_guard import guard

        if not settings.remote_deep_enabled:
            raise ValueError(
                "远程深度渗透未启用。请在 .env 中设置 REMOTE_DEEP_ENABLED=true 并配置 REMOTE_AGENTS。"
            )

        target = (args.get("target") or "").strip()
        if not target:
            raise ValueError("target 参数不能为空")
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        max_iterations = args.get("max_iterations")
        if max_iterations is not None:
            try:
                max_iterations = max(1, int(max_iterations))
            except (TypeError, ValueError):
                raise ValueError("max_iterations 必须是正整数")

        if not guard.require_approval("remote_deep_penetrate", f"target={target}"):
            return {
                "content": [{
                    "type": "text",
                    "text": json.dumps({
                        "status": "denied",
                        "target": target,
                        "reason": "DangerGuard 拒绝远程深度渗透（remote_deep_penetrate）；"
                                  "需 DANGEROUS_MODE=allow 或 DANGEROUS_ALLOW=remote_deep_penetrate",
                    }, ensure_ascii=False, indent=2),
                }],
            }

        logger.info(f"MCP 远程深度渗透: {target} (max_iterations={max_iterations or '默认'})")
        report = await delegate_deep(
            target=target,
            context={"source": "mcp", "max_iterations": max_iterations},
            max_iterations=max_iterations or 10,
        )
        if report is None:
            raise ValueError("远程深度渗透失败：未配置可用远程 Agent 或全部委派失败")

        # 兼容两种远程返回结构：直接是漏洞数组 / 含 vulnerabilities/findings 字段
        vulnerabilities = report.get("vulnerabilities") or report.get("findings") or []
        if not vulnerabilities and isinstance(report, list):
            vulnerabilities = report

        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "status": "success",
                    "mode": "remote_deep",
                    "target": target,
                    "findings_count": len(vulnerabilities),
                    "report": report,
                }, ensure_ascii=False, indent=2, default=str),
            }],
        }

    async def _tool_code_audit(self, args: dict) -> dict:
        """代码安全审计（Semgrep + CodeQL + 依赖 CVE + AI 复核）。"""
        from argparse import Namespace

        from vulnclaw.config import PROJECT_CACHE_DIR
        from vulnclaw.runners.code_audit_runner import run_code_audit

        repo = (args.get("repo") or "").strip()
        if not repo:
            raise ValueError("repo 参数不能为空（本地路径或 Git URL）")
        lang = (args.get("lang") or "python").strip()

        logger.info(f"MCP 代码审计: {repo} (lang={lang})")
        # run_code_audit 会 print 大量进度到 stdout，必须隔离以免污染 JSON-RPC 流
        await _run_quietly(run_code_audit(Namespace(code=repo, repo=repo, lang=lang)))

        summary_path = Path(PROJECT_CACHE_DIR) / "reports" / "code_audit_summary.json"
        summary: dict = {}
        if summary_path.is_file():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"代码审计摘要解析失败: {exc}")

        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "status": "success",
                    "repo": repo,
                    "lang": lang,
                    "summary": summary or "摘要未生成（见执行日志）",
                    "summary_path": str(summary_path),
                }, ensure_ascii=False, indent=2, default=str),
            }],
        }

    async def _tool_intel_lookup(self, args: dict) -> dict:
        """威胁情报查询（Shodan 优先、Censys 兜底）。"""
        target = (args.get("target") or "").strip()
        if not target:
            raise ValueError("target 参数不能为空（域名或 IP）")

        from vulnclaw.modules.intelligence.shodan_client import (
            CensysClient,
            ShodanClient,
            lookup_ip,
            resolve_ip,
        )

        shodan, censys = ShodanClient(), CensysClient()
        if not (shodan.enabled or censys.enabled):
            return {
                "content": [{
                    "type": "text",
                    "text": json.dumps({
                        "target": target,
                        "available": False,
                        "reason": "未配置 SHODAN_API_KEY 或 CENSYS_API_ID/SECRET，情报查询不可用",
                    }, ensure_ascii=False, indent=2),
                }],
            }

        ip = await resolve_ip(target)
        if not ip:
            raise ValueError(f"无法解析目标 IP: {target}")

        info = await _run_quietly(lookup_ip(ip))
        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "target": target,
                    "ip": ip,
                    "available": info is not None,
                    "providers": {
                        "shodan": shodan.enabled,
                        "censys": censys.enabled,
                    },
                    "intel": info or "未查到情报（目标可能未被收录）",
                }, ensure_ascii=False, indent=2, default=str),
            }],
        }

    async def _tool_engine_list(self, args: dict) -> dict:
        """列出所有已注册确定性检测引擎及其能力入口。"""
        from vulnclaw.core.scanner import get_all_engines, engine_capability

        items = []
        from vulnclaw.core.scanner import engine_param_schema as _engine_schema
        for eng in get_all_engines():
            has_scan, has_check = engine_capability(eng)
            caps = []
            if has_scan:
                caps.append("scan")
            if has_check:
                caps.append("check")
            items.append({
                "name": eng.name,
                "description": getattr(eng, "description", "") or "",
                "capabilities": caps,
                # SP7: 逐引擎 OpenAPI 式入参 schema（常驻主链路）
                "schema": _engine_schema(eng),
            })

        logger.info(f"MCP engine.list → {len(items)} 个引擎")
        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "count": len(items),
                    "engines": items,
                }, ensure_ascii=False, indent=2, default=str),
            }],
        }

    async def _tool_engine_run(self, args: dict) -> dict:
        """运行指定确定性检测引擎（scan / check 由引擎能力自动选择）。"""
        from vulnclaw.core.scanner import run_engine

        engine_name = (args.get("engine") or "").strip()
        if not engine_name:
            raise ValueError("engine 参数不能为空（可用引擎见 engine.list）")

        target = (args.get("target") or "").strip()
        url = (args.get("url") or "").strip()
        param = (args.get("param") or "").strip()
        jwt_token = args.get("jwt_token")

        kwargs = {}
        if jwt_token:
            kwargs["jwt_token"] = jwt_token

        logger.info(f"MCP engine.run: {engine_name} (target={target or url}, param={param or '-'})")
        try:
            findings = await run_engine(
                engine_name,
                target=target or None,
                url=url or None,
                param=param or None,
                **kwargs,
            )
        except ValueError as exc:
            raise ValueError(str(exc))
        except Exception as exc:
            logger.error(f"MCP engine.run 失败: {exc}\n{traceback.format_exc()}")
            raise ValueError(f"引擎执行失败: {exc}")

        findings = findings or []
        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "engine": engine_name,
                    "target": target or url,
                    "findings_count": len(findings),
                    "findings": findings,
                }, ensure_ascii=False, indent=2, default=str),
            }],
        }

    @staticmethod
    def _success_response(req_id: Any, result: Any) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    @staticmethod
    def _error_response(req_id: Any, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


class MCPStdioServer:
    """MCP stdio 传输层：stdin 读取 JSON-RPC 请求，stdout 写入响应。

    与 VS Code / Cursor 的 MCP 客户端通过 stdin/stdout 通信。
    """

    def __init__(self, event_bus: Optional[ScanEventBus] = None):
        self._event_bus = event_bus or get_event_bus()
        self._handler = MCPJsonRpcHandler(self._event_bus)
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._writer_lock = asyncio.Lock()
        # 暴露工具注册表（委托给 handler），便于外部/测试直接查询可用工具
        self._tools = self._handler._tools

    async def run(self) -> None:
        logger.info("MCP Server 已启动（stdio 模式），等待客户端连接...")

        try:
            await self._read_loop()
        except asyncio.CancelledError:
            logger.info("MCP Server 收到取消信号")
        except Exception as exc:
            logger.error(f"MCP Server 异常退出: {exc}\n{traceback.format_exc()}")

    async def _read_loop(self) -> None:
        """逐行读取 stdin 上的 JSON-RPC 请求。

        Windows 的 ProactorEventLoop 不支持 connect_read_pipe 读取匿名管道
        （会抛 _ProactorReadPipeTransport 异常，导致外部 AI 客户端接不上），
        因此统一用后台线程阻塞读 stdin，跨平台行为一致。
        """
        loop = asyncio.get_running_loop()
        stdin = sys.stdin
        buffer = b""

        while True:
            try:
                line = await loop.run_in_executor(None, stdin.buffer.readline)
            except (OSError, ValueError, asyncio.IncompleteReadError):
                break

            if not line:
                break

            buffer += line
            try:
                data = buffer.decode("utf-8")
                if not data.strip():
                    buffer = b""
                    continue
                request = json.loads(data)
                buffer = b""
                response = await self._handler.handle_request(request)
                if response:
                    self._write_response(response)
            except json.JSONDecodeError:
                continue
            except Exception as exc:
                logger.error(f"消息处理异常: {exc}")
                buffer = b""

    def _write_response(self, response: dict) -> None:
        """同步写 stdout 并立即 flush（MCP 响应量小，同步写最可靠）。"""
        try:
            data = json.dumps(response, ensure_ascii=False) + "\n"
            sys.stdout.buffer.write(data.encode("utf-8"))
            sys.stdout.buffer.flush()
        except (OSError, ConnectionResetError, AttributeError) as exc:
            logger.error(f"写入响应失败: {exc}")


# ============================================================
# HTTP 传输层（远程接入；默认只听本机）
# ============================================================

# 视为"本机"的地址：外网物理不可达，允许免鉴权
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "::"}

# 请求体上限：JSON-RPC 调用体本就很小，超限直接拒绝
MAX_BODY_BYTES = 512 * 1024

# 鉴权失败封禁：连续失败达上限后临时拉黑（暴力破解本就无效，主要为降噪并压缩探测面）
MAX_AUTH_FAILURES = 5
AUTH_BLOCK_SECONDS = 900  # 15 分钟
# 追踪表上限：防止海量伪造 IP 把内存撑爆
_MAX_TRACKED_IPS = 10000

# ===== 入侵检测（IDS）=====

# 渐进封禁阶梯：第 n 次触发封禁时的时长（秒）；超出列表长度即永久封禁
# 15 分钟 → 1 小时 → 1 天 → 7 天 → 永久
BAN_LADDER_SECONDS = (900, 3600, 86400, 604800)

# 正常的 MCP 客户端只会访问这两个路径；访问其它路径 = 探测行为
ALLOWED_PATHS = ("/mcp", "/healthz")

# 已知攻击/扫描工具的 User-Agent 特征（不含 curl / python-requests 这类通用客户端，避免误伤自己）
SCANNER_UA_PATTERNS = (
    "sqlmap", "nmap", "masscan", "nikto", "dirbuster", "gobuster", "ffuf",
    "wpscan", "acunetix", "nessus", "openvas", "metasploit", "havij",
    "w3af", "arachni", "zgrab", "shodan", "censys", "zmap", "brutex",
)

# 洪泛阈值：窗口期内请求数上限（正常 AI 客户端远低于此，自动化工具会瞬间突破）
FLOOD_WINDOW_SECONDS = 10
FLOOD_MAX_REQUESTS = 60

# 永久封禁的哨兵值
BAN_FOREVER = float("inf")


class BanList:
    """IP 封禁表：渐进升级 + 永久封禁 + 落盘持久化。

    设计取舍——不一击永久：手滑打错密码是常态，直接永久会把使用者自己锁死。
    因此采用阶梯：反复违规逐步加码，累计到阈值才永久。
    但"路径探测"和"已知攻击工具 UA"这两类是**零容忍**信号（正常客户端绝不会触发），
    命中即永久，不做阶梯。
    """

    def __init__(self, path: Optional[str] = None):
        if path:
            from pathlib import Path as _Path

            self._path = _Path(path)
        else:
            from vulnclaw.config import PROJECT_CACHE_DIR

            self._path = __import__("pathlib").Path(PROJECT_CACHE_DIR) / "mcp_banned.json"
        self._permanent: dict = {}   # ip -> {"reason":..., "at":...}
        self._temporary: dict = {}   # ip -> {"until":..., "reason":...}
        self._strikes: dict = {}     # ip -> 累计违规次数
        self._load()

    # ---------- 持久化 ----------
    def _load(self) -> None:
        try:
            if self._path.is_file():
                data = json.loads(self._path.read_text(encoding="utf-8"))
                self._permanent = data.get("permanent") or {}
                self._temporary = data.get("temporary") or {}
                self._strikes = data.get("strikes") or {}
        except Exception:  # noqa: BLE001
            logger.warning("封禁表读取失败，按空表启动")

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(
                    {"permanent": self._permanent, "temporary": self._temporary, "strikes": self._strikes},
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"封禁表写入失败: {exc}")

    # ---------- 查询 ----------
    def remaining(self, ip: str) -> float:
        """剩余封禁秒数；0=未封禁，inf=永久。"""
        if ip in self._permanent:
            return BAN_FOREVER
        entry = self._temporary.get(ip)
        if not entry:
            return 0.0
        left = float(entry.get("until", 0)) - time.time()
        if left <= 0:
            self._temporary.pop(ip, None)
            self._save()
            return 0.0
        return left

    def strikes(self, ip: str) -> int:
        return int(self._strikes.get(ip, 0))

    # ---------- 处置 ----------
    def strike(self, ip: str, reason: str) -> float:
        """记录一次违规，按阶梯升级封禁。返回本次封禁时长（inf=永久）。"""
        if not ip:
            return 0.0
        count = self.strikes(ip) + 1
        self._strikes[ip] = count

        if count > len(BAN_LADDER_SECONDS):
            duration = BAN_FOREVER
            self._permanent[ip] = {"reason": reason, "at": time.time(), "strikes": count}
            self._temporary.pop(ip, None)
            logger.warning(f"🚫 [IDS] {ip} 累计 {count} 次违规 → **永久封禁**（{reason}）")
        else:
            duration = float(BAN_LADDER_SECONDS[count - 1])
            self._temporary[ip] = {"until": time.time() + duration, "reason": reason}
            logger.warning(f"🚫 [IDS] {ip} 第 {count} 次违规 → 封禁 {int(duration)}s（{reason}）")
        self._save()
        return duration

    def ban_forever(self, ip: str, reason: str) -> None:
        """立即永久封禁（用于零容忍信号）。"""
        if not ip:
            return
        self._strikes[ip] = max(self.strikes(ip), len(BAN_LADDER_SECONDS) + 1)
        self._permanent[ip] = {"reason": reason, "at": time.time(), "strikes": self.strikes(ip)}
        self._temporary.pop(ip, None)
        logger.warning(f"🚫 [IDS] {ip} 命中零容忍规则 → **永久封禁**（{reason}）")
        self._save()

    def unban(self, ip: str) -> bool:
        removed = bool(self._permanent.pop(ip, None) or self._temporary.pop(ip, None))
        if ip in self._strikes:
            self._strikes.pop(ip, None)
            removed = True
        if removed:
            self._save()
        return removed

    def clear(self) -> int:
        count = len(set(self._permanent) | set(self._temporary))
        self._permanent.clear()
        self._temporary.clear()
        self._strikes.clear()
        self._save()
        return count

    def snapshot(self) -> dict:
        now = time.time()
        return {
            "path": str(self._path),
            "permanent": {ip: dict(v) for ip, v in self._permanent.items()},
            "temporary": {
                ip: {"seconds_left": int(float(v.get("until", 0)) - now), "reason": v.get("reason")}
                for ip, v in self._temporary.items()
                if float(v.get("until", 0)) > now
            },
            "strikes": dict(self._strikes),
        }


def generate_mcp_token() -> str:
    """生成强随机 token（32 字节 URL-safe，约 43 字符）。"""
    return secrets.token_urlsafe(32)


def is_local_host(host: str) -> bool:
    return (host or "").strip().lower() in LOCAL_HOSTS


class MCPHttpServer:
    """MCP HTTP 传输层（JSON-RPC over POST）。

    安全设计（默认零暴露）：
      * 默认只监听 127.0.0.1 —— 外网物理不可达
      * 监听非本机地址时**强制**要求 token（run_mcp_http 与 CLI 双重闸门）
      * token 校验用 hmac.compare_digest 恒定时间比较，防时序侧信道
      * 鉴权失败统一 401 且不泄露原因（不提示 token 错在哪）
      * 请求体 512KB 上限，超限直接拒绝
      * 危险操作仍受 danger_guard 第二道锁控制（即便 token 泄露也打不出利用）
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8765,
        token: Optional[str] = None,
        event_bus: Optional[ScanEventBus] = None,
        allow_ips: Optional[list] = None,
        trust_proxy: bool = False,
        max_failures: int = MAX_AUTH_FAILURES,
        block_seconds: int = AUTH_BLOCK_SECONDS,
        banlist: Optional[BanList] = None,
    ):
        self._host = host
        self._port = port
        self._token = (token or "").strip()
        self._handler = MCPJsonRpcHandler(event_bus or get_event_bus())
        self._runner: Optional[web.AppRunner] = None
        self._banlist = banlist if banlist is not None else BanList()
        self._requests: dict = {}  # ip -> 请求时间戳队列（洪泛检测）

        # IP 白名单（CIDR 或单个 IP）；为空表示不限制
        self._allow_networks: list = []
        for entry in allow_ips or []:
            try:
                self._allow_networks.append(ipaddress.ip_network(str(entry).strip(), strict=False))
            except ValueError as exc:
                raise ValueError(f"非法 --allow-ip 条目: {entry}（{exc}）")

        # 反向代理后的真实 IP：默认不信任 XFF，否则任何人都能伪造头绕过白名单
        self._trust_proxy = bool(trust_proxy)
        self._max_failures = max(1, int(max_failures))
        self._block_seconds = max(1, int(block_seconds))
        self._failures: dict = {}   # ip -> [失败时间戳...]（仅用于累计连续失败，封禁由 BanList 管）

    @property
    def requires_auth(self) -> bool:
        return bool(self._token)

    # ---------- 访问控制 ----------

    def _client_ip(self, request: web.Request) -> str:
        """取客户端 IP。只有显式 --trust-proxy 才采信 X-Forwarded-For。"""
        if self._trust_proxy:
            forwarded = request.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[0].strip() or (request.remote or "")
        return request.remote or ""

    def _ip_allowed(self, ip: str) -> bool:
        if not self._allow_networks:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for net in self._allow_networks:
            if addr.version == net.version and addr in net:
                return True
        return False

    def _blocked_for(self, ip: str) -> float:
        """剩余封禁秒数（0=未封禁，inf=永久）。"""
        return self._banlist.remaining(ip)

    def _record_failure(self, ip: str) -> None:
        """累计连续失败；达到阈值才升级封禁（避免手滑打错两次就被永久拉黑）。"""
        if not ip:
            return
        now = time.time()
        # 只保留窗口内的失败记录
        attempts = [t for t in self._failures.get(ip, []) if now - t < self._block_seconds]
        attempts.append(now)
        self._failures[ip] = attempts

        if len(attempts) >= self._max_failures:
            self._failures.pop(ip, None)
            self._banlist.strike(ip, f"连续 {len(attempts)} 次鉴权失败")

        # 内存兜底：超过上限时清掉最旧的一半
        if len(self._failures) > _MAX_TRACKED_IPS:
            for key in sorted(self._failures, key=lambda k: self._failures[k][-1])[:_MAX_TRACKED_IPS // 2]:
                self._failures.pop(key, None)

    def _clear_failures(self, ip: str) -> None:
        self._failures.pop(ip, None)

    # ---------- 入侵检测 ----------

    def _is_flooding(self, ip: str) -> bool:
        if not ip:
            return False
        now = time.time()
        window = self._requests.setdefault(ip, deque())
        window.append(now)
        while window and now - window[0] > FLOOD_WINDOW_SECONDS:
            window.popleft()

        if len(self._requests) > _MAX_TRACKED_IPS:
            for key in list(self._requests)[:_MAX_TRACKED_IPS // 2]:
                self._requests.pop(key, None)

        return len(window) > FLOOD_MAX_REQUESTS

    @staticmethod
    def _reject(status: int, message: str, retry_after: int = 0) -> web.Response:
        headers = {"Retry-After": str(retry_after)} if retry_after else None
        return web.json_response({"error": message}, status=status, headers=headers)

    def _security_middleware(self):
        """统一安全中间件：封禁 → 攻击工具 UA → 路径探测 → 洪泛。

        正常 MCP 客户端只会 POST /mcp（偶尔 GET /healthz），
        因此"访问其它路径"和"带扫描器 UA"是零容忍信号，直接永久封禁。
        """

        @web.middleware
        async def middleware(request: web.Request, handler):
            ip = self._client_ip(request)

            # 1) 已封禁
            left = self._banlist.remaining(ip)
            if left > 0:
                return self._reject(429, "Too many requests", int(left) + 1 if left != BAN_FOREVER else 86400)

            # 2) 已知攻击/扫描工具特征（零容忍）
            ua = (request.headers.get("User-Agent") or "").lower()
            for pattern in SCANNER_UA_PATTERNS:
                if pattern in ua:
                    self._banlist.ban_forever(ip, f"攻击工具特征 UA: {pattern}")
                    return self._reject(403, "Forbidden")

            # 3) 路径探测（零容忍）：正常客户端不会去试 /admin、/.env 之类的路径
            if request.path not in ALLOWED_PATHS:
                self._banlist.ban_forever(ip, f"探测非服务路径: {request.path}")
                return self._reject(403, "Forbidden")

            # 4) 洪泛
            if self._is_flooding(ip):
                self._banlist.strike(ip, "请求频率异常（疑似自动化洪泛）")
                return self._reject(429, "Too many requests", FLOOD_WINDOW_SECONDS)

            return await handler(request)

        return middleware

    def _authorized(self, request: web.Request) -> bool:
        if not self._token:
            return True  # 仅本机模式允许免鉴权
        auth = request.headers.get("Authorization", "")
        presented = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not presented:
            return False
        return hmac.compare_digest(presented, self._token)

    async def _handle_rpc(self, request: web.Request) -> web.Response:
        ip = self._client_ip(request)

        # 1) 封禁检查（优先于一切，不透露任何校验细节）
        remaining = self._blocked_for(ip)
        if remaining > 0:
            return web.json_response(
                {"jsonrpc": "2.0", "error": {"code": -32029, "message": "Too many requests"}},
                status=429,
                headers={"Retry-After": str(int(remaining) + 1)},
            )

        # 2) IP 白名单
        if not self._ip_allowed(ip):
            logger.warning(f"MCP HTTP: 拒绝非白名单来源 {ip}")
            return web.json_response(
                {"jsonrpc": "2.0", "error": {"code": -32003, "message": "Forbidden"}},
                status=403,
            )

        # 3) token 校验
        if not self._authorized(request):
            self._record_failure(ip)
            logger.warning(f"MCP HTTP 鉴权失败（来源 {ip}）")
            return web.json_response(
                {"jsonrpc": "2.0", "error": {"code": -32001, "message": "Unauthorized"}},
                status=401,
            )
        self._clear_failures(ip)

        try:
            body = await request.json()
        except Exception:
            return web.json_response(
                {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}},
                status=400,
            )
        if not isinstance(body, dict):
            return web.json_response(
                {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}},
                status=400,
            )

        result = await self._handler.handle_request(body)
        # aiohttp 的 json_response 不支持 ensure_ascii；工具描述含中文，需保留原文
        return web.Response(
            text=json.dumps(result, ensure_ascii=False),
            content_type="application/json",
        )

    async def _handle_healthz(self, request: web.Request) -> web.Response:
        """探活端点（不泄露 token，仅告知是否需要鉴权）。"""
        return web.json_response({"status": "ok", "auth_required": self.requires_auth})

    def make_app(self) -> web.Application:
        app = web.Application(
            client_max_size=MAX_BODY_BYTES,
            middlewares=[self._security_middleware()],
        )
        app.router.add_post("/mcp", self._handle_rpc)
        app.router.add_get("/healthz", self._handle_healthz)
        return app

    @property
    def actual_port(self) -> int:
        """实际监听端口（--port 0 时由系统分配，启动后才有意义）。"""
        return getattr(self, "_actual_port", self._port)

    async def run(self) -> None:
        self._runner = web.AppRunner(self.make_app())
        await self._runner.setup()
        site = web.TCPSite(self._runner, self._host, self._port)
        await site.start()

        # --port 0 时由系统分配随机端口，回填真实值便于打印与配置生成
        self._actual_port = self._port
        try:
            server = getattr(site, "_server", None)
            if server is not None and getattr(server, "sockets", None):
                self._actual_port = server.sockets[0].getsockname()[1]
        except Exception:  # noqa: BLE001
            logger.debug("suppressed exception (core audit)")

        scope = "本机（外网不可达）" if is_local_host(self._host) else "外部网络"
        logger.info(f"MCP HTTP Server 已启动: http://{self._host}:{self.actual_port}/mcp")
        logger.info(f"   监听范围: {scope} | 鉴权: {'开启（token 校验）' if self.requires_auth else '关闭'}")
        if self._allow_networks:
            logger.info(f"   IP 白名单: {', '.join(str(n) for n in self._allow_networks)}")
        if not is_local_host(self._host):
            logger.warning("⚠️ 监听非本机地址：请确保 token 足够强，并走加密通道（HTTPS / SSH 隧道）")

        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            logger.debug("suppressed exception (core audit)")
        finally:
            await self._runner.cleanup()


async def run_mcp_http(
    host: str = "127.0.0.1",
    port: int = 8765,
    token: Optional[str] = None,
    with_worker: bool = True,
    allow_ips: Optional[list] = None,
    trust_proxy: bool = False,
) -> None:
    """启动 MCP HTTP Server。

    安全闸门：监听非本机地址却没给 token 时直接拒绝启动——不允许裸奔上网。
    """
    if not is_local_host(host) and not (token or "").strip():
        raise ValueError(
            "拒绝启动：监听非本机地址（host=%s）必须提供 token。"
            "请用 --mcp-token 指定或 --mcp-token-file 从文件读取；"
            "也可以保持默认 127.0.0.1（本机模式免鉴权）。" % host
        )

    bus = get_event_bus()
    server = MCPHttpServer(
        host=host,
        port=port,
        token=token,
        event_bus=bus,
        allow_ips=allow_ips,
        trust_proxy=trust_proxy,
    )

    tasks = [asyncio.create_task(server.run())]
    if with_worker:
        tasks.append(asyncio.create_task(scan_worker(event_bus=bus)))

    try:
        _done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.wait(pending)
    except asyncio.CancelledError:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


# ============================================================
# 客户端配置生成（一键接入）
# ============================================================

MCP_CLIENT_PROFILES = {
    "cursor": {
        "label": "Cursor",
        "config_path": "~/.cursor/mcp.json",
    },
    "claude-desktop": {
        "label": "Claude Desktop",
        "config_path": (
            "~/Library/Application Support/Claude/claude_desktop_config.json (macOS) 或 "
            "%APPDATA%\\Claude\\claude_desktop_config.json (Windows)"
        ),
    },
    "generic": {
        "label": "通用 MCP 客户端",
        "config_path": "由客户端决定——把下面的 mcpServers 片段粘进它的配置里",
    },
}


def build_mcp_server_entry(
    mode: str = "stdio",
    cwd: Optional[str] = None,
    python_path: Optional[str] = None,
    http_url: Optional[str] = None,
    token: Optional[str] = None,
) -> dict:
    """生成单个 MCP server 的配置条目。"""
    if mode == "http":
        if not http_url:
            raise ValueError("http 模式必须提供 http_url")
        entry: dict = {"type": "http", "url": http_url}
        entry["headers"] = {"Authorization": f"Bearer {token}" if token else "Bearer <TOKEN>"}
        return entry

    entry = {
        "command": python_path or sys.executable or "python",
        "args": ["-m", "vulnclaw.core.mcp_server"],
    }
    if cwd:
        entry["cwd"] = cwd
    entry["env"] = {"PYTHONIOENCODING": "utf-8"}
    return entry


def build_mcp_client_config(
    client: str = "generic",
    mode: str = "stdio",
    cwd: Optional[str] = None,
    python_path: Optional[str] = None,
    http_url: Optional[str] = None,
    token: Optional[str] = None,
) -> dict:
    """生成完整客户端配置（mcpServers 结构），可直接粘贴或写入。"""
    if client not in MCP_CLIENT_PROFILES:
        raise ValueError(f"未知客户端: {client}（可选: {', '.join(MCP_CLIENT_PROFILES)}）")
    return {
        "mcpServers": {
            "vulnclaw": build_mcp_server_entry(mode, cwd, python_path, http_url, token)
        }
    }


async def scan_worker(event_bus: Optional[ScanEventBus] = None) -> None:
    """后台扫描 Worker：消费事件总线中的 scan.start 事件并执行扫描。

    通过事件总线与 MCP Server 解耦，不直接依赖 scan_main.py 或 orchestrator.py。
    实际扫描逻辑通过 import 延迟加载，避免启动时的循环依赖。
    """
    bus = event_bus or get_event_bus()
    logger.info("Scan Worker 已启动，等待扫描任务...")

    while True:
        try:
            event = await bus.consume()
        except asyncio.CancelledError:
            logger.info("Scan Worker 收到取消信号")
            break

        if event.get("type") != "scan.start":
            continue

        scan_id = event["scan_id"]
        target = event["target"]
        max_tasks = event.get("max_tasks")
        initial_qps = event.get("initial_qps")

        logger.info(f"Scan Worker 开始执行扫描: {scan_id} → {target}")

        try:
            await bus.update_job(
                scan_id,
                status=ScanStatus.RUNNING,
                started_at=time.time(),
            )

            from vulnclaw.core.utils import get_shared_session, close_shared_session
            session = await get_shared_session(target=target)

            try:
                from vulnclaw.ai.v100 import run_v100_scan
                report = await run_v100_scan(
                    target=target,
                    session=session,
                    max_tasks=max_tasks,
                    initial_qps=initial_qps,
                )
            finally:
                await close_shared_session()

            findings = report.get("vulnerabilities", report.get("findings", [])) if isinstance(report, dict) else []

            await bus.update_job(
                scan_id,
                status=ScanStatus.COMPLETED,
                progress=100,
                findings=findings,
                completed_at=time.time(),
            )
            logger.info(f"Scan Worker 扫描完成: {scan_id}，发现 {len(findings)} 个漏洞")

        except Exception as exc:
            logger.error(f"Scan Worker 扫描失败: {scan_id} - {exc}\n{traceback.format_exc()}")
            await bus.update_job(
                scan_id,
                status=ScanStatus.FAILED,
                error=str(exc),
                completed_at=time.time(),
            )


async def run_mcp_server(with_worker: bool = True) -> None:
    """启动 MCP Server 及后台 Scan Worker。

    Args:
        with_worker: 是否同时启动后台扫描 Worker（默认 True）
    """
    bus = get_event_bus()
    server = MCPStdioServer(event_bus=bus)

    tasks = [asyncio.create_task(server.run())]

    if with_worker:
        tasks.append(asyncio.create_task(scan_worker(event_bus=bus)))

    try:
        # stdio 关闭（客户端断开）即视为服务结束：
        # scan_worker 是无限循环，若用 gather 等待会导致进程在客户端断开后仍挂起不退出。
        _done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.wait(pending)
    except asyncio.CancelledError:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def main() -> None:
    """MCP Server 入口（供 CLI 或直接调用）"""
    try:
        asyncio.run(run_mcp_server())
    except KeyboardInterrupt:
        logger.info("MCP Server 已停止")
    except Exception as exc:
        logger.error(f"MCP Server 启动失败: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()