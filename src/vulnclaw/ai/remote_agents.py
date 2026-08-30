# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/remote_agents.py
"""
远程 AI Agent 统一适配器（v200 - 全后端）

让平台作为「客户端」外接远程 AI Agent，与内置 Agent 舰队互补：
  * type=mcp + transport=http  -> 平台作为 MCP 客户端连接远程 MCP HTTP Server（标准协议，推荐）
  * type=mcp + transport=stdio -> 平台启动本地/容器 MCP Server 子进程，stdin/stdout 走 JSON-RPC
  * type=mcp + transport=sse   -> MCP 2024-11-05 SSE transport（兼容旧实现）
  * type=http                  -> 远程 Agent 的 HTTP / OpenAI 兼容 chat/completions 接口
  * type=cli                   -> 外部 Agent CLI 子进程（command 含 {prompt} 占位符，或从 stdin 读取）

配置（.env REMOTE_AGENTS，JSON 数组，0~N 个随意增删）：
  REMOTE_AGENTS=[
    {"name":"codex-http","type":"mcp","transport":"http","url":"http://127.0.0.1:8765/mcp","tool":"analyze"},
    {"name":"codex-stdio","type":"mcp","transport":"stdio","command":"python","args":["/path/to/agent.py"],"tool":"analyze"},
    {"name":"codex-sse","type":"mcp","transport":"sse","url":"http://127.0.0.1:8765/sse","tool":"analyze"},
    {"name":"my-http","type":"http","url":"https://agent.example.com/v1","token":"xxx","model":"deepseek-v3"},
    {"name":"cli-helper","type":"cli","command":"myagent --prompt {prompt}"}
  ]

安全默认（与 core/mcp_server.py 同源策略）：
  * 非本机地址必须带 token，否则该 Agent 被忽略（本机 127.0.0.1/localhost 可免 token）
  * HTTPS 证书校验默认开启（独立会话，不复用扫描的 ssl=False 共享会话）
  * 每次委派有超时 + 逐个熔断，全部失败自动降级回本地逻辑（不影响主流程）
  * 数据最小化：只传分析所需文本，不传密钥 / 本地文件路径
  * 所有委派过程全程记日志（审计）
"""
import asyncio
import json
import shlex
import sys
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import aiohttp

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}
SUPPORTED_TYPES = ("mcp", "http", "cli")
MCP_TRANSPORTS = ("http", "stdio", "sse")
MCP_PROTOCOL_VERSION = "2024-11-05"


# ============================================================
# 配置模型
# ============================================================

@dataclass
class RemoteAgent:
    name: str
    type: str
    url: str = ""
    token: str = ""
    command: str = ""                    # cli / stdio 后端：可执行命令
    args: List[str] = field(default_factory=list)   # stdio 后端：命令参数
    env: Dict[str, str] = field(default_factory=dict)  # stdio 后端：环境变量
    cwd: str = ""                        # stdio 后端：工作目录
    tool: str = "analyze"                # mcp 后端：调用远程 MCP 的工具名
    model: str = ""                      # http 后端：模型名（留空用默认）
    timeout: int = 60
    transport: str = "http"              # mcp 后端：http | stdio | sse
    extra_headers: Dict[str, str] = field(default_factory=dict)
    ssl_verify: bool = True              # http/sse 后端：是否校验 TLS


# ============================================================
# 配置解析与安全校验
# ============================================================

def _is_local_url(url: str) -> bool:
    """判断 URL 是否为本机地址（127.0.0.1 / localhost / ::1）。"""
    try:
        host = urllib.parse.urlparse(url).hostname or ""
        return host.strip().lower() in LOCAL_HOSTS
    except Exception:
        return False


def _validate_agent(raw: Dict[str, Any]) -> Optional[RemoteAgent]:
    """校验单个 Agent 配置；不合法 / 不安全 -> 返回 None 并记日志。"""
    try:
        name = str(raw.get("name", "")).strip() or "unnamed"
        atype = str(raw.get("type", "")).strip().lower()
        if atype not in SUPPORTED_TYPES:
            logger.warning(f"远程 Agent[{name}]：未知类型 {atype!r}（支持 {SUPPORTED_TYPES}），已忽略")
            return None

        url = str(raw.get("url", "")).strip()
        transport = str(raw.get("transport", "http")).strip().lower()
        if atype == "mcp" and transport not in MCP_TRANSPORTS:
            logger.warning(f"远程 Agent[{name}]：MCP transport {transport!r} 不支持（支持 {MCP_TRANSPORTS}），已忽略")
            return None

        # http / sse 必须有 url；stdio / cli 必须有 command
        if atype == "mcp" and transport in ("http", "sse") and not (url.startswith("http://") or url.startswith("https://")):
            logger.warning(f"远程 Agent[{name}]：MCP {transport} 必须提供 http/https url，已忽略")
            return None
        if atype == "mcp" and transport == "stdio" and not str(raw.get("command", "")).strip():
            logger.warning(f"远程 Agent[{name}]：stdio 后端必须配置 command，已忽略")
            return None
        if atype == "cli" and not str(raw.get("command", "")).strip():
            logger.warning(f"远程 Agent[{name}]：cli 后端必须配置 command，已忽略")
            return None

        token = str(raw.get("token", "")).strip()
        # 安全默认：非本机地址必须带 token，否则该 Agent 不生效
        if atype != "cli" and url and not _is_local_url(url) and not token:
            logger.warning(
                f"远程 Agent[{name}]：非本机地址({url})未配置 token，为安全已忽略（本机地址可免 token）"
            )
            return None

        timeout = int(raw.get("timeout", 60) or 60)
        extra = raw.get("headers") or {}
        if isinstance(extra, str):
            try:
                extra = json.loads(extra)
            except Exception:
                extra = {}

        args = raw.get("args") or []
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                args = shlex.split(args)
        args = [str(a) for a in args]

        env = raw.get("env") or {}
        if isinstance(env, str):
            try:
                env = json.loads(env)
            except Exception:
                env = {}
        env = {str(k): str(v) for k, v in env.items()}

        return RemoteAgent(
            name=name,
            type=atype,
            url=url,
            token=token,
            command=str(raw.get("command", "")).strip(),
            args=args,
            env=env,
            cwd=str(raw.get("cwd", "")).strip(),
            tool=str(raw.get("tool", "analyze")).strip() or "analyze",
            model=str(raw.get("model", "")).strip(),
            timeout=max(5, min(timeout, 600)),
            transport=transport,
            extra_headers={str(k): str(v) for k, v in (extra or {}).items()},
            ssl_verify=bool(raw.get("ssl_verify", True)),
        )
    except Exception as exc:
        logger.warning(f"远程 Agent 配置解析失败: {exc}")
        return None


def get_remote_agents() -> List[RemoteAgent]:
    """返回当前配置下启用的远程 AI Agent 列表（0~N 个，已过安全校验）。"""
    raw = getattr(settings, "remote_agents", None) or []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            return []
    if not isinstance(raw, list):
        return []
    agents = []
    for item in raw:
        if isinstance(item, dict):
            agent = _validate_agent(item)
            if agent is not None:
                agents.append(agent)
    return agents


# ============================================================
# 统一后端抽象
# ============================================================

class AgentBackend(ABC):
    def __init__(self, agent: RemoteAgent):
        self.agent = agent

    @abstractmethod
    async def analyze(self, prompt: str, system: str, temperature: float, max_tokens: int) -> str:
        """返回分析文本。"""
        ...

    @abstractmethod
    async def execute(self, name: str, arguments: Dict[str, Any]) -> Any:
        """执行工具/任务，返回结构化结果。"""
        ...

    @abstractmethod
    async def deep(self, target: str, context: Dict[str, Any], max_iterations: int) -> Any:
        """执行深度渗透，返回结构化结果。"""
        ...

    @abstractmethod
    async def close(self) -> None:
        """释放资源。"""
        ...


def _content_to_text(content: Any) -> str:
    if isinstance(content, list):
        return "".join(
            c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"
        ).strip()
    if isinstance(content, dict):
        return str(content.get("text", content)).strip()
    return str(content).strip()


def _normalize_remote_result(result: Any) -> Dict[str, Any]:
    """把远程 Agent 返回的任意结果标准化为 tool_registry 风格的 dict。"""
    if isinstance(result, dict):
        return dict(result)
    if isinstance(result, str):
        if result.strip():
            try:
                return json.loads(result)
            except json.JSONDecodeError:
                pass
        return {"stdout": result, "success": True}
    return {"output": result, "success": True}


# ============================================================
# MCP over HTTP（stateless JSON-RPC，完整 initialize 握手）
# ============================================================

class MCPHttpBackend(AgentBackend):
    def __init__(self, agent: RemoteAgent):
        super().__init__(agent)
        self._initialized = False
        self._client_session: Optional[aiohttp.ClientSession] = None
        self._server_info: Dict[str, Any] = {}
        self._capabilities: Dict[str, Any] = {}
        self._request_id = 0

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.agent.token:
            headers["Authorization"] = f"Bearer {self.agent.token}"
        headers.update(self.agent.extra_headers)
        return headers

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._client_session is None or self._client_session.closed:
            self._client_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.agent.timeout, connect=10),
                headers=self._headers(),
            )
        return self._client_session

    async def _rpc(self, method: str, params: Any = None) -> Any:
        session = await self._get_session()
        self._request_id += 1
        payload: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params
        timeout = aiohttp.ClientTimeout(total=self.agent.timeout, connect=10)
        ssl = self.agent.ssl_verify if self.agent.url.startswith("https://") else None
        async with session.post(
            self.agent.url, json=payload, headers=self._headers(), timeout=timeout, ssl=ssl
        ) as resp:
            body = await resp.json(content_type=None)
        if resp.status >= 400:
            raise RuntimeError(f"MCP HTTP {resp.status}: {str(body)[:200]}")
        if body.get("error"):
            raise RuntimeError(f"MCP error: {body['error']}")
        return body.get("result")

    async def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        result = await self._rpc("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "vulnclaw", "version": "1.0.0"},
        })
        self._server_info = result.get("serverInfo", {})
        self._capabilities = result.get("capabilities", {})
        await self._rpc("notifications/initialized", {})
        self._initialized = True
        logger.debug(
            f"MCP HTTP Agent[{self.agent.name}] 握手成功: "
            f"{self._server_info.get('name')} {self._server_info.get('version')}"
        )

    async def _tools_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        await self._ensure_initialized()
        result = await self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        if result.get("isError"):
            raise RuntimeError(f"MCP tool error: {str(result)[:200]}")
        return result.get("content", [])

    async def analyze(self, prompt: str, system: str, temperature: float, max_tokens: int) -> str:
        content = await self._tools_call(self.agent.tool or "analyze", {
            "prompt": prompt,
            "system": system or "",
            "temperature": temperature,
            "max_tokens": max_tokens,
        })
        return _content_to_text(content)

    async def execute(self, name: str, arguments: Dict[str, Any]) -> Any:
        content = await self._tools_call(name, arguments)
        text = _content_to_text(content)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"stdout": text, "success": True}

    async def deep(self, target: str, context: Dict[str, Any], max_iterations: int) -> Any:
        return await self.execute("deep_penetrate", {
            "target": target,
            "context": context or {},
            "max_iterations": max_iterations,
        })

    async def close(self) -> None:
        if self._client_session is not None and not self._client_session.closed:
            await self._client_session.close()
            self._client_session = None


# ============================================================
# MCP over stdio（子进程 stdin/stdout JSON-RPC，完整 initialize 握手）
# ============================================================

class MCPStdioBackend(AgentBackend):
    def __init__(self, agent: RemoteAgent):
        super().__init__(agent)
        self._initialized = False
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._server_info: Dict[str, Any] = {}
        self._capabilities: Dict[str, Any] = {}
        self._request_id = 0
        self._lock = asyncio.Lock()

    async def _ensure_proc(self) -> asyncio.subprocess.Process:
        if self._proc is not None and self._proc.returncode is None:
            return self._proc
        command = self.agent.command
        if not command:
            raise RuntimeError("stdio 后端未配置 command")
        tokens = [command] + self.agent.args
        env = None
        if self.agent.env:
            import os
            env = {**os.environ, **self.agent.env}
        logger.info(f"启动 stdio MCP Agent[{self.agent.name}]: {' '.join(shlex.quote(t) for t in tokens)}")
        self._proc = await asyncio.create_subprocess_exec(
            *tokens,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd=self.agent.cwd or None,
        )
        return self._proc

    async def _read_line(self) -> str:
        proc = await self._ensure_proc()
        if proc.stdout is None:
            raise RuntimeError("stdio Agent 未打开 stdout")
        line = await proc.stdout.readline()
        if not line:
            raise RuntimeError("stdio Agent 已关闭 stdout")
        return line.decode("utf-8", errors="replace").strip()

    async def _rpc(self, method: str, params: Any = None) -> Any:
        async with self._lock:
            proc = await self._ensure_proc()
            if proc.stdin is None:
                raise RuntimeError("stdio Agent 未打开 stdin")
            self._request_id += 1
            payload: Dict[str, Any] = {
                "jsonrpc": "2.0",
                "id": self._request_id,
                "method": method,
            }
            if params is not None:
                payload["params"] = params
            data = json.dumps(payload, ensure_ascii=False) + "\n"
            proc.stdin.write(data.encode("utf-8"))
            await proc.stdin.drain()

            deadline = asyncio.get_event_loop().time() + self.agent.timeout
            while True:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    raise asyncio.TimeoutError("stdio Agent 响应超时")
                line = await asyncio.wait_for(self._read_line(), timeout=remaining)
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    logger.debug(f"stdio Agent[{self.agent.name}] 非 JSON 行: {line[:200]}")
                    continue
                if "id" not in msg:
                    continue
                if msg.get("id") == self._request_id:
                    if msg.get("error"):
                        raise RuntimeError(f"MCP error: {msg['error']}")
                    return msg.get("result")

    async def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        result = await self._rpc("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "vulnclaw", "version": "1.0.0"},
        })
        self._server_info = result.get("serverInfo", {})
        self._capabilities = result.get("capabilities", {})
        await self._rpc("notifications/initialized", {})
        self._initialized = True
        logger.debug(
            f"MCP stdio Agent[{self.agent.name}] 握手成功: "
            f"{self._server_info.get('name')} {self._server_info.get('version')}"
        )

    async def _tools_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        await self._ensure_initialized()
        result = await self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        if result.get("isError"):
            raise RuntimeError(f"MCP tool error: {str(result)[:200]}")
        return result.get("content", [])

    async def analyze(self, prompt: str, system: str, temperature: float, max_tokens: int) -> str:
        content = await self._tools_call(self.agent.tool or "analyze", {
            "prompt": prompt,
            "system": system or "",
            "temperature": temperature,
            "max_tokens": max_tokens,
        })
        return _content_to_text(content)

    async def execute(self, name: str, arguments: Dict[str, Any]) -> Any:
        content = await self._tools_call(name, arguments)
        text = _content_to_text(content)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"stdout": text, "success": True}

    async def deep(self, target: str, context: Dict[str, Any], max_iterations: int) -> Any:
        return await self.execute("deep_penetrate", {
            "target": target,
            "context": context or {},
            "max_iterations": max_iterations,
        })

    async def close(self) -> None:
        if self._proc is not None and self._proc.returncode is None:
            try:
                self._proc.kill()
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except Exception:
                pass
            self._proc = None


# ============================================================
# MCP over SSE（2024-11-05 规范：GET /sse -> endpoint，POST endpoint -> message）
# ============================================================

class MCPSSEBackend(AgentBackend):
    def __init__(self, agent: RemoteAgent):
        super().__init__(agent)
        self._initialized = False
        self._client_session: Optional[aiohttp.ClientSession] = None
        self._sse_response: Optional[aiohttp.ClientResponse] = None
        self._message_endpoint: Optional[str] = None
        self._pending: Dict[int, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None
        self._server_info: Dict[str, Any] = {}
        self._capabilities: Dict[str, Any] = {}
        self._request_id = 0
        self._lock = asyncio.Lock()

    def _headers(self) -> Dict[str, str]:
        headers = {"Accept": "text/event-stream"}
        if self.agent.token:
            headers["Authorization"] = f"Bearer {self.agent.token}"
        headers.update(self.agent.extra_headers)
        return headers

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._client_session is None or self._client_session.closed:
            self._client_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.agent.timeout, connect=10),
            )
        return self._client_session

    async def _connect_sse(self) -> None:
        session = await self._get_session()
        ssl = self.agent.ssl_verify if self.agent.url.startswith("https://") else None
        timeout = aiohttp.ClientTimeout(total=None, connect=10)
        self._sse_response = await session.get(
            self.agent.url, headers=self._headers(), timeout=timeout, ssl=ssl
        )
        if self._sse_response.status >= 400:
            raise RuntimeError(f"MCP SSE 连接失败 HTTP {self._sse_response.status}")
        self._reader_task = asyncio.create_task(self._read_sse_loop())
        for _ in range(50):
            if self._message_endpoint:
                return
            await asyncio.sleep(0.1)
        raise RuntimeError("MCP SSE 未收到 endpoint 事件")

    async def _read_sse_loop(self) -> None:
        try:
            event_name = None
            data_lines: List[str] = []
            async for line in self._sse_response.content:
                line = line.decode("utf-8", errors="replace")
                if line.startswith("event:"):
                    event_name = line[len("event:"):].strip()
                    data_lines = []
                elif line.startswith("data:"):
                    data_lines.append(line[len("data:"):].strip())
                elif line.strip() == "":
                    if event_name is not None and data_lines:
                        await self._handle_sse_event(event_name, "\n".join(data_lines))
                    event_name = None
                    data_lines = []
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(f"MCP SSE Agent[{self.agent.name}] 读取循环异常: {exc}")
        finally:
            for fut in list(self._pending.values()):
                if not fut.done():
                    fut.set_exception(RuntimeError("MCP SSE 连接已断开"))
            self._pending.clear()

    async def _handle_sse_event(self, event: str, data: str) -> None:
        if event == "endpoint":
            self._message_endpoint = urllib.parse.urljoin(self.agent.url, data.strip())
            logger.debug(f"MCP SSE Agent[{self.agent.name}] endpoint: {self._message_endpoint}")
            return
        if event == "message":
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                logger.debug(f"MCP SSE Agent[{self.agent.name}] 非 JSON message: {data[:200]}")
                return
            msg_id = msg.get("id")
            if msg_id is not None and msg_id in self._pending:
                fut = self._pending.pop(msg_id)
                if not fut.done():
                    if msg.get("error"):
                        fut.set_exception(RuntimeError(f"MCP error: {msg['error']}"))
                    else:
                        fut.set_result(msg.get("result"))

    async def _ensure_connected(self) -> None:
        if self._sse_response is None or self._sse_response.closed:
            self._initialized = False
            self._message_endpoint = None
            await self._connect_sse()

    async def _rpc(self, method: str, params: Any = None) -> Any:
        await self._ensure_connected()
        if not self._message_endpoint:
            raise RuntimeError("MCP SSE message endpoint 未就绪")

        async with self._lock:
            self._request_id += 1
            req_id = self._request_id
            payload: Dict[str, Any] = {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": method,
            }
            if params is not None:
                payload["params"] = params

            loop = asyncio.get_event_loop()
            fut: asyncio.Future = loop.create_future()
            self._pending[req_id] = fut

            try:
                session = await self._get_session()
                headers = {"Content-Type": "application/json"}
                if self.agent.token:
                    headers["Authorization"] = f"Bearer {self.agent.token}"
                headers.update(self.agent.extra_headers)
                ssl = self.agent.ssl_verify if self._message_endpoint.startswith("https://") else None
                timeout = aiohttp.ClientTimeout(total=self.agent.timeout, connect=10)
                async with session.post(
                    self._message_endpoint, json=payload, headers=headers, timeout=timeout, ssl=ssl
                ) as resp:
                    if resp.status >= 400:
                        raise RuntimeError(f"MCP SSE POST 失败 HTTP {resp.status}")
                result = await asyncio.wait_for(fut, timeout=self.agent.timeout)
                return result
            finally:
                self._pending.pop(req_id, None)

    async def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        result = await self._rpc("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "vulnclaw", "version": "1.0.0"},
        })
        self._server_info = result.get("serverInfo", {})
        self._capabilities = result.get("capabilities", {})
        await self._rpc("notifications/initialized", {})
        self._initialized = True
        logger.debug(
            f"MCP SSE Agent[{self.agent.name}] 握手成功: "
            f"{self._server_info.get('name')} {self._server_info.get('version')}"
        )

    async def _tools_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        await self._ensure_initialized()
        result = await self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        if result.get("isError"):
            raise RuntimeError(f"MCP tool error: {str(result)[:200]}")
        return result.get("content", [])

    async def analyze(self, prompt: str, system: str, temperature: float, max_tokens: int) -> str:
        content = await self._tools_call(self.agent.tool or "analyze", {
            "prompt": prompt,
            "system": system or "",
            "temperature": temperature,
            "max_tokens": max_tokens,
        })
        return _content_to_text(content)

    async def execute(self, name: str, arguments: Dict[str, Any]) -> Any:
        content = await self._tools_call(name, arguments)
        text = _content_to_text(content)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"stdout": text, "success": True}

    async def deep(self, target: str, context: Dict[str, Any], max_iterations: int) -> Any:
        return await self.execute("deep_penetrate", {
            "target": target,
            "context": context or {},
            "max_iterations": max_iterations,
        })

    async def close(self) -> None:
        if self._reader_task is not None:
            self._reader_task.cancel()
            try:
                await asyncio.wait_for(self._reader_task, timeout=2)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
            self._reader_task = None
        if self._sse_response is not None:
            self._sse_response.close()
            self._sse_response = None
        if self._client_session is not None and not self._client_session.closed:
            await self._client_session.close()
            self._client_session = None


# ============================================================
# HTTP / OpenAI 兼容后端
# ============================================================

class HTTPBackend(AgentBackend):
    def __init__(self, agent: RemoteAgent):
        super().__init__(agent)
        self._client_session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._client_session is None or self._client_session.closed:
            self._client_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.agent.timeout, connect=10),
            )
        return self._client_session

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.agent.token:
            headers["Authorization"] = f"Bearer {self.agent.token}"
        headers.update(self.agent.extra_headers)
        return headers

    async def _chat(self, prompt: str, system: str, temperature: float, max_tokens: int) -> str:
        session = await self._get_session()
        url = self.agent.url.rstrip("/")
        if not url.endswith("/chat/completions"):
            url = url + "/chat/completions"
        payload = {
            "model": self.agent.model or "remote-agent",
            "messages": [
                {"role": "system", "content": system or "你是渗透测试助手。"},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        ssl = self.agent.ssl_verify if url.startswith("https://") else None
        timeout = aiohttp.ClientTimeout(total=self.agent.timeout, connect=10)
        async with session.post(url, json=payload, headers=self._headers(), timeout=timeout, ssl=ssl) as resp:
            body = await resp.json(content_type=None)
        if resp.status >= 400:
            raise RuntimeError(f"HTTP Agent 调用失败 HTTP {resp.status}: {str(body)[:200]}")
        try:
            return str(body["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError):
            raise RuntimeError(f"HTTP Agent 响应格式异常: {str(body)[:200]}")

    async def _task_post(self, path: str, payload: Any) -> Any:
        session = await self._get_session()
        url = self.agent.url.rstrip("/") + path
        ssl = self.agent.ssl_verify if url.startswith("https://") else None
        timeout = aiohttp.ClientTimeout(total=self.agent.timeout, connect=10)
        async with session.post(url, json=payload, headers=self._headers(), timeout=timeout, ssl=ssl) as resp:
            body = await resp.json(content_type=None)
        if resp.status >= 400:
            raise RuntimeError(f"HTTP Agent POST {path} 失败 HTTP {resp.status}: {str(body)[:200]}")
        return body

    async def analyze(self, prompt: str, system: str, temperature: float, max_tokens: int) -> str:
        return await self._chat(prompt, system, temperature, max_tokens)

    async def execute(self, name: str, arguments: Dict[str, Any]) -> Any:
        return await self._task_post(f"/tasks/{name}/run", arguments or {})

    async def deep(self, target: str, context: Dict[str, Any], max_iterations: int) -> Any:
        return await self._task_post("/deep", {"target": target, "context": context or {}, "max_iterations": max_iterations})

    async def close(self) -> None:
        if self._client_session is not None and not self._client_session.closed:
            await self._client_session.close()
            self._client_session = None


# ============================================================
# CLI 子进程后端
# ============================================================

class CLIBackend(AgentBackend):
    async def _run(self, command: str, stdin: Optional[bytes] = None) -> bytes:
        if not command:
            raise RuntimeError("CLI 后端未配置 command")
        # Windows 路径含反斜杠，POSIX 模式会错误转义；非 Windows 仍用 POSIX
        tokens = shlex.split(command, posix=(sys.platform != "win32"))
        proc = await asyncio.create_subprocess_exec(
            *tokens,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(stdin), self.agent.timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            raise RuntimeError(f"CLI Agent 超时（{self.agent.timeout}s）")
        if proc.returncode != 0:
            raise RuntimeError(
                f"CLI Agent 退出码 {proc.returncode}: {(stderr or b'').decode('utf-8', 'replace')[:200]}"
            )
        return stdout

    async def analyze(self, prompt: str, system: str, temperature: float, max_tokens: int) -> str:
        command = self.agent.command
        if "{prompt}" in command:
            command = command.replace("{prompt}", prompt)
            stdout = await self._run(command)
        else:
            payload = f"{system}\n\n{prompt}" if system else prompt
            stdout = await self._run(command, payload.encode("utf-8", errors="replace"))
        return stdout.decode("utf-8", errors="replace").strip()

    async def execute(self, name: str, arguments: Dict[str, Any]) -> Any:
        command = self.agent.command
        payload_json = json.dumps(arguments or {}, ensure_ascii=False)
        if "{task}" in command or "{payload}" in command:
            command = command.replace("{task}", name or "").replace("{payload}", payload_json)
            stdout = await self._run(command)
        else:
            payload = json.dumps({"task": name, "payload": arguments or {}}, ensure_ascii=False)
            stdout = await self._run(command, payload.encode("utf-8", errors="replace"))
        text = stdout.decode("utf-8", errors="replace").strip()
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"stdout": text, "success": True}
        return {"stdout": "", "success": True}

    async def deep(self, target: str, context: Dict[str, Any], max_iterations: int) -> Any:
        return await self.execute("deep_penetrate", {
            "target": target,
            "context": context or {},
            "max_iterations": max_iterations,
        })

    async def close(self) -> None:
        pass


# ============================================================
# Backend 工厂 & 缓存
# ============================================================

_backend_cache: Dict[str, AgentBackend] = {}
_backend_lock = asyncio.Lock()


def _create_backend(agent: RemoteAgent) -> AgentBackend:
    if agent.type == "mcp":
        if agent.transport == "stdio":
            return MCPStdioBackend(agent)
        if agent.transport == "sse":
            return MCPSSEBackend(agent)
        return MCPHttpBackend(agent)
    if agent.type == "http":
        return HTTPBackend(agent)
    if agent.type == "cli":
        return CLIBackend(agent)
    raise RuntimeError(f"未知 Agent 类型: {agent.type}")


async def _get_backend(agent: RemoteAgent) -> AgentBackend:
    async with _backend_lock:
        backend = _backend_cache.get(agent.name)
        if backend is None:
            backend = _create_backend(agent)
            _backend_cache[agent.name] = backend
        return backend


async def close_remote_agents() -> None:
    """释放所有远程 Agent 后端（应用退出时调用）。"""
    global _backend_cache
    async with _backend_lock:
        for backend in list(_backend_cache.values()):
            try:
                await backend.close()
            except Exception as exc:
                logger.warning(f"关闭远程 Agent 后端失败: {exc}")
        _backend_cache.clear()


# ============================================================
# 统一委派入口
# ============================================================

async def delegate_analysis(
    prompt: str,
    system: str = "你是渗透测试助手。",
    temperature: float = 0.2,
    max_tokens: int = 500,
) -> Optional[str]:
    """把一次分析任务委派给已配置的远程 Agent（逐个尝试，首个成功即返回）。

    未配置任何远程 Agent / 全部失败 -> 返回 None，调用方回退本地逻辑。
    """
    agents = get_remote_agents()
    if not agents:
        return None
    last_error = None
    for agent in agents:
        try:
            backend = await _get_backend(agent)
            text = await backend.analyze(prompt, system, temperature, max_tokens)
            if text:
                logger.info(f"远程 Agent[{agent.name}]({agent.type}/{agent.transport}) 委派成功")
                return text
            last_error = RuntimeError(f"Agent[{agent.name}] 返回空结果")
        except Exception as exc:
            last_error = exc
            logger.warning(f"远程 Agent[{agent.name}]({agent.type}/{agent.transport}) 委派失败: {exc}")
    if last_error:
        logger.warning(f"远程 Agent 全部不可用，本次委派回退本地逻辑: {last_error}")
    return None


def run_remote_analysis(
    prompt: str,
    system: str = "你是渗透测试助手。",
    temperature: float = 0.2,
    max_tokens: int = 500,
) -> Optional[str]:
    """同步版委派入口（内部跑事件循环）。"""
    try:
        return asyncio.run(
            delegate_analysis(prompt=prompt, system=system, temperature=temperature, max_tokens=max_tokens)
        )
    except RuntimeError:
        return None


async def delegate_task(
    name: str,
    arguments: Optional[Dict[str, Any]] = None,
    agent_name: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """把一次工具/任务调用委派给已配置的远程 Agent（逐个尝试，首个成功即返回）。

    未配置任何远程 Agent / 全部失败 -> 返回 None，调用方回退本地逻辑。
    """
    agents = get_remote_agents()
    if not agents:
        return None
    if agent_name:
        agents = [a for a in agents if a.name == agent_name]
        if not agents:
            logger.warning(f"未找到指定远程 Agent: {agent_name}")
            return None
    last_error = None
    for agent in agents:
        try:
            backend = await _get_backend(agent)
            result = await backend.execute(name, arguments or {})
            logger.info(f"远程 Agent[{agent.name}]({agent.type}/{agent.transport}) 任务 {name} 委派成功")
            return _normalize_remote_result(result)
        except Exception as exc:
            last_error = exc
            logger.warning(f"远程 Agent[{agent.name}]({agent.type}/{agent.transport}) 任务 {name} 委派失败: {exc}")
    if last_error:
        logger.warning(f"远程 Agent 任务 {name} 全部不可用，回退本地逻辑: {last_error}")
    return None


async def delegate_deep(
    target: str,
    context: Optional[Dict[str, Any]] = None,
    max_iterations: int = 10,
    agent_name: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """把单点深度渗透任务委派给远程 Agent（逐个尝试，首个成功即返回）。"""
    agents = get_remote_agents()
    if not agents:
        return None
    if agent_name:
        agents = [a for a in agents if a.name == agent_name]
        if not agents:
            logger.warning(f"未找到指定远程 Agent: {agent_name}")
            return None
    last_error = None
    for agent in agents:
        try:
            backend = await _get_backend(agent)
            result = await backend.deep(target, context or {}, max_iterations)
            logger.info(f"远程 Agent[{agent.name}]({agent.type}/{agent.transport}) 深度渗透 {target} 委派成功")
            return _normalize_remote_result(result)
        except Exception as exc:
            last_error = exc
            logger.warning(f"远程 Agent[{agent.name}]({agent.type}/{agent.transport}) 深度渗透 {target} 委派失败: {exc}")
    if last_error:
        logger.warning(f"远程 Agent 深度渗透 {target} 全部不可用，回退本地逻辑: {last_error}")
    return None
