"""远程 AI Agent 统一适配器冒烟测试。

覆盖 5 种后端：MCP over HTTP、MCP over stdio、MCP over SSE、HTTP(OpenAI 兼容)、CLI。
所有测试使用本地 mock server/子进程，不依赖外网与真实 AI。
"""

import asyncio
import json
import socket
import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import aiohttp
import pytest
from aiohttp import web

from vulnclaw.ai.remote_agents import (
    CLIBackend,
    HTTPBackend,
    MCPHttpBackend,
    MCPStdioBackend,
    MCPSSEBackend,
    RemoteAgent,
    _validate_agent,
    close_remote_agents,
    delegate_analysis,
    delegate_deep,
    delegate_task,
    get_remote_agents,
)


# ============================================================
# 辅助函数
# ============================================================

def _free_port() -> int:
    """获取一个空闲端口。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _start_mock_server(app: web.Application) -> tuple[str, Any]:
    """启动本地 aiohttp mock server，返回 (base_url, runner)。"""
    port = _free_port()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    return f"http://127.0.0.1:{port}", runner


# ============================================================
# 配置解析测试
# ============================================================

class TestConfigValidation:
    def test_local_mcp_http_no_token_ok(self):
        agent = _validate_agent({"name": "local", "type": "mcp", "url": "http://127.0.0.1:8765/mcp"})
        assert agent is not None
        assert agent.name == "local"
        assert agent.transport == "http"

    def test_remote_mcp_requires_token(self):
        agent = _validate_agent({"name": "remote", "type": "mcp", "url": "http://example.com/mcp"})
        assert agent is None

    def test_remote_mcp_with_token_ok(self):
        agent = _validate_agent({"name": "remote", "type": "mcp", "url": "https://example.com/mcp", "token": "secret"})
        assert agent is not None
        assert agent.token == "secret"

    def test_mcp_stdio_requires_command(self):
        agent = _validate_agent({"name": "bad", "type": "mcp", "transport": "stdio"})
        assert agent is None

    def test_mcp_stdio_ok(self):
        agent = _validate_agent({"name": "stdio", "type": "mcp", "transport": "stdio", "command": "python"})
        assert agent is not None
        assert agent.transport == "stdio"

    def test_unknown_type_ignored(self):
        agent = _validate_agent({"name": "x", "type": "ws"})
        assert agent is None

    @patch("vulnclaw.ai.remote_agents.settings")
    def test_get_remote_agents_from_settings(self, mock_settings):
        mock_settings.remote_agents = [
            {"name": "a", "type": "http", "url": "http://127.0.0.1:1/v1"},
            {"name": "b", "type": "cli", "command": "echo"},
        ]
        agents = get_remote_agents()
        assert len(agents) == 2
        assert {a.name for a in agents} == {"a", "b"}


# ============================================================
# MCP over HTTP 测试
# ============================================================

async def _mcp_http_handler(request: web.Request) -> web.Response:
    body = await request.json()
    method = body.get("method")
    req_id = body.get("id")
    headers = {"Content-Type": "application/json"}
    if method == "initialize":
        result = {"serverInfo": {"name": "mock-http", "version": "1.0"}, "capabilities": {}}
    elif method == "notifications/initialized":
        result = None
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "mcp-http-ok"}]}
    else:
        return web.Response(
            text=json.dumps({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "not found"}}),
            headers=headers,
        )
    return web.Response(
        text=json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}),
        headers=headers,
    )


class TestMCPHttpBackend:
    @pytest.mark.asyncio
    async def test_analyze(self):
        app = web.Application()
        app.router.add_post("/mcp", _mcp_http_handler)
        base_url, runner = await _start_mock_server(app)
        try:
            agent = RemoteAgent(name="mcp-http", type="mcp", url=base_url + "/mcp")
            backend = MCPHttpBackend(agent)
            text = await backend.analyze("hello", "system", 0.2, 100)
            assert text == "mcp-http-ok"
            await backend.close()
        finally:
            await runner.cleanup()

    @pytest.mark.asyncio
    async def test_execute(self):
        app = web.Application()
        app.router.add_post("/mcp", _mcp_http_handler)
        base_url, runner = await _start_mock_server(app)
        try:
            agent = RemoteAgent(name="mcp-http", type="mcp", url=base_url + "/mcp")
            backend = MCPHttpBackend(agent)
            result = await backend.execute("nuclei", {"target": "http://t"})
            assert result == {"stdout": "mcp-http-ok", "success": True}
            await backend.close()
        finally:
            await runner.cleanup()


# ============================================================
# MCP over stdio 测试
# ============================================================

def _write_stdio_mock(tmp_path: Path) -> Path:
    script = tmp_path / "mcp_stdio_mock.py"
    script.write_text(
        "import sys, json\n"
        "for line in sys.stdin:\n"
        "    msg = json.loads(line)\n"
        "    method, req_id = msg.get('method'), msg.get('id')\n"
        "    if method == 'initialize':\n"
        "        result = {'serverInfo': {'name': 'mock-stdio', 'version': '1.0'}, 'capabilities': {}}\n"
        "    elif method == 'notifications/initialized':\n"
        "        result = None\n"
        "    elif method == 'tools/call':\n"
        "        result = {'content': [{'type': 'text', 'text': 'mcp-stdio-ok'}]}\n"
        "    else:\n"
        "        result = {'code': -32601, 'message': 'not found'}\n"
        "    print(json.dumps({'jsonrpc': '2.0', 'id': req_id, 'result': result}), flush=True)\n",
        encoding="utf-8",
    )
    return script


class TestMCPStdioBackend:
    @pytest.mark.asyncio
    async def test_analyze(self, tmp_path):
        script = _write_stdio_mock(tmp_path)
        agent = RemoteAgent(name="mcp-stdio", type="mcp", transport="stdio", command=sys.executable, args=[str(script)])
        backend = MCPStdioBackend(agent)
        try:
            text = await backend.analyze("hello", "system", 0.2, 100)
            assert text == "mcp-stdio-ok"
        finally:
            await backend.close()


# ============================================================
# MCP over SSE 测试
# ============================================================

async def _sse_handler(request: web.Request) -> web.StreamResponse:
    resp = web.StreamResponse(
        status=200,
        headers={"Content-Type": "text/event-stream"},
    )
    await resp.prepare(request)
    resp.write(b"event: endpoint\ndata: /messages\n\n")
    await resp.drain()
    # 保持连接，等待后续 message 请求触发响应
    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        raise


async def _sse_messages_handler(request: web.Request) -> web.Response:
    body = await request.json()
    method = body.get("method")
    req_id = body.get("id")
    request.app["last_request"] = body
    if method == "initialize":
        result = {"serverInfo": {"name": "mock-sse", "version": "1.0"}, "capabilities": {}}
    elif method == "notifications/initialized":
        result = None
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "mcp-sse-ok"}]}
    else:
        result = {"code": -32601, "message": "not found"}

    # 通过 SSE 推送响应
    sse_payload = json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})
    # 这里不能直接推，因为 SSE handler 在另一个连接上。我们使用 app 级队列传递。
    queue: asyncio.Queue = request.app["sse_queue"]
    await queue.put(sse_payload)
    return web.Response(status=202, text="accepted")


async def _sse_reader(app: web.Application, resp: web.StreamResponse) -> None:
    queue: asyncio.Queue = app["sse_queue"]
    try:
        while True:
            payload = await asyncio.wait_for(queue.get(), timeout=30)
            await resp.write(f"event: message\ndata: {payload}\n\n".encode("utf-8"))
    except asyncio.TimeoutError:
        pass


async def _sse_handler_v2(request: web.Request) -> web.StreamResponse:
    resp = web.StreamResponse(
        status=200,
        headers={"Content-Type": "text/event-stream"},
    )
    await resp.prepare(request)
    await resp.write(b"event: endpoint\ndata: /messages\n\n")
    await _sse_reader(request.app, resp)
    return resp


class TestMCPSSEBackend:
    @pytest.mark.asyncio
    async def test_analyze(self):
        app = web.Application()
        app["sse_queue"] = asyncio.Queue()
        app.router.add_get("/sse", _sse_handler_v2)
        app.router.add_post("/messages", _sse_messages_handler)
        base_url, runner = await _start_mock_server(app)
        try:
            agent = RemoteAgent(name="mcp-sse", type="mcp", transport="sse", url=base_url + "/sse")
            backend = MCPSSEBackend(agent)
            try:
                text = await backend.analyze("hello", "system", 0.2, 100)
                assert text == "mcp-sse-ok"
            finally:
                await backend.close()
        finally:
            await runner.cleanup()


# ============================================================
# HTTP / OpenAI 兼容后端测试
# ============================================================

async def _openai_chat_handler(request: web.Request) -> web.Response:
    return web.json_response({
        "choices": [{"message": {"content": "http-openai-ok"}}],
    })


async def _openai_task_handler(request: web.Request) -> web.Response:
    body = await request.json()
    return web.json_response({"task": request.match_info["name"], "args": body})


async def _openai_deep_handler(request: web.Request) -> web.Response:
    body = await request.json()
    return web.json_response({"target": body.get("target"), "deep": True})


class TestHTTPBackend:
    @pytest.mark.asyncio
    async def test_analyze(self):
        app = web.Application()
        app.router.add_post("/v1/chat/completions", _openai_chat_handler)
        base_url, runner = await _start_mock_server(app)
        try:
            agent = RemoteAgent(name="http", type="http", url=base_url + "/v1")
            backend = HTTPBackend(agent)
            text = await backend.analyze("hello", "system", 0.2, 100)
            assert text == "http-openai-ok"
            await backend.close()
        finally:
            await runner.cleanup()

    @pytest.mark.asyncio
    async def test_execute_and_deep(self):
        app = web.Application()
        app.router.add_post("/v1/tasks/{name}/run", _openai_task_handler)
        app.router.add_post("/v1/deep", _openai_deep_handler)
        base_url, runner = await _start_mock_server(app)
        try:
            agent = RemoteAgent(name="http", type="http", url=base_url + "/v1")
            backend = HTTPBackend(agent)
            result = await backend.execute("nuclei", {"target": "http://t"})
            assert result["task"] == "nuclei"
            deep = await backend.deep("http://t", {}, 5)
            assert deep["deep"] is True
            await backend.close()
        finally:
            await runner.cleanup()


# ============================================================
# CLI 后端测试
# ============================================================

def _write_cli_mock(tmp_path: Path, use_prompt_placeholder: bool = True) -> Path:
    script = tmp_path / "cli_mock.py"
    if use_prompt_placeholder:
        code = (
            "import sys\n"
            "print('cli-ok:' + sys.argv[sys.argv.index('--prompt') + 1], flush=True)\n"
        )
    else:
        code = (
            "import sys\n"
            "data = sys.stdin.read()\n"
            "print('cli-stdin:' + data.strip()[-20:], flush=True)\n"
        )
    script.write_text(code, encoding="utf-8")
    return script


def _write_cli_execute_mock(tmp_path: Path) -> Path:
    script = tmp_path / "cli_exec_mock.py"
    script.write_text(
        "import sys\n"
        "idx = sys.argv.index('--payload')\n"
        "payload_str = sys.argv[idx + 1]\n"
        "task = sys.argv[idx - 1]\n"
        "print('cli-task:' + task + '|payload:' + payload_str, flush=True)\n",
        encoding="utf-8",
    )
    return script


class TestCLIBackend:
    @pytest.mark.asyncio
    async def test_analyze_with_placeholder(self, tmp_path):
        script = _write_cli_mock(tmp_path, use_prompt_placeholder=True)
        agent = RemoteAgent(name="cli", type="cli", command=f"{sys.executable} {script} --prompt {{prompt}}")
        backend = CLIBackend(agent)
        text = await backend.analyze("hello", "system", 0.2, 100)
        assert text == "cli-ok:hello"

    @pytest.mark.asyncio
    async def test_analyze_with_stdin(self, tmp_path):
        script = _write_cli_mock(tmp_path, use_prompt_placeholder=False)
        agent = RemoteAgent(name="cli", type="cli", command=f"{sys.executable} {script}")
        backend = CLIBackend(agent)
        text = await backend.analyze("hello", "system", 0.2, 100)
        assert "cli-stdin:" in text

    @pytest.mark.asyncio
    async def test_execute(self, tmp_path):
        script = _write_cli_execute_mock(tmp_path)
        # 外层单引号保护 JSON，避免 Windows shlex 在 payload 内部空格处拆分
        agent = RemoteAgent(
            name="cli", type="cli",
            command=f"{sys.executable} {script} --task {{task}} --payload '{{payload}}'"
        )
        backend = CLIBackend(agent)
        result = await backend.execute("nuclei", {"target": "http://t"})
        assert result["stdout"].startswith("cli-task:nuclei|payload:{\"target\": \"http://t\"}")


# ============================================================
# 统一委派入口测试
# ============================================================

class TestDelegation:
    @pytest.mark.asyncio
    async def test_delegate_analysis_no_agents(self):
        with patch("vulnclaw.ai.remote_agents.settings") as mock_settings:
            mock_settings.remote_agents = []
            result = await delegate_analysis("prompt")
            assert result is None

    @pytest.mark.asyncio
    async def test_delegate_task_no_agents(self):
        with patch("vulnclaw.ai.remote_agents.settings") as mock_settings:
            mock_settings.remote_agents = []
            result = await delegate_task("nuclei", {})
            assert result is None

    @pytest.mark.asyncio
    async def test_delegate_deep_no_agents(self):
        with patch("vulnclaw.ai.remote_agents.settings") as mock_settings:
            mock_settings.remote_agents = []
            result = await delegate_deep("http://t")
            assert result is None

    @pytest.mark.asyncio
    async def test_close_remote_agents_safe(self):
        await close_remote_agents()
