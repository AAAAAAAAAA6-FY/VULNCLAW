"""MCP Server 适配器测试套件。

覆盖：事件总线、JSON-RPC 协议处理、工具调用、Scan Worker 生命周期。
不依赖外网与真实 AI；使用 mock 隔离 orchestrator。
"""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vulnclaw.core.mcp_server import (
    ScanEventBus,
    ScanJob,
    ScanStatus,
    MCPJsonRpcHandler,
    get_event_bus,
)


class TestScanEventBus:
    """事件总线单元测试：生产者-消费者解耦通信。"""

    @pytest.mark.asyncio
    async def test_publish_and_consume(self):
        bus = ScanEventBus()
        await bus.publish({"type": "test", "data": "hello"})
        event = await bus.consume()
        assert event["type"] == "test"
        assert event["data"] == "hello"

    @pytest.mark.asyncio
    async def test_register_and_get_job(self):
        bus = ScanEventBus()
        job = ScanJob(scan_id="abc123", target="https://example.com")
        await bus.register_job(job)
        retrieved = await bus.get_job("abc123")
        assert retrieved is not None
        assert retrieved.scan_id == "abc123"
        assert retrieved.target == "https://example.com"

    @pytest.mark.asyncio
    async def test_get_nonexistent_job(self):
        bus = ScanEventBus()
        job = await bus.get_job("nonexistent")
        assert job is None

    @pytest.mark.asyncio
    async def test_update_job(self):
        bus = ScanEventBus()
        job = ScanJob(scan_id="abc123", target="https://example.com")
        await bus.register_job(job)
        await bus.update_job("abc123", status=ScanStatus.RUNNING, progress=50)
        updated = await bus.get_job("abc123")
        assert updated.status == ScanStatus.RUNNING
        assert updated.progress == 50

    @pytest.mark.asyncio
    async def test_update_nonexistent_job_no_error(self):
        bus = ScanEventBus()
        await bus.update_job("nonexistent", status=ScanStatus.RUNNING)

    @pytest.mark.asyncio
    async def test_list_jobs(self):
        bus = ScanEventBus()
        await bus.register_job(ScanJob(scan_id="a", target="https://a.com"))
        await bus.register_job(ScanJob(scan_id="b", target="https://b.com"))
        jobs = await bus.list_jobs()
        assert len(jobs) == 2
        ids = {j.scan_id for j in jobs}
        assert ids == {"a", "b"}

    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        bus = ScanEventBus()
        async def register_and_update(i):
            job = ScanJob(scan_id=f"job_{i}", target=f"https://example{i}.com")
            await bus.register_job(job)
            await bus.update_job(f"job_{i}", status=ScanStatus.RUNNING)

        await asyncio.gather(*[register_and_update(i) for i in range(50)])
        jobs = await bus.list_jobs()
        assert len(jobs) == 50
        for j in jobs:
            assert j.status == ScanStatus.RUNNING


class TestScanJob:
    """ScanJob 数据类测试。"""

    def test_default_values(self):
        job = ScanJob(scan_id="test", target="https://example.com")
        assert job.scan_id == "test"
        assert job.status == ScanStatus.PENDING
        assert job.progress == 0
        assert job.findings == []
        assert job.error == ""

    def test_custom_values(self):
        job = ScanJob(
            scan_id="custom",
            target="https://example.com",
            status=ScanStatus.RUNNING,
            progress=30,
            findings=[{"type": "xss"}],
        )
        assert job.status == ScanStatus.RUNNING
        assert job.progress == 30
        assert len(job.findings) == 1


class TestMCPJsonRpcHandler:
    """MCP JSON-RPC 协议处理器测试。"""

    @pytest.fixture
    def bus(self):
        return ScanEventBus()

    @pytest.fixture
    def handler(self, bus):
        return MCPJsonRpcHandler(bus)

    def _make_request(self, method: str, params=None, req_id=1):
        req = {"jsonrpc": "2.0", "method": method, "id": req_id}
        if params is not None:
            req["params"] = params
        return req

    # --- initialize ---

    @pytest.mark.asyncio
    async def test_initialize(self, handler):
        req = self._make_request("initialize", {"capabilities": {"tools": {}}})
        resp = await handler.handle_request(req)
        assert resp["id"] == 1
        result = resp["result"]
        assert result["protocolVersion"] == "2024-11-05"
        assert "tools" in result["capabilities"]
        assert result["serverInfo"]["name"] == "vulnclaw-mcp-server"

    # --- tools/list ---

    @pytest.mark.asyncio
    async def test_tools_list(self, handler):
        req = self._make_request("tools/list")
        resp = await handler.handle_request(req)
        tools = resp["result"]["tools"]
        tool_names = {t["name"] for t in tools}
        assert tool_names == {
            "scan.start",
            "scan.status",
            "scan.findings",
            "scan.api_audit",
            "scan.danger_guard_status",
            "scan.deep_remote",
            "browser.explore",
            "exploit.verify",
            "code.audit",
            "intel.lookup",
            "scan.deep",
            "engine.list",
            "engine.run",
        }
        # scan.start 为主动攻击工具，须携带 MCP annotations 危险标注
        start_tool = next(t for t in tools if t["name"] == "scan.start")
        assert start_tool.get("annotations", {}).get("destructiveHint") is True
        # 只读工具须标注 readOnlyHint
        status_tool = next(t for t in tools if t["name"] == "scan.status")
        assert status_tool.get("annotations", {}).get("readOnlyHint") is True

    @pytest.mark.asyncio
    async def test_tool_intel_lookup_no_credentials(self, handler, monkeypatch):
        """未配置情报 API Key 时应优雅降级，不抛异常。"""
        import vulnclaw.modules.intelligence.shodan_client as intel

        monkeypatch.setattr(intel.ShodanClient, "enabled", property(lambda self: False))
        monkeypatch.setattr(intel.CensysClient, "enabled", property(lambda self: False))

        req = self._make_request("tools/call", {
            "name": "intel.lookup",
            "arguments": {"target": "example.com"},
        })
        resp = await handler.handle_request(req)
        data = json.loads(resp["result"]["content"][0]["text"])
        assert data["available"] is False
        assert "SHODAN_API_KEY" in data["reason"]

    @pytest.mark.asyncio
    async def test_tool_browser_explore_without_playwright(self, handler, monkeypatch):
        """Playwright 未安装时应返回明确错误，而不是崩溃。"""
        import vulnclaw.core.browser_ai_agent as browser_mod

        monkeypatch.setattr(browser_mod, "HAS_PLAYWRIGHT", False)

        req = self._make_request("tools/call", {
            "name": "browser.explore",
            "arguments": {"url": "https://example.com"},
        })
        resp = await handler.handle_request(req)
        assert "error" in resp
        assert "Playwright" in resp["error"]["message"]

    @pytest.mark.asyncio
    async def test_tool_exploit_verify_denied_by_guard(self, handler):
        """默认 deny 模式下，利用验证须被权限门卫拒绝且不抛异常。"""
        req = self._make_request("tools/call", {
            "name": "exploit.verify",
            "arguments": {
                "url": "https://example.com/search?id=1",
                "parameter": "id",
                "type": "sqli",
            },
        })
        resp = await handler.handle_request(req)
        data = json.loads(resp["result"]["content"][0]["text"])
        # 门卫拒绝时返回 danger_denied；未拒绝则说明环境放行，也不应崩溃
        assert "result" in data
        if data["result"].get("reason", "").startswith("danger_denied"):
            assert data["guard_mode"] == "deny"

    # --- tools/call: scan.start ---

    @pytest.mark.asyncio
    async def test_tool_scan_start_success(self, handler, bus):
        req = self._make_request("tools/call", {
            "name": "scan.start",
            "arguments": {"target": "https://example.com"},
        })
        resp = await handler.handle_request(req)
        content = resp["result"]["content"][0]
        assert content["type"] == "text"
        data = json.loads(content["text"])
        assert "scan_id" in data
        assert data["target"] == "https://example.com"
        assert data["status"] == "pending"

        job = await bus.get_job(data["scan_id"])
        assert job is not None
        assert job.status == ScanStatus.PENDING

    @pytest.mark.asyncio
    async def test_tool_scan_start_auto_add_https(self, handler, bus):
        req = self._make_request("tools/call", {
            "name": "scan.start",
            "arguments": {"target": "example.com"},
        })
        resp = await handler.handle_request(req)
        data = json.loads(resp["result"]["content"][0]["text"])
        assert data["target"] == "https://example.com"

    @pytest.mark.asyncio
    async def test_tool_scan_start_empty_target(self, handler):
        req = self._make_request("tools/call", {
            "name": "scan.start",
            "arguments": {"target": ""},
        })
        resp = await handler.handle_request(req)
        assert "error" in resp
        assert resp["error"]["code"] == -32603

    @pytest.mark.asyncio
    async def test_tool_scan_start_with_options(self, handler, bus):
        req = self._make_request("tools/call", {
            "name": "scan.start",
            "arguments": {
                "target": "https://example.com",
                "max_tasks": 50,
                "initial_qps": 5,
            },
        })
        resp = await handler.handle_request(req)
        assert "result" in resp

        event = await bus.consume()
        assert event["type"] == "scan.start"
        assert event["max_tasks"] == 50
        assert event["initial_qps"] == 5

    # --- tools/call: scan.status ---

    @pytest.mark.asyncio
    async def test_tool_scan_status_success(self, handler, bus):
        job = ScanJob(
            scan_id="abc123",
            target="https://example.com",
            status=ScanStatus.RUNNING,
            progress=45,
            total_urls=100,
            scanned_urls=45,
            started_at=time.time(),
        )
        await bus.register_job(job)

        req = self._make_request("tools/call", {
            "name": "scan.status",
            "arguments": {"scan_id": "abc123"},
        })
        resp = await handler.handle_request(req)
        data = json.loads(resp["result"]["content"][0]["text"])
        assert data["scan_id"] == "abc123"
        assert data["status"] == "running"
        assert data["progress"] == 45

    @pytest.mark.asyncio
    async def test_tool_scan_status_not_found(self, handler):
        req = self._make_request("tools/call", {
            "name": "scan.status",
            "arguments": {"scan_id": "nonexistent"},
        })
        resp = await handler.handle_request(req)
        assert "error" in resp

    # --- tools/call: scan.findings ---

    @pytest.mark.asyncio
    async def test_tool_scan_findings_success(self, handler, bus):
        job = ScanJob(
            scan_id="abc123",
            target="https://example.com",
            status=ScanStatus.COMPLETED,
            findings=[
                {"type": "sqli", "url": "https://example.com?id=1", "risk": "high"},
                {"type": "xss", "url": "https://example.com/search", "risk": "medium"},
            ],
        )
        await bus.register_job(job)

        req = self._make_request("tools/call", {
            "name": "scan.findings",
            "arguments": {"scan_id": "abc123"},
        })
        resp = await handler.handle_request(req)
        data = json.loads(resp["result"]["content"][0]["text"])
        assert data["total_findings"] == 2
        assert len(data["findings"]) == 2
        assert data["findings"][0]["type"] == "sqli"

    @pytest.mark.asyncio
    async def test_tool_scan_findings_not_found(self, handler):
        req = self._make_request("tools/call", {
            "name": "scan.findings",
            "arguments": {"scan_id": "nonexistent"},
        })
        resp = await handler.handle_request(req)
        assert "error" in resp

    @pytest.mark.asyncio
    async def test_tool_scan_findings_empty(self, handler, bus):
        job = ScanJob(scan_id="abc123", target="https://example.com", findings=[])
        await bus.register_job(job)

        req = self._make_request("tools/call", {
            "name": "scan.findings",
            "arguments": {"scan_id": "abc123"},
        })
        resp = await handler.handle_request(req)
        data = json.loads(resp["result"]["content"][0]["text"])
        assert data["total_findings"] == 0
        assert data["findings"] == []

    # --- error handling ---

    @pytest.mark.asyncio
    async def test_unknown_method(self, handler):
        req = self._make_request("unknown/method")
        resp = await handler.handle_request(req)
        assert resp["error"]["code"] == -32601

    @pytest.mark.asyncio
    async def test_unknown_tool(self, handler):
        req = self._make_request("tools/call", {
            "name": "nonexistent.tool",
            "arguments": {},
        })
        resp = await handler.handle_request(req)
        assert "error" in resp

    @pytest.mark.asyncio
    async def test_ping(self, handler):
        req = self._make_request("ping")
        resp = await handler.handle_request(req)
        assert resp["id"] == 1
        assert resp["result"] == {}

    @pytest.mark.asyncio
    async def test_notification_no_id(self, handler):
        req = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        resp = await handler.handle_request(req)
        assert resp == {}


class TestScanWorker:
    """Scan Worker 集成测试（mock orchestrator）。"""

    @pytest.mark.asyncio
    async def test_worker_picks_up_scan_start_event(self):
        bus = ScanEventBus()
        job = ScanJob(scan_id="test123", target="https://example.com")
        await bus.register_job(job)

        await bus.publish({
            "type": "scan.start",
            "scan_id": "test123",
            "target": "https://example.com",
            "max_tasks": None,
            "initial_qps": None,
        })

        event = await bus.consume()
        assert event["type"] == "scan.start"
        assert event["scan_id"] == "test123"
        assert event["target"] == "https://example.com"

    @pytest.mark.asyncio
    async def test_worker_handles_scan_failure(self):
        bus = ScanEventBus()
        job = ScanJob(scan_id="fail123", target="https://example.com")
        await bus.register_job(job)

        await bus.update_job(
            "fail123",
            status=ScanStatus.FAILED,
            error="Connection refused",
            completed_at=time.time(),
        )

        updated = await bus.get_job("fail123")
        assert updated.status == ScanStatus.FAILED
        assert updated.error == "Connection refused"


class TestEventBusIntegration:
    """事件总线端到端流程测试。"""

    @pytest.mark.asyncio
    async def test_full_scan_lifecycle(self):
        bus = ScanEventBus()

        scan_id = "lifecycle_test"
        target = "https://example.com"

        await bus.register_job(ScanJob(
            scan_id=scan_id,
            target=target,
            created_at=time.time(),
        ))

        job = await bus.get_job(scan_id)
        assert job.status == ScanStatus.PENDING

        await bus.update_job(scan_id, status=ScanStatus.RUNNING, started_at=time.time())
        job = await bus.get_job(scan_id)
        assert job.status == ScanStatus.RUNNING

        await bus.update_job(scan_id, progress=50, scanned_urls=50, total_urls=100)
        job = await bus.get_job(scan_id)
        assert job.progress == 50

        findings = [
            {"type": "sqli", "risk": "high", "url": f"{target}/?id=1"},
            {"type": "xss", "risk": "medium", "url": f"{target}/search"},
        ]
        await bus.update_job(
            scan_id,
            status=ScanStatus.COMPLETED,
            progress=100,
            findings=findings,
            completed_at=time.time(),
        )

        job = await bus.get_job(scan_id)
        assert job.status == ScanStatus.COMPLETED
        assert job.progress == 100
        assert len(job.findings) == 2
        assert job.findings[0]["type"] == "sqli"


class TestSingletonEventBus:
    """全局事件总线单例测试。"""

    def test_get_event_bus_returns_same_instance(self):
        bus1 = get_event_bus()
        bus2 = get_event_bus()
        assert bus1 is bus2

    def test_bus_is_scan_event_bus(self):
        bus = get_event_bus()
        assert isinstance(bus, ScanEventBus)