# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""workflow7 生态/API：webhook 路由 + SDK 客户端离线验收。

全部离线确定性：用 fastapi TestClient 走 ASGI（不联网）；SDK 仅构造请求不发送。
webhook feed 写到 tmp_path 下的缓存目录，测试后由 tmp_path 自动清理。
"""
import asyncio
import json

import pytest

from vulnclaw.dashboard import server as _server
from vulnclaw.dashboard.server import DashboardServer
from vulnclaw.client import DashboardClient, build_payload
from vulnclaw.core.interop import export_jsonl, UnifiedFinding

NUCLEI_SAMPLE = json.dumps({
    "template-id": "CVE-2021-44228",
    "info": {"name": "Log4Shell", "severity": "critical", "description": "JNDI"},
    "type": "http",
    "host": "t.example",
    "matched-at": "http://t.example/api",
})


def _finding(**kw):
    base = dict(source="vulnclaw", scanner="vulnclaw", rule_id="r1", title="SQL注入",
                severity="high", confidence="medium", url="http://t.example/a?id=1",
                method="GET", parameter="id", evidence="SQL syntax error")
    base.update(kw)
    return UnifiedFinding(**base)


def _secret_client(monkeypatch, tmp_path, token="sekrit"):
    monkeypatch.setattr(_server, "PROJECT_CACHE_DIR", str(tmp_path))
    srv = DashboardServer()
    srv._token = token
    from fastapi.testclient import TestClient
    return TestClient(srv.create_app())


# ============================================================
# 入站 webhook
# ============================================================
class TestWebhookIngest:
    def test_unauthorized(self, monkeypatch, tmp_path):
        c = _secret_client(monkeypatch, tmp_path)
        r = c.post("/api/webhook/ingest",
                   json={"format": "nuclei_jsonl", "payload": NUCLEI_SAMPLE})
        assert r.status_code == 401
        assert r.json()["error"] == "unauthorized"

    def test_authorized_ok_and_feed(self, monkeypatch, tmp_path, capsys):
        c = _secret_client(monkeypatch, tmp_path)
        r = c.post("/api/webhook/ingest",
                   headers={"X-Dashboard-Token": "sekrit"},
                   json={"format": "nuclei_jsonl", "payload": NUCLEI_SAMPLE})
        assert r.status_code == 200
        body = r.json()
        assert body["accepted"] == 1 and body["skipped"] == 0
        assert body["finding_count"] == 1
        assert body["ref"].count("-") == 1 and body["ref"]
        # feed 落盘
        feed = tmp_path / "webhook" / "feed.jsonl"
        assert feed.is_file()
        lines = [l for l in feed.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert len(lines) == 1
        ev = json.loads(lines[0])
        assert ev["accepted"] == 1 and ev["format"] == "nuclei_jsonl"
        assert ev["findings"][0]["rule_id"] == "CVE-2021-44228"

    def test_list_payload_accepted(self, monkeypatch, tmp_path):
        c = _secret_client(monkeypatch, tmp_path)
        payload = [{"type": "SQL注入", "severity": "high", "url": "http://t.example/a?id=1"}]
        r = c.post("/api/webhook/ingest",
                   headers={"X-Dashboard-Token": "sekrit"},
                   json={"format": "vulnclaw_json", "payload": payload})
        assert r.status_code == 200
        assert r.json()["accepted"] == 1

    def test_unknown_format_400(self, monkeypatch, tmp_path):
        c = _secret_client(monkeypatch, tmp_path)
        r = c.post("/api/webhook/ingest",
                   headers={"X-Dashboard-Token": "sekrit"},
                   json={"format": "bogus", "payload": "x"})
        assert r.status_code == 400

    def test_missing_body_400(self, monkeypatch, tmp_path):
        c = _secret_client(monkeypatch, tmp_path)
        r = c.post("/api/webhook/ingest",
                   headers={"X-Dashboard-Token": "sekrit"}, json={"format": "jsonl"})
        assert r.status_code == 400

    def test_payload_too_large_413(self, monkeypatch, tmp_path):
        c = _secret_client(monkeypatch, tmp_path)
        big = "x" * (5 * 1024 * 1024 + 64)
        r = c.post("/api/webhook/ingest",
                   headers={"X-Dashboard-Token": "sekrit"},
                   json={"format": "raw_http", "payload": big})
        assert r.status_code == 413

    def test_openapi_describes_webhook(self, monkeypatch, tmp_path):
        c = _secret_client(monkeypatch, tmp_path)
        spec = c.get("/openapi.json").json()
        assert "/api/webhook/ingest" in spec["paths"]
        assert spec["info"]["description"] and "format" in spec["info"]["description"]
        tags = {t["name"] for t in spec.get("tags", [])}
        assert "webhook" in tags


# ============================================================
# SDK 客户端（离线：仅构造请求，不发送）
# ============================================================
class TestDashboardClient:
    def test_token_header_and_urls(self):
        async def go():
            cli_ = DashboardClient("http://localhost:8080/", token="abc")
            try:
                req = cli_.build_request("GET", "/api/status")
                assert req.method == "GET"
                assert str(req.url).endswith("/api/status")
                assert req.headers["X-Dashboard-Token"] == "abc"
            finally:
                await cli_.aclose()
        asyncio.run(go())

    def test_no_auth_header_when_no_token(self):
        async def go():
            cli_ = DashboardClient("http://localhost:8080")
            try:
                req = cli_.build_request("GET", "/api/scans")
                assert "X-Dashboard-Token" not in req.headers
            finally:
                await cli_.aclose()
        asyncio.run(go())

    def test_push_findings_body(self):
        async def go():
            cli_ = DashboardClient("http://localhost:8080", token="t")
            try:
                req = cli_.build_request("POST", "/api/webhook/ingest",
                                         json={"format": "jsonl", "payload": "{\"a\":1}"})
                assert json.loads(req.content.decode("utf-8"))["format"] == "jsonl"
                assert req.headers["X-Dashboard-Token"] == "t"
            finally:
                await cli_.aclose()
        asyncio.run(go())

    def test_start_scan_body(self):
        async def go():
            cli_ = DashboardClient("http://localhost:8080")
            try:
                req = cli_.build_request("POST", "/api/scans",
                                         json={"target": "http://t.example", "max_tasks": 5})
                body = json.loads(req.content.decode("utf-8"))
                assert body == {"target": "http://t.example", "max_tasks": 5}
            finally:
                await cli_.aclose()
        asyncio.run(go())

    def test_build_payload_wraps_export(self):
        p = build_payload("jsonl", [_finding()])
        assert p["format"] == "jsonl"
        assert "SQL注入" in p["payload"]
        # 导出文本可由 interop 回读成 1 条
        from vulnclaw.core.interop import import_jsonl
        assert len(import_jsonl(p["payload"])) == 1

    def test_export_jsonl_compat_helper(self):
        # import_jsonl 与 client 序列化链路一致
        text = export_jsonl([_finding()])
        from vulnclaw.core.interop import import_jsonl
        assert len(import_jsonl(text)) == 1