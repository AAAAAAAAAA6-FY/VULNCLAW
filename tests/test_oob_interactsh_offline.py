# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""OOB / interactsh 离线闭环测试（无网络、无 Docker、无真实 interactsh-client）。

与 ``tests/test_oob_channel.py`` 的区别：本文件不 mock 「函数返回值」，而是用
``aiohttp`` 在 ``127.0.0.1`` 上真起一个 **本地 mock interactsh server**（TestServer），
由替身 client 走真实 HTTP 完成「注册 → 持续订阅轮询」，从而在完全离线的条件下
覆盖带外回连的完整数据通路：

  1. 回调收取并把 interaction 正确绑定到发起注入的 token（finding 绑定）；
  2. 同一 interaction 重复出现 → 证据链只计一次（去重）；
  3. 误关联防护：非本通道注册域名的回调、前缀相似的 token 一律不得绑定；
  4. 无回调 → 在有界时间内收敛返回空（不空转、不误报）；
  5. 服务不可用（5xx）→ fail-closed：不产证据、不产 finding；
  6. 熔断触发 → 恢复窗口到期后重新注册成功。

mock server 刻意返回 **明文** ``{"data": [...]}``（真实 interactsh 为 AES 加密 +
``aes_key``）；加密态解析不属于本文件范围，加密/证书链路只能在真实自部署
interactsh 上验证（见 ``docs/OOB_VALIDATION.md`` 的「未执行项」）。

运行：python -m pytest tests/test_oob_interactsh_offline.py -q --disable-warnings
"""
from __future__ import annotations

import asyncio
import json
import time
from contextlib import asynccontextmanager

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer

import vulnclaw.core.oob_channel as oob_mod
from vulnclaw.core.oob_channel import OOBChannel

# mock 注册根域名：必须能被 _OAST_DOMAIN_RE 识别（后缀限 pro/live/site/online/fun/me）
MOCK_DOMAIN = "mock7f3a.oast.pro"
MOCK_CORRELATION = "corr-2c93fa"
MOCK_TIMESTAMP = "2026-09-13T10:00:00Z"


# ============================================================
# 本地 mock interactsh server（aiohttp TestServer，真 HTTP）
# ============================================================
class MockInteractshServer:
    """最小 interactsh server 语义：注册发域名 + 轮询取交互。

    - ``POST /register`` → ``{"domain": ..., "correlationID": ...}``
    - ``GET  /poll``     → ``{"data": [interaction, ...]}``（取出即消费，模拟真实语义）
    - ``register_status`` / ``poll_status`` 可置为 5xx 以模拟服务不可用。
    """

    def __init__(self, domain: str = MOCK_DOMAIN):
        self.domain = domain
        self.register_status = 200
        self.poll_status = 200
        self.register_calls = 0
        self.poll_calls = 0
        self.pending: list = []
        app = web.Application()
        app.router.add_post("/register", self._handle_register)
        app.router.add_get("/poll", self._handle_poll)
        self._server = TestServer(app)
        self._session = None

    # --- HTTP 面 -------------------------------------------------
    async def _handle_register(self, request):
        self.register_calls += 1
        if self.register_status != 200:
            return web.json_response({"error": "mock register unavailable"},
                                     status=self.register_status)
        return web.json_response({"domain": self.domain,
                                  "correlationID": MOCK_CORRELATION})

    async def _handle_poll(self, request):
        self.poll_calls += 1
        if self.poll_status != 200:
            return web.json_response({"error": "mock poll unavailable"},
                                     status=self.poll_status)
        data, self.pending = self.pending, []
        return web.json_response({"data": data, "correlationID": MOCK_CORRELATION})

    # --- 生命周期 ------------------------------------------------
    async def start(self):
        await self._server.start_server()
        self._session = aiohttp.ClientSession()
        return self

    async def stop(self):
        if self._session is not None:
            await self._session.close()
            self._session = None
        await self._server.close()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.port}"

    # --- 替身 client 用到的两个出口 -------------------------------
    async def http_register(self):
        async with self._session.post(f"{self.url}/register") as resp:
            body = await resp.json(content_type=None)
            return resp.status, (body if isinstance(body, dict) else {})

    async def http_poll(self):
        async with self._session.get(f"{self.url}/poll") as resp:
            body = await resp.json(content_type=None)
            return resp.status, (body if isinstance(body, dict) else {})


def _event(token: str, protocol: str = "dns", *, domain: str = MOCK_DOMAIN,
           ts: str = MOCK_TIMESTAMP, remote: str = "203.0.113.7",
           raw: str = "question; 203.0.113.7") -> dict:
    """构造一条 interactsh 回调记录（字段名对齐 v1.3.x JSON 输出）。"""
    return {
        "protocol": protocol,
        "type": protocol,
        "fullId": f"{token}.{domain}",
        "remote_address": remote,
        "timestamp": ts,
        "raw_request": raw,
    }


# ============================================================
# 替身 client：把 oob_channel 的两条出口接到 mock server 上
# ============================================================
class _QueueStdout:
    """异步可迭代 stdout：从一个队列取行，空行为结束标记。"""

    def __init__(self, queue: asyncio.Queue):
        self._q = queue

    def __aiter__(self):
        return self

    async def __anext__(self):
        item = await self._q.get()
        if not item:
            raise StopAsyncIteration
        return item


class _FakeProc:
    """fake create_subprocess_exec 返回体（常驻订阅进程替身）。"""

    def __init__(self, queue: asyncio.Queue):
        self.stdout = _QueueStdout(queue)
        self.stderr = None
        self.returncode = None

    def terminate(self):
        self.returncode = 0


def _install_itsh_transport(monkeypatch, server: MockInteractshServer) -> None:
    """把 interactsh-client 的注册/轮询出口改接到本地 mock server（真 HTTP）。"""
    monkeypatch.setattr(oob_mod, "load_tool_config", lambda *a, **k: True)
    monkeypatch.setattr(oob_mod, "resolve_tool_path", lambda *a, **k: "mock-itsh-client")

    async def _run_tool(name, args=None, timeout=None, **k):
        status, body = await server.http_register()
        if status != 200:
            return {"success": False, "returncode": 1, "stdout": "",
                    "stderr": f"mock register http {status}", "error": ""}
        return {"success": True, "returncode": 0,
                "stdout": json.dumps(body), "stderr": "", "error": ""}

    monkeypatch.setattr(oob_mod, "run_tool", _run_tool)

    async def _spawn(*a, **k):
        status, body = await server.http_poll()
        queue: asyncio.Queue = asyncio.Queue()
        if status == 200:
            for ev in (body.get("data") or []):
                queue.put_nowait((json.dumps(ev) + "\n").encode("utf-8"))
        queue.put_nowait(b"")
        return _FakeProc(queue)

    monkeypatch.setattr(oob_mod.asyncio, "create_subprocess_exec", _spawn)


@asynccontextmanager
async def _channel(provider: str = "interactsh"):
    """构造 OOBChannel 并保证退出时释放常驻订阅协程/进程。"""
    ch = OOBChannel(provider=provider)
    try:
        yield ch
    finally:
        await ch.aclose()


async def _await_buffer(ch: OOBChannel, expected: int = 1, timeout: float = 2.0) -> bool:
    """有界等待常驻订阅把回调读进缓冲（避免固定 sleep）。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if len(ch._itsh_buffer) >= expected:
            return True
        await asyncio.sleep(0.01)
    return False


# ============================================================
# 夹具：全局状态隔离（熔断器/缓存/审计链/证据落盘）
# ============================================================
@pytest.fixture(autouse=True)
def _isolate_oob_state(monkeypatch, tmp_path):
    """OOB 全部状态都是进程级全局，用例之间必须隔离（否则假失败/串台）。"""
    monkeypatch.setattr(oob_mod, "_oob_evidence_path",
                        lambda: str(tmp_path / "oob_interactions.jsonl"))
    monkeypatch.setattr(oob_mod, "_OOB_AUDIT", [])
    monkeypatch.setattr(oob_mod, "_OOB_AUDIT_SEEN", set())
    oob_mod._ITSH_DOWN_UNTIL = 0.0
    oob_mod._ITSH_FAIL_STREAK = 0
    oob_mod.reset_oob_breaker()
    yield
    oob_mod._ITSH_DOWN_UNTIL = 0.0
    oob_mod._ITSH_FAIL_STREAK = 0
    oob_mod.reset_oob_breaker()
    oob_mod._DOMAIN_CACHE.clear()
    oob_mod._INTERACTSH_SESSION.clear()


@pytest_asyncio.fixture
async def itsh_server():
    server = await MockInteractshServer().start()
    try:
        yield server
    finally:
        await server.stop()


# ============================================================
# 0. mock server 契约自证（先证明 mock 本身可信）
# ============================================================
@pytest.mark.asyncio
async def test_mock_server_register_and_poll_contract(itsh_server):
    """mock server 暴露 register/poll 且 poll 为「取出即消费」语义。"""
    itsh_server.pending = [_event("tok1")]
    status, body = await itsh_server.http_register()
    assert status == 200 and body["domain"] == MOCK_DOMAIN

    status, body = await itsh_server.http_poll()
    assert status == 200 and len(body["data"]) == 1
    status, body = await itsh_server.http_poll()
    assert body["data"] == [], "同一条 interaction 不得被重复投递"
    assert itsh_server.register_calls == 1 and itsh_server.poll_calls == 2


# ============================================================
# 1. 回调收取 + 正确绑定 token（finding 绑定）
# ============================================================
@pytest.mark.asyncio
async def test_callback_received_and_bound_to_token(itsh_server, monkeypatch):
    """注册 → 注入 → 轮询真实 HTTP 通路，回调绑定到发起注入的那个 token。"""
    _install_itsh_transport(monkeypatch, itsh_server)
    itsh_server.pending = [_event("tokabc123")]

    async with _channel() as ch:
        domain = await ch.request_domain()
        assert domain == MOCK_DOMAIN
        assert ch._resolved_provider == "interactsh"
        assert itsh_server.register_calls == 1, "注册必须走 mock server 的真实 HTTP"

        token = ch.new_token()
        assert ch.dns_label(token).endswith("." + MOCK_DOMAIN)

        assert await _await_buffer(ch), "常驻订阅未把回调读入缓冲"
        hits = await ch.interactions_for("tokabc123", timeout=2)
        assert len(hits) == 1 and itsh_server.poll_calls >= 1
        assert hits[0].protocol == "dns"
        assert hits[0].from_addr == "203.0.113.7"
        assert hits[0].channel == "interactsh"

        # 证据链按 token 绑定 → finding/报告侧据此展开 oob_* 字段
        views = oob_mod.get_oob_evidence("tokabc123")
        assert len(views) == 1
        assert views[0]["oob_token"] == "tokabc123"
        assert views[0]["oob_channel"] == "interactsh:dns"
        assert views[0]["oob_ts"] == MOCK_TIMESTAMP

        # 本次注入的 token 未收到回调 → 不得借用别人的回调
        assert oob_mod.get_oob_evidence(token) == []


@pytest.mark.asyncio
async def test_callback_binds_through_module_level_poll(itsh_server, monkeypatch):
    """模块级 get_interactsh_poll（引擎侧真实调用点）同链路可绑定回调。"""
    from vulnclaw.modules.vuln_scanner.oob_interactsh import get_interactsh_poll

    _install_itsh_transport(monkeypatch, itsh_server)

    async with _channel() as ch:
        assert await ch.request_domain() == MOCK_DOMAIN  # 预热 域名/会话缓存

    itsh_server.pending = [_event("tokzzz9", protocol="http", raw="GET / HTTP/1.1")]
    target = "http://victim.example:8080"
    # 先制造 6 次零回调 → 熔断；真实回调必须能把它解除（判定有误自愈）
    for _ in range(oob_mod._OOB_MISS_THRESHOLD):
        oob_mod.record_oob_result(target, False)
    assert oob_mod.is_oob_blocked(target)

    out = await get_interactsh_poll(MOCK_DOMAIN, timeout=2, target=target)
    assert out and out[0]["protocol"] == "http"
    assert out[0]["raw-request"] == "GET / HTTP/1.1"   # 兼容旧消费者的 kebab-case 键
    assert out[0]["q-type"] == "http"
    assert not oob_mod.is_oob_blocked(target), "收到真实回调后目标级熔断必须解除"


# ============================================================
# 2. 回调去重（同 interaction 不重复计）
# ============================================================
@pytest.mark.asyncio
async def test_duplicate_interaction_counted_once(itsh_server, monkeypatch):
    """同一 interaction 在批次内重复、跨轮次重投 → 证据链只计一次。"""
    _install_itsh_transport(monkeypatch, itsh_server)
    ev = _event("tokdup1")
    itsh_server.pending = [ev, dict(ev), dict(ev)]

    async with _channel() as ch:
        await ch.request_domain()
        assert await _await_buffer(ch, expected=1)
        first = await ch.poll(timeout=2)
        assert len(first) == 3, "生产端重复投递本身不做去重（保持原始证据）"
        assert oob_mod.OOBChannel.audit_size() == 1, "同一 interaction 只计一次"

        # 服务端重投同一条 → 仍只计一次
        itsh_server.pending = [dict(ev)]
        ch._itsh_buffer.clear()
        await ch._start_itsh_stream(ch._itsh_payload_file)
        await _await_buffer(ch, expected=1)
        await ch.poll(timeout=2)
        assert oob_mod.OOBChannel.audit_size() == 1
        assert len(oob_mod.get_oob_audit("tokdup1")) == 1


# ============================================================
# 3. 误关联防护（token 不匹配不得绑定）
# ============================================================
@pytest.mark.asyncio
async def test_foreign_domain_callback_is_discarded(itsh_server, monkeypatch):
    """非本通道注册域名发来的回调 → 解析不出归属 token，不得绑定。"""
    _install_itsh_transport(monkeypatch, itsh_server)
    itsh_server.pending = [
        _event("tokghost", domain="attacker.example"),          # 完全外部域名
        _event("tokghost2", domain=f"{MOCK_DOMAIN}.attacker.example"),  # 后缀伪装
        _event("tokreal1"),                                     # 唯一合法回调
    ]

    async with _channel() as ch:
        await ch.request_domain()
        assert await _await_buffer(ch, expected=1)
        await ch.poll(timeout=2)

    assert len(oob_mod.get_oob_audit("tokreal1")) == 1
    assert oob_mod.get_oob_audit("tokghost") == []
    assert oob_mod.get_oob_audit("tokghost2") == []
    assert oob_mod.OOBChannel.audit_size() == 1


@pytest.mark.asyncio
async def test_token_must_match_exactly_no_prefix_binding(itsh_server, monkeypatch):
    """前缀相似/大小写不同的 token 一律不得命中（精确相等）。"""
    _install_itsh_transport(monkeypatch, itsh_server)
    itsh_server.pending = [_event("tokabc123")]

    async with _channel() as ch:
        await ch.request_domain()
        assert await _await_buffer(ch)
        for wrong in ("tokabc12", "tokabc1234", "tokabc123.suffix", "abc123"):
            assert await ch.interactions_for(wrong, timeout=1) == []
        # 大小写不敏感匹配（token 规范化为小写）
        assert len(await ch.interactions_for("TOKABC123", timeout=1)) == 1


# ============================================================
# 4. 无回调 → 有界收敛（不空转、不误报）
# ============================================================
@pytest.mark.asyncio
async def test_no_callback_times_out_within_bound(itsh_server, monkeypatch):
    """目标不回连 → wait_for_interaction 在 timeout 量级内返回空，不产证据。"""
    _install_itsh_transport(monkeypatch, itsh_server)
    target = "http://silent.example"

    async with _channel() as ch:
        await ch.request_domain()
        t0 = time.monotonic()
        hits = await ch.wait_for_interaction("toknever", timeout=1, interval=0.2,
                                             target=target)
        elapsed = time.monotonic() - t0
        assert hits == []
        assert elapsed < 4.0, f"无回调应收敛返回，实测 {elapsed:.2f}s"
        assert oob_mod.OOBChannel.audit_size() == 0, "零回调绝不能产出证据"
        assert oob_mod.oob_state_snapshot()["miss_streak"][target] == 1


@pytest.mark.asyncio
async def test_zero_callback_waits_accumulate_into_target_breaker(itsh_server, monkeypatch):
    """连续零回调累加到达阈值 → 目标级熔断，后续等待立即返回（不再空等）。"""
    _install_itsh_transport(monkeypatch, itsh_server)
    target = "http://silent.example"

    async with _channel() as ch:
        await ch.request_domain()
        for _ in range(oob_mod._OOB_MISS_THRESHOLD):
            assert await ch.wait_for_interaction("toknever", timeout=0.4, interval=0.1,
                                                 target=target) == []
        assert oob_mod.is_oob_blocked(target)

        t0 = time.monotonic()
        assert await ch.wait_for_interaction("toknever", timeout=5, target=target) == []
        assert time.monotonic() - t0 < 1.0, "熔断后不得再空等 timeout"


# ============================================================
# 5. 服务不可用（5xx）→ fail-closed
# ============================================================
@pytest.mark.asyncio
async def test_server_unavailable_fails_closed(itsh_server, monkeypatch):
    """register/poll 均 5xx → 拿不到域名、无回调、无任何证据或 finding。"""
    _install_itsh_transport(monkeypatch, itsh_server)
    itsh_server.register_status = 503
    itsh_server.poll_status = 500

    async with _channel() as ch:
        assert await ch.request_domain() is None, "服务不可用不得谎报域名"
        assert ch._resolved_provider is None
        assert await ch.poll(timeout=1) == []
        assert await ch.wait_for_interaction("tokx", timeout=0.5) == []

    assert oob_mod.OOBChannel.audit_size() == 0
    assert oob_mod.get_oob_evidence() == []
    assert oob_mod._ITSH_FAIL_STREAK == 1


@pytest.mark.asyncio
async def test_repeated_register_failure_short_circuits(itsh_server, monkeypatch):
    """连续注册失败达阈值 → interactsh 短期熔断，后续不再白等一次注册。"""
    _install_itsh_transport(monkeypatch, itsh_server)
    itsh_server.register_status = 502

    async with _channel() as ch:
        assert await ch.request_domain() is None
        assert await ch.request_domain() is None
        assert oob_mod._ITSH_FAIL_STREAK >= oob_mod._ITSH_FAIL_THRESHOLD
        assert time.monotonic() < oob_mod._ITSH_DOWN_UNTIL, "熔断窗口未开启"
        calls = itsh_server.register_calls
        t0 = time.monotonic()
        assert await ch.request_domain() is None
        assert itsh_server.register_calls == calls, "熔断期内不得再发起注册"
        assert time.monotonic() - t0 < 0.5


# ============================================================
# 6. 熔断触发 → 恢复窗口重置
# ============================================================
@pytest.mark.asyncio
async def test_breaker_window_expiry_recovers(itsh_server, monkeypatch):
    """interactsh 熔断窗口到期 → 重新注册成功并复位失败计数。"""
    _install_itsh_transport(monkeypatch, itsh_server)
    itsh_server.register_status = 500

    async with _channel() as ch:
        await ch.request_domain()
        await ch.request_domain()
        assert time.monotonic() < oob_mod._ITSH_DOWN_UNTIL

        # 模拟恢复窗口到期（不真等 300s）
        itsh_server.register_status = 200
        oob_mod._ITSH_DOWN_UNTIL = time.monotonic() - 1.0
        assert await ch.request_domain() == MOCK_DOMAIN
        assert oob_mod._ITSH_FAIL_STREAK == 0, "恢复成功后失败计数必须复位"


@pytest.mark.asyncio
async def test_channel_breaker_reset_reopens_window(monkeypatch):
    """通道级熔断 → reset_oob_breaker() 后申请窗口重新打开。"""
    oob_mod.mark_channel_down("test")
    assert oob_mod.is_channel_down() and oob_mod.channel_down_remaining() > 0

    async with _channel() as ch:
        assert await ch.request_domain() is None

    oob_mod.reset_oob_breaker()
    assert not oob_mod.is_channel_down()
    assert oob_mod.oob_state_snapshot()["channel_down"] is False


@pytest.mark.asyncio
async def test_target_breaker_reset_after_hit(itsh_server, monkeypatch):
    """目标级熔断被真实回调解除：命中清零 streak，快照同步反映。"""
    _install_itsh_transport(monkeypatch, itsh_server)
    target = "http://victim.example"
    itsh_server.pending = [_event("tokrise")]

    for _ in range(oob_mod._OOB_MISS_THRESHOLD):
        oob_mod.record_oob_result(target, False)
    assert oob_mod.is_oob_blocked(target)

    async with _channel() as ch:
        await ch.request_domain()
        assert await _await_buffer(ch)
        hits = await ch.wait_for_interaction("tokrise", timeout=1, target=target)
        assert len(hits) == 1
        assert not oob_mod.is_oob_blocked(target)
        snap = oob_mod.oob_state_snapshot()
        assert snap["miss_streak"][target] == 0
        assert snap["hit_count"][target] == 1


@pytest.mark.asyncio
async def test_poll_without_domain_never_raises(monkeypatch):
    """无域名（通道不可用）→ poll / wait / error 面一律返回空且不抛错。"""
    monkeypatch.setattr(oob_mod, "load_tool_config", lambda *a, **k: False)
    async with _channel() as ch:
        assert await ch.poll(timeout=1) == []
        assert await ch.wait_for_interaction("tok", timeout=0.5) == []
        assert await ch.interactions_for("tok", timeout=0.5) == []
