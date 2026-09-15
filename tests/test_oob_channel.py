"""OOB 通道单元测试（Z2.1 验收，纯离线、全 mock 网络）。

覆盖：
  1. 域名申请：dnslog 备选通道可用性 + all-unavailable 返回 None；
  2. interactsh：v1.3.x 从 stdout/会话文件揪出 oast 根域名，JSON 行回调解析；
  3. dnslog.cn：dict 与 array 两种记录形态解析，字段映射正确；
  4. 按 token 精确过滤，杜绝历史/串台回调串读；
  5. 地址拼接：interaction_url / dns_label。

运行：python -m pytest tests/test_oob_channel.py -v
"""
import pytest
import pytest_asyncio

import vulnclaw.core.oob_channel as oob_mod
from vulnclaw.core.oob_channel import OOBChannel, OOBInteraction


@pytest.fixture(autouse=True)
def _isolate_oob_breaker():
    """OOB 熔断器是进程级全局状态，用例之间必须隔离。

    否则某个用例触发通道熔断（TTL 300s）后，后续所有用例的 request_domain
    都会直接返回 None，造成"看起来像功能坏了"的假失败。
    """
    # interactsh 短期熔断（_ITSH_DOWN_UNTIL）是独立全局状态，reset_oob_breaker
    # 不复位；真实注册失败≥2 次后会让后序用例全部短路成 None —— 一并复位
    oob_mod._ITSH_DOWN_UNTIL = 0.0
    oob_mod._ITSH_FAIL_STREAK = 0
    oob_mod.reset_oob_breaker()
    yield
    oob_mod._ITSH_DOWN_UNTIL = 0.0
    oob_mod._ITSH_FAIL_STREAK = 0
    oob_mod.reset_oob_breaker()


# ============================================================
# mock 工具：假 aiohttp session / 假 run_tool
# ============================================================
class _FakeStdout:
    """异步可迭代 stdout（StreamReader 协议），逐行产出已经拆好的 bytes。"""

    def __init__(self, lines):
        self._it = iter(lines)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._it)
        except StopIteration as exc:
            raise StopAsyncIteration from exc


class _FakeProc:
    """fake create_subprocess_exec 返回体：携带可迭代 stdout。"""

    def __init__(self, lines):
        self.stdout = _FakeStdout(lines)
        self.stderr = None
        self.returncode = None

    def terminate(self):
        self.returncode = 0


class _FakeResp:
    def __init__(self, text: str):
        self._text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self) -> str:
        return self._text


class _FakeSession:
    """对所有 GET 返回同一 body，满足 oob_channel 内的 session.get 用法。

    注意：oob_channel 用 `async with session.get(url) as resp`，aiohttp 的
    session.get 返回 async context manager（而非 coroutine），因此这里 get
    必须是普通方法并返回一个带 __aenter__/__aexit__ 的对象。
    """

    def __init__(self, text: str):
        self._text = text

    def get(self, *a, **k):
        return _FakeResp(self._text)


def _fake_get_shared_session(body: str):
    async def _f(*a, **k):
        return _FakeSession(body)
    return _f


def _fake_run_tool(stdout: str, returncode: int = 0):
    async def _f(name, args=None, timeout=None, **k):
        return {"success": returncode == 0, "returncode": returncode,
                "stdout": stdout, "stderr": "", "error": ""}
    return _f


@pytest_asyncio.fixture(autouse=True)
async def _clean_cache(monkeypatch):
    oob_mod._DOMAIN_CACHE.clear()
    oob_mod._INTERACTSH_SESSION.clear()
    yield
    oob_mod._DOMAIN_CACHE.clear()
    oob_mod._INTERACTSH_SESSION.clear()


# ============================================================
# 1. 通道选择 + 域名申请
# ============================================================
@pytest.mark.asyncio
async def test_auto_falls_back_to_dnslog(monkeypatch):
    """interactsh 不可用 → auto 自动降级到 dnslog.cn。"""
    monkeypatch.setattr(oob_mod, "load_tool_config", lambda *a, **k: False)
    monkeypatch.setattr("vulnclaw.core.utils.get_shared_session",
                        _fake_get_shared_session("abc123.dnslog.cn"))
    ch = OOBChannel(provider="auto")
    domain = await ch.request_domain()
    assert domain == "abc123.dnslog.cn"
    assert ch._resolved_provider == "dnslog"


@pytest.mark.asyncio
async def test_all_channels_unavailable_returns_none(monkeypatch):
    """interactsh 缺失且 dnslog 取不到域名 → 返回 None，不抛异常。"""
    monkeypatch.setattr(oob_mod, "load_tool_config", lambda *a, **k: False)
    monkeypatch.setattr("vulnclaw.core.utils.get_shared_session",
                        _fake_get_shared_session(""))
    ch = OOBChannel(provider="auto")
    assert await ch.request_domain() is None


# ============================================================
# 2. interactsh v1.3.x 接入
# ============================================================
@pytest.mark.asyncio
async def test_interactsh_domain_from_stdout(monkeypatch):
    """interactsh-client 输出含 oast 域名时能被揪出并缓存。"""
    monkeypatch.setattr(oob_mod, "load_tool_config", lambda *a, **k: True)
    monkeypatch.setattr(oob_mod, "resolve_tool_path",
                        lambda *a, **k: "fake-itsh-bin")
    monkeypatch.setattr(oob_mod, "run_tool",
                        _fake_run_tool("1a2b3c4d5e6f7a.oast.pro", returncode=0))
    ch = OOBChannel(provider="interactsh")
    domain = await ch.request_domain()
    assert domain and domain.endswith(".oast.pro")
    assert ch._resolved_provider == "interactsh"
    assert oob_mod._DOMAIN_CACHE.get("interactsh") == domain


@pytest.mark.asyncio
async def test_interactsh_domain_from_payload_file(monkeypatch, tmp_path):
    """stdout 无域名但会话/载荷文件里有 → 也能揪出。"""
    pf = tmp_path / "payload.txt"
    pf.write_text("host=4d5e6f7a8b9c0d.oast.live\n", encoding="utf-8")
    monkeypatch.setattr(oob_mod, "load_tool_config", lambda *a, **k: True)
    monkeypatch.setattr(
        oob_mod, "run_tool",
        _fake_run_tool("", returncode=0))
    # 直接测静态抽取：伪造会话/载荷文件路径
    domain = oob_mod.OOBChannel._extract_itsh_domain("", str(pf), "")
    assert domain == "4d5e6f7a8b9c0d.oast.live"


@pytest.mark.asyncio
async def test_interactsh_poll_parses_json_lines(monkeypatch):
    """interactsh 轮询输出 JSON 行 → 解析成回传，按 token 过滤。"""
    monkeypatch.setattr(oob_mod, "load_tool_config", lambda *a, **k: True)
    monkeypatch.setattr(oob_mod, "resolve_tool_path",
                        lambda *a, **k: "fake-itsh-bin")
    async def _fake_spawn(*a, **k):
        return _FakeProc([
            ('{"protocol":"dns","type":"dns","fullId":"tok9.xyz.oast.pro",'
             '"remote_address":"8.8.8.8","timestamp":"2026-09-01T00:00:00Z",'
             '"raw_request":"61.2.3.4"}').encode("utf-8"),
            b"",
        ])

    monkeypatch.setattr(
        oob_mod.asyncio, "create_subprocess_exec", _fake_spawn
    )
    async def _fake_spawn(*a, **k):
        return _FakeProc([
            ('{"protocol":"dns","type":"dns","fullId":"tok9.xyz.oast.pro",'
             '"remote_address":"8.8.8.8","timestamp":"2026-09-01T00:00:00Z",'
             '"raw_request":"61.2.3.4"}').encode("utf-8"),
            b"",
        ])

    monkeypatch.setattr(
        oob_mod.asyncio, "create_subprocess_exec", _fake_spawn
    )
    async def _fake_spawn(*a, **k):
        return _FakeProc([
            ('{"protocol":"dns","type":"dns","fullId":"tok9.xyz.oast.pro",'
             '"remote_address":"8.8.8.8","timestamp":"2026-09-01T00:00:00Z",'
             '"raw_request":"61.2.3.4"}').encode("utf-8"),
            b"",
        ])

    monkeypatch.setattr(
        oob_mod.asyncio, "create_subprocess_exec", _fake_spawn
    )
    line = ('{"protocol":"dns","type":"dns","fullId":"tok9.xyz.oast.pro",'
            '"remote_address":"8.8.8.8","timestamp":"2026-09-01T00:00:00Z",'
            '"raw_request":"61.2.3.4"}')
    monkeypatch.setattr(oob_mod, "run_tool", _fake_run_tool(line, returncode=0))
    ch = OOBChannel(provider="interactsh")
    ch._domain = "xyz.oast.pro"
    ch._resolved_provider = "interactsh"
    ch._itsh_session_file = "dummy_session.yaml"
    hits = await ch.interactions_for("tok9", timeout=5)
    assert len(hits) == 1
    assert hits[0].protocol == "dns"


# ============================================================
# 3. dnslog.cn 双形态解析
# ============================================================
@pytest.mark.asyncio
async def test_dnslog_poll_dict_format(monkeypatch):
    """dnslog 返回 dict 形态记录 → 字段映射 data/remote_ip/time。"""
    monkeypatch.setattr(oob_mod, "load_tool_config", lambda *a, **k: False)
    body = '[{"data":"tok1.abc.dnslog.cn","remote_ip":"1.2.3.4","time":"12:00"}]'
    monkeypatch.setattr("vulnclaw.core.utils.get_shared_session",
                        _fake_get_shared_session(body))
    ch = OOBChannel(provider="dnslog")
    ch._domain = "abc.dnslog.cn"
    ch._resolved_provider = "dnslog"
    hits = await ch.poll(timeout=5)
    assert len(hits) == 1
    assert hits[0].token == "tok1"
    assert hits[0].from_addr == "1.2.3.4"
    assert hits[0].time == "12:00"


@pytest.mark.asyncio
async def test_dnslog_poll_array_format(monkeypatch):
    """dnslog 返回数组形态记录 [host, ip, time] → 索引映射正确。"""
    monkeypatch.setattr(oob_mod, "load_tool_config", lambda *a, **k: False)
    body = '[["tok2.abc.dnslog.cn","5.6.7.8","12:30"]]'
    monkeypatch.setattr("vulnclaw.core.utils.get_shared_session",
                        _fake_get_shared_session(body))
    ch = OOBChannel(provider="dnslog")
    ch._domain = "abc.dnslog.cn"
    ch._resolved_provider = "dnslog"
    hits = await ch.poll(timeout=5)
    assert len(hits) == 1
    assert hits[0].token == "tok2"
    assert hits[0].from_addr == "5.6.7.8"
    assert hits[0].time == "12:30"


# ============================================================
# 4. 按 token 精确过滤（防串台）
# ============================================================
@pytest.mark.asyncio
async def test_token_filter_no_crosstalk(monkeypatch):
    """同一域名两条不同 token 回调 → 只返回匹配的那条。"""
    monkeypatch.setattr(oob_mod, "load_tool_config", lambda *a, **k: False)
    body = ('[{"data":"aaa111.abc.dnslog.cn","remote_ip":"1.1.1.1","time":"t"},'
            '{"data":"bbb222.abc.dnslog.cn","remote_ip":"2.2.2.2","time":"t"}]')
    monkeypatch.setattr("vulnclaw.core.utils.get_shared_session",
                        _fake_get_shared_session(body))
    ch = OOBChannel(provider="dnslog")
    ch._domain = "abc.dnslog.cn"
    ch._resolved_provider = "dnslog"
    hits = await ch.interactions_for("bbb222", timeout=5)
    assert len(hits) == 1
    assert hits[0].token == "bbb222"


# ============================================================
# 5. 地址拼接
# ============================================================
@pytest.mark.asyncio
async def test_address_building(monkeypatch):
    monkeypatch.setattr(oob_mod, "load_tool_config", lambda *a, **k: False)
    monkeypatch.setattr("vulnclaw.core.utils.get_shared_session",
                        _fake_get_shared_session("abc.dnslog.cn"))
    ch = OOBChannel(provider="dnslog")
    await ch.request_domain()
    token = ch.new_token()
    assert ch.interaction_url(token, "https") == f"https://{token}.abc.dnslog.cn/"
    assert ch.dns_label(token) == f"{token}.abc.dnslog.cn"
    assert ch.require_domain() == "abc.dnslog.cn"


# ============================================================
# SP14.3-B: 结构化证据视图（oob.* 字段约定）+ JSONL 落盘
# ============================================================
class TestEvidenceView:
    def test_four_keys_and_channel_fallback(self):
        it = OOBInteraction(token="tok123", protocol="dns", from_addr="1.2.3.4")
        v = it.evidence_view()
        assert set(v) == {"oob_ts", "oob_channel", "oob_token", "oob_detail"}
        assert v["oob_channel"] == "dns:dns"  # 未解析 provider 时退化为 protocol
        assert v["oob_token"] == "tok123"
        assert "dns" in v["oob_detail"] and "1.2.3.4" in v["oob_detail"]

    def test_channel_precedence(self):
        it = OOBInteraction(token="tok123", protocol="http")
        it.channel = "interactsh"
        assert it.evidence_view()["oob_channel"] == "interactsh:http"
        assert it.evidence_view(channel="dnslog")["oob_channel"] == "dnslog:http"

    def test_record_persists_jsonl_deduped(self, tmp_path, monkeypatch):
        import json as _json
        path = tmp_path / "oob.jsonl"
        monkeypatch.setattr(oob_mod, "_oob_evidence_path", lambda: str(path))
        monkeypatch.setattr(oob_mod, "_OOB_AUDIT", [])
        monkeypatch.setattr(oob_mod, "_OOB_AUDIT_SEEN", set())
        ch = OOBChannel()
        ch._resolved_provider = "interactsh"
        it = OOBInteraction(token="tok123", protocol="dns")
        ch.record_interactions([it])
        # 同五元组重复录入 → 审计链与落盘均去重
        ch.record_interactions([OOBInteraction(token="tok123", protocol="dns")])
        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        rec = _json.loads(lines[0])
        assert rec["oob_channel"] == "interactsh:dns"
        assert rec["oob_token"] == "tok123" and rec["oob_ts"]
        assert ch.audit_size() == 1 and ch.get_audit("tok123")

    def test_get_oob_evidence_filters_by_token(self, monkeypatch):
        monkeypatch.setattr(oob_mod, "_OOB_AUDIT", [
            OOBInteraction(token="tk", protocol="http", channel="interactsh"),
            OOBInteraction(token="other", protocol="dns"),
        ])
        monkeypatch.setattr(oob_mod, "_OOB_AUDIT_SEEN", set())
        views = oob_mod.get_oob_evidence("tk")
        assert len(views) == 1 and views[0]["oob_channel"] == "interactsh:http"
        assert oob_mod.get_oob_evidence("nope") == []
        assert len(oob_mod.get_oob_evidence()) == 2

    def test_poll_injects_channel(self, monkeypatch):
        """poll 收割后 channel provider 随证据链传递。"""
        async def fake_poll_interactsh(timeout):
            return [OOBInteraction(token="tk", protocol="dns")]
        ch = OOBChannel(provider="interactsh")
        ch._domain = "abc.oast.pro"
        ch._resolved_provider = "interactsh"
        monkeypatch.setattr(ch, "_poll_interactsh", fake_poll_interactsh)
        monkeypatch.setattr(oob_mod, "_OOB_AUDIT", [])
        monkeypatch.setattr(oob_mod, "_OOB_AUDIT_SEEN", set())
        items = asyncio_run(ch.poll(timeout=1))
        assert items[0].channel == "interactsh"
        assert items[0].evidence_view()["oob_channel"] == "interactsh:dns"


def asyncio_run(coro):
    import asyncio
    return asyncio.new_event_loop().run_until_complete(coro)


# ============================================================
# SP15-B: B-SP15.1 OOB 回查自证（双通道结构化 / 落盘去重 / 超时空回查不抛错）
# ============================================================
class TestSelfCheck:
    def _isolated(self, monkeypatch, tmp_path):
        monkeypatch.setattr(oob_mod, "_oob_evidence_path",
                            lambda: str(tmp_path / "oob.jsonl"))
        monkeypatch.setattr(oob_mod, "_OOB_AUDIT", [])
        monkeypatch.setattr(oob_mod, "_OOB_AUDIT_SEEN", set())

    def test_dual_channel_structured(self, monkeypatch, tmp_path):
        """双通道（interactsh/dnslog）poll → evidence_view 通道标识各自正确。"""
        self._isolated(monkeypatch, tmp_path)

        async def fake_itsh(timeout):
            return [OOBInteraction(token="tk1", protocol="dns")]

        async def fake_dnslog(timeout):
            return [OOBInteraction(token="tk2", protocol="dns")]

        ch1 = OOBChannel(provider="interactsh")
        ch1._domain, ch1._resolved_provider = "x.oast.pro", "interactsh"
        monkeypatch.setattr(ch1, "_poll_interactsh", fake_itsh)
        ch2 = OOBChannel(provider="dnslog")
        ch2._domain, ch2._resolved_provider = "abc.dnslog.cn", "dnslog"
        monkeypatch.setattr(ch2, "_poll_dnslog", fake_dnslog)

        v1 = asyncio_run(ch1.poll(timeout=1))[0].evidence_view()
        v2 = asyncio_run(ch2.poll(timeout=1))[0].evidence_view()
        assert v1["oob_channel"] == "interactsh:dns"
        assert v2["oob_channel"] == "dnslog:dns"
        assert v1["oob_token"] == "tk1" and v2["oob_token"] == "tk2"

    def test_cross_instance_dedupe_on_disk(self, monkeypatch, tmp_path):
        """跨 OOBChannel 实例的同一条回调 → 落盘仅 1 行（全局去重）。"""
        self._isolated(monkeypatch, tmp_path)
        path = tmp_path / "oob.jsonl"
        it = OOBInteraction(token="tok1", protocol="dns", time="2026-09-06 00:00:00")
        ch1 = OOBChannel()
        ch1._resolved_provider = "interactsh"
        ch1.record_interactions([it])
        ch2 = OOBChannel()
        ch2._resolved_provider = "interactsh"
        ch2.record_interactions([OOBInteraction(token="tok1", protocol="dns",
                                                time="2026-09-06 00:00:00")])
        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        assert oob_mod.OOBChannel.audit_size() == 1

    def test_timeout_and_empty_poll_never_raise(self, monkeypatch, tmp_path):
        """超时/无域名/内部异常 → poll/wait_for_interaction 一律返回空，不抛错。"""
        self._isolated(monkeypatch, tmp_path)
        # 无域名 → poll 空
        ch = OOBChannel(provider="interactsh")
        assert asyncio_run(ch.poll(timeout=1)) == []

        # interactsh 轮询抛 TimeoutError → poll 吞掉返回 []
        ch2 = OOBChannel(provider="interactsh")
        ch2._domain, ch2._resolved_provider = "x.oast.pro", "interactsh"

        async def boom(timeout):
            import asyncio
            raise asyncio.TimeoutError("poll timeout")
        monkeypatch.setattr(ch2, "_poll_interactsh", boom)
        assert asyncio_run(ch2.poll(timeout=1)) == []
        assert asyncio_run(ch2.wait_for_interaction("tk", timeout=1)) == []

        # wait_for_interaction 通道不可用 → 空
        ch3 = OOBChannel(provider="interactsh")
        assert asyncio_run(ch3.wait_for_interaction("tk", timeout=0.5)) == []


class TestOOBBreaker:
    """P0：OOB 熔断器（通道级 + 目标级）。

    背景：目标无出网能力 / 外发域被封禁时，引擎仍逐个等待带外回调，空等占满
    worker（实测 attack 阶段 545s 仅产出 2 个 finding）。熔断后这些等待被跳过，
    时间还给确定性检测；只影响"等待"，不产生 finding，不影响误报率。
    """

    def setup_method(self):
        oob_mod.reset_oob_breaker()

    def teardown_method(self):
        oob_mod.reset_oob_breaker()

    def test_target_key_from_url(self):
        assert oob_mod.target_key_from_url("https://Example.COM:8443/a/b?x=1") == "example.com:8443"
        assert oob_mod.target_key_from_url("not-a-url") == "not-a-url"

    def test_miss_streak_trips_breaker(self):
        tgt = "example.com"
        # 未达阈值前不熔断
        for _ in range(oob_mod._OOB_MISS_THRESHOLD - 1):
            oob_mod.record_oob_result(tgt, False)
            assert not oob_mod.is_oob_blocked(tgt)
        # 达阈值 → 熔断
        oob_mod.record_oob_result(tgt, False)
        assert oob_mod.is_oob_blocked(tgt)

    def test_hit_resets_streak(self):
        tgt = "a.com"
        for _ in range(oob_mod._OOB_MISS_THRESHOLD):
            oob_mod.record_oob_result(tgt, False)
        assert oob_mod.is_oob_blocked(tgt)
        oob_mod.record_oob_result(tgt, True)   # 收到回调 → 判定有误，立即解除
        assert not oob_mod.is_oob_blocked(tgt)

    def test_blocked_target_skips_wait(self):
        """熔断后 wait_for_interaction 立即返回空，不再空等 timeout 秒。"""
        import time as _t
        ch = OOBChannel(provider="interactsh")
        ch._domain, ch._resolved_provider = "x.oast.pro", "interactsh"
        tgt = "blocked.example"
        for _ in range(oob_mod._OOB_MISS_THRESHOLD):
            oob_mod.record_oob_result(tgt, False)
        assert oob_mod.is_oob_blocked(tgt)

        _t0 = _t.monotonic()
        assert asyncio_run(ch.wait_for_interaction("tk", timeout=5, target=tgt)) == []
        assert _t.monotonic() - _t0 < 1.0, "熔断后应立即返回，不应空等 timeout"

    def test_channel_down_skips_domain_request(self, monkeypatch):
        """通道熔断期内不再重复走 8s 的域名注册流程。"""
        oob_mod.mark_channel_down("test")
        assert oob_mod.is_channel_down()
        assert oob_mod.channel_down_remaining() > 0

        async def _should_not_run(*a, **k):
            raise AssertionError("通道熔断期间不应再申请域名")

        ch = OOBChannel(provider="interactsh")
        monkeypatch.setattr(ch, "_request_interactsh_domain", _should_not_run)
        monkeypatch.setattr(ch, "_request_dnslog_domain", _should_not_run)
        assert asyncio_run(ch.request_domain()) is None

    def test_snapshot_and_reset(self):
        oob_mod.record_oob_result("s.com", False)
        snap = oob_mod.oob_state_snapshot()
        assert snap["miss_streak"]["s.com"] == 1
        assert snap["miss_threshold"] == oob_mod._OOB_MISS_THRESHOLD
        oob_mod.reset_oob_breaker()
        assert oob_mod.oob_state_snapshot()["miss_streak"] == {}


class TestInteractshConfiguration:
    """Configuration diagnostics are offline and must not imply a callback."""

    def test_server_validation_accepts_origin_only(self):
        result = oob_mod.validate_interactsh_server("https://oob.example.test")
        assert result["configured"] is True
        assert result["valid"] is True

    @pytest.mark.parametrize("value", [
        "oob.example.test",
        "ftp://oob.example.test",
        "https://user:pass@oob.example.test",
        "https://oob.example.test/api",
        "https://oob.example.test/?x=1",
    ])
    def test_server_validation_rejects_unsafe_or_ambiguous_values(self, value):
        result = oob_mod.validate_interactsh_server(value)
        assert result["valid"] is False
        assert result["error"]

    def test_diagnostics_do_not_claim_network_success(self, monkeypatch):
        monkeypatch.delenv("OOB_INTERACTSH_SERVER", raising=False)
        result = oob_mod.get_oob_diagnostics()
        assert result["configured"] is False
        assert result["network_checked"] is False
        assert result["callback_verified"] is False