"""Z2.4 单测：OOB 盲打 finding 的带外证据入报告（framework_zero_day_engines）。

覆盖 `_run_oob_scan` 产出的 finding 是否携带：
  1. evidence 文本含回调节点时间戳 + curl 复现命令；
  2. 结构化 oob_evidence 字段（protocol/host/token/callback_count/callback_time/reproduce）；
  3. 无回调 / 无通道 / 通道异常 → 一律返回 None（低误报铁律）；
  4. 同引擎同源去重，避免重复盲打。

全部 mock，离线运行，不触网、不等待真实轮询（payload_templates=[] 跳过注入循环）。
"""
import pytest
import pytest_asyncio

import vulnclaw.engines.framework_zero_day_engines as fwk
from vulnclaw.core.oob_channel import OOBInteraction


# ============================================================
# mock 工具
# ============================================================
class _FakeOOBChannel:
    """可控的假 OOB 通道：probe 固定返回指定域名，回调数由调用方决定。"""

    def __init__(self, token="tok1", domain="oast.pro",
                 hits=None, probe=None, raise_on_make_probe=False):
        self.token = token
        self.domain = domain
        self.hits = hits if hits is not None else []
        self._probe = probe
        self._raise = raise_on_make_probe

    async def make_probe(self, scheme):
        if self._raise:
            raise RuntimeError("oob 不可用")
        if self._probe is None:
            return {"token": self.token,
                    "url": f"https://{self.token}.{self.domain}/",
                    "domain": self.domain}
        return self._probe

    async def wait_for_interaction(self, token, timeout=None):
        return self.hits


def _install_mocks(monkeypatch, channel):
    """把 fwk 内 OOB 依赖替换为假实现。

    OOBChannel 是 _run_oob_scan 函数内 `from ... import`，需 patch 源模块；
    build_attack_url/async_get/enrich_finding 是模块级 import，patch fwk 即可。
    """
    async def _fake_get(*a, **k):
        pass
    monkeypatch.setattr("vulnclaw.core.oob_channel.OOBChannel",
                        lambda *a, **k: channel)
    monkeypatch.setattr(fwk, "build_attack_url", lambda *a, **k: "http://t/?q=x")
    monkeypatch.setattr(fwk, "async_get", _fake_get)
    monkeypatch.setattr(fwk, "enrich_finding", lambda d: d)


@pytest_asyncio.fixture(autouse=True)
async def _clean_dedup():
    fwk._OOB_ATTEMPTED.clear()
    yield
    fwk._OOB_ATTEMPTED.clear()


def _hit(token="tok1", ts="2026-09-01 10:00:00"):
    return OOBInteraction(
        token=token, protocol="dns", tag="dns", time="",
        extra={"timestamp": ts, "time": "2026-09-01 09:00:00"},
    )


async def _run(monkeypatch, channel, engine_name="Log4Shell"):
    _install_mocks(monkeypatch, channel)
    return await fwk._run_oob_scan(
        engine_name=engine_name,
        url="https://target.example/app",
        param="p",
        parsed_query="p=x",
        session=None,
        payload_templates=[],       # 跳过注入循环与 sleep
        type_label="Log4Shell",
        evidence_note="log4shell 测试",
        recommendation="升级依赖",
        oob_wait=3,
    )


# ============================================================
# 1. 命中时：证据入报告
# ============================================================
@pytest.mark.asyncio
async def test_emit_oob_evidence_on_hit(monkeypatch):
    ch = _FakeOOBChannel(hits=[_hit()])
    res = await _run(monkeypatch, ch)

    assert res is not None
    assert res["type"] == "Log4Shell(带外实锤)"
    assert res["severity"] == "Critical"

    # oob_evidence 结构化字段
    ev = res["oob_evidence"]
    assert ev["protocol"] == "dns"
    assert ev["host"] == "tok1.oast.pro"
    assert ev["token"] == "tok1"
    assert ev["callback_count"] == 1
    assert ev["callback_time"] == "2026-09-01 10:00:00"     # 取交互原始时间
    assert ev["reproduce"].startswith("curl -s --max-time 5")

    # evidence 文本含时间戳与复现命令
    assert "首条回调节点时间=2026-09-01 10:00:00" in res["evidence"]
    assert "http://tok1.oast.pro/" in res["evidence"]


@pytest.mark.asyncio
async def test_callback_time_prefers_raw_timestamp(monkeypatch):
    """extra 无 timestamp 时回退到原始 time，避免默认当前时间造成误证。"""
    ch = _FakeOOBChannel(hits=[OOBInteraction(
        token="tok1", protocol="http", tag="http", time="",
        extra={"time": "2026-08-01 01:02:03"},
    )])
    res = await _run(monkeypatch, ch)
    assert res["oob_evidence"]["callback_time"] == "2026-08-01 01:02:03"
    assert res["oob_evidence"]["protocol"] == "http"


# ============================================================
# 2. 低误报铁律：无判据一律返回 None
# ============================================================
@pytest.mark.asyncio
async def test_none_when_no_callback(monkeypatch):
    ch = _FakeOOBChannel(hits=[])
    assert await _run(monkeypatch, ch) is None


@pytest.mark.asyncio
async def test_none_when_no_probe(monkeypatch):
    ch = _FakeOOBChannel(probe=None)
    assert await _run(monkeypatch, ch) is None


@pytest.mark.asyncio
async def test_none_when_oob_channel_raises(monkeypatch):
    ch = _FakeOOBChannel(raise_on_make_probe=True)
    assert await _run(monkeypatch, ch) is None


# ============================================================
# 3. 去重：同引擎同源只盲打一次
# ============================================================
@pytest.mark.asyncio
async def test_dedup_prevents_redundant_oob(monkeypatch):
    ch_hit = _FakeOOBChannel(hits=[_hit()])
    first = await _run(monkeypatch, ch_hit, engine_name="Fastjson")
    assert first is not None
    # 同 engine_name + 同源 url 第二次直接去重返回 None
    assert await _run(monkeypatch, ch_hit, engine_name="Fastjson") is None


@pytest.mark.asyncio
async def test_distinct_target_not_deduped(monkeypatch):
    ch_hit = _FakeOOBChannel(hits=[_hit()])

    async def run_unique_target(engine_name, url):
        _install_mocks(monkeypatch, ch_hit)
        return await fwk._run_oob_scan(
            engine_name=engine_name, url=url, param="p", parsed_query="p=x",
            session=None, payload_templates=[], type_label="X",
            evidence_note="n", recommendation="r", oob_wait=3,
        )

    assert await run_unique_target("Struts2", "https://a.example/x") is not None
    assert await run_unique_target("Struts2", "https://b.example/y") is not None