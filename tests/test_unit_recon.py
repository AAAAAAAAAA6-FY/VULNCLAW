"""单元测试：_is_internal_domain 内网/回环/伪TLD 分类器 + SP14.1-B 参数挖掘器。"""
import json as _json

import pytest

import vulnclaw.core.utils as core_utils
import vulnclaw.modules.recon as recon_mod
from vulnclaw.modules.recon import (
    _is_internal_domain,
    append_param_candidates,
    mine_params,
    param_pool_path,
)


class TestLoopbackAndPrivate:
    def test_loopback_v4(self):
        assert _is_internal_domain("127.0.0.1") is True

    def test_loopback_range(self):
        assert _is_internal_domain("127.255.255.254") is True

    def test_private_10(self):
        assert _is_internal_domain("10.0.0.5") is True

    def test_private_172(self):
        assert _is_internal_domain("172.16.1.1") is True

    def test_private_192(self):
        assert _is_internal_domain("192.168.1.100") is True

    def test_link_local(self):
        assert _is_internal_domain("169.254.169.254") is True

    def test_loopback_v6(self):
        assert _is_internal_domain("::1") is True


class TestPseudoTld:
    def test_local(self):
        assert _is_internal_domain("myhost.local") is True

    def test_internal(self):
        assert _is_internal_domain("app.internal") is True

    def test_corp(self):
        assert _is_internal_domain("git.corp") is True

    def test_lan(self):
        assert _is_internal_domain("nas.lan") is True


class TestPublicDomains:
    def test_public_domain(self):
        assert _is_internal_domain("baidu.com") is False

    def test_public_subdomain(self):
        assert _is_internal_domain("api.stripe.com") is False

    def test_multi_tld(self):
        assert _is_internal_domain("sub.example.co.uk") is False

    def test_public_ip(self):
        assert _is_internal_domain("8.8.8.8") is False

    def test_public_ip2(self):
        assert _is_internal_domain("1.1.1.1") is False


class TestEdgeCases:
    def test_empty(self):
        assert _is_internal_domain("") is True

    def test_none_like(self):
        assert _is_internal_domain(None) is True

    def test_bare_hostname(self):
        # 无点主机名视为内网
        assert _is_internal_domain("localhost") is True

    def test_whitespace(self):
        assert _is_internal_domain("  127.0.0.1  ") is True

    def test_uppercase(self):
        assert _is_internal_domain("MYAPP.LOCAL") is True

    def test_trailing_dot_ip(self):
        assert _is_internal_domain("127.0.0.1.") is True


# ============================================================
# SP14.1-B: D3.5 参数挖掘器（词典 + 差异判定 + 入池）
# ============================================================
def _mk_get(responses):
    """responses: {"<url子串>": (status, text), "_base": (status, text)}；未命中词返回基线。"""
    async def fake_async_get(url, **kw):
        for key, val in responses.items():
            if key != "_base" and key and key in url:
                return val + ({},)
        return responses.get("_base", (200, "hello")) + ({},)
    return fake_async_get


class TestParamMiner:
    @pytest.mark.asyncio
    async def test_reflected_signal(self, monkeypatch):
        monkeypatch.setattr(core_utils, "async_get", _mk_get({
            "_base": (200, "welcome home"),
            "debug=vulnclaw_p0": (200, "welcome home vulnclaw_p0"),
        }))
        out = await mine_params("http://t.example.com/?id=1")
        hit = [c for c in out if c["param"] == "debug"]
        assert hit and hit[0]["signal"] == "reflected"
        assert hit[0]["base_len"] == len("welcome home")

    @pytest.mark.asyncio
    async def test_diff_len_signal(self, monkeypatch):
        monkeypatch.setattr(core_utils, "async_get", _mk_get({
            "_base": (200, "welcome home"),
            "order=vulnclaw_p0": (200, "welcome home" + "x" * 200),
        }))
        out = await mine_params("http://t.example.com/")
        hit = [c for c in out if c["param"] == "order"]
        assert hit and hit[0]["signal"] == "diff_len"

    @pytest.mark.asyncio
    async def test_status_change_signal(self, monkeypatch):
        monkeypatch.setattr(core_utils, "async_get", _mk_get({
            "_base": (200, "welcome home"),
            "file=vulnclaw_p0": (403, "forbidden page" * 10),
        }))
        out = await mine_params("http://t.example.com/")
        hit = [c for c in out if c["param"] == "file"]
        assert hit and hit[0]["signal"] == "status_change"

    @pytest.mark.asyncio
    async def test_5xx_and_0_noise_skipped(self, monkeypatch):
        monkeypatch.setattr(core_utils, "async_get", _mk_get({
            "_base": (200, "welcome home"),
            "admin=vulnclaw_p0": (500, "server error" * 50),
        }))
        assert await mine_params("http://t.example.com/") == []
        assert await mine_params("") == []  # 非法 URL 防御

    @pytest.mark.asyncio
    async def test_baseline_failure_returns_empty(self, monkeypatch):
        async def fail_get(url, **kw):
            raise OSError("down")
        monkeypatch.setattr(core_utils, "async_get", fail_get)
        assert await mine_params("http://t.example.com/") == []


class TestParamPool:
    def test_append_and_dedupe(self, tmp_path, monkeypatch):
        monkeypatch.setattr(recon_mod, "param_pool_path",
                            lambda: str(tmp_path / "pool.jsonl"))
        recon_mod._PARAM_POOL_SEEN.clear()
        c = [{"param": "debug", "url": "http://t/", "base_len": 5, "signal": "reflected"}]
        assert append_param_candidates(c) == 1
        assert append_param_candidates(c) == 0  # 进程内 (url,param) 去重
        lines = (tmp_path / "pool.jsonl").read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        assert _json.loads(lines[0])["param"] == "debug"
        assert _json.loads(lines[0])["signal"] == "reflected"

    def test_append_malformed_skipped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(recon_mod, "param_pool_path",
                            lambda: str(tmp_path / "pool.jsonl"))
        recon_mod._PARAM_POOL_SEEN.clear()
        assert append_param_candidates([{"no_url": True}, "junk", None]) == 0

    def test_pool_path_layout(self):
        p = param_pool_path().replace("\\", "/")
        assert p.endswith("_runtime_cache/recon/param_candidates.jsonl")


class TestMiningHook:
    @pytest.mark.asyncio
    async def test_disabled_by_default(self, monkeypatch):
        monkeypatch.setitem(recon_mod.settings.__dict__, "enable_param_mining", False)
        from vulnclaw.modules.recon import EndpointCollector
        c = EndpointCollector()
        assert await c.mine_hidden_params(["http://t.example.com/"]) == []

    @pytest.mark.asyncio
    async def test_enabled_mines_and_pools(self, tmp_path, monkeypatch):
        monkeypatch.setitem(recon_mod.settings.__dict__, "enable_param_mining", True)
        monkeypatch.setattr(recon_mod, "param_pool_path",
                            lambda: str(tmp_path / "pool.jsonl"))
        recon_mod._PARAM_POOL_SEEN.clear()

        async def fake_mine(endpoints, session=None, max_endpoints=10, per_url_words=120):
            return [{"param": "debug", "url": sorted(endpoints)[0],
                     "base_len": 5, "signal": "reflected"}]
        monkeypatch.setattr(recon_mod, "mine_params_for_endpoints", fake_mine)
        from vulnclaw.modules.recon import EndpointCollector
        c = EndpointCollector()
        out = await c.mine_hidden_params({"http://t.example.com/"})
        assert out and (tmp_path / "pool.jsonl").exists()

    @pytest.mark.asyncio
    async def test_enabled_but_mine_fails_isolated(self, monkeypatch):
        monkeypatch.setitem(recon_mod.settings.__dict__, "enable_param_mining", True)

        async def boom(*a, **k):
            raise RuntimeError("x")
        monkeypatch.setattr(recon_mod, "mine_params_for_endpoints", boom)
        from vulnclaw.modules.recon import EndpointCollector
        c = EndpointCollector()
        assert await c.mine_hidden_params(["http://t.example.com/"]) == []  # 异常隔离不上抛


# ============================================================
# SP15-B: B-SP15.2 挖掘器真扫自证（噪声反例 + 端点去重）
#          B-SP15.4 recon_brief 回灌（字段与 A 侧消费完全一致）
# ============================================================
class TestNoiseRules:
    @pytest.mark.asyncio
    async def test_404_not_counted_as_status_change(self, monkeypatch):
        """404 是全参数常态噪声 → 不计入 status_change（反例钉死）。"""
        monkeypatch.setattr(core_utils, "async_get", _mk_get({
            "_base": (200, "welcome home"),
            "admin=vulnclaw_p0": (404, "not found page" * 10),
        }))
        assert await mine_params("http://t.example.com/") == []

    @pytest.mark.asyncio
    async def test_small_len_delta_ignored(self, monkeypatch):
        """长度差 <64 视为噪声 → 不收录（反例钉死）。"""
        monkeypatch.setattr(core_utils, "async_get", _mk_get({
            "_base": (200, "welcome home"),
            "q=vulnclaw_p0": (200, "welcome home" + "x" * 10),
        }))
        assert await mine_params("http://t.example.com/") == []

    @pytest.mark.asyncio
    async def test_pool_entry_fields_complete(self, tmp_path, monkeypatch):
        """入池字段完整性：四字段齐全且类型正确。"""
        monkeypatch.setattr(core_utils, "async_get", _mk_get({
            "_base": (200, "welcome home"),
            "debug=vulnclaw_p0": (200, "welcome home vulnclaw_p0"),
        }))
        monkeypatch.setattr(recon_mod, "param_pool_path",
                            lambda: str(tmp_path / "pool.jsonl"))
        recon_mod._PARAM_POOL_SEEN.clear()
        out = await mine_params("http://t.example.com/?id=1")
        assert out and append_param_candidates(out) == len(out)
        rec = _json.loads((tmp_path / "pool.jsonl").read_text(encoding="utf-8").splitlines()[0])
        assert set(rec) == {"param", "url", "base_len", "signal"}
        assert isinstance(rec["param"], str) and isinstance(rec["url"], str)
        assert isinstance(rec["base_len"], int) and rec["signal"] == "reflected"


class TestEndpointDedup:
    @pytest.mark.asyncio
    async def test_duplicate_url_mined_once(self, monkeypatch):
        calls = []

        async def fake_mine(url, session=None, max_params=120, **kw):
            calls.append(url)
            return [{"param": "debug", "url": url, "base_len": 5, "signal": "reflected"}]

        monkeypatch.setattr(recon_mod, "mine_params", fake_mine)
        out = await recon_mod.mine_params_for_endpoints(
            ["http://t.example.com/a", "http://t.example.com/a",
             "http://t.example.com/b"])
        assert calls == ["http://t.example.com/a", "http://t.example.com/b"]
        assert len(out) == 2

    @pytest.mark.asyncio
    async def test_static_suffix_skipped(self, monkeypatch):
        calls = []

        async def fake_mine(url, session=None, max_params=120, **kw):
            calls.append(url)
            return []

        monkeypatch.setattr(recon_mod, "mine_params", fake_mine)
        await recon_mod.mine_params_for_endpoints(
            ["http://t.example.com/app.css", "http://t.example.com/logo.png",
             "http://t.example.com/search?id=1"])
        assert calls == ["http://t.example.com/search?id=1"]


class TestBriefParamMining:
    """B-SP15.4：回灌字段与 phases_taskgen 消费契约完全一致。"""

    def test_writes_normalized_four_fields(self):
        brief = {}
        items = [{"param": "debug", "url": "http://t/a?x=1", "base_len": 12,
                  "signal": "reflected", "extra": "junk-ignored"}]
        out = recon_mod.brief_param_mining(brief, items=items)
        assert len(out) == 1
        rec = out[0]
        assert set(rec) == {"param", "url", "base_len", "signal"}
        assert rec["param"] == "debug" and rec["url"] == "http://t/a?x=1"
        assert rec["base_len"] == 12 and rec["signal"] == "reflected"
        assert brief["param_mining"] is out

    def test_signals_ranked_reflected_first(self):
        out = recon_mod.brief_param_mining({}, items=[
            {"param": "a", "url": "http://t/1", "base_len": 1, "signal": "status_change"},
            {"param": "b", "url": "http://t/2", "base_len": 1, "signal": "reflected"},
            {"param": "c", "url": "http://t/3", "base_len": 1, "signal": "diff_len"},
        ])
        assert [d["param"] for d in out] == ["b", "c", "a"]

    def test_dirty_entries_rejected(self):
        out = recon_mod.brief_param_mining({}, items=[
            {"param": "ok", "url": "http://t/x", "base_len": 1, "signal": "reflected"},
            {"param": "no_sig", "url": "http://t/y", "base_len": 1, "signal": "weird"},
            {"param": "", "url": "http://t/z", "base_len": 1, "signal": "reflected"},
            {"param": "nourl", "url": "ftp://t/w", "base_len": 1, "signal": "reflected"},
            "junk",
        ])
        assert [d["param"] for d in out] == ["ok"]

    def test_idempotent_merge(self):
        brief = {}
        first = recon_mod.brief_param_mining(brief, items=[
            {"param": "debug", "url": "http://t/a", "base_len": 1, "signal": "reflected"}])
        second = recon_mod.brief_param_mining(brief, items=[
            {"param": "debug", "url": "http://t/a", "base_len": 1, "signal": "reflected"},
            {"param": "q", "url": "http://t/b", "base_len": 1, "signal": "diff_len"},
        ])
        assert len(first) == 1
        assert [d["param"] for d in second] == ["debug", "q"]  # 无重复

    def test_load_from_pool_and_max_items(self, tmp_path, monkeypatch):
        pool = tmp_path / "pool.jsonl"
        pool.write_text(
            _json.dumps({"param": "debug", "url": "http://t/a", "base_len": 5,
                         "signal": "reflected"}) + "\n" +
            _json.dumps({"param": "bad", "url": "http://t/b"}) + "\n" +  # 缺字段
            "not-json\n",
            encoding="utf-8")
        monkeypatch.setattr(recon_mod, "param_pool_path", lambda: str(pool))
        loaded = recon_mod.load_param_candidates()
        assert [d["param"] for d in loaded] == ["debug"]
        brief = {}
        out = recon_mod.brief_param_mining(brief)  # 缺省读池
        assert [d["param"] for d in out] == ["debug"]
        out2 = recon_mod.brief_param_mining({}, items=loaded, max_items=0)
        assert len(out2) == 1

    def test_taskgen_contract_simulation(self):
        """模拟 phases_taskgen 消费逻辑：剥 query/凭据过滤/静态过滤全兼容。"""
        import re as _re
        out = recon_mod.brief_param_mining({}, items=[
            {"param": "debug", "url": "http://t/search?q=1", "base_len": 9,
             "signal": "reflected"},
            {"param": "password", "url": "http://t/login", "base_len": 9,
             "signal": "reflected"},
            {"param": "file", "url": "http://t/style.css", "base_len": 9,
             "signal": "diff_len"},
        ])
        kept = []
        for item in out:
            url = item.get("url", "")
            param = str(item.get("param", ""))
            if url.split("?")[0].lower().endswith((".css", ".png", ".js")):
                continue  # _is_static_resource_url 等价
            if _re.fullmatch(r"(?i)(password|passwd|pwd|token|secret|api_?key)",
                             param or ""):
                continue  # _is_credential_param 等价
            kept.append((url.split("?")[0], param, item.get("signal", ""),
                         item.get("base_len", 0)))
        assert kept == [("http://t/search", "debug", "reflected", 9)]
