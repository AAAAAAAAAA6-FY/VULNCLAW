# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""SP14.3 (Z2.4 A线) OOB 证据 enrich 单元测试。

覆盖：自带 oob 上下文组装；oob_channel 查询接口（try-import）；
      无回调不写字段；空 dict 不写；http 回调生成 curl；enrich_finding 链路。
"""

import pytest

from vulnclaw.engines.base import attach_oob_evidence, enrich_finding


def _install_fake_oob(monkeypatch, query_fn=None):
    """在真实 oob_channel 模块上 patch query_oob_evidence（B 侧接口未就绪时模拟）。

    注意：不能用 sys.modules 假模块替换——`from vulnclaw.core import oob_channel`
    在真实模块已导入后直接命中包属性，绕过 sys.modules；必须 patch 真实模块对象。
    """
    import vulnclaw.core.oob_channel as real_mod
    if query_fn is None:
        def query_fn(tok):
            return {"ts": "2026-09-05T10:00:00Z", "channel": "dns",
                    "token": tok, "detail": "dnslog hit example.dnslog.cn: 1.2.3.4"}
    monkeypatch.setattr(real_mod, "query_oob_evidence", query_fn, raising=False)
    # 屏蔽 B 侧实供接口，避免真实审计数据串入（单测隔离）
    monkeypatch.setattr(real_mod, "get_oob_evidence", lambda tok: [], raising=False)
    return real_mod


class TestAttachOobEvidence:
    def test_finding_own_oob_dict(self):
        f = attach_oob_evidence({
            "url": "http://t/x?url=http://e",
            "oob": {"ts": "2026-09-05T10:00:00Z", "channel": "http",
                    "token": "abc123", "detail": "callback http://oob.local/c/abc123"},
        })
        oe = f.get("oob_evidence")
        assert oe
        assert oe["ts"].startswith("2026-09-05")
        assert oe["channel"] == "http"
        assert oe["token"] == "abc123"
        assert oe["curl"]  # http 通道 → 生成 curl
        assert "callback" in oe["detail"]
        assert f["url"] == "http://t/x?url=http://e"  # 原字段保留

    def test_no_oob_yields_no_field(self):
        f = attach_oob_evidence({"url": "http://t/x", "evidence": "plain"})
        assert "oob_evidence" not in f

    def test_empty_oob_dict_skipped(self):
        f = attach_oob_evidence({"url": "http://t/x", "oob": {}})
        assert "oob_evidence" not in f

    def test_channel_query_try_import(self, monkeypatch):
        # 未装假模块 → 真模块有实现则查询，无实现则跳过（不可抛异常）
        f = attach_oob_evidence({"url": "http://t/x", "oob_token": "tok1"})
        assert "oob_evidence" not in f or isinstance(f["oob_evidence"], dict)

    def test_query_interface_used(self, monkeypatch):
        mod = _install_fake_oob(monkeypatch)
        f = attach_oob_evidence({"url": "http://t/x", "oob_token": "tok9"})
        oe = f.get("oob_evidence")
        assert oe and oe["token"] == "tok9"
        assert oe["channel"] == "dns"

    def test_query_exception_graceful(self, monkeypatch):
        def boom(tok):
            raise RuntimeError("oob backend down")
        _install_fake_oob(monkeypatch, query_fn=boom)
        f = attach_oob_evidence({"url": "http://t/x", "oob_token": "t1"})
        assert "oob_evidence" not in f

    def test_dns_channel_no_curl(self):
        f = attach_oob_evidence({"url": "http://t/x",
                                 "oob": {"ts": "2026-09-05T10:00:00Z", "channel": "dns",
                                         "token": "t", "detail": "hit 1.2.3.4"}})
        assert f["oob_evidence"]["curl"] == ""

    # ---- SP15.1 合流：B 侧实供 get_oob_evidence -> List[evidence_view] ----
    def _install_fake_oob_list(self, monkeypatch, views=None, getter=None, raise_on_get=False):
        import vulnclaw.core.oob_channel as real_mod

        def default_getter(tok):
            return views if views is not None else []

        def raising_getter(tok):
            raise RuntimeError("oob backend down")

        target = raising_getter if raise_on_get else (getter or default_getter)
        monkeypatch.setattr(real_mod, "get_oob_evidence", target, raising=False)
        # 屏蔽旧约定查询接口，避免 get 空结果时回退串入真实审计数据
        monkeypatch.setattr(real_mod, "query_oob_evidence", lambda tok: None, raising=False)
        return real_mod

    def test_b_interface_view_list_mapped(self, monkeypatch):
        self._install_fake_oob_list(monkeypatch, views=[{
            "oob_ts": "2026-09-06T08:00:00Z", "oob_channel": "dnslog:dns",
            "oob_token": "tok9", "oob_detail": "hit 9.9.9.9:53",
        }])
        f = attach_oob_evidence({"url": "http://t/x", "oob_token": "tok9"})
        oe = f.get("oob_evidence")
        assert oe and oe["token"] == "tok9"          # oob_token -> token
        assert oe["ts"].startswith("2026-09-06")     # oob_ts -> ts
        assert "dnslog:dns" in oe["channel"]          # oob_channel 原样保留
        assert oe["detail"] == "hit 9.9.9.9:53"
        assert oe["curl"] == ""                       # dns 通道不生成 curl

    def test_b_interface_http_channel_builds_curl(self, monkeypatch):
        self._install_fake_oob_list(monkeypatch, views=[{
            "oob_ts": "2026-09-06T08:01:00Z", "oob_channel": "interactsh:http",
            "oob_token": "tok1", "oob_detail": "GET http://oob.local/c/tok1",
        }])
        f = attach_oob_evidence({"url": "http://t/y", "oob_token": "tok1"})
        oe = f.get("oob_evidence")
        assert oe and oe["curl"].startswith("curl -s")
        assert "oob.local/c/tok1" in oe["curl"]

    def test_b_interface_empty_list_yields_no_field(self, monkeypatch):
        self._install_fake_oob_list(monkeypatch, views=[])
        f = attach_oob_evidence({"url": "http://t/z", "oob_token": "nohit"})
        assert "oob_evidence" not in f

    def test_b_interface_exception_graceful(self, monkeypatch):
        self._install_fake_oob_list(monkeypatch, raise_on_get=True)
        f = attach_oob_evidence({"url": "http://t/q", "oob_token": "t1"})
        assert "oob_evidence" not in f


class TestThroughEnrichFinding:
    def test_enrich_finding_chain(self):
        f = enrich_finding({"url": "http://t/x", "type": "盲SSRF",
                            "oob": {"ts": "2026-09-05T10:00:00Z", "channel": "http",
                                    "token": "t1", "detail": "hit http://oob.local/x"}})
        assert f.get("oob_evidence")
        assert f.get("curl_command")  # P2-5 原有能力不丢
        assert f.get("reproduction_steps")