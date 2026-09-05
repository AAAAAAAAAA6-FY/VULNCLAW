# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""SP14.2 (D4.1+D4.3) request_feed 单元测试。

覆盖：三源归一入同一队列；精确去重（同 URL 同参数值去重、不同参数/值保留）；
      URL 归一化；restful 路径模板聚类；Jaccard 相似度工具；上限与非法输入。
"""

from vulnclaw.modules.request_feed import (
    RequestFeed,
    RequestRecord,
    dedup_key,
    jaccard_similarity,
    jaccard_url_similarity,
    normalize_url,
    parse_params,
    path_template,
)


class TestNormalize:
    def test_defrag_and_scheme(self):
        assert normalize_url("example.com/x?a=1#sec") == "http://example.com/x?a=1"

    def test_query_key_order_stable(self):
        assert normalize_url("http://e/x?b=2&a=1") == normalize_url("http://e/x?a=1&b=2")

    def test_default_path(self):
        assert normalize_url("http://e") == "http://e/"

    def test_port_dropped_when_default(self):
        assert normalize_url("http://e:80/x") == "http://e/x"
        assert normalize_url("https://e:443/x") == "https://e/x"
        assert normalize_url("http://e:8080/x") == "http://e:8080/x"

    def test_invalid_input(self):
        assert normalize_url("") == ""
        assert parse_params("http://e/x?q=1") == {"q": ["1"]}


class TestDedupKey:
    def test_same_url_same_param_same_key(self):
        assert dedup_key("http://e/x", {"a": "1"}) == dedup_key("http://e/x", {"a": "1"})

    def test_no_param_vs_param_differ(self):
        assert dedup_key("http://e/x") != dedup_key("http://e/x", {"a": "1"})

    def test_different_param_values_differ(self):
        # 不同值是不同注入面 → 不同键（保留）
        assert dedup_key("http://e/x", {"a": "1"}) != dedup_key("http://e/x", {"a": "2"})


class TestPathTemplate:
    def test_numeric_id(self):
        assert path_template("http://e/users/123/profile") == "http://e/users/{id}/profile"

    def test_uuid_id(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert path_template(f"http://e/items/{uuid}") == "http://e/items/{id}"

    def test_short_segment_kept(self):
        assert path_template("http://e/a/1b/profile") == "http://e/a/1b/profile"


class TestJaccard:
    def test_identical(self):
        assert jaccard_similarity({"a", "b"}, {"a", "b"}) == 1.0

    def test_disjoint(self):
        assert jaccard_similarity({"a"}, {"b"}) == 0.0

    def test_url_tool(self):
        # 相同路径不同参数键与值：路径相似度高
        sim = jaccard_url_similarity("http://e/api/list?q=1&p=2", "http://e/api/list?q=3&z=9")
        assert sim > 0.5


class TestFeed:
    def test_three_sources_into_one_queue(self):
        feed = RequestFeed()
        assert feed.add("http://e/p1", source="browser") is True
        assert feed.add("http://e/p2?a=1#x", source="burp") is True
        assert feed.add("http://e/p3", source="passive") is True
        assert len(feed) == 3
        assert len(feed.records("browser")) == 1
        assert len(feed.records("burp")) == 1
        assert len(feed.records("passive")) == 1
        st = feed.stats()
        assert st["added"] == 3
        assert set(st["sources"]) == {"browser", "burp", "passive"}

    def test_dup_same_url_same_param_rejected(self):
        feed = RequestFeed()
        assert feed.add("http://e/x", params={"a": "1"}) is True
        assert feed.add("http://e/x", params={"a": "1"}) is False
        assert len(feed) == 1

    def test_same_url_different_param_kept(self):
        feed = RequestFeed()
        assert feed.add("http://e/x", params={"a": "1"}) is True
        assert feed.add("http://e/x", params={"b": "1"}) is True
        assert feed.add("http://e/x", params={"a": "2"}) is True  # 同参数不同值 → 保留
        assert len(feed) == 3

    def test_fragment_ignored_in_dup(self):
        feed = RequestFeed()
        assert feed.add("http://e/x?a=1#frag") is True
        assert feed.add("http://e/x?a=1") is False  # fragment 不参与去重

    def test_invalid_or_empty_rejected(self):
        feed = RequestFeed()
        assert feed.add("") is False
        assert feed.add(None) is False
        assert len(feed) == 0

    def test_max_size_cap(self):
        feed = RequestFeed(max_size=2)
        assert feed.add("http://e/1") is True
        assert feed.add("http://e/2") is True
        assert feed.add("http://e/3") is False
        assert len(feed) == 2

    def test_method_normalized_upper(self):
        feed = RequestFeed()
        feed.add("http://e/x", method="post")
        assert feed.records()[0].method == "POST"

    def test_path_templates(self):
        feed = RequestFeed()
        feed.add("http://e/users/1")
        feed.add("http://e/users/42")
        feed.add("http://e/api/7")  # 数字段 → restful id 位
        tmpls = feed.path_templates()
        assert "http://e/users/{id}" in tmpls
        assert "http://e/api/{id}" in tmpls

    def test_record_fields_complete(self):
        feed = RequestFeed()
        feed.add("http://e/x?q=1", method="GET", params={"q": "1"},
                 auth_state="sess1", source="burp", raw={"url": "orig"})
        r: RequestRecord = feed.records()[0]
        assert r.url == "http://e/x?q=1"
        assert r.method == "GET"
        assert r.params == {"q": "1"}
        assert r.auth_state == "sess1"
        assert r.source == "burp"
        assert r.raw == {"url": "orig"}
        assert r.dedup_key
        assert r.path == "/x"