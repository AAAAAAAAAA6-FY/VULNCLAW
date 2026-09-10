# -*- coding: utf-8 -*-
"""统一攻击面抽象（ControlledPoint / RequestSpec）专项测试。

验证：六类注入点的枚举、渲染不可变性、JSON 嵌套路径读写与类型保真。
"""
from vulnclaw.core.attack_surface import (
    ControlledPoint,
    PointLocation,
    enumerate_points,
    get_json_path,
    render,
    set_json_path,
    spec_from_url,
)


# ---------------------------------------------------------------- 枚举
def test_enumerate_query_and_form():
    spec = spec_from_url("https://x.test/a?p=1&q=2", "POST", form={"f": "3"})
    locs = {(p.location.value, p.name, p.value) for p in enumerate_points(spec)}
    assert ("query", "p", "1") in locs
    assert ("body_form", "f", "3") in locs


def test_enumerate_json_nested_paths():
    spec = spec_from_url("https://x.test/a", "POST",
                         json_obj={"total": 200, "items": [{"price": 50}]})
    paths = {p.json_path for p in enumerate_points(spec)
             if p.location == PointLocation.BODY_JSON}
    assert paths == {"total", "items.0.price"}


def test_enumerate_path_header_cookie():
    spec = spec_from_url("https://x.test/user/1001/profile", "GET",
                         headers={"X-User-Id": "1001", "Cookie": "uid=1001; sess=abc"})
    pts = enumerate_points(spec)
    assert any(p.location == PointLocation.PATH and p.value == "1001" for p in pts)
    assert any(p.location == PointLocation.COOKIE and p.name == "uid" for p in pts)
    assert any(p.location == PointLocation.HEADER and p.name == "X-User-Id" for p in pts)


def test_enumerate_skips_meaningless_headers():
    spec = spec_from_url("https://x.test/a", "GET",
                         headers={"Host": "x.test", "Content-Length": "0", "X-A": "1"})
    names = {p.name for p in enumerate_points(spec) if p.location == PointLocation.HEADER}
    assert "X-A" in names
    assert "Host" not in names and "Content-Length" not in names


# ---------------------------------------------------------------- 渲染
def test_render_query_keeps_original_unchanged():
    spec = spec_from_url("https://x.test/a?p=1")
    new = render(spec, ControlledPoint(PointLocation.QUERY, "p", "1"), "9")
    assert new.url.endswith("p=9")
    assert spec.url.endswith("p=1")  # 原对象不可变


def test_render_header_and_cookie():
    spec = spec_from_url("https://x.test/a", "GET",
                         headers={"X-A": "1", "Cookie": "uid=1; sess=s"})
    assert render(spec, ControlledPoint(PointLocation.HEADER, "X-A", "1"), "2").headers["X-A"] == "2"
    ck = render(spec, ControlledPoint(PointLocation.COOKIE, "uid", "1"), "9").headers["Cookie"]
    assert "uid=9" in ck and "sess=s" in ck  # 只改目标 cookie


def test_render_path_segment():
    spec = spec_from_url("https://x.test/user/1001/profile", "GET")
    pt = ControlledPoint(PointLocation.PATH, "1001", "1001", path_index=1)
    assert render(spec, pt, "1002").url == "https://x.test/user/1002/profile"


def test_render_json_nested_preserves_numeric_type():
    spec = spec_from_url("https://x.test/a", "POST",
                         json_obj={"total": 200, "items": [{"price": 50}]})
    n = render(spec, ControlledPoint(PointLocation.BODY_JSON, "price", "50",
                                     json_path="items.0.price"), "0.01")
    assert n.json_obj["items"][0]["price"] == 0.01          # 数字字段仍写数字
    assert spec.json_obj["items"][0]["price"] == 50         # 原对象未被污染

    n2 = render(spec, ControlledPoint(PointLocation.BODY_JSON, "total", "200",
                                      json_path="total"), "1")
    assert n2.json_obj["total"] == 1 and isinstance(n2.json_obj["total"], int)


# ---------------------------------------------------------------- JSON 路径
def test_json_path_get_set():
    obj = {"a": {"b": [{"c": 1}]}}
    assert get_json_path(obj, "a.b.0.c") == 1
    assert set_json_path(obj, "a.b.0.c", 9) is True
    assert get_json_path(obj, "a.b.0.c") == 9
    assert set_json_path(obj, "a.x.y", 1) is False   # 路径不存在：False 而不抛异常
    assert get_json_path(obj, "a.nope") is None


# ---------------------------------------------------------------- 请求描述
def test_to_send_kwargs_json_and_form():
    spec = spec_from_url("https://x.test/a", "POST", json_obj={"k": 1})
    assert spec.to_send_kwargs()["json"] == {"k": 1}
    spec2 = spec_from_url("https://x.test/a", "POST", form={"k": "1"},
                          headers={"X-A": "1"})
    kw = spec2.to_send_kwargs()
    assert kw["data"] == {"k": "1"} and kw["headers"] == {"X-A": "1"}
