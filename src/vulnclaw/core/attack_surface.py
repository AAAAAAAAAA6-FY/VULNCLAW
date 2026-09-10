# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""统一攻击面抽象（ControlledPoint）——新范式的地基。

背景：现有引擎的注入能力几乎都收敛在 `build_attack_url(url, param, payload, query)`
这一条路径上，它**只认 URL query 参数**。于是 header / cookie / body(form) /
JSON 键 / 路径段 里的可控点全部测不到，而这些恰恰是现代 API（JSON body 为主）
的主要注入面。每加一类注入点就要改一批引擎——这正是"逐加引擎"的根源之一。

本模块把"可控点"提升为一等公民：

    ControlledPoint  = 一个可被攻击者控制的输入位置（含位置类型、名字、当前值）
    RequestSpec      = 一次完整请求的可变描述（url / method / headers / body / json）
    render(point, v) = 把某可控点替换成新值，产出新的 RequestSpec（不改原对象）

有了这层，探针（元orphic / 差分 / 反射 …）只针对 `ControlledPoint` 工作，
**与"参数在哪个位置"解耦**——新增注入点类型只需扩展 Location，不必改探针。

设计原则：
  - 纯数据 + 纯函数，不发起网络请求（发送由探针决定，便于测试注入 mock）；
  - 不可变语义：render 返回新 RequestSpec，绝不原地修改；
  - 宽容解析：任何解析失败都降级为"跳过该点"，绝不抛异常打断扫描。
"""
from __future__ import annotations

import json as _json
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse


__all__ = [
    "PointLocation",
    "ControlledPoint",
    "RequestSpec",
    "render",
    "enumerate_points",
    "spec_from_url",
    "set_json_path",
    "get_json_path",
]


class PointLocation(str, Enum):
    """可控点所在位置。"""

    QUERY = "query"          # URL 查询参数
    PATH = "path"            # URL 路径段（如 /user/1001 的 1001）
    HEADER = "header"        # 请求头
    COOKIE = "cookie"        # Cookie 子键
    BODY_FORM = "body_form"  # application/x-www-form-urlencoded 表单字段
    BODY_JSON = "body_json"  # JSON body 的某个键（用 json_path 定位，支持 a.b.0.c）


# 不参与注入的请求头（改了只会破坏请求本身，无安全意义）
_SKIP_HEADERS = {
    "host", "content-length", "connection", "transfer-encoding",
    "expect", "upgrade", "te", "trailer",
}


@dataclass(frozen=True)
class ControlledPoint:
    """一个可被攻击者控制的输入位置。"""

    location: PointLocation
    name: str                       # 参数名 / header 名 / cookie 名 / JSON 键名
    value: str = ""                 # 当前观测到的值
    json_path: str = ""             # 仅 BODY_JSON：点分路径（支持下标，如 items.0.price）
    path_index: int = -1            # 仅 PATH：段索引
    # 语义提示（可选，供探针/编排做优先级排序）
    kind: str = ""                  # 如 amount / id / generic，由识别逻辑填

    @property
    def key(self) -> Tuple[str, str, str, int]:
        return (self.location.value, self.name, self.json_path, self.path_index)

    def label(self) -> str:
        """人类可读标识（用于 finding 的 parameter 字段）。"""
        if self.location == PointLocation.BODY_JSON:
            return f"json:{self.json_path or self.name}"
        if self.location == PointLocation.PATH:
            return f"path[{self.path_index}]:{self.name}"
        return f"{self.location.value}:{self.name}"


@dataclass(frozen=True)
class RequestSpec:
    """一次请求的可变描述（不可变对象，render 返回新实例）。"""

    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    form: Optional[Dict[str, Any]] = None   # 表单字段（application/x-www-form-urlencoded）
    json_obj: Optional[Any] = None          # JSON body（任意结构）
    body_raw: Optional[str] = None          # 其它原始 body（优先级低于 form/json）

    def is_json(self) -> bool:
        return self.json_obj is not None

    def to_send_kwargs(self) -> Dict[str, Any]:
        """转成 async_get / async_post 可接受的 kwargs。"""
        kw: Dict[str, Any] = {"headers": dict(self.headers) or None}
        if self.json_obj is not None:
            kw["json"] = self.json_obj
        elif self.form is not None:
            kw["data"] = self.form
        elif self.body_raw is not None:
            kw["data"] = self.body_raw
        return {k: v for k, v in kw.items() if v is not None}


# --------------------------------------------------------------------------
# 渲染：把某个可控点替换成新值
# --------------------------------------------------------------------------
def render(spec: RequestSpec, point: ControlledPoint, value: str) -> RequestSpec:
    """把 point 处的值替换为 value，返回新的 RequestSpec（不修改原对象）。"""
    loc = point.location
    if loc == PointLocation.QUERY:
        return replace(spec, url=_set_query(spec.url, point.name, value))
    if loc == PointLocation.PATH:
        return replace(spec, url=_set_path_segment(spec.url, point.path_index, value))
    if loc == PointLocation.HEADER:
        headers = dict(spec.headers)
        headers[point.name] = value
        return replace(spec, headers=headers)
    if loc == PointLocation.COOKIE:
        headers = dict(spec.headers)
        headers["Cookie"] = _set_cookie(headers.get("Cookie", ""), point.name, value)
        return replace(spec, headers=headers)
    if loc == PointLocation.BODY_FORM:
        form = dict(spec.form or {})
        form[point.name] = value
        return replace(spec, form=form)
    if loc == PointLocation.BODY_JSON:
        try:
            obj = _json.loads(_json.dumps(spec.json_obj))  # 深拷贝，避免污染原对象
        except Exception:  # noqa: BLE001 - json 不可序列化时退化为浅引用
            obj = spec.json_obj
        set_json_path(obj, point.json_path or point.name, _coerce(value, spec.json_obj,
                                                                 point.json_path or point.name))
        return replace(spec, json_obj=obj)
    return spec


# --------------------------------------------------------------------------
# 枚举：从一个请求中找出所有可控点
# --------------------------------------------------------------------------
def enumerate_points(spec: RequestSpec, include_headers: bool = True) -> List[ControlledPoint]:
    """枚举 spec 中所有可控点（探针的输入来源）。"""
    out: List[ControlledPoint] = []

    parsed = urlparse(spec.url)
    # 1) query
    for k, v in parse_qsl(parsed.query, keep_blank_values=True):
        out.append(ControlledPoint(PointLocation.QUERY, k, str(v)))
    # 2) path 段（只取"看起来像值"的段：纯数字或较长标识）
    segments = [s for s in parsed.path.split("/") if s]
    for idx, seg in enumerate(segments):
        if _looks_like_value(seg):
            out.append(ControlledPoint(PointLocation.PATH, seg, seg, path_index=idx))
    # 3) headers / cookie
    if include_headers:
        for k, v in (spec.headers or {}).items():
            if k.lower() == "cookie":
                for ck, cv in _parse_cookie(v):
                    out.append(ControlledPoint(PointLocation.COOKIE, ck, cv))
                continue
            if k.lower() in _SKIP_HEADERS:
                continue
            out.append(ControlledPoint(PointLocation.HEADER, k, str(v)))
    # 4) body form
    for k, v in (spec.form or {}).items():
        out.append(ControlledPoint(PointLocation.BODY_FORM, str(k), str(v)))
    # 5) body json（递归到叶节点）
    if spec.json_obj is not None:
        for path, val in _walk_json(spec.json_obj):
            out.append(ControlledPoint(
                PointLocation.BODY_JSON,
                name=path.rsplit(".", 1)[-1],
                value=str(val),
                json_path=path,
            ))
    return out


def spec_from_url(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
                  form: Optional[Dict[str, Any]] = None,
                  json_obj: Optional[Any] = None) -> RequestSpec:
    """便捷构造（向后兼容老的 endpoint+params 用法）。"""
    return RequestSpec(url=url, method=method, headers=dict(headers or {}),
                       form=form, json_obj=json_obj)


# --------------------------------------------------------------------------
# JSON 路径读写（支持 a.b.0.c）
# --------------------------------------------------------------------------
def set_json_path(obj: Any, path: str, value: Any) -> bool:
    if obj is None or not path:
        return False
    parts = path.split(".")
    cur = obj
    for p in parts[:-1]:
        if isinstance(cur, list):
            if not p.isdigit() or int(p) >= len(cur):
                return False
            cur = cur[int(p)]
        elif isinstance(cur, dict):
            if p not in cur:
                return False
            cur = cur[p]
        else:
            return False
    last = parts[-1]
    try:
        if isinstance(cur, list):
            if not last.isdigit() or int(last) >= len(cur):
                return False
            cur[int(last)] = value
        elif isinstance(cur, dict):
            cur[last] = value
        else:
            return False
    except Exception:  # noqa: BLE001
        return False
    return True


def get_json_path(obj: Any, path: str) -> Any:
    cur = obj
    for p in path.split("."):
        try:
            if isinstance(cur, list):
                cur = cur[int(p)]
            else:
                cur = cur[p]
        except Exception:  # noqa: BLE001
            return None
    return cur


# --------------------------------------------------------------------------
# 内部工具
# --------------------------------------------------------------------------
def _set_query(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q[key] = value
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, urlencode(q), parsed.fragment))


def _set_path_segment(url: str, index: int, value: str) -> str:
    parsed = urlparse(url)
    segments = [s for s in parsed.path.split("/")]
    # 还原带空段的原样结构，只对非空段计数
    pos = -1
    for i, seg in enumerate(segments):
        if seg:
            pos += 1
            if pos == index:
                segments[i] = quote(str(value), safe="")
                break
    return urlunparse((parsed.scheme, parsed.netloc, "/".join(segments),
                       parsed.params, parsed.query, parsed.fragment))


def _parse_cookie(raw: str) -> List[Tuple[str, str]]:
    out = []
    for part in (raw or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out.append((k.strip(), v.strip()))
    return out


def _set_cookie(raw: str, key: str, value: str) -> str:
    parts = []
    replaced = False
    for k, v in _parse_cookie(raw):
        if k == key:
            parts.append(f"{k}={value}")
            replaced = True
        else:
            parts.append(f"{k}={v}")
    if not replaced:
        parts.append(f"{key}={value}")
    return "; ".join(parts)


def _looks_like_value(seg: str) -> bool:
    """路径段是否像一个"值"（可替换），而不是固定的资源名。"""
    if not seg:
        return False
    if seg.isdigit():
        return True
    # 长随机串 / uuid 形态
    return len(seg) >= 8 and bool(_IDISH_RE.fullmatch(seg))


import re  # noqa: E402 - 仅被 _looks_like_value 使用，置于文件尾避免与 dataclass 抢读

_IDISH_RE = re.compile(r"[A-Za-z0-9_-]+")


def _coerce(value: str, original_obj: Any, path: str) -> Any:
    """尽量保持原字段类型（数字字段仍写数字），减少因类型变化导致的噪声。"""
    try:
        cur = get_json_path(original_obj, path)
    except Exception:  # noqa: BLE001
        return value
    if isinstance(cur, bool):
        return value.lower() in ("1", "true", "yes")
    if isinstance(cur, (int, float)) and not isinstance(cur, bool):
        # 数字字段保持数字类型：0.01 写入 int 字段时降级为 float，
        # 避免"期望 number 却收到 string"导致服务端直接报错而漏判。
        try:
            f = float(value)
            if isinstance(cur, int) and f.is_integer():
                return int(f)
            return f
        except (TypeError, ValueError):
            return value
    return value


def _walk_json(obj: Any, prefix: str = "") -> List[Tuple[str, Any]]:
    """深度遍历 JSON，返回 (点分路径, 叶值)；只取标量叶节点。"""
    out: List[Tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                out.extend(_walk_json(v, path))
            else:
                out.append((path, v))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            path = f"{prefix}.{i}" if prefix else str(i)
            if isinstance(v, (dict, list)):
                out.extend(_walk_json(v, path))
            else:
                out.append((path, v))
    return out
