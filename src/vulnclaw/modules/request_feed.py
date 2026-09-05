# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# modules/request_feed.py
"""
请求级采集抽象（D4.1）与去重（D4.3）

- 三源归一：浏览器流（browser）/ Burp 代理流（burp）/ 被动爬取（passive）
  -> 统一的 RequestRecord，写入同一 RequestFeed 队列。
- 精确去重：同 URL 同参数（名+值）丢弃；同 URL 不同参数/不同值保留
  （不同参数值是不同注入面，对扫描有价值）。
- 路径模板聚类 + Jaccard 相似度工具：供任务生成侧做 restful id 归一复用
  （默认不删除相似请求，避免误删）。

设计约束（SP14.2 验收）：
- 本期仅抽象 + 队列 + 去重，不接主扫描链路（零行为影响、零回归）。
- 纯同步轻量实现（无网络/无外部依赖），便于单测与后续接入。
"""
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import parse_qs, urldefrag, urlencode, urlparse


# 无 emoji 约束（B heap 规则同源，保持全局一致）
_RESTFUL_ID_RE = re.compile(r"\b(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}|[0-9]{1,})\b", re.I)


def normalize_url(url: str, default_scheme: str = "http") -> str:
    """URL 归一化：去 fragment、补默认 scheme、路径非空、query 键序稳定。

    仅用于比较/去重键，不改变原始请求语义。
    """
    if not url or not isinstance(url, str):
        return ""
    url = url.strip()
    if "://" not in url:
        url = default_scheme + "://" + url
    url, _ = urldefrag(url)
    parsed = urlparse(url)
    path = parsed.path or "/"
    # 键序稳定：按参数名排序后重编码（值保留）
    params = parse_qs(parsed.query, keep_blank_values=True)
    if params:
        query = urlencode(
            [(k, v) for k in sorted(params) for v in params[k]], doseq=True
        )
    else:
        query = ""
    netloc = parsed.netloc
    if parsed.port and (
        (parsed.scheme == "http" and parsed.port == 80)
        or (parsed.scheme == "https" and parsed.port == 443)
    ):
        netloc = f"{parsed.hostname}"
    return f"{parsed.scheme}://{netloc}{path}" + (f"?{query}" if query else "")


def parse_params(url: str) -> Dict[str, List[str]]:
    """从 URL query 中提取参数（keep_blank_values）。"""
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def dedup_key(url: str, params: Optional[Dict[str, str]] = None) -> str:
    """精确去重键：path（归一化）+ 排序后的 name=value 对。

    同 URL 同参数（名+值）=> 同键（去重）；
    同 URL 不同参数/不同值 => 不同键（保留）。
    """
    norm = normalize_url(url)
    parsed = urlparse(norm)
    path = parsed.path or "/"
    pieces = [path]
    try:
        items = sorted((params or {}).items(), key=lambda kv: str(kv[0]))
        for k, v in items:
            pieces.append(f"{k}={v}")
    except Exception:  # noqa: BLE001
        pieces.append(hashlib.sha1(repr(params).encode()).hexdigest()[:12])
    return "|".join(pieces)


def path_template(url: str) -> str:
    """restful id 位归一为 {id}：/users/123/profile -> /users/{id}/profile。

    供任务生成侧模板聚类复用（D3.6 前置工具）。
    """
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    path = parsed.path or "/"
    # 模板带 scheme://host：不同站点各自聚类，不与纯 path 混淆
    return f"{parsed.scheme}://{parsed.netloc}{_RESTFUL_ID_RE.sub(chr(123)+chr(105)+chr(100)+chr(125), path)}"


def jaccard_similarity(seq_a: Set, seq_b: Set) -> float:
    if not seq_a and not seq_b:
        return 1.0
    union = seq_a | seq_b
    if not union:
        return 0.0
    return len(seq_a & seq_b) / len(union)


def jaccard_url_similarity(url_a: str, url_b: str) -> float:
    """URL 结构化 Jaccard：路径段集合 + 参数键集合（不含值，模糊可比）。

    阈值使用方按需设置；本模块默认不用它做删除，仅作聚类工具。
    """
    a_path = set(segment for segment in urlparse(normalize_url(url_a)).path.split("/") if segment)
    b_path = set(segment for segment in urlparse(normalize_url(url_b)).path.split("/") if segment)
    a_keys = set(parse_params(url_a).keys())
    b_keys = set(parse_params(url_b).keys())
    path_sim = 0.0
    key_sim = 1.0
    if (a_path or b_path):
        path_sim = jaccard_similarity(a_path, b_path)
    if (a_keys or b_keys):
        key_sim = jaccard_similarity(a_keys, b_keys)
    if not (a_path or b_path):
        return key_sim
    return 0.7 * path_sim + 0.3 * key_sim

"""D4.5 采集质量评分（SP15.3/SP15.5，A 线）。

0-10 分：带参 > 无参；短 URL 优；静态资源直接 0（不进任务生成）；
来源加权（browser/render、burp 高于被动爬取）。低于
settings.live_intake_min_score 的样本不进实时任务生成（控噪声预算）。
"""
_STATIC_PATH_HINTS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
)


def acq_score(record: "RequestRecord") -> int:
    path = (urlparse(record.url).path or "/").lower()
    if path.endswith(_STATIC_PATH_HINTS):
        return 0
    score = 6
    if record.params:
        score += 2
        if len(record.params) >= 2:
            score += 1
    if len(record.url) <= 200:
        score += 1
    src = (record.source or "").lower()
    if "render" in src or "browser" in src or "burp" in src:
        score += 1
    return min(score, 10)


@dataclass

class RequestRecord:
    """统一请求记录（三源归一后的最小信息集）。"""

    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    auth_state: str = ""  # 登录态标识（如会话标签/cookie 摘要），空=未认证
    source: str = ""  # browser | burp | passive
    raw: Dict = field(default_factory=dict)  # 原始报文摘要（保留原始头/体）
    ts: float = field(default_factory=time.time)
    dedup_key: str = ""
    path: str = ""

    def __post_init__(self):
        if not self.dedup_key:
            self.dedup_key = dedup_key(self.url, self.params)
        if not self.path:
            self.path = urlparse(normalize_url(self.url)).path or "/"


class RequestFeed:
    """三源请求统一队列（D4.1）+ 精确去重（D4.3）。

    - add() 返回 True 表示新记录入队；重复记录返回 False（不入队）。
    - 同 URL 不同参数/值保留（信息量不同，构成不同注入面）。
    """

    def __init__(self, max_size: int = 10000):
        self._records: List[RequestRecord] = []
        self._max_size = max_size
        self._keys: Set[str] = set()
        self._sources: Dict[str, int] = {}
        self._rejected = 0
        self._added = 0

    def add(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, str]] = None,
        auth_state: str = "",
        source: str = "",
        raw: Optional[Dict] = None,
    ) -> bool:
        """记录入队。返回 True=新增；False=重复（未入队）或非法 URL。"""
        if not url or not isinstance(url, str):
            self._rejected += 1
            return False
        method = (method or "GET").upper()
        record = RequestRecord(
            url=url,
            method=method,
            params=dict(params or {}),
            auth_state=auth_state or "",
            source=source or "",
            raw=dict(raw or {}),
        )
        if record.dedup_key in self._keys:
            self._rejected += 1
            return False
        if len(self._records) >= self._max_size:
            self._rejected += 1
            return False
        self._keys.add(record.dedup_key)
        self._records.append(record)
        src_key = record.source or "unknown"
        self._sources[src_key] = self._sources.get(src_key, 0) + 1
        self._added += 1
        return True

    # ---- 查询 / 统计 ----
    def records(self, source: Optional[str] = None) -> List[RequestRecord]:
        if not source:
            return list(self._records)
        return [r for r in self._records if r.source == source]

    def path_templates(self) -> List[str]:
        """路径模板聚类（restful id 位归一），供任务生成复用。"""
        seen: Set[str] = set()
        out: List[str] = []
        for r in self._records:
            tmpl = path_template(r.url)
            if tmpl not in seen:
                seen.add(tmpl)
                out.append(tmpl)
        return out

    def stats(self) -> Dict:
        return {
            "added": self._added,
            "rejected_dup_or_invalid": self._rejected,
            "size": len(self._records),
            "sources": dict(self._sources),
        }

    def __len__(self) -> int:
        return len(self._records)