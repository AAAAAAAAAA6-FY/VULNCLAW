# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""请求侧变异 / 模糊测试（最基础版，全离线、确定性、无随机）。

覆盖三组：
  A 解析器健壮性     —— 变异语料喂核心解析函数：不崩、返回合法结构
  B 规则不被简单绕过 —— 编码/大小写变异 payload 打内嵌 aiohttp 靶场
  C 资源边界         —— 超长输入与超大响应截断有界

约定与限制（如实声明，不做断言放宽）：
  * 环境无 pytest-timeout，耗时上限一律用 ``time.monotonic()`` 自建。
  * 靶场只模拟 "HTTP 层解一次 + 应用层再解一次" 的两层解码链；
    三层编码（``%252e``）超出该模型，因此**不断言其命中**，
    只断言它不会凭空被判成 Critical（详见 docs/MUTATION_FINDINGS.md）。
  * 变异语料由 ``scripts/mutation_probe.py`` 生成（零随机，多次运行逐字节一致）。
"""
import json
import os
import posixpath
import sys
import time
from html import escape as _html_escape
from urllib.parse import parse_qsl, quote, unquote, urlparse

import pytest
import pytest_asyncio
from aiohttp import ClientSession, web
from aiohttp.test_utils import TestServer

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPTS_DIR = os.path.join(_PROJECT_ROOT, "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from mutation_probe import mutate, variant_values  # noqa: E402

# ============================================================
# 语料与靶场常量
# ============================================================
#: 变异种子：普通文本、非 ASCII、查询串、注入特征、路径穿越、XML、空串
_CORPUS_SEEDS = (
    "hello world",
    "caf\u00e9",
    "a=1&b=2",
    "' OR 1=1--",
    "../../../../etc/passwd",
    "<xml>root</xml>",
    "",
)
#: 语料刻意用很小的 long_len / json_depth，保证整文件秒级跑完
_CORPUS = tuple(
    dict.fromkeys(
        value
        for seed in _CORPUS_SEEDS
        for value in variant_values(seed, "all", long_len=128, json_depth=8)
    )
)

_SAFE_PAGE = (
    "<html><body><h1>Search</h1><div>idle</div><p>ok</p>"
    "<span>no result for your query</span></body></html>"
)

#: 靶场回显的 passwd 内容（含 FILE_INCLUDE_INDICATORS 里的 root:x:0:0:）
_LAB_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/bin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
)

#: LFI 的编码等价类维度（靶场两层解码链下与原文语义等价）
_LFI_EQUIVALENT_DIMENSIONS = (
    "url_encode",
    "percent_case_lower",
    "percent_case_upper",
    "path_traversal_dotdot_encoded_lower",
    "path_traversal_dotdot_encoded_upper",
    "path_traversal_encoded_dots",
)
#: 纯三层编码（不含明文 ../），超出靶场两层解码链 → 用于负向对照。
#: 注意：不能复用 mutation_probe 的 path_traversal_double_encoded 维度 ——
#: 该维度尾部保留明文 "../../../../etc/passwd"，靶场仍会读到文件，
#: 引擎报 Critical 属**真实检出**而非幻觉，拿它做负向用例会成立不了。
_LFI_PURE_TRIPLE_ENCODED = "%252e%252e%252f" * 4 + "etc/passwd"


def _normal_resp(text: str = _SAFE_PAGE):
    return (200, text, {})


def _variants_by_dimension(text: str, **kwargs) -> dict:
    """dimension -> value（同维度重复时保留首个，顺序由 mutation_probe 保证）。"""
    out = {}
    for item in mutate(text, ("all",), **kwargs):
        out.setdefault(item["dimension"], item["value"])
    return out


def _timebound(t0: float, max_seconds: float, what: str) -> None:
    elapsed = time.monotonic() - t0
    assert elapsed < max_seconds, f"{what} 耗时 {elapsed:.2f}s 超上限 {max_seconds}s"


# ============================================================
# A. 解析器健壮性
# ============================================================
def test_deep_nested_json_does_not_crash_clean_ai_json():
    """深层嵌套 JSON 曾让 clean_ai_json 抛 RecursionError 直接冒泡（解析崩溃）。

    ``json.loads`` 对超深嵌套抛的是 RecursionError（继承 RuntimeError），
    而非 JSONDecodeError —— 原实现只捕获后者。这里锁死修复。
    """
    from vulnclaw.core.utils import clean_ai_json

    for depth in (200, 2000, 5000):
        deep = "[" * depth + "1" + "]" * depth
        t0 = time.monotonic()
        out = clean_ai_json(deep)
        _timebound(t0, 5.0, f"clean_ai_json(深度 {depth})")
        json.loads(out)  # 返回值必须是合法 JSON（不得是半截原文）


def test_mutation_corpus_does_not_break_core_parsers():
    """全部变异样本喂给核心解析函数：不得抛未捕获异常。

    这批函数都在请求/响应主链路上，任何一个崩掉都会让整次扫描中断。
    """
    from vulnclaw.core.utils import (
        build_attack_url,
        clean_ai_json,
        compress_http_response,
        ensure_scheme,
        limit_response_size,
    )
    from vulnclaw.engines.web_engines import LFIEngine
    from vulnclaw.runners.scan_runner import parse_cookie_str

    engine = LFIEngine()
    base_url = "http://t.local/s?q=1"

    checks = (
        ("ensure_scheme", lambda v: ensure_scheme(v)),
        ("build_attack_url/payload", lambda v: build_attack_url(base_url, "q", v, "q=1")),
        ("build_attack_url/param", lambda v: build_attack_url(base_url, v, "1", "q=1")),
        ("clean_ai_json", lambda v: json.loads(clean_ai_json(v))),
        ("limit_response_size", lambda v: limit_response_size(v)),
        ("compress_http_response", lambda v: compress_http_response(v)),
        ("parse_cookie_str", lambda v: parse_cookie_str(v)),
        ("strip_payload_reflection", lambda v: engine.strip_payload_reflection(v, v)),
        ("has_response_diff", lambda v: engine.has_response_diff((200, v, {}), (200, v, {}))),
    )

    failures = []
    for value in _CORPUS:
        for name, fn in checks:
            try:
                fn(value)
            except Exception as exc:  # noqa: BLE001 - 这里就是要抓一切异常
                failures.append(f"{name}({value[:30]!r}) -> {type(exc).__name__}: {exc}")
    assert not failures, (
        f"解析器在变异输入上崩溃 {len(failures)} 处（共 {len(_CORPUS)} 个样本）：\n"
        + "\n".join(failures[:10])
    )


def test_build_attack_url_roundtrip_is_stable():
    """请求侧不得丢/改 payload：URL 构造后服务端单次解码必须还原原值。

    build_attack_url 用 urlencode(doseq=True) 承载 payload，服务端解一次即应
    拿到原值；任何编码形态被二次编码或截断，都会让变异 payload 在半路失真。
    """
    from vulnclaw.core.utils import build_attack_url

    broken = []
    for value in _CORPUS:
        url = build_attack_url("http://t.local/s?q=1", "q", value, "q=1")
        got = dict(parse_qsl(urlparse(url).query, keep_blank_values=True)).get("q")
        if got != value:
            broken.append((value[:40], url[:100], (got or "")[:40]))
    assert not broken, f"URL 构造往返失真 {len(broken)} 处：{broken[:3]}"


# ============================================================
# B. 规则不被简单绕过 / 不产生幻觉
# ============================================================
def test_html_escaped_echo_does_not_create_phantom_diff():
    """回显型目标：服务端把参数 HTML 转义后回显，不得产生幻影 diff。

    原 strip_payload_reflection 只剥离「原文 / URL 编码 / URL 解码」三种形态，
    被 HTML 转义（``<`` → ``&lt;``、``'`` → ``&#x27;``）的回显会整体残留，
    使 A/B 两响应"天然不同" → 所有 diff 型判定误报。
    """
    from vulnclaw.engines.web_engines import LFIEngine

    engine = LFIEngine()
    payloads = [
        "<script>alert(1)</script>",   # 标签型 → HTML 转义后大幅变形
        "a'b\"c",                      # 引号型 → 转义成 &#x27; / &quot;
        "{{7*7}}",
        "..%2f..%2fetc%2fpasswd",
        ";id",
    ]

    phantom = []
    for payload in payloads:
        attack_text = _SAFE_PAGE.replace("idle", _html_escape(payload, quote=True))
        stripped = engine.strip_payload_reflection(attack_text, payload)
        has_diff, ratio = engine.has_response_diff(
            _normal_resp(), (200, stripped, {}), threshold=0.3
        )
        if has_diff:
            phantom.append((payload, round(ratio, 3)))
    assert not phantom, f"回显型目标产生幻影 diff（剥离形态不全）: {phantom}"


def test_long_control_chars_do_not_trigger_phantom_indicator():
    """含控制字符/长串的变异体自身不得被判成"回显即漏洞"。

    把变异体原文当响应体（即目标原样回显），剥离后不应剩下任何指示器特征。
    """
    from vulnclaw.engines.net_engines import SSRFEngine

    engine = SSRFEngine()
    benign_seeds = ("hello world", "caf\u00e9", "a=1&b=2", "<xml>root</xml>")

    hits = []
    for seed in benign_seeds:
        for value in variant_values(seed, "all", long_len=64, json_depth=4):
            stripped = engine._strip_payload_refl(value, value)
            if engine._has_ssrf_indicator(stripped):
                hits.append((seed, value[:40], stripped[:60]))
    assert not hits, f"回显变异体被误判为 SSRF 指示器：{hits[:3]}"


# ============================================================
# B'. 内嵌 aiohttp 靶场：编码变体不导致漏检
# ============================================================
@web.middleware
async def _lab_hit_counter(request, handler):
    _LAB_HITS[request.path] = _LAB_HITS.get(request.path, 0) + 1
    return await handler(request)


_LAB_HITS: dict = {}


def _build_lab_app() -> web.Application:
    """最小靶场：模拟 "HTTP 层解一次 + 应用层再解一次" 的两层解码链。"""
    app = web.Application(middlewares=[_lab_hit_counter])

    async def lfi_view(request: web.Request) -> web.Response:
        raw = request.query.get("file", "")
        decoded = unquote(raw)          # 应用层再解一次
        normalized = posixpath.normpath(decoded)
        if "../" in normalized and normalized.endswith("etc/passwd"):
            return web.Response(text=_LAB_PASSWD)
        return web.Response(text="not found")

    async def echo_view(request: web.Request) -> web.Response:
        raw = request.query.get("q", "")
        return web.Response(text=f"<html><body><div>{_html_escape(raw, quote=True)}</div></body></html>")

    app.router.add_get("/lfi", lfi_view)
    app.router.add_get("/echo", echo_view)
    return app


@pytest_asyncio.fixture
async def lab_base():
    _LAB_HITS.clear()
    server = TestServer(_build_lab_app())
    await server.start_server(host="127.0.0.1", port=None)
    try:
        yield f"http://127.0.0.1:{server.port}"
    finally:
        await server.close()


@pytest_asyncio.fixture
async def session():
    async with ClientSession() as sess:
        yield sess


def _pin_payload(engine, payload: str) -> None:
    """把引擎 payload 表钉成单个变异体，专测"判定链是否会被该形态绕过"。"""
    engine.get_payloads = lambda param=None, max_count=None, _p=payload: [(_p, "mutation")]


@pytest.mark.asyncio
async def test_encoded_lfi_variant_still_detected(lab_base, session):
    """编码/大小写变异 payload 打靶场：编码变体不得导致漏检（正向对照）。"""
    from vulnclaw.engines.web_engines import LFIEngine

    canonical = "../../../../etc/passwd"
    dims = _variants_by_dimension(canonical, long_len=64, json_depth=4)
    candidates = [canonical] + [
        dims[name] for name in _LFI_EQUIVALENT_DIMENSIONS if name in dims
    ]
    assert len(candidates) >= 4, f"编码等价类语料不足: {candidates}"

    for payload in candidates:
        engine = LFIEngine()
        _pin_payload(engine, payload)
        t0 = time.monotonic()
        result = await engine.check(
            f"{lab_base}/lfi?file=x", "file", _normal_resp(), "file=x", session
        )
        _timebound(t0, 15.0, f"LFI 检查({payload!r})")
        assert result, f"编码变体漏检: {payload!r}"
        assert result.get("severity") in ("Critical", "High"), (
            f"编码变体严重级异常: {payload!r} -> {result}"
        )
        assert result.get("parameter") == "file"


@pytest.mark.asyncio
async def test_beyond_lab_decoding_chain_not_flagged_critical(lab_base, session):
    """纯三层编码超出靶场两层解码链：不得凭空判 Critical（如实记录为已知局限）。

    靶场此时确实没读到文件（解码后是 ``%2e%2e%2f...``，不含明文 ``../``），
    因此引擎不得给出 Critical —— 给了就是幻觉。
    """
    from vulnclaw.engines.web_engines import LFIEngine

    engine = LFIEngine()
    _pin_payload(engine, _LFI_PURE_TRIPLE_ENCODED)
    result = await engine.check(
        f"{lab_base}/lfi?file=x", "file", _normal_resp(), "file=x", session
    )
    assert not result or result.get("severity") != "Critical", (
        f"纯三层编码被凭空判 Critical: {_LFI_PURE_TRIPLE_ENCODED!r} -> {result}"
    )


@pytest.mark.asyncio
async def test_echo_endpoint_variant_not_flagged(lab_base, session):
    """echo 靶场（HTML 转义回显）不得被判成文件包含。"""
    from vulnclaw.engines.web_engines import LFIEngine

    dims = _variants_by_dimension("../../../../etc/passwd", long_len=64, json_depth=4)
    payload = dims["url_encode"]

    engine = LFIEngine()
    _pin_payload(engine, payload)
    result = await engine.check(
        f"{lab_base}/echo?q=x", "q", _normal_resp(), "q=x", session
    )
    assert not result or result.get("severity") != "Critical", (
        f"纯回显端点被判成文件包含: {result}"
    )


# ============================================================
# C. 资源边界（最基础：超长输入 + 截断有界）
# ============================================================
def test_long_input_and_response_truncation_are_bounded():
    """超长 payload 与超大响应必须有界，不得出现无界读取/卡死。"""
    from vulnclaw.core.utils import (
        build_attack_url,
        compress_http_response,
        limit_response_size,
    )

    long_value = "A" * 200_000
    t0 = time.monotonic()
    url = build_attack_url("http://t.local/s?q=1", "q", long_value, "q=1")
    _timebound(t0, 5.0, "build_attack_url(200KB)")
    carried = unquote(urlparse(url).query.split("=", 1)[1])
    assert carried == long_value, "超长 payload 在 URL 构造中被截断"

    big = "B" * 2_000_000
    t0 = time.monotonic()
    limited = limit_response_size(big, max_len=2000)
    _timebound(t0, 2.0, "limit_response_size(2MB)")
    assert len(limited) < 2100, f"limit_response_size 未截断: {len(limited)}"

    compressed = compress_http_response(big, max_len=1500)
    assert len(compressed) < 1600, f"compress_http_response 未截断: {len(compressed)}"


def test_mutation_probe_is_deterministic():
    """变异生成器必须零随机：同输入多次调用结果逐字节一致。"""
    seed = "../../../../etc/passwd"
    first = mutate(seed, ("all",), long_len=64, json_depth=4)
    second = mutate(seed, ("all",), long_len=64, json_depth=4)
    assert first == second, "变异输出不稳定（存在随机或哈希序依赖）"

    families = {item["family"] for item in first}
    assert families == {"url", "unicode", "boundary", "path", "case", "query", "header"}, families
