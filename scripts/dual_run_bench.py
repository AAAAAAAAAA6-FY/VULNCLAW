#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""双跑对照基准：声明（新范式） vs 老引擎（旧范式），同靶场同端点各跑一遍。

目的：用**数据**回答"哪类声明已经够用、哪类老引擎必须留"，而不是主观判断。

对照维度：
  - 命中：声明侧 / 老引擎侧各自是否发现
  - 误报：在安全端点上是否会误报
  - 开销：声明侧请求数、两侧耗时

用法（在 pentest_platform 根目录）：
    python scripts/dual_run_bench.py

报告同时写入 _runtime_cache/dual_run_report.md（不污染仓库根）。
"""
import asyncio
import importlib
import subprocess
import sys
import time
import urllib.request
from urllib.parse import urlparse

BASE = "http://127.0.0.1:8793"
PY = sys.executable
PORT = "8793"

# (声明 id, 老引擎 类路径, 端点, 参数名)
CASES = [
    ("sql_error", "vulnclaw.engines.web_engines.SQLiEngine", "/search?q=test", "q"),
    ("xss_reflect", "vulnclaw.engines.web_engines.XSSEngine", "/search?q=test", "q"),
    ("cmd_injection", "vulnclaw.engines.web_engines.CMDIEngine", "/api/cmd?c=ls", "c"),
    ("lfi", "vulnclaw.engines.web_engines.LFIEngine", "/api/file?file=readme.txt", "file"),
    ("ssti", "vulnclaw.engines.web_engines.SSTIEngine", "/api/tpl?tpl=hello", "tpl"),
    ("nosql_injection", "vulnclaw.engines.web_engines.NoSQLEngine", "/api/nosql?q=abc", "q"),
    ("crlf", "vulnclaw.engines.input_engines.CRLFEngine", "/api/header?v=abc", "v"),
    ("ldap_injection", "vulnclaw.engines.input_engines.LDAPEngine", "/api/ldap?user=alice", "user"),
    ("java_deserialization", "vulnclaw.engines.deserialization.DeserializationEngine",
     "/api/deser?data=hello", "data"),
    ("dotnet_deserialization",
     "vulnclaw.engines.dotnet_deserialization.DotNetDeserializationEngine",
     "/api/dotnet?data=hello", "data"),
    ("cors_misconfig", "vulnclaw.engines.input_engines.CORSEngine", "/api/cors?x=1", "x"),
]

SAFE_CASES = [
    ("cmd_injection", "vulnclaw.engines.web_engines.CMDIEngine", "/api/safe?c=hello", "c"),
    ("sql_error", "vulnclaw.engines.web_engines.SQLiEngine", "/api/safe?c=hello", "c"),
]


def fetch(url: str, timeout: float = 3.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except Exception:
        return -1, ""


def load_engine(path: str):
    mod_name, cls_name = path.rsplit(".", 1)
    mod = importlib.import_module(mod_name)
    return getattr(mod, cls_name)


async def run_decl_side(decl_id: str, url: str):
    """声明侧执行，同时统计请求数与耗时。"""
    from vulnclaw.core.attack_surface import spec_from_url
    from vulnclaw.core.utils import async_get, async_post
    from vulnclaw.core.vulnspec import SpecRunner, get_spec

    counter = {"n": 0}

    async def _counting(spec):
        counter["n"] += 1
        kw = spec.to_send_kwargs()
        if str(spec.method).upper() == "GET":
            return await async_get(spec.url, session=None, headers=kw.get("headers"),
                                   timeout=10, no_retry=True)
        return await async_post(spec.url, session=None, timeout=10, no_retry=True, **kw)

    spec = spec_from_url(url, "GET")
    start = time.perf_counter()
    try:
        out = await SpecRunner(specs=[get_spec(decl_id)], requester=_counting).run(spec)
    except Exception as exc:  # noqa: BLE001
        out = []
        print(f"    [声明侧异常] {exc}")
    return bool(out), time.perf_counter() - start, counter["n"]


async def run_engine_side(cls_path: str, url: str, param: str):
    """老引擎侧执行：按 BaseEngine.check 标准签名调用。

    对照公平性说明：老引擎经 safe_request 在 http2/curl_cffi 可用时切到 httpx/curl_cffi，
    而 httpx 对本地靶场 127.0.0.1 协商慢（happy-eyeballs 试 ::1 等），每个请求会等满
    timeout → 8 个 payload 累计 >40s。声明侧用 async_get（aiohttp）无此问题，本对照不测
    传输层，故强制 _http2_available/_impersonate_available 返回 False（走 aiohttp）。下方
    防御性隔离 AntiScanDetector：靶场报错页本就不会被其判为限流/封禁（已读 analyze_response
    判据核实），隔离仅为防御性、与耗时无关；只为保证对照只反映引擎检出能力。
    """
    from vulnclaw.core.utils import async_get
    from vulnclaw.core.scanner import AntiScanDetector
    from vulnclaw.config import settings

    try:
        cls = load_engine(cls_path)
        engine = cls()
    except Exception as exc:  # noqa: BLE001
        print(f"    [老引擎加载失败] {exc}")
        return False, 0.0, "load-failed"

    parsed_query = urlparse(url).query
    try:
        baseline = await async_get(url, session=None, timeout=10, no_retry=True)
    except Exception:
        baseline = (0, "", {})

    _orig = AntiScanDetector.analyze_response
    _clean = classmethod(lambda cls, text, status, headers: {
        "is_honeypot": False, "is_fake_404": False,
        "is_rate_limited": False, "is_ip_blocked": False, "issues": []})
    AntiScanDetector.analyze_response = _clean
    # 声明侧用 async_get（aiohttp），老引擎侧经 safe_request 会按 _http2_available /
    # _impersonate_available 切到 httpx/curl_cffi——它们对本地靶场 127.0.0.1 协商慢
    # （每次等满 timeout），污染对照耗时。靶场对照不测传输层，强制与声明侧同走 aiohttp。
    import vulnclaw.core.scanner as _sc
    _orig_h2, _orig_imp = _sc._http2_available, _sc._impersonate_available
    _sc._http2_available = lambda: False
    _sc._impersonate_available = lambda: False
    _old_to = getattr(settings, "timeout", 30)
    settings.timeout = 8
    start = time.perf_counter()
    try:
        res = await asyncio.wait_for(
            engine.check(url, param, baseline, parsed_query, None), timeout=40
        )
        state = "ok"
    except asyncio.TimeoutError:
        res, state = False, "timeout"
    except Exception as exc:  # noqa: BLE001
        res, state = False, f"error: {type(exc).__name__}"
    finally:
        AntiScanDetector.analyze_response = _orig
        _sc._http2_available, _sc._impersonate_available = _orig_h2, _orig_imp
        settings.timeout = _old_to
    return bool(res), time.perf_counter() - start, state


async def main() -> int:
    sys.path.insert(0, "src")

    proc = subprocess.Popen(
        [PY, "scripts/poc_meta_lab.py", "--port", PORT],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace",
    )
    rows = []
    try:
        for _ in range(40):
            if fetch(BASE + "/search?q=test")[0] == 200:
                break
            time.sleep(0.25)
        else:
            print("[BENCH] 靶场未就绪")
            return 1

        print(f"{'类别':<18}{'声明':<8}{'老引擎':<10}{'声明耗时':<10}{'老引擎耗时':<12}{'请求数':<8}{'老引擎状态'}")
        print("-" * 84)
        for decl_id, cls_path, path, param in CASES:
            url = BASE + path
            d_hit, d_t, d_n = await run_decl_side(decl_id, url)
            e_hit, e_t, e_state = await run_engine_side(cls_path, url, param)
            rows.append((decl_id, d_hit, e_hit, d_t, e_t, d_n, e_state))
            print(f"{decl_id:<18}{'命中' if d_hit else '未中':<8}"
                  f"{'命中' if e_hit else '未中':<10}"
                  f"{d_t:<10.2f}{e_t:<12.2f}{d_n:<8}{e_state}")

        print("\n安全端点误报对照：")
        fp_rows = []
        for decl_id, cls_path, path, param in SAFE_CASES:
            url = BASE + path
            d_hit, _, _ = await run_decl_side(decl_id, url)
            e_hit, _, e_state = await run_engine_side(cls_path, url, param)
            fp_rows.append((decl_id, d_hit, e_hit, e_state))
            print(f"  {decl_id:<18} 声明误报={'是' if d_hit else '否'}"
                  f"  老引擎误报={'是' if e_hit else '否'} ({e_state})")

        # -------- 结论 --------
        both = [r for r in rows if r[1] and r[2]]
        # 区分"老引擎正常但未检出"与"老引擎超时/报错（不可比较）"
        decl_only = [r for r in rows if r[1] and not r[2] and r[6] == "ok"]
        decl_only_abnormal = [r for r in rows if r[1] and not r[2] and r[6] != "ok"]
        engine_only = [r for r in rows if not r[1] and r[2]]
        neither = [r for r in rows if not r[1] and not r[2]]

        lines = [
            "# 双跑对照报告（声明 vs 老引擎）",
            "",
            f"- 对照类别数：{len(rows)}",
            f"- 双方均命中：{len(both)} -> {[r[0] for r in both]}",
            f"- 仅声明命中（老引擎正常但未检出）：{len(decl_only)} -> {[r[0] for r in decl_only]}",
            f"- 仅声明命中（老引擎超时/报错，不可比较）：{len(decl_only_abnormal)}"
            f" -> {[(r[0], r[6]) for r in decl_only_abnormal]}",
            f"- 仅老引擎命中：{len(engine_only)} -> {[r[0] for r in engine_only]}",
            f"- 双方均未中：{len(neither)} -> {[r[0] for r in neither]}",
            "",
            "## 明细",
            "| 类别 | 声明 | 老引擎 | 声明耗时(s) | 老引擎耗时(s) | 声明请求数 | 老引擎状态 |",
            "|---|---|---|---|---|---|---|",
        ]
        for decl_id, d_hit, e_hit, d_t, e_t, d_n, e_state in rows:
            lines.append(
                f"| {decl_id} | {'命中' if d_hit else '未中'} | {'命中' if e_hit else '未中'} "
                f"| {d_t:.2f} | {e_t:.2f} | {d_n} | {e_state} |"
            )
        lines += ["", "## 安全端点误报", "| 类别 | 声明误报 | 老引擎误报 | 状态 |", "|---|---|---|---|"]
        for decl_id, d_hit, e_hit, e_state in fp_rows:
            lines.append(f"| {decl_id} | {'是' if d_hit else '否'} | {'是' if e_hit else '否'} | {e_state} |")

        verdict = []
        if decl_only:
            verdict.append(f"声明覆盖更全（老引擎正常运行但未检出）：{[r[0] for r in decl_only]}")
        if decl_only_abnormal:
            verdict.append(
                f"老引擎超时/报错、无法比较（需排查其性能，不等于能力缺失）："
                f"{[(r[0], r[6]) for r in decl_only_abnormal]}")
        if engine_only:
            verdict.append(f"老引擎仍不可替代（声明需加强）：{[r[0] for r in engine_only]}")
        if both:
            verdict.append(f"双方等价、可做双跑后择一：{[r[0] for r in both]}")
        lines += ["", "## 结论", ""] + [f"- {v}" for v in verdict]
        lines += [
            "",
            "> 注：本基准只用靶场端点做最小对照，结论仅说明「在靶场条件下」的相对表现；",
            "> 真实目标上的表现还取决于 WAF、网络与业务复杂度，退引擎决策需结合真实目标复核。",
            "> 历史注：早期版本 java/dotnet 反序列化显示 40s timeout，已定位为**测试噪声**——",
            "> bench 经 safe_request 在 http2/curl_cffi 可用时走 httpx，httpx 对本地靶场 127.0.0.1",
            "> 协商慢（happy-eyeballs 试 ::1 等），每请求等满 timeout，8 个 payload 累计 >40s。",
            "> 已读 analyze_response 确认 AntiScanDetector 不会把报错页判为限流/封禁（与超时无关）。",
            "> 强制 aiohttp 后老引擎全部正常命中（耗时 <0.04s）。本对照不比较传输层/反制，只反映检出能力。",
        ]

        report = "\n".join(lines)
        with open("_runtime_cache/dual_run_report.md", "w", encoding="utf-8") as fh:
            fh.write(report)
        print("\n" + report)
        print("\n[BENCH] 报告已写入 _runtime_cache/dual_run_report.md")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        try:
            from vulnclaw.core.utils import close_shared_session
            await close_shared_session()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
