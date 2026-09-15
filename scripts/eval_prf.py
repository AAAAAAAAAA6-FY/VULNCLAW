#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""秒级 P/R/F1 评测闭环（声明线直跑，不跑完整 scan）。

为什么需要它：
  完整 `scan.py scan` 一次约 12 分钟，改一版判据/声明不可能等 12 分钟才知道涨没涨。
  本脚本用 `SpecRunner` 直跑靶场端点（无 LLM、无编排、无爬虫），**秒级**给出
  Recall / Precision / F1，作为"改动前 vs 改动后"的即时标尺。

口径说明（避免自欺）：
  - TP：期望端点被对应声明命中
  - FN：期望端点有声明覆盖、但未命中（真漏报）
  - NA：该端点没有任何声明能覆盖（属**覆盖缺口**，不计入 FN——否则等于用
        "没写声明"冒充"漏报"，数字会失去意义）
  - FP：负样本端点被任意声明命中
  - Recall 只按 (TP+FN) 计算，NA 单独列出

用法（仓库根目录）：
    python scripts/eval_prf.py              # 起靶机 + 秒级评测
    python scripts/eval_prf.py --no-lab     # 靶机已在跑，直接评测
"""
import argparse
import asyncio
import collections
import json
import logging
import os
import subprocess
import tempfile
import sys
import time
import urllib.request
import re
from pathlib import Path

# 评测脚本只关心 P/R/F1：屏蔽 vulnclaw 导入期的 INFO 噪音，让结果一眼可读
# （WARNING 及以上保留，异常仍可见）
logging.disable(logging.INFO)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DEFAULT_TARGET = "http://127.0.0.1:8090"
LAB_PORT = 8090

# 评测防污染：FFUF 结果走 SQLite 持久缓存（24h TTL），若在评测中生效会
# 用"上一轮的缓存结果"冒充本轮检测 → P/R/F1 与耗时对照全部失真。
# 评测口径必须是无缓存全量重放，故这里强制旁路（directory_ffuf 读取此开关）。
os.environ.setdefault("VULNCLAW_FFUF_CACHE", "0")

# 真值表 expect 关键词 → 声明 id 的**分词 token**（按 `_`/`-` 切分后的片段）。
# 匹配规则：wanted 中的 token 与声明 id 的某个分词 token **精确相等**才命中。
# 教训（三版走过的坑）：
#   v1 任意子串 → "sql" 命中 `nosql_injection`、"信息泄露" 命中 `graphql_introspection`，FN/TP 全不可信；
#   v2 startswith(id) → `open_redirect` 不以 "redirect" 开头、`java_deserialization` 不以
#       "deserial" 开头，本该命中的声明全漏（/redirect、/deser 从 100% 掉到 NA）；
#   v3 分词 token 前缀 → 修好上述两点，但"前缀"在相近 token 间仍可能误配（短词撞长 token）。
#   v4（现行）分词 token **精确相等** → 最严口径；要覆盖某族就在 _ALIAS 写**完整 token**。
# 值为空列表 = 明确"当前无声明覆盖"（判 NA，而非误配到别的声明）。
_ALIAS = {
    "xss": ["xss"],
    "sql注入": ["sql", "sqli"],
    "sqli": ["sql", "sqli"],
    "ssti": ["ssti"],
    "模板注入": ["ssti"],
    "环境变量泄露": ["dotenv", "env"],
    ".env": ["dotenv", "env"],
    "文件上传": ["upload"],
    "nosql": ["nosql"],
    "ldap": ["ldap"],
    "开放重定向": ["redirect", "open"],
    "open redirect": ["redirect", "open"],
    "cors": ["cors"],
    "反序列化": ["deserialization"],
    "deserialization": ["deserialization"],
    "ssrf": ["ssrf"],
    "xxe": ["xxe"],
    "实体注入": ["xxe"],
    "越权": ["idor"],
    "idor": ["idor"],
    "未授权": ["actuator", "unauth"],
    "actuator": ["actuator", "unauth"],
    "信息泄露": [],          # 过宽 → 不映射（避免误配 graphql_introspection）
    "组件": ["component"],
    "cve": ["component"],
    "jquery": ["component"],
    "命令注入": ["cmd"],
    "cmdi": ["cmd"],
    "命令执行": ["cmd"],
    "php对象注入": ["php"],
    "pickle": ["pickle"],
    ".net": ["dotnet"],
    "dotnet": ["dotnet"],
    "源码泄露": ["git"],
    "git": ["git"],
    "存储xss": ["stored"],
    "存储型xss": ["stored"],
    "二次注入": ["second"],
    "依赖审计": ["dependency"],
    "sca": ["dependency"],
    "供应链": ["dependency"],
    "domxss": ["dom"],
    "dom xss": ["dom"],
    "dom型xss": ["dom"],
    "业务逻辑": ["biz"],
    "biz": ["biz"],
    "逻辑漏洞": ["biz"],
    # 密钥/凭证泄露（规则来自 gitleaks，经 build_external_sigs.py 注入）
    "密钥泄露": ["secret"],
    "密钥": ["secret"],
    "凭证泄露": ["secret"],
    "secret": ["secret"],
}


def _log(msg: str) -> None:
    print(f"[eval] {msg}", flush=True)


def _alive(url: str, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def _port_listening(url: str) -> bool:
    """TCP 层端口是否可连接（与 HTTP 是否正常响应无关）。

    2026-09-15 修复实例堆积：local_lab 用 ThreadingHTTPServer（SO_REUSEADDR），
    允许多个进程绑同一端口。若端口被僵尸实例占用（TCP 可连但 HTTP 不响应），
    再 Popen 新实例只会叠加 —— 请求被随机分发到僵尸，表现为"靶机时好时坏"。
    """
    from urllib.parse import urlparse as _up
    import socket
    try:
        p = _up(url)
        host = p.hostname or "127.0.0.1"
        port = p.port or (443 if p.scheme == "https" else 80)
        with socket.create_connection((host, port), timeout=1.5):
            return True
    except OSError:
        return False


def _ensure_lab() -> bool:
    if _alive(DEFAULT_TARGET):
        _log(f"靶机已存活: {DEFAULT_TARGET}")
        return True
    # 端口已被占用但不响应 HTTP → 僵尸实例，绝不再叠加（提示清理而非拉起）。
    if _port_listening(DEFAULT_TARGET):
        _log("端口已被占用但 HTTP 不响应 —— 疑似僵尸 local_lab 实例（历史堆积）。")
        _log("请先清理再跑：powershell -c \"Get-CimInstance Win32_Process -Filter \\\"Name='python.exe'\\\" | ? { $_.CommandLine -like '*local_lab*' } | % { Stop-Process -Id $_.ProcessId -Force }\"")
        return False
    _log("拉起 local_lab ...")
    subprocess.Popen(
        [sys.executable, str(HERE / "local_lab.py")],
        cwd=str(HERE), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(24):
        time.sleep(0.5)
        if _alive(DEFAULT_TARGET):
            _log("local_lab 已就绪")
            return True
    return False


def _load_expected():
    sys.path.insert(0, str(HERE))
    import local_lab  # type: ignore
    return local_lab.EXPECTED_FINDINGS


# ================================================================
# 外部测试集（别人的漏洞样本）接入
# ================================================================
# 为什么只认一种格式：外部靶场（DVWA/Juice Shop/WAVSEP）、别人的数据集、
# 客户授权的真实目标，差别只在 "target + 端点级真值"，评测逻辑完全一致。
# 因此外部测试集统一表达为与 `local_lab.EXPECTED_FINDINGS` **同构**的清单：
#   {"name": str, "target": url,
#    "endpoints": {"/path?q=": {"expect": [...], "min_severity": ..., "tier": "base|hard"}},
#    "negatives": {"/path": "说明"}}
# 这样自建靶场的真值表可以直接当外部清单跑，外部清单也可直接喂给本地评测。
def _load_manifest(path: str) -> dict:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f"[eval] 外部清单不存在: {path}")
    raw = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError:
            raise SystemExit("[eval] 读取 yaml 清单需要 PyYAML（或改用 .json）")
        data = yaml.safe_load(raw)
    else:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"[eval] 清单不是合法 JSON: {exc}")
    if not isinstance(data, dict) or not data.get("target"):
        raise SystemExit("[eval] 清单格式错误：必须是含 target/endpoints 的映射")
    if not isinstance(data.get("endpoints", {}), dict):
        # benchmark.py 的剧本是"类别级"（expected_vulns），没有端点级真值 →
        # 直接拒绝：拿它算端点级 P/R/F1 只会产出看似有据、实则无据的数字。
        raise SystemExit(
            "[eval] 该清单是**类别级剧本**（无端点级真值），不能算 P/R/F1。\n"
            "       它只能由 `scripts/benchmark.py --mode eval` 消费（需完整扫描报告）。\n"
            "       要用于本评测，请改写成端点级真值：\n"
            '       "endpoints": {"/path?q=": {"expect": ["XSS"], "tier": "hard"}}'
        )
    return data


def _host_of(url: str) -> str:
    from urllib.parse import urlparse as _up
    try:
        return (_up(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_loopback_or_local(url: str) -> bool:
    """回环 / 本机 / 私网地址视为"自有环境"，无需额外授权声明。"""
    h = _host_of(url)
    if not h:
        return False
    if h in ("localhost", "::1", "0.0.0.0"):
        return True
    if h.startswith("127.") or h.endswith(".local"):
        return True
    if h.startswith("192.168.") or h.startswith("10."):
        return True
    if h.startswith("172."):
        try:
            return 16 <= int(h.split(".")[1]) <= 31
        except (IndexError, ValueError):
            return False
    return False


async def _preflight(url):
    """连通性预检——必须用**与执行器同一套 HTTP 层**（async_get）。

    踩过的坑（2026-09-12）：用 urllib 预检不走 settings.proxy，而执行器走；
    于是 .env 里配了未启动的 Burp 代理时"预检通过、执行器全挂在代理上"，
    真实目标上整条线静默返回 0 命中，被误读成"目标干净"。
    预检复用 async_get 才能在执行前把代理/网络故障暴露出来（fail-closed）。
    返回 (ok, detail)。
    """
    sys.path.insert(0, str(ROOT / "src"))
    try:
        from vulnclaw.core.utils import async_get
    except Exception as exc:  # noqa: BLE001
        return False, f"导入 HTTP 层失败: {exc}"
    try:
        status, text, _ = await async_get(url, session=None, timeout=10, no_retry=True)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    if status == 0:
        return False, str(text)[:200]
    return True, f"HTTP {status}"


class _OobListener:
    """本地带外回连监听器：只用于**本地闭环验证** OOB（带外）oracle。

    真实场景的回调通道是交互式 DNS/HTTP（interactsh 等），靶场无法闭环；
    本地监听器让"盲 SSRF / 盲命令注入"的判据在靶机上**可证伪、可回归**。
    """

    def __init__(self, hits_file: str):
        self.hits_file = hits_file
        self.port = 0
        self._srv = None

    def start(self) -> int:
        import http.server
        import threading
        hits = self.hits_file

        class _H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                try:
                    with open(hits, "a", encoding="utf-8") as fh:
                        fh.write(self.path + "\n")
                except OSError:
                    pass
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                try:
                    self.wfile.write(b"ok")
                except OSError:
                    pass

            def log_message(self, *args):  # 静音访问日志
                return

        self._srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
        self.port = int(self._srv.server_address[1])
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self.port

    def stop(self) -> None:
        try:
            if self._srv is not None:
                self._srv.shutdown()
                self._srv.server_close()
        except Exception:  # noqa: BLE001
            pass


def _start_local_oob(base: str):
    """仅当目标是本机/私网（能被我们的监听器回连）时启用 OOB 本地闭环。

    外部目标回连不到 127.0.0.1 → 绝不能启用（否则每个 oob 声明要白等 OOB_WAIT_SECONDS）。
    返回 (listener, hits_file) 或 (None, "")。
    """
    if not _is_loopback_or_local(base):
        return None, ""
    try:
        sys.path.insert(0, str(ROOT / "src"))
        from vulnclaw.config import settings as _st
        fd, hits = tempfile.mkstemp(prefix="oob_hits_", suffix=".txt")
        os.close(fd)
        listener = _OobListener(hits)
        listener.start()
        _st.oob_base_url = f"http://127.0.0.1:{listener.port}"
        _st.oob_hits_file = hits
        _log(f"OOB 本地闭环已启用: {_st.oob_base_url}")
        return listener, hits
    except Exception as exc:  # noqa: BLE001
        _log(f"OOB 本地监听不可用（oob 型声明将 fail-closed 跳过）: {exc}")
        return None, ""


def _stop_local_oob(listener, hits_file: str) -> None:
    if listener is not None:
        listener.stop()
    if hits_file:
        try:
            os.unlink(hits_file)
        except OSError:
            pass


def _disable_proxy() -> None:
    """--no-proxy：显式关闭 settings.proxy / 代理池，用于外部测试集验收。

    只影响本次进程（不写 .env），且打印出来保证可审计。
    """
    sys.path.insert(0, str(ROOT / "src"))
    try:
        from vulnclaw.config import settings as _st
        _st.proxy = None
        _st.proxy_list = []
        _log("--no-proxy：已关闭 settings.proxy 与代理池（仅本次进程）")
    except Exception as exc:  # noqa: BLE001
        _log(f"--no-proxy 设置失败（忽略）: {exc}")


def _specs_for(expect_words, builtin_specs):
    """按真值表 expect 关键词挑出相关声明（**id 分词 token 前缀匹配**；无匹配 → NA）。"""
    wanted = []
    for w in expect_words or []:
        ks = str(w).lower()
        wanted.extend(_ALIAS[ks] if ks in _ALIAS else [ks])
    if not wanted:
        return []
    picked = []
    for d in builtin_specs:
        did = str(getattr(d, "id", "")).lower()
        toks = re.split(r"[_\-]", did)
        if any(w and any(tok == w for tok in toks) for w in wanted):
            picked.append(d)
    return picked


# ---- 引擎线（老范式）映射：expect 关键词 → 引擎类路径 ----
# 用于双线对照：同一样本，声明线检出 vs 引擎线检出。空列表 = 该族无引擎覆盖。
_ENGINE_MAP = {
    "xss": ["vulnclaw.engines.web_engines.XSSEngine"],
    "sql注入": ["vulnclaw.engines.web_engines.SQLiEngine"],
    "sqli": ["vulnclaw.engines.web_engines.SQLiEngine"],
    "ssti": ["vulnclaw.engines.web_engines.SSTIEngine"],
    "模板注入": ["vulnclaw.engines.web_engines.SSTIEngine"],
    "nosql": ["vulnclaw.engines.web_engines.NoSQLEngine"],
    "ldap": ["vulnclaw.engines.input_engines.LDAPEngine"],
    "开放重定向": ["vulnclaw.engines.http_engines.OpenRedirectEngine"],
    "open redirect": ["vulnclaw.engines.http_engines.OpenRedirectEngine"],
    "cors": ["vulnclaw.engines.input_engines.CORSEngine"],
    "反序列化": ["vulnclaw.engines.deserialization.DeserializationEngine"],
    "deserialization": ["vulnclaw.engines.deserialization.DeserializationEngine"],
    "ssrf": ["vulnclaw.engines.net_engines.SSRFEngine"],
    "xxe": ["vulnclaw.engines.net_engines.XXEEngine"],
    "实体注入": ["vulnclaw.engines.net_engines.XXEEngine"],
    "越权": ["vulnclaw.engines.auth_engines.IDOREngine"],
    "idor": ["vulnclaw.engines.auth_engines.IDOREngine"],
    "文件上传": ["vulnclaw.engines.input_engines.FileUploadEngine"],
    "lfi": ["vulnclaw.engines.web_engines.LFIEngine"],
    "cmdi": ["vulnclaw.engines.web_engines.CMDIEngine"],
    "环境变量泄露": [], ".env": [], "未授权": [], "actuator": [],
    "信息泄露": [], "组件": [], "cve": [], "jquery": [],
}


def _engines_for(expect_words):
    got = []
    for w in expect_words or []:
        ks = str(w).lower()
        for p in (_ENGINE_MAP[ks] if ks in _ENGINE_MAP else []):
            if p not in got:
                got.append(p)
    return got


async def _engine_any_hit(ep: str, cls_paths, base: str = DEFAULT_TARGET) -> bool:
    """对单个端点跑给定引擎，任一引擎报结果即算命中（与引擎线真实调用方式一致）。

    ep 传完整 http(s) URL 时直接用（真实目标模式）；否则拼在 base 之后（靶场模式）。
    """
    import asyncio as _aio
    import importlib
    from urllib.parse import urlparse as _up

    from vulnclaw.core.scanner import AntiScanDetector
    from vulnclaw.core.utils import async_get

    url = ep if ep.startswith(("http://", "https://")) else base.rstrip("/") + ep
    param = ep.split("?")[1].split("=")[0] if "?" in ep else ""
    parsed_query = _up(url).query
    try:
        baseline = await async_get(url, session=None, timeout=10, no_retry=True)
    except Exception:  # noqa: BLE001
        baseline = (0, "", {})

    # 靶场对照：隔离反扫描误判（与 dual_run_bench 同口径），只测检出能力
    _orig = AntiScanDetector.analyze_response
    _clean = classmethod(lambda cls, text, status, headers: {
        "is_honeypot": False, "is_fake_404": False,
        "is_rate_limited": False, "is_ip_blocked": False, "issues": []})
    AntiScanDetector.analyze_response = _clean
    try:
        for cp in cls_paths:
            try:
                mod_name, cls_name = cp.rsplit(".", 1)
                engine = getattr(importlib.import_module(mod_name), cls_name)()
                res = await _aio.wait_for(
                    engine.check(url, param, baseline, parsed_query, None), timeout=45)
                if res:
                    return True
            except Exception:  # noqa: BLE001
                continue
    finally:
        AntiScanDetector.analyze_response = _orig
    return False


async def _run_live(target: str, line: str = "spec", json_out: bool = False,
                    authorized: bool = False) -> int:
    """对**真实目标**跑检测（声明线 / 引擎线）。

    与靶场评测的关键差别：真实目标**没有真值表** → 本模式不产出 P/R/F1
    （无真值算出的"准确率"是自欺）。它唯一能闭环的断言是：
      真实无洞目标上应为 0 命中，出现命中即为**真实误报证据**。
    合规：非回环/私网目标必须显式 --authorized（声明已获授权），否则拒绝执行。
    """
    sys.path.insert(0, str(ROOT / "src"))
    url = target if "://" in target else "http://" + target
    if not _is_loopback_or_local(url) and not authorized:
        print("[eval] 拒绝执行：目标是外部地址，需显式 --authorized 声明已获授权。")
        return 3
    ok, detail = await _preflight(url)
    if not ok:
        print(f"[eval] 预检失败 → 未执行（不产出任何 0 命中的结论）: {url}\n       原因: {detail}")
        return 2
    _log(f"真实目标: {url}（{line} 线，预检 {detail}）")

    from vulnclaw.core.attack_surface import spec_from_url
    from vulnclaw.core.vulnspec import BUILTIN_SPECS, SpecRunner

    t0 = time.time()
    hits: list = []
    runner = SpecRunner()
    if line == "engine":
        cls_paths: list = []
        for paths in _ENGINE_MAP.values():
            for cp in paths:
                if cp not in cls_paths:
                    cls_paths.append(cp)
        if await _engine_any_hit(url, cls_paths):
            hits.append({"type": "engine_hit", "parameter": "", "severity": "",
                         "evidence": f"引擎线命中（{len(cls_paths)} 个引擎中至少 1 个报结果）"})
    else:
        hits = await runner.run(spec_from_url(url, "GET"), specs=list(BUILTIN_SPECS))
    req_err = getattr(runner, "request_errors", 0)

    elapsed = time.time() - t0
    if json_out:
        print(json.dumps({
            "mode": "live", "line": line, "target": url, "elapsed": round(elapsed, 1),
            "hit_count": len(hits), "hits": hits, "request_errors": req_err,
            "note": "无真值表 → 不产出 P/R/F1；真实无洞目标应为 0 命中",
        }, ensure_ascii=False, indent=2))
        return 0
    print("\n" + "=" * 64)
    print(f"  真实目标检测（{('引擎' if line == 'engine' else '声明')}线，{url}，耗时 {elapsed:.1f}s）")
    print("=" * 64)
    for f in hits:
        print(f"  · [{f.get('severity')}] {f.get('type')} @ {f.get('parameter')}"
              f"  {(f.get('evidence') or '')[:90]}")
    if not hits:
        print("  命中 0 条（真实无洞目标应为 0 —— 本模式下唯一可闭环的断言）")
    if req_err:
        print(f"  ⚠️ 请求失败 {req_err} 次（网络/代理/DNS）—— 失败请求**不等于**目标干净，"
              f"本次结论不可信；请检查 PROXY 配置或加 --no-proxy 重跑")
    print(f"  合计命中 {len(hits)} 条  |  注意：无真值表，本结果不可用于准确率结论")
    print("=" * 64)
    return 1 if (req_err and not hits) else 0


async def _evaluate(expected: dict, base: str, src_name: str, line: str,
                    json_out: bool = False, mode: str = "local_lab") -> dict:
    """对**一个目标**跑一轮评测并返回统计（OOB 监听器生命周期由调用方管理）。

    多目标（多个外部清单）复用它：每个目标独立算 P/R/F1，最后汇总——
    因为不同站点的真值表不同，混在一起算会掩盖"某个站点整体不可达/整体漏报"。
    """
    sys.path.insert(0, str(ROOT / "src"))
    from vulnclaw.core.attack_surface import spec_from_url
    from vulnclaw.core.vulnspec import BUILTIN_SPECS, SpecRunner

    runner = SpecRunner()
    t0 = time.time()

    tp, fn, na, ep_err = [], [], [], []
    tier_stat = collections.defaultdict(lambda: {"tp": 0, "fn": 0, "na": 0, "err": 0})
    for ep, spec_meta in expected["endpoints"].items():
        tier = str(spec_meta.get("tier") or "base")
        url = base.rstrip("/") + ep
        if line == "engine":
            labels = _engines_for(spec_meta.get("expect") or [])
            specs = None
        else:
            specs = _specs_for(spec_meta.get("expect") or [], BUILTIN_SPECS)
            labels = [s.id for s in specs]
        if not labels:
            na.append(ep)
            tier_stat[tier]["na"] += 1
            continue
        _err0 = getattr(runner, "request_errors", 0)
        try:
            if line == "engine":
                hit = await _engine_any_hit(ep, labels, base=base)
                detail = "引擎: " + ",".join(p.rsplit(".", 1)[-1] for p in labels)
            else:
                out = await runner.run(spec_from_url(url, "GET"), specs=specs)
                hit = bool(out)
                detail = (out[0].get("evidence") or "")[:60] if out else ""
        except Exception as exc:  # noqa: BLE001
            _log(f"  {ep} 执行异常: {exc}")
            hit, detail = False, ""
        # 该端点**自身探测期间**有请求失败 → "未命中"不可信：单列 ERROR，
        # 既不算 TP 也不算 FN（把网络故障伪装成漏报/干净，是最危险的自欺）。
        if getattr(runner, "request_errors", 0) > _err0 and not hit:
            ep_err.append(ep)
            tier_stat[tier]["err"] += 1
            continue
        if hit:
            tp.append((ep, labels[0], detail))
            tier_stat[tier]["tp"] += 1
        else:
            fn.append((ep, labels))
            tier_stat[tier]["fn"] += 1

    # 负样本：全部声明打过去，任一命中即误报
    fp = []
    for neg_path, _desc in (expected.get("negatives") or {}).items():
        neg_url = base.rstrip("/") + neg_path
        for d in BUILTIN_SPECS:
            if getattr(d.detect, "header_absent", False):
                continue  # 靶场确实缺安全头，命中属实而非误报
            try:
                got = await runner.run(spec_from_url(neg_url, "GET"), specs=[d])
            except Exception:  # noqa: BLE001
                got = []
            if got:
                fp.append((neg_path, d.id))

    # 请求层失败计数：失败请求**不等于**目标干净。全失败还报 0 命中 = 最危险的假结论。
    req_err = getattr(runner, "request_errors", 0)

    elapsed = time.time() - t0
    denom_r = len(tp) + len(fn)
    recall = len(tp) / denom_r if denom_r else 0.0
    precision = len(tp) / (len(tp) + len(fp)) if (len(tp) + len(fp)) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    total_ep = len(expected["endpoints"])

    _line_name = "引擎线（老范式）" if line == "engine" else "声明线（新范式）"
    stats = {
        "mode": mode, "source": src_name, "line": line, "target": base,
        "elapsed": round(elapsed, 1), "total_endpoints": total_ep,
        "tp": len(tp), "fn": len(fn), "na": len(na), "fp": len(fp), "err": len(ep_err),
        "recall": round(recall, 4), "precision": round(precision, 4), "f1": round(f1, 4),
        "tp_endpoints": [e for e, _l, _d in tp],
        "fn_detail": [{"endpoint": e, "specs": i} for e, i in fn],
        "fp_detail": [{"endpoint": e, "spec": s} for e, s in fp],
        "na_detail": na, "request_errors": req_err, "probe_error_endpoints": ep_err,
    }
    if json_out:
        return stats
    print("\n" + "=" * 64)
    print(f"  秒级 P/R/F1 评测（{_line_name}，来源 {src_name}，耗时 {elapsed:.1f}s）")
    print("=" * 64)
    print(f"  真值端点 {total_ep}  |  TP {len(tp)}  FN {len(fn)}  NA(无声明覆盖) {len(na)}"
          f"  FP {len(fp)}  ERR(探测失败) {len(ep_err)}")
    # 口径提示：分母为 0 有两种完全不同的原因，必须分开报，否则会误导
    # （"正样本全部探测失败" ≠ "本目标没有正样本"；前者是**数据无效**）。
    if denom_r:
        print(f"  ★ 检出率 Recall    = {recall*100:6.1f}%   ({len(tp)}/{denom_r} 有声明覆盖的端点)")
    elif ep_err and total_ep:
        print("  ★ 检出率 Recall    =    N/A   （正样本全部探测失败 → **本轮数据无效**）")
    else:
        print("  ★ 检出率 Recall    =    N/A   （本目标无正样本）")
    if (len(tp) + len(fp)):
        print(f"  ★ 精确率 Precision = {precision*100:6.1f}%   (TP {len(tp)} / (TP+FP {len(tp)+len(fp)}))")
    else:
        print("  ★ 精确率 Precision =    N/A   （无可判定样本）")
    print(f"  ★ F1               = {f1*100:6.1f}%")
    if total_ep == 0:
        print("  · 注意：本目标**没有正样本**（只放负样本）→ 只验证误报，不参与 Recall")
    # 分组：基础 vs 难样本（难样本是标尺的区分度来源，基础 100% 并不说明问题）
    for _tier in ("base", "hard"):
        _st = tier_stat.get(_tier)
        if not _st:
            continue
        _d = _st["tp"] + _st["fn"]
        _r = (_st["tp"] / _d * 100) if _d else 0.0
        _label = {"base": "基础样本", "hard": "难样本  "}.get(_tier, _tier)
        print(f"  · {_label}: TP {_st['tp']} / FN {_st['fn']} / NA {_st['na']}"
              + (f" / ERR {_st['err']}" if _st.get("err") else "")
              + f"  → Recall {_r:5.1f}%")
    if fn:
        print("\n  漏报 FN（有声明却没命中，优先查）:")
        for ep, ids in fn:
            print(f"    - {ep}  可用声明: {ids}")
    if fp:
        print("\n  误报 FP（负样本被命中）:")
        for ep, sid in fp:
            print(f"    - {ep}  by {sid}")
    if na:
        print("\n  NA 覆盖缺口（无声明可覆盖，属功能缺口非漏报）:")
        for ep in na:
            print(f"    - {ep}")
    if ep_err:
        print("\n  ERR 探测失败端点（有请求失败 → 结论不可信，单列不冒充干净/漏报）:")
        for ep in ep_err:
            print(f"    - {ep}")
    if req_err:
        print(f"\n  ⚠️ 请求失败共 {req_err} 次（网络/代理/DNS）：失败请求不等于目标干净"
              f"（检查 PROXY 或加 --no-proxy）")
    print("=" * 64)
    return stats


async def _main(no_lab: bool, line: str = "spec", target: str = "",
                manifests=None, json_out: bool = False,
                authorized: bool = False, no_proxy: bool = False,
                repeat: int = 1, min_f1: float = None,
                min_recall: float = None) -> int:
    """评测入口：真实目标(单) / 自建靶机 / 一个或多个外部测试集清单。"""
    if no_proxy:
        _disable_proxy()
    if target:
        return await _run_live(target, line=line, json_out=json_out, authorized=authorized)

    jobs = []          # (expected, base, src_name, mode)
    unavailable = []   # 不可用目标：跳过而非中止（否则一个站点挂掉会拖垮整轮外部评测）
    if manifests:
        for m in manifests:
            expected = _load_manifest(m)
            base = str(expected["target"])
            src_name = f"外部清单 {Path(m).name}"
            if not _is_loopback_or_local(base):
                if not authorized:
                    print(f"[eval] 拒绝执行（{src_name}）：目标是外网地址，"
                          f"需显式 --authorized 声明已获授权。")
                    return 3
                # 每个外部目标都独立预检：某个站点挂了不能拖累其它站点，更不能产出假数字
                ok, detail = await _preflight(base)
                if not ok:
                    print(f"[eval] ⚠️ 目标不可用 → **跳过**该测试集"
                          f"（不产出任何 0 命中的结论，也不计入分母）: {base}\n"
                          f"       原因: {detail}")
                    unavailable.append((src_name, base, detail))
                    continue
                _log(f"外部测试集: {src_name} → {base}（预检 {detail}）")
            else:
                _log(f"外部测试集（本地目标）: {src_name} → {base}")
            jobs.append((expected, base, src_name, "manifest"))
    else:
        if not no_lab and not _ensure_lab():
            _log("靶机不可用")
            return 2
        jobs.append((_load_expected(), DEFAULT_TARGET, "local_lab(自建)", "local_lab"))

    if not jobs:
        print("[eval] 所有外部目标都不可用 → 本轮无有效数据（不做任何 0 命中的推断）")
        return 2

    repeats = max(1, int(repeat or 1))
    runs = []
    for _i in range(repeats):
        if repeats > 1:
            _log(f"—— 第 {_i + 1}/{repeats} 轮 ——")
        one = []
        for expected, base, src_name, mode in jobs:
            # 带外回连（OOB）本地闭环：只有本机/私网目标能回连到我们的监听器
            _oob, _oob_hits = _start_local_oob(base)
            try:
                one.append(await _evaluate(expected, base, src_name, line, json_out, mode))
            finally:
                _stop_local_oob(_oob, _oob_hits)
        runs.append(one)
    results = runs[-1]

    def _agg(rs):
        a = {
            "targets": len(rs),
            "total_endpoints": sum(r["total_endpoints"] for r in rs),
            "tp": sum(r["tp"] for r in rs),
            "fn": sum(r["fn"] for r in rs),
            "na": sum(r["na"] for r in rs),
            "fp": sum(r["fp"] for r in rs),
            "err": sum(r["err"] for r in rs),
        }
        d = a["tp"] + a["fn"]
        p = a["tp"] + a["fp"]
        a["recall"] = round(a["tp"] / d, 4) if d else None
        a["precision"] = round(a["tp"] / p, 4) if p else None
        a["f1"] = (round(2 * a["recall"] * a["precision"]
                        / (a["recall"] + a["precision"]), 4)
                   if a["recall"] and a["precision"] else None)
        # 有效性判据：有端点探测失败 → 该轮数字不可信（不是"检出变差"，是**没测成**）
        a["valid"] = a["err"] == 0
        return a

    per_run = [_agg(rs) for rs in runs]
    agg = per_run[-1]

    # 稳定性：同一 (来源, 端点) 在不同轮次里结论是否一致
    flaky = {}
    for rs in runs:
        for r in rs:
            src = r["source"]
            for kind in ("tp", "fn", "na", "err"):
                key = "tp_endpoints" if kind == "tp" else ("fn_detail" if kind == "fn"
                                                           else ("na_detail" if kind == "na"
                                                                 else "probe_error_endpoints"))
                for item in r.get(key) or []:
                    ep = item.get("endpoint") if isinstance(item, dict) else item
                    flaky.setdefault((src, ep), set()).add(kind)
    unstable = {k: v for k, v in flaky.items() if len(v) > 1}

    if json_out:
        print(json.dumps({"repeat": repeats, "per_run": per_run, "aggregate": agg,
                          "unavailable_targets": [{"source": n, "target": b, "reason": d}
                                                  for n, b, d in unavailable],
                          "unstable_endpoints": [{"source": k[0], "endpoint": k[1],
                                                  "outcomes": sorted(v)}
                                                 for k, v in unstable.items()],
                          "results": results}, ensure_ascii=False, indent=2))
    elif repeats > 1 or len(results) > 1:
        print("\n" + "=" * 64)
        print(f"  汇总（{agg['targets']} 个目标 × {repeats} 轮，与自建靶场同口径）")
        print("=" * 64)
        print(f"  真值端点 {agg['total_endpoints']}  |  TP {agg['tp']}  FN {agg['fn']}"
              f"  NA {agg['na']}  FP {agg['fp']}  ERR {agg['err']}")
        if repeats > 1:
            print("  逐轮：", "  ".join(
                f"#{i+1} TP{a['tp']}/FN{a['fn']}/FP{a['fp']}/ERR{a['err']}"
                f" R={'-' if a['recall'] is None else format(a['recall']*100, '.0f') + '%'}"
                f" P={'-' if a['precision'] is None else format(a['precision']*100, '.0f') + '%'}"
                + ("" if a["valid"] else "⚠️无效")
                for i, a in enumerate(per_run)))
            _invalid = [i + 1 for i, a in enumerate(per_run) if not a["valid"]]
            if _invalid:
                print(f"  ⚠️ 无效轮次 {_invalid}：端点探测失败 → 该轮数字不可信，"
                      f"不要当成\"检出变差\"，应重跑该轮")
            if unstable:
                print(f"  ⚠️ 不稳定端点 {len(unstable)} 个（轮次间结论不一致，这才是真正的隐患）:")
                for k, v in unstable.items():
                    print(f"    - {k[0]} {k[1]}  → {sorted(v)}")
            else:
                print(f"  ✅ 稳定性：{repeats} 轮结论完全一致（无端点结果翻转）")
        else:
            print(f"  ★ 检出率 Recall    = {agg['recall']*100:6.1f}%")
            print(f"  ★ 精确率 Precision = {agg['precision']*100:6.1f}%")
        if unavailable:
            print(f"\n  ⚠️ 不可用目标 {len(unavailable)} 个（**未测**，不计入分母；不是 0 命中）:")
            for _n, _b, _d in unavailable:
                print(f"    - {_n} → {_b}（{_d}）")
        print("=" * 64)
    ok = (all(not a["fn"] and not a["fp"] and not a["err"] for a in per_run)
          and not unstable and not unavailable)
    # 可选阈值门禁（CI 用）：给定时按 F1/Recall 数值判定——允许"已知缺口"存在
    # （如 DOM XSS 需浏览器渲染 oracle），但拦大幅回归；未给定时沿用"全清"严格口径。
    # 注意：不稳定端点/不可用目标/探测失败在两种口径下都视为结果不可信，一律拦截。
    if min_f1 is not None or min_recall is not None:
        if unstable or unavailable or any(not a["valid"] for a in per_run):
            print("[eval] ❌ 存在不稳定端点/不可用目标/探测失败 → 结果不可信，门禁不通过")
            return 1
        if min_f1 is not None and (agg.get("f1") is None or agg["f1"] < min_f1):
            print(f"[eval] ❌ F1 门禁未过: {agg.get('f1')} < {min_f1}")
            return 1
        if min_recall is not None and (agg.get("recall") is None or agg["recall"] < min_recall):
            print(f"[eval] ❌ Recall 门禁未过: {agg.get('recall')} < {min_recall}")
            return 1
        print(f"[eval] ✅ 阈值门禁通过: F1={agg.get('f1')} Recall={agg.get('recall')}"
              f"（FN={agg.get('fn')} FP={agg.get('fp')}，允许已知缺口）")
        return 0
    return 0 if ok else 1


if __name__ == "__main__":
    for _s in (sys.stdout, sys.stderr):
        if hasattr(_s, "reconfigure"):
            _s.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-lab", action="store_true", help="靶机已在跑，跳过拉起")
    ap.add_argument("--line", choices=("spec", "engine"), default="spec",
                    help="spec=声明线（默认，快）; engine=引擎线（老范式，慢一些）")
    ap.add_argument("--manifest", dest="manifests", action="append",
                    help="外部测试集（端点级真值清单 .json/.yaml）：可重复给出多个，跑别人的靶场/数据集，"
                         "与自建靶场同口径算 P/R/F1（多个则各自计分并汇总）")
    ap.add_argument("--target", default="",
                    help="对任意真实目标跑检测（无真值表 → 只列命中，用于验证真实误报）")
    ap.add_argument("--json", dest="json_out", action="store_true",
                    help="以 JSON 输出结果（便于 CI / 真实目标结果留档）")
    ap.add_argument("--authorized", action="store_true",
                    help="声明已获目标方授权（扫描非回环/私网目标时必须显式给出，否则拒绝执行）")
    ap.add_argument("--no-proxy", dest="no_proxy", action="store_true",
                    help="本次进程关闭 settings.proxy/代理池（.env 里配了未启动的 Burp 代理时用）")
    ap.add_argument("--repeat", type=int, default=1,
                    help="重复轮数（默认 1）。>1 时逐轮对照并列出**不稳定端点**——"
                         "单轮结果在远程目标上不可信（网络抖动/超时会让结论翻转）")
    ap.add_argument("--min-f1", dest="min_f1", type=float, default=None,
                    help="F1 门禁阈值（CI 用）：给定后按阈值判定（允许已知缺口存在），"
                         "未给定时沿用'零 FN+零 FP'的严格全清口径")
    ap.add_argument("--min-recall", dest="min_recall", type=float, default=None,
                    help="Recall 门禁阈值（CI 用），与 --min-f1 可并用")
    _args = ap.parse_args()
    raise SystemExit(asyncio.run(_main(_args.no_lab, _args.line, _args.target,
                                       _args.manifests, _args.json_out, _args.authorized,
                                       _args.no_proxy, _args.repeat, _args.min_f1,
                                       _args.min_recall)))
