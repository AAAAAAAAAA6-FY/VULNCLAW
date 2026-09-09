#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API Compare Testkit entry.

Purpose:
  * Fire the same target URLs from multiple HTTP clients (http.client,
    requests, urllib3) and print a side-by-side timing + diff report.
  * Each client/case pair has its own timeout and exception capture so one
    slow or dead backend never hides the rest of the comparison.
  * Uses the workspace 3-layer header so __pycache__ / .config / mojibake
    do not leak.
"""

import os
import sys

# ============================================================
# 1. Block bytecode cache (covers py_compile + child processes too)
#    Note: env vars alone don't cover "python -m py_compile %s"; launcher
#    (see .bat / .ps1 templates below) MUST also set them.
# ============================================================
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
os.environ.setdefault("PYTHONPYCACHEPREFIX", "")
sys.dont_write_bytecode = True

# ============================================================
# 2. Redirect Nuclei / uncover HOME into _runtime_cache/tools/
#    Prevents project-root .config/ from reappearing.
# ============================================================
_HERE = os.path.dirname(os.path.abspath(__file__))
# Heuristic: if __file__ lives under scripts/ / tests/ / dashboard/ / thirdparty/ / distributed/ / _runtime_cache/ / code/ / deepsec/ / dag/
# go up one level to PROJECT_ROOT. Otherwise assume the containing dir IS the project root.
if os.path.basename(_HERE) in {"scripts","tests","dashboard","thirdparty","distributed","_runtime_cache","code","deepsec","dag","engines","ai","core","modules","config"}:
    _PROJECT_ROOT = os.path.dirname(_HERE)
else:
    _PROJECT_ROOT = _HERE
_RT = os.path.join(_PROJECT_ROOT, "_runtime_cache", "tools")
for _sub in ("", "nuclei", "uncover"):
    try:
        os.makedirs(os.path.join(_RT, _sub), exist_ok=True)
    except Exception:
        pass
for _k, _v in (
    ("HOME",               _RT),
    ("USERPROFILE",        _RT),
    ("NUCLEI_CONFIG_DIR",  os.path.join(_RT, "nuclei")),
    ("UNCOVER_CONFIG_DIR", os.path.join(_RT, "uncover")),
):
    os.environ[_k] = _v

# ============================================================
# 3. Windows stdout/stderr UTF-8 + disable tqdm bars
# ============================================================
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("TQDM_DISABLE", "1")
if sys.platform.startswith("win"):
    import io as _io
    for _name in ("stdout", "stderr"):
        _stream = getattr(sys, _name)
        try:
            if hasattr(_stream, "reconfigure"):
                _stream.reconfigure(encoding="utf-8", errors="replace")
                continue
        except Exception:
            pass
        if hasattr(_stream, "buffer"):
            try:
                setattr(sys, _name,
                        _io.TextIOWrapper(_stream.buffer, encoding="utf-8",
                                          errors="replace", line_buffering=True))
            except Exception:
                pass
del _HERE, _PROJECT_ROOT, _RT, _sub, _k, _v, _name, _stream

# ===== REAL business imports start BELOW this line =====
import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from typing import Any

import urllib3  # type: ignore
import requests  # type: ignore

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
_SRC = os.path.join(PROJECT_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# ---- user-supplied targets; edit before running ------------------------
DEFAULT_CASES: list[dict[str, Any]] = [
    {
        "name": "baseline_GET_localhost_8000_health",
        "method": "GET",
        "url": "http://127.0.0.1:8000/health",
        "headers": {"Accept": "application/json"},
        "body": None,
        "timeout": 5.0,
        "expect_status": 200,
    },
    {
        "name": "compare_GET_localhost_8000_health",
        "method": "GET",
        "url": "http://127.0.0.1:8000/health",
        "headers": {"Accept": "application/json", "X-Compare": "1"},
        "body": None,
        "timeout": 5.0,
        "expect_status": 200,
    },
]
# ------------------------------------------------------------------------

@dataclass
class Timing:
    dns_ms: float = 0.0
    tcp_ms: float = 0.0
    tls_ms: float = 0.0
    ttfb_ms: float = 0.0
    total_ms: float = 0.0

@dataclass
class Result:
    case: str
    client: str
    ok: bool
    status: int | None
    body_preview: str
    error: str
    timing: Timing

    def header(self) -> str:
        return (f"{'CASE':<34} {'CLIENT':<14} {'OK':<4} {'STATUS':<6} "
                f"{'DNS':>6} {'TCP':>6} {'TLS':>6} {'TTFB':>6} {'TOTAL':>6}  ERROR/PREVIEW")

    def row(self) -> str:
        t = self.timing
        extra = self.error if self.error else (self.body_preview[:60].replace("\n", " "))
        return (f"{self.case:<34} {self.client:<14} "
                f"{'Y' if self.ok else 'N':<4} "
                f"{(str(self.status) if self.status else '-'):<6} "
                f"{t.dns_ms:>6.1f} {t.tcp_ms:>6.1f} {t.tls_ms:>6.1f} "
                f"{t.ttfb_ms:>6.1f} {t.total_ms:>6.1f}  {extra}")


def _preview(body: bytes | None) -> str:
    if not body:
        return "<empty>"
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        text = repr(body[:120])
    if len(text) > 200:
        text = text[:200] + "\u2026"
    return text


def _run_http_client(case: dict) -> Result:
    """Standard-library http.client probe. Yields the finest-grained stage
    timings (dns/tcp/tls are resolved manually because http.client does not
    split them for us, but it gives us raw socket access.)"""
    name = case["name"]
    url = case["url"]
    method = case.get("method", "GET")
    headers = dict(case.get("headers") or {})
    body = case.get("body")
    timeout = float(case.get("timeout", 5.0))
    expect = case.get("expect_status")
    t = Timing()
    t_total_0 = time.perf_counter()

    import http.client

    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        is_https = parsed.scheme == "https"

        # 1) DNS
        t0 = time.perf_counter()
        addr = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        t.dns_ms = (time.perf_counter() - t0) * 1000
        af, socktype, proto, _canon, sockaddr = addr[0]

        # 2) TCP connect
        sock = socket.socket(af, socktype, proto)
        sock.settimeout(max(0.1, timeout / 3))
        t0 = time.perf_counter()
        sock.connect(sockaddr)
        t.tcp_ms = (time.perf_counter() - t0) * 1000

        # 3) TLS wrap (https only)
        conn: http.client.HTTPConnection
        if is_https:
            ctx = ssl.create_default_context()
            t0 = time.perf_counter()
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            t.tls_ms = (time.perf_counter() - t0) * 1000
            conn = http.client.HTTPSConnection(host, port, timeout=timeout)
            conn.sock = ssock
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.sock = sock

        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        if isinstance(body, (dict, list)):
            payload = json.dumps(body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        elif isinstance(body, str):
            payload = body.encode("utf-8")
        else:
            payload = None  # type: ignore[assignment]

        conn.request(method, target, body=payload, headers=headers)
        t0 = time.perf_counter()
        resp = conn.getresponse()
        status = resp.status
        data = resp.read()
        t.ttfb_ms = (time.perf_counter() - t0) * 1000
        t.total_ms = (time.perf_counter() - t_total_0) * 1000
        ok = (expect is None) or (status == expect)
        return Result(name, "http.client", ok, status, _preview(data), "", t)
    except Exception as exc:  # noqa: BLE001 — surface any error
        t.total_ms = (time.perf_counter() - t_total_0) * 1000
        return Result(name, "http.client", False, None, "", f"{type(exc).__name__}: {exc}", t)


def _run_requests(case: dict) -> Result:
    name = case["name"]
    timeout = float(case.get("timeout", 5.0))
    expect = case.get("expect_status")
    t = Timing()
    t0 = time.perf_counter()
    try:
        method = case.get("method", "GET").lower()
        body = case.get("body")
        json_body = body if isinstance(body, (dict, list)) else None
        data_body = body if isinstance(body, str) else None
        resp = requests.request(
            method,
            case["url"],
            headers=case.get("headers"),
            json=json_body,
            data=data_body,
            timeout=timeout,
            allow_redirects=True,
        )
        t.ttfb_ms = (time.perf_counter() - t0) * 1000
        t.total_ms = (time.perf_counter() - t0) * 1000
        ok = (expect is None) or (resp.status_code == expect)
        return Result(name, "requests", ok, resp.status_code,
                      _preview(resp.content), "", t)
    except Exception as exc:
        t.total_ms = (time.perf_counter() - t0) * 1000
        return Result(name, "requests", False, None, "",
                      f"{type(exc).__name__}: {exc}", t)


def _run_urllib3(case: dict) -> Result:
    name = case["name"]
    timeout = float(case.get("timeout", 5.0))
    expect = case.get("expect_status")
    t = Timing()
    t0 = time.perf_counter()
    try:
        method = case.get("method", "GET")
        headers = dict(case.get("headers") or {})
        body = case.get("body")
        fields = None
        if isinstance(body, (dict, list)):
            body_json = json.dumps(body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        elif isinstance(body, str):
            body_json = body.encode("utf-8")
        else:
            body_json = None  # type: ignore[assignment]

        http = urllib3.PoolManager(timeout=urllib3.Timeout(total=timeout),
                                   retries=False)
        resp = http.request(method, case["url"], headers=headers,
                            body=body_json, fields=fields,
                            preload_content=True)
        t.ttfb_ms = (time.perf_counter() - t0) * 1000
        t.total_ms = (time.perf_counter() - t0) * 1000
        data = resp.data if hasattr(resp, "data") else resp.read()
        ok = (expect is None) or (resp.status == expect)
        return Result(name, "urllib3", ok, resp.status, _preview(data), "", t)
    except Exception as exc:
        t.total_ms = (time.perf_counter() - t0) * 1000
        return Result(name, "urllib3", False, None, "",
                      f"{type(exc).__name__}: {exc}", t)


CLIENTS = {
    "http.client": _run_http_client,
    "requests": _run_requests,
    "urllib3": _run_urllib3,
}


def _cases_from_env() -> list[dict[str, Any]] | None:
    """Load compare cases from the AUTO_VAL_API_COMPARE_CASES env var if set.

    The payload is either a JSON array of case dicts OR the path to a JSON
    file that contains such an array. Used by orchestrators (ZCode auto
    validation) so they do not need to rewrite DEFAULT_CASES in-place,
    which would risk leaving syntax errors on early-exit branches.
    """
    raw = os.environ.get("AUTO_VAL_API_COMPARE_CASES")
    if not raw:
        return None
    payload: Any
    if raw.lower().endswith(".json") and os.path.exists(raw):
        try:
            with open(raw, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except Exception:
            return None
    else:
        try:
            payload = json.loads(raw)
        except Exception:
            return None
    if isinstance(payload, list) and payload and all(isinstance(x, dict) for x in payload):
        return [dict(x) for x in payload]
    return None


def run_compare(cases: list[dict] | None = None) -> int:
    cases = cases or _cases_from_env() or DEFAULT_CASES
    if not cases:
        print("No cases defined. Fill DEFAULT_CASES or pass cases= in.")
        return 2

    print("\n" + "=" * 78)
    print("  API Compare Testkit")
    print("=" * 78)
    print(f"  Total cases : {len(cases)}")
    print(f"  Clients     : {', '.join(CLIENTS)}")
    print("=" * 78)

    results: list[Result] = []
    print()
    header_written = False
    for case in cases:
        for client_name, fn in CLIENTS.items():
            try:
                r = fn(case)
            except Exception as exc:  # noqa: BLE001 — defensive
                r = Result(case["name"], client_name, False, None, "",
                           f"WRAPPER: {type(exc).__name__}: {exc}", Timing())
            if not header_written:
                print(r.header())
                print("-" * len(r.header()))
                header_written = True
            print(r.row())
            results.append(r)

    # ---- Diff report: PER-CASE reference (earliest PASS within that case)
    print()
    print("--- DIFF REPORT (per-case reference = earliest PASS within case) ---")
    failed_n = sum(0 if r.ok else 1 for r in results)
    mismatches_any = 0
    all_ok = all(r.ok for r in results)

    # Group results by logical case so we never compare /health to /api/status.
    per_case: dict[str, list[Result]] = {}
    for r in results:
        per_case.setdefault(r.case, []).append(r)

    any_reference = False
    for case_name, crs in per_case.items():
        first_in_case = next((x for x in crs if x.ok), None)
        if first_in_case is None:
            continue
        any_reference = True
        try:
            ref_raw = (first_in_case.body_preview
                       if first_in_case.body_preview.startswith(("{", "["))
                       else "{}")
            ref_json = json.loads(ref_raw) if first_in_case.body_preview else None
        except Exception:
            ref_json = None
        # Reference timing: median of this case's PASS totals so a single
        # fast cold-response from http.client doesn't penalise the others.
        pass_totals = sorted(x.timing.total_ms for x in crs if x.ok)
        if not pass_totals:
            continue
        median_ref = pass_totals[len(pass_totals) // 2]

        for r in crs:
            if r is first_in_case or not r.ok:
                continue
            status_diff = (r.status != first_in_case.status)
            total = r.timing.total_ms
            if median_ref > 0 and total > 0:
                time_ratio = total / median_ref
            else:
                time_ratio = float("nan")
            abs_delta_ms = abs(total - median_ref)
            # Flag slow only if BOTH ratio AND absolute gap are exceeded:
            # on localhost 6ms -> 10ms is a 1.6x swing with zero real meaning.
            slow = bool(
                time_ratio == time_ratio
                and time_ratio >= 2.0
                and abs_delta_ms >= 25.0
            )
            body_diff = False
            if ref_json is not None and r.body_preview.startswith(("{", "[")):
                try:
                    cur_json = json.loads(r.body_preview)
                    body_diff = (cur_json != ref_json)
                except Exception:
                    body_diff = True
            else:
                body_diff = (r.body_preview != first_in_case.body_preview)
            if status_diff or slow or body_diff:
                mismatches_any += 1
                print(f"  [!] {r.case} :: {r.client}")
                if status_diff:
                    print(f"      status {r.status} vs ref "
                          f"{first_in_case.status}")
                if slow:
                    print(f"      total {total:.1f}ms vs median-ref "
                          f"{median_ref:.1f}ms (x{time_ratio:.2f}, "
                          f"delta={abs_delta_ms:.1f}ms)")
                if body_diff:
                    print(
                        f"      body differs (preview len "
                        f"{len(r.body_preview)} vs ref "
                        f"{len(first_in_case.body_preview)})"
                    )

    if not any_reference:
        print("No PASS result available to use as diff reference.")
    elif mismatches_any == 0 and all_ok:
        print("  All results consistent with per-case reference.")
    print()

    verdict = all_ok and (mismatches_any == 0)
    print("VERDICT:", "CONSISTENT" if verdict else
          f"{failed_n} FAILED / {mismatches_any} DIFFS")
    # Also write a machine-readable JSON artifact into _runtime_cache
    try:
        from vulnclaw.core.settings import PROJECT_CACHE_DIR  # noqa: F401
        report_dir = os.path.join(str(PROJECT_CACHE_DIR), "reports")
    except Exception:
        report_dir = os.path.join(PROJECT_ROOT, "_runtime_cache", "reports")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, "api_compare_latest.json")
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump([asdict(r) for r in results], fh, ensure_ascii=False, indent=2)
    print(f"REPORT: {report_path}")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(run_compare())
