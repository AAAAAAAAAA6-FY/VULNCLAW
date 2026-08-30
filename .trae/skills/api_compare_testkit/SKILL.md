---
name: "api_compare_testkit"
description: "Scaffolds scripts/api_compare.py + scripts/start_api_compare.bat with 3-layer guards, multi-client comparison, and diff report. Invoke when user says 新增 API 对比测试."
---

# API Compare Testkit

End-to-end skill that creates a Python + BAT entry pair which performs a
multi-strategy HTTP request comparison against one or more target APIs. It
uses the same 3-layer header convention as the rest of the workspace so the
comparison script never leaks `__pycache__`, never drops `.config/nuclei`,
and never mojibakes on Chinese Windows.

The compare body is intentionally implemented in pure Python with per-request
short timeouts and exception-per-test capture. This avoids the common pitfall
of chaining `timeout ... && curl ...` in the shell, which fails on Windows
PowerShell/cmd (`&&` parsing) and hides individual request errors.

## When to use (触发条件)

Invoke when the user says anything like:
- "新增 API 对比测试" / "add API comparison test"
- "多种方式访问测试同一接口" / "hit the same endpoint in multiple ways and compare"
- "requests / urllib3 / http.client 对比" / "compare different HTTP client libraries"
- Any task where the user wants two or more HTTP strategies (different
  libraries, different headers, different proxies, different servers) hitting
  one endpoint and producing a side-by-side timing + diff report.

Do NOT use for:
- Heavy load testing / fuzzing (use locust or specialized tools).
- Pure browser-based fingerprint tests (execjs workflow; use a separate script).

## Output contract

Creates two files (ask user for custom names; defaults below are mandatory so
the `scripts/` one-up PROJECT_ROOT heuristic works):

1. `scripts/api_compare.py` – Python entry with 3-layer header + compare runner.
2. `scripts/start_api_compare.bat` – ASCII-only BAT launcher. DO NOT put any
   Chinese inside the BAT file (CP936 parsing turns UTF-8 comments into
   commands -> error 9009).

The skill only **creates** the files. Running them and verifying residuals is
left to the requesting workflow (or the testkit that called this skill). This
keeps the skill deterministic and safe for offline planning.

## Step 1 – Apply `pentest_platform_entry_bootstrap` first

Every Python entry MUST start with the 3-layer header. Invoke
`pentest_platform_entry_bootstrap` BEFORE pasting any business code so the
header order is correct:

| Layer | Guard | Position |
|-------|-------|----------|
| 1. Bytecode block | `PYTHONDONTWRITEBYTECODE=1`, `sys.dont_write_bytecode=True` | First lines of file, before real imports |
| 2. Nuclei HOME | `HOME`, `USERPROFILE`, `NUCLEI_CONFIG_DIR`, `UNCOVER_CONFIG_DIR` → `_runtime_cache/tools/` | Immediately after layer 1; create dirs first |
| 3. UTF-8 | `PYTHONIOENCODING=utf-8`, stdout/stderr reconfigure, `TQDM_DISABLE=1` | Windows-only, right after layer 2 |
| Path heuristic | `scripts/` → one-up → `sys.path.insert(0, PROJECT_ROOT)` | After layer 3, before `del` cleanup line |

## Step 2 – Python body template (`scripts/api_compare.py`)

Paste the template below right after the bootstrap header. Replace
`<ENDPOINT_JSON_CASES>` with user-supplied targets. The template is defensive:
every sub-test has an **independent short timeout** and exception capture; a
slow/failed request never prevents the rest of the comparison from being
printed.

```python
# ===== REAL business imports start BELOW this line =====
import json
import os
import socket
import ssl
import sys
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
        text = text[:200] + "…"
    return text


def _run_http_client(case: dict) -> Result:
    """Standard-library http.client probe. Yields the finest-grained stage
    timings (dns/tcp/tls are resolved manually because http.client does not
    split them for us, but it gives us raw socket access.)"""
    name = case["name"]
    url = case["url"]
    method = case.get("method", "GET")
    headers = case.get("headers", {})
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
        headers = case.get("headers") or {}
        body = case.get("body")
        fields = None
        if isinstance(body, (dict, list)):
            body_json = json.dumps(body).encode("utf-8")
            headers = dict(headers)
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


def run_compare(cases: list[dict] | None = None) -> int:
    cases = cases or DEFAULT_CASES
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
    first = None
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
            if first is None and r.ok:
                first = r

    # ---- Diff report: first PASS body is the reference ------------------
    print()
    print("--- DIFF REPORT (reference = earliest PASS response body) ---")
    if first is None:
        print("No PASS result available to use as diff reference.")
        return 1
    try:
        ref_json = json.loads(first.body_preview if first.body_preview.startswith(
            ("{", "[")) else "{}") if first.body_preview else None
    except Exception:
        ref_json = None

    mismatches = 0
    for r in results:
        if r is first or not r.ok:
            continue
        status_diff = (r.status != first.status)
        time_ratio = (r.timing.total_ms / first.timing.total_ms
                      if first.timing.total_ms > 0 else float("nan"))
        slow = time_ratio >= 1.5
        body_diff = False
        if ref_json is not None and r.body_preview.startswith(("{", "[")):
            try:
                cur_json = json.loads(r.body_preview)
                body_diff = (cur_json != ref_json)
            except Exception:
                body_diff = True
        else:
            body_diff = (r.body_preview != first.body_preview)
        if status_diff or slow or body_diff:
            mismatches += 1
            print(f"  [!] {r.case} :: {r.client}")
            if status_diff:
                print(f"      status {r.status} vs ref {first.status}")
            if slow:
                print(f"      total {r.timing.total_ms:.1f}ms vs ref "
                      f"{first.timing.total_ms:.1f}ms (x{time_ratio:.2f})")
            if body_diff:
                print(f"      body differs (preview len {len(r.body_preview)} "
                      f"vs ref {len(first.body_preview)})")
    if mismatches == 0:
        print("  All results consistent with reference.")
    print()

    verdict = all(r.ok for r in results) and (mismatches == 0)
    print("VERDICT:", "CONSISTENT" if verdict else
          f"{sum(0 if r.ok else 1 for r in results)} FAILED / "
          f"{mismatches} DIFFS")
    # Also write a machine-readable JSON artifact into _runtime_cache
    try:
        from core.settings import PROJECT_CACHE_DIR  # noqa: F401
        report_dir = os.path.join(PROJECT_CACHE_DIR, "reports")
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
```

## Step 3 – BAT launcher template (`scripts/start_api_compare.bat`)

All comments MUST be English. Same PYEXE-resolve + cleanup block as
`pentest_entry_testkit`, custom banner, same 3 environment guard layers.

```bat
@echo off
REM ============================================================
REM API Compare Testkit launcher.
REM ALL comments must be plain ASCII English. cmd.exe parses .bat
REM files with system ANSI CP (CP936 on Chinese Windows); UTF-8
REM comments get parsed as commands -> error 9009. Do NOT add Chinese.
REM ============================================================
cd /d "%~dp0.."
set "PROJECT_ROOT=%cd%"

REM 1. Bytecode block (parent-process scope; guarantees children inherit)
set "PYTHONDONTWRITEBYTECODE=1"
set "PYTHONPYCACHEPREFIX="

REM 2. Nuclei / uncover HOME redirect (avoids .config/ at project root)
set "TOOLS_DIR=%PROJECT_ROOT%\_runtime_cache\tools"
if not exist "%TOOLS_DIR%\nuclei"   mkdir "%TOOLS_DIR%\nuclei"   >nul 2>&1
if not exist "%TOOLS_DIR%\uncover" mkdir "%TOOLS_DIR%\uncover" >nul 2>&1
set "HOME=%TOOLS_DIR%"
set "USERPROFILE=%TOOLS_DIR%"
set "NUCLEI_CONFIG_DIR=%TOOLS_DIR%\nuclei"
set "UNCOVER_CONFIG_DIR=%TOOLS_DIR%\uncover"
set "TQDM_DISABLE=1"

REM 3. Force UTF-8 output (stops mojibake)
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
chcp 65001 >nul

REM Resolve python: prefer project-local venvs; fall back to global
set "PYEXE="
if exist "%PROJECT_ROOT%\.venv\Scripts\python.exe"            set "PYEXE=%PROJECT_ROOT%\.venv\Scripts\python.exe"
if exist "%PROJECT_ROOT%\thirdparty\venv\Scripts\python.exe"  set "PYEXE=%PROJECT_ROOT%\thirdparty\venv\Scripts\python.exe"
if not defined PYEXE set "PYEXE=python"

REM Whitelist-only residual junk cleanup (never touch .venv / thirdparty)
if exist "%PROJECT_ROOT%\__pycache__"   rmdir /s /q "%PROJECT_ROOT%\__pycache__"   >nul 2>&1
if exist "%PROJECT_ROOT%\.pytest_cache" rmdir /s /q "%PROJECT_ROOT%\.pytest_cache" >nul 2>&1
if exist "%PROJECT_ROOT%\.config"       rmdir /s /q "%PROJECT_ROOT%\.config"       >nul 2>&1

echo ============================================================
echo   API Compare Testkit Launcher
echo ============================================================
echo   PROJECT_ROOT = %PROJECT_ROOT%
echo   PYEXE        = %PYEXE%
echo ============================================================
"%PYEXE%" "%PROJECT_ROOT%\scripts\api_compare.py"
set "RC=%ERRORLEVEL%"
echo.
echo === Launcher exit: entry script returned %RC% ===
exit /b %RC%
```

## Step 4 – Dependency pre-flight (informational, do not run on behalf)

The compare runner imports `requests` and `urllib3`. Both are listed in
`pyproject.toml` and are expected to already be present in `thirdparty\venv`
after `pentest_entry_testkit`'s dependency pass. If they are missing, tell
the caller to run:

```
<thirdparty_venv_python> -m pip install requests urllib3
```

Do NOT run `pip install -e .` on this repo (flat-layout multi-package error).

## Acceptance checklist (验收标准)

Verify **each** of these before reporting the skill application as done:

### A. File-level

| # | Requirement |
|---|-------------|
| A1 | `scripts/api_compare.py` exists, starts with 3-layer bootstrap header (bytecode / Nuclei HOME / UTF-8) in exact order |
| A2 | Header includes `scripts/` one-up PROJECT_ROOT heuristic and `sys.path.insert` before `del` cleanup |
| A3 | Business imports (`requests`, `urllib3`, `http.client`) are ONLY below the `# ===== REAL business imports start BELOW this line =====` separator |
| A4 | `scripts/start_api_compare.bat` exists, is 100% ASCII (no Chinese, no emoji, no BOM) |
| A5 | BAT sets `PYTHONDONTWRITEBYTECODE=1` BEFORE the `"%PYEXE%"` invocation line |
| A6 | BAT resolves python with the double-check: `.venv` first, `thirdparty\venv` second, fallback plain `python` |

### B. Semantics-level (template internal)

| # | Requirement |
|---|-------------|
| B1 | Every client call has an **individual timeout** parameter (default 5.0s). No blocking `requests.request(...)` without timeout. |
| B2 | Every client call is wrapped in exception capture. A single case/client failure must print a row with ERROR column instead of aborting. |
| B3 | Timing columns `DNS / TCP / TLS / TTFB / TOTAL` are printed side-by-side for every row, not collapsed into a single number. |
| B4 | Diff report uses the **first PASS result** as reference and flags status / ≥1.5× slowdown / body-diff separately. |
| B5 | Machine-readable JSON is written to `_runtime_cache/reports/api_compare_latest.json` regardless of pass/fail. |

### C. Residual hygiene (must hold AFTER an actual run, NOT after template creation only)

| # | Requirement |
|---|-------------|
| C1 | No `scripts/__pycache__/` created (BAT must have set `PYTHONDONTWRITEBYTECODE=1` as a process env var before python.exe starts). |
| C2 | No project-root `__pycache__/` created. |
| C3 | No project-root `.config/` created (HOME must redirect into `_runtime_cache/tools/` BEFORE python.exe starts). |

## Common pitfalls to avoid

1. **Shell command chains (`timeout ... && curl ... && ...`) on Windows.**
   PowerShell 5 and cmd have incompatible `&&` parsing; the chain often dies
   on the first non-zero exit and hides the rest of the comparison. The
   compare body MUST be implemented in Python only.
2. **Shared exception-handler that forgets to record timings.** Every result
   row must have populated `total_ms` even on failure so the operator can
   tell at which stage a timeout happened. The template populates
   `total_ms` in the `except` branches.
3. **Chinese comments inside BAT.** This turns into error 9009 on CP936
   systems. Every line inside `REM` must be ASCII.
4. **Missing `timeout=` on `requests.request(...)` / `urllib3.PoolManager`.**
   One hanging backend blocks the whole comparison. Keep per-call timeouts
   and keep them short (default 5 s).
5. **Diff done on raw preview only.** If both sides parse as JSON, compare
   decoded JSON so key-order differences don't get flagged.
6. **Report written to `scripts/` or project root.** All reports go under
   `_runtime_cache/reports/` per workspace convention; use `PROJECT_CACHE_DIR`
   when importable else compute the same path manually.
