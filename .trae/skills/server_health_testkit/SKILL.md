---
name: "server_health_testkit"
description: "Scaffolds scripts/server_health.py + scripts/start_server_health.bat with 3-layer guards, server launch, /health polling, and status report. Invoke when user says 新增服务端健康检查."
---

# Server Health Testkit

End-to-end skill that creates a Python + BAT entry pair which:

1. (Optional) launches the project backend server as a detached background
   process,
2. waits for it to come up by polling a health endpoint (default `/health`)
   with per-request short timeouts and backoff,
3. emits a tabular status report covering health, liveness, readiness,
   extra probe URLs (e.g. `/openapi.json`, `/metrics`, root `/`), and
4. optionally tears down the background process on exit, or leaves it
   running for subsequent tests.

The skill reuses the workspace 3-layer header so the script never creates
`__pycache__`, never drops `.config/`, and never mojibakes under Chinese
Windows. Polling is implemented purely in Python with per-attempt
timeouts — not shell `curl` + `&&` chains, which are unreliable on
Windows cmd / PowerShell 5.

## When to use (触发条件)

Invoke when the user says anything like:
- "新增服务端健康检查" / "add server-side health check"
- "启动并探活 /health" / "launch backend and probe /health"
- "服务启动冒烟 / 健康检查" / "server launch smoke test"
- Any task that requires bringing a local backend up, waiting for a health
  endpoint to report OK within N seconds, and printing a pass/fail summary.

Do NOT use for:
- Remote infrastructure health (use Prometheus/Blackbox exporter).
- Stress / soak testing.
- Pure unit tests of individual handlers (write pytest tests instead).

## Output contract

Creates exactly two files. Default paths are mandatory so the `scripts/` →
one-up PROJECT_ROOT heuristic matches. Ask the user only if they want custom
names.

1. `scripts/server_health.py` – Python entry with 3-layer header + launch +
   poll + report logic.
2. `scripts/start_server_health.bat` – ASCII-only BAT launcher (no Chinese
   characters; CP936 parses UTF-8 comments as commands -> error 9009).

The skill only **creates** the files. Running them is the caller's
responsibility (and is typically done by the orchestrating testkit).

## Step 1 – Apply `pentest_platform_entry_bootstrap` first

Every Python entry MUST start with the 3-layer header. Invoke
`pentest_platform_entry_bootstrap` BEFORE pasting business code. Header
order contract:

| Layer | Guard | Position |
|-------|-------|----------|
| 1. Bytecode block | `PYTHONDONTWRITEBYTECODE=1`, `sys.dont_write_bytecode=True` | First lines of file, before real imports |
| 2. Nuclei HOME | `HOME`, `USERPROFILE`, `NUCLEI_CONFIG_DIR`, `UNCOVER_CONFIG_DIR` → `_runtime_cache/tools/` | Immediately after layer 1; create dirs first |
| 3. UTF-8 | `PYTHONIOENCODING=utf-8`, stdout/stderr reconfigure, `TQDM_DISABLE=1` | Windows-only, right after layer 2 |
| Path heuristic | `scripts/` → one-up → `sys.path.insert(0, PROJECT_ROOT)` | After layer 3, before `del` cleanup line |

## Step 2 – Python body template (`scripts/server_health.py`)

Paste BELOW the bootstrap separator line. The template is defensive: each
probe has a short timeout and the overall wait has a total deadline so the
script never hangs.

```python
# ===== REAL business imports start BELOW this line =====
import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict, field
from typing import Any

import requests  # type: ignore

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---- Defaults; users can override via CLI or editing -------------------
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
DEFAULT_BASE = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"

# Launch command; keep it a list so Popen escapes args correctly.
# Set to None or [] to skip launching (assume server already running).
DEFAULT_LAUNCH_CMD: list[str] | None = [
    sys.executable,
    os.path.join(PROJECT_ROOT, "scan.py"),  # NOTE: swap to real backend entry.
    "--api",                                # NOTE: swap to real serve flags.
]

DEFAULT_EXTRA_PROBES: list[tuple[str, int]] = [
    # (path, expected_status)
    ("/", 200),
    ("/openapi.json", 200),
    ("/docs", 200),
    ("/metrics", 200),
]

DEFAULT_WAIT_TOTAL = 30.0   # seconds, overall deadline
DEFAULT_INTERVAL   = 0.5    # seconds between probes
DEFAULT_CONNECT_TO = 2.0    # seconds, per-attempt HTTP timeout


@dataclass
class ProbeResult:
    name: str
    url: str
    ok: bool
    status: int | None
    elapsed_ms: float
    body_preview: str
    error: str

    def row(self) -> str:
        extra = self.error if self.error else (self.body_preview[:48].replace("\n", " "))
        return (f"{self.name:<20} {('OK' if self.ok else 'FAIL'):<4} "
                f"{str(self.status) if self.status else '-':<6} "
                f"{self.elapsed_ms:>7.1f} ms  {extra}")


@dataclass
class LaunchState:
    launched: bool = False
    pid: int | None = None
    returncode: int | None = None
    stderr_preview: str = ""
    popen: Any = field(default=None, repr=False)


def _http_probe(name: str, url: str, expect_status: int | None,
                timeout: float) -> ProbeResult:
    t0 = time.perf_counter()
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False)
        ms = (time.perf_counter() - t0) * 1000
        ok = (expect_status is None) or (resp.status_code == expect_status)
        preview = resp.text[:200] if isinstance(resp.text, str) else ""
        return ProbeResult(name, url, ok, resp.status_code, ms, preview, "")
    except Exception as exc:  # noqa: BLE001 — keep going
        ms = (time.perf_counter() - t0) * 1000
        return ProbeResult(name, url, False, None, ms, "",
                           f"{type(exc).__name__}: {exc}")


def _tcp_ping(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _start_server(cmd: list[str] | None, base: str) -> LaunchState:
    state = LaunchState()
    if not cmd:
        return state
    # Derive logs dir once; guarantee it exists before Popen so redirection
    # file paths always resolve (Popen with shell=False does not create dirs).
    logs_dir = os.path.join(PROJECT_ROOT, "_runtime_cache", "logs")
    os.makedirs(logs_dir, exist_ok=True)
    stdout_path = os.path.join(logs_dir, "server_health.stdout.log")
    stderr_path = os.path.join(logs_dir, "server_health.stderr.log")
    env = os.environ.copy()
    # Inherit parent-process 3-layer guards in case the server is itself a
    # python entry (prevents __pycache__/.config inside server children).
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    try:
        fh_out = open(stdout_path, "ab", buffering=0)
        fh_err = open(stderr_path, "ab", buffering=0)
        proc = subprocess.Popen(
            cmd,
            cwd=PROJECT_ROOT,
            stdout=fh_out,
            stderr=fh_err,
            env=env,
            close_fds=True,
            creationflags=(0x00000008 if sys.platform.startswith("win") else 0),
            # DETACHED_PROCESS on Windows so Ctrl+C at parent does not kill server.
        )
    except Exception as exc:  # noqa: BLE001
        state.stderr_preview = f"LAUNCH FAIL: {type(exc).__name__}: {exc}"
        return state

    state.launched = True
    state.pid = proc.pid
    state.popen = proc
    time.sleep(0.2)  # allow process to start and exit-early if broken
    proc.poll()
    state.returncode = proc.returncode
    if proc.returncode is not None:
        try:
            with open(stderr_path, "rb") as fh:
                raw = fh.read()
            state.stderr_preview = raw.decode("utf-8", errors="replace")[-800:]
        except Exception:
            state.stderr_preview = "(process exited before stderr could be read)"
    return state


def _wait_healthy(base: str, health_path: str, expect_status: int,
                  total: float, interval: float, per_connect: float) -> tuple[bool, float | None]:
    deadline = time.perf_counter() + total
    first_ok_at: float | None = None
    attempt = 0
    while time.perf_counter() < deadline:
        attempt += 1
        r = _http_probe("health", base.rstrip("/") + health_path,
                        expect_status, per_connect)
        if r.ok:
            first_ok_at = r.elapsed_ms
            return True, first_ok_at
        time.sleep(interval)
    return False, first_ok_at


def _run_probes(base: str, extra: list[tuple[str, int]],
                per_connect: float) -> list[ProbeResult]:
    out: list[ProbeResult] = []
    out.append(_http_probe("health", base.rstrip("/") + "/health",
                           200, per_connect))
    for path, status in extra:
        # If user wrote a full URL, use it verbatim; else join to base.
        url = path if path.startswith(("http://", "https://")) else (
            base.rstrip("/") + (path if path.startswith("/") else "/" + path)
        )
        out.append(_http_probe(f"probe:{path}"[:20], url, status, per_connect))
    return out


def run(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="server_health",
                                 description="Launch backend and probe /health.")
    ap.add_argument("--base", default=DEFAULT_BASE, help="Server base URL")
    ap.add_argument("--health", default="/health", help="Health endpoint path")
    ap.add_argument("--expect-status", type=int, default=200)
    ap.add_argument("--wait", type=float, default=DEFAULT_WAIT_TOTAL,
                    help="Seconds to wait for health to pass.")
    ap.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                    help="Seconds between retries.")
    ap.add_argument("--timeout", type=float, default=DEFAULT_CONNECT_TO,
                    help="Per-request HTTP timeout seconds.")
    ap.add_argument("--no-launch", action="store_true",
                    help="Skip launching server, assume already running.")
    ap.add_argument("--kill-after", action="store_true",
                    help="Terminate launched server at script exit.")
    args = ap.parse_args(argv)

    print("\n" + "=" * 78)
    print("  Server Health Testkit")
    print("=" * 78)
    print(f"  base         : {args.base}")
    print(f"  health       : {args.health} (expect HTTP {args.expect_status})")
    print(f"  wait deadline: {args.wait:.1f}s")
    print(f"  probe interval: {args.interval:.2f}s")
    print(f"  per-request TO: {args.timeout:.1f}s")
    print(f"  launch server : {'NO (use running one)' if args.no_launch else 'YES'}")
    print()

    # 1) TCP pre-ping: quick fail when nothing is listening at all.
    parsed = urllib.request.urlparse(args.base)
    host = parsed.hostname or DEFAULT_HOST
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    tcp_ready = _tcp_ping(host, port, min(args.timeout, 1.0))
    print(f"  TCP ping {host}:{port} : {'OK' if tcp_ready else 'NOT LISTENING YET'}")

    # 2) Launch, if requested.
    state: LaunchState
    if args.no_launch:
        state = LaunchState()
    else:
        state = _start_server(DEFAULT_LAUNCH_CMD, args.base)
        if state.launched:
            print(f"  server PID : {state.pid}")
            print(f"  launch rc  : {state.returncode if state.returncode is not None else '(still running)'}")
            if state.returncode is not None and state.returncode != 0:
                print("  ----- early stderr tail -----")
                for line in state.stderr_preview.splitlines()[-16:]:
                    print(f"   | {line}")
                print("  -----------------------------")

    # 3) Wait for health endpoint (bounded total deadline).
    print()
    print(f"  polling {args.health} for up to {args.wait:.1f}s...")
    healthy, first_ms = _wait_healthy(args.base, args.health, args.expect_status,
                                      args.wait, args.interval, args.timeout)
    print(f"  health after poll : {'PASS' if healthy else 'FAIL'} "
          f"(first-OK HTTP latency {first_ms:.1f} ms)" if first_ms else "")

    # 4) Full probe run (after health, so dependent endpoints are likely up).
    print()
    print("  Probe results:")
    header = f"{'NAME':<20} {'RES':<4} {'STATUS':<6} {'ELAPSED':>11}  BODY/ERROR"
    print("   " + header)
    print("   " + "-" * len(header))
    probes = _run_probes(args.base, DEFAULT_EXTRA_PROBES, args.timeout)
    for r in probes:
        print("   " + r.row())

    # 5) Verdict.
    all_probes_ok = all(r.ok for r in probes)
    verdict = healthy and all_probes_ok
    print()
    print("VERDICT:", "HEALTHY" if verdict else
          (f"UNHEALTHY: {'health never OK; ' if not healthy else ''}"
           f"{sum(1 for r in probes if not r.ok)} probe(s) failed"))

    # 6) Write JSON report under _runtime_cache/reports.
    try:
        from core.settings import PROJECT_CACHE_DIR  # noqa: F401
        report_dir = os.path.join(str(PROJECT_CACHE_DIR), "reports")
    except Exception:
        report_dir = os.path.join(PROJECT_ROOT, "_runtime_cache", "reports")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, "server_health_latest.json")
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump({
            "args": vars(args),
            "launch": {
                "launched": state.launched,
                "pid": state.pid,
                "returncode": state.returncode,
                "stderr_preview": state.stderr_preview,
            },
            "health": {"ok": healthy, "first_ok_ms": first_ms},
            "probes": [asdict(r) for r in probes],
            "verdict": verdict,
        }, fh, ensure_ascii=False, indent=2)
    print(f"REPORT : {report_path}")

    # 7) (Optional) teardown.
    if args.kill_after and state.popen is not None and state.returncode is None:
        try:
            state.popen.terminate()
            try:
                state.popen.wait(timeout=3)
            except subprocess.TimeoutExpired:
                state.popen.kill()
            print(f"TEARDOWN: killed PID {state.pid} (--kill-after)")
        except Exception as exc:  # noqa: BLE001
            print(f"TEARDOWN: error during kill: {type(exc).__name__}: {exc}")
    elif state.launched and state.returncode is None:
        print(f"LEAVING : PID {state.pid} running (no --kill-after). "
              f"Re-run with --kill-after to stop it, or --no-launch next time to reuse.")

    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(run())
```

### Important template notes (remind the caller)

- `DEFAULT_LAUNCH_CMD`: swap `scan.py` + `"--api"` to the real backend entry
  and serve flags for this project. The template ships with sensible
  placeholders; the user is responsible for correctness.
- `DEFAULT_EXTRA_PROBES`: adjust `/docs`, `/metrics`, etc. to match the
  actual backend surface.
- Windows `creationflags=DETACHED_PROCESS (0x00000008)`: keeps the server
  alive after the health script exits. Without it, Ctrl+C at the launcher
  terminal often cascades into the backend.

## Step 3 – BAT launcher template (`scripts/start_server_health.bat`)

Same 3-layer env guard + PYEXE resolve + white-list cleanup as all other
entry launchers. All comments MUST be English.

```bat
@echo off
REM ============================================================
REM Server Health Testkit launcher.
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

REM Ensure logs dir exists so Popen redirection never fails
if not exist "%PROJECT_ROOT%\_runtime_cache\logs" mkdir "%PROJECT_ROOT%\_runtime_cache\logs" >nul 2>&1

echo ============================================================
echo   Server Health Testkit Launcher
echo ============================================================
echo   PROJECT_ROOT = %PROJECT_ROOT%
echo   PYEXE        = %PYEXE%
echo ============================================================
"%PYEXE%" "%PROJECT_ROOT%\scripts\server_health.py" %*
set "RC=%ERRORLEVEL%"
echo.
echo === Launcher exit: entry script returned %RC% ===
exit /b %RC%
```

Key difference vs other launchers: `%*` is forwarded to the Python script so
callers can run `start_server_health.bat --no-launch`,
`start_server_health.bat --wait 60`, `--kill-after`, etc.

## Step 4 – Dependency pre-flight (informational only)

`requests` is the only third-party import; it is already in `pyproject.toml`
and should be present in `thirdparty\venv` after
`pentest_entry_testkit`'s dependency pass. If missing, tell the caller to:

```
<thirdparty_venv_python> -m pip install requests
```

Do NOT use `pip install -e .` on this repo (flat-layout multi-package
error).

## Acceptance checklist (验收标准)

### A. File-level

| # | Requirement |
|---|-------------|
| A1 | `scripts/server_health.py` exists and starts with the 3-layer header in exact order (bytecode → Nuclei HOME → UTF-8 → path heuristic + `sys.path.insert`). |
| A2 | All real business imports are BELOW the `# ===== REAL business imports start BELOW this line =====` separator. |
| A3 | `scripts/start_server_health.bat` exists, is 100% ASCII (no Chinese / emoji / BOM). |
| A4 | BAT sets `PYTHONDONTWRITEBYTECODE=1` BEFORE the `"%PYEXE%" ...` invocation line. |
| A5 | BAT forwards CLI args via `%*` so `--no-launch`, `--wait`, `--kill-after` propagate. |
| A6 | BAT ensures `_runtime_cache\logs` exists before invoking python (so Popen redirection never fails with a missing-directory error). |

### B. Semantics-level

| # | Requirement |
|---|-------------|
| B1 | TCP pre-ping before launch. Catches port-in-use / nothing-listening quickly without the HTTP deadline. |
| B2 | Total deadline on health polling. `_wait_healthy` must return False within `args.wait` seconds; no infinite loop. |
| B3 | Per-request timeout on every probe (`args.timeout`). One slow endpoint never blocks the whole report. |
| B4 | Server launch uses a list-based `Popen(cmd)` not `shell=True`. Inherits `PYTHONDONTWRITEBYTECODE=1`, `PYTHONIOENCODING=utf-8` via `env=` copy so the child also gets 3-layer guards. |
| B5 | Early-exit detection: if `Popen.poll()` is non-zero inside the launch block, print the last 16 lines of captured stderr as part of the report. |
| B6 | Windows detach via `creationflags=0x00000008` (DETACHED_PROCESS) so Ctrl+C on the launcher does not cascade into the server. Non-Windows must pass `0` instead (no `AttributeError`). |
| B7 | JSON report always written to `_runtime_cache/reports/server_health_latest.json` regardless of pass/fail. Include launch info, health, probes array, and verdict. |
| B8 | Optional `--kill-after` flag terminates the launched server on exit; otherwise the server is left running with an informative message. |

### C. Residual hygiene (after an actual run)

| # | Requirement |
|---|-------------|
| C1 | No `scripts/__pycache__/` created. |
| C2 | No project-root `__pycache__/` created. |
| C3 | No project-root `.config/` created. |
| C4 | Server log files are written under `_runtime_cache/logs/` only, not under `scripts/` or project root. |

## Common pitfalls to avoid

1. **`shell=True` + command string** in Popen. Breaks on Windows paths with
   spaces and opens up quoting issues. Always use a list argument.
2. **Forgetting `DETACHED_PROCESS` on Windows.** The first Ctrl+C in the
   launcher window kills both client AND the just-started server, which is
   never the desired behavior for a health check.
3. **Polling without a total deadline.** A stuck endpoint keeps the script
   running forever. Use `time.perf_counter()` + `deadline` and always exit
   with a non-zero code on deadline miss.
4. **Chinese comments in the BAT launcher** (`REM 启动服务` style). cmd.exe
   runs with CP936 by default; UTF-8 Chinese bytes get parsed as token
   fragments and hit `error 9009`. Keep every line ASCII.
5. **Forgetting to create `_runtime_cache/logs` before Popen.** If you
   redirect stdout/stderr to a file under a nonexistent directory,
   `Popen` itself raises FileNotFoundError *before* the child ever runs.
   Both Python (`logs_dir = ...; os.makedirs(logs_dir, exist_ok=True)`) and
   BAT (`if not exist ... mkdir ...`) sides create it.
6. **Missing `timeout=` on `requests.get(...)`**. A single dead probe blocks
   the entire report and defeats the deadline. Every HTTP call must carry
   the per-request timeout argument.
7. **Health polling with shell `curl ... && ...`**. Shell chains are not
   portable, cannot compute per-attempt backoff accurately, and swallow
   structured errors. All waiting logic must live in the Python file.
