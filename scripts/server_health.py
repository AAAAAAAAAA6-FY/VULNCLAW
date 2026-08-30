#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Server Health Testkit entry.

Purpose:
  * (Optional) Launch the project backend server as a detached child.
  * TCP pre-ping the target host:port to fail-fast when nothing is listening.
  * Poll a health endpoint with bounded total deadline and per-request
    short timeouts; no Windows curl/cmd && chain needed.
  * Print per-probe (name / status / elapsed / preview-or-error) table and
    emit one JSON report under _runtime_cache/reports.
  * Honor --kill-after on exit; otherwise leave the launched server alive
    for subsequent tests.
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
import argparse
import json
import socket
import subprocess
import time
import urllib.parse
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
        popen_kwargs: dict[str, Any] = dict(
            cwd=PROJECT_ROOT,
            stdout=fh_out,
            stderr=fh_err,
            env=env,
            close_fds=True,
        )
        if sys.platform.startswith("win"):
            # DETACHED_PROCESS: Ctrl+C at parent does not cascade to server.
            popen_kwargs["creationflags"] = 0x00000008
        proc = subprocess.Popen(cmd, **popen_kwargs)
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
    while time.perf_counter() < deadline:
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
        if path.startswith(("http://", "https://")):
            url = path
        else:
            url = base.rstrip("/") + (path if path.startswith("/") else "/" + path)
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
    parsed = urllib.parse.urlparse(args.base)
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
    health_msg = f"  health after poll : {'PASS' if healthy else 'FAIL'}"
    if first_ms is not None:
        health_msg += f" (first-OK HTTP latency {first_ms:.1f} ms)"
    print(health_msg)

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
    failed_count = sum(1 for r in probes if not r.ok)
    print()
    if verdict:
        print("VERDICT: HEALTHY")
    else:
        reason = []
        if not healthy:
            reason.append("health never OK")
        if failed_count:
            reason.append(f"{failed_count} probe(s) failed")
        print("VERDICT: UNHEALTHY - " + "; ".join(reason))

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
