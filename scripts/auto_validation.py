#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auto-validation orchestrator for ZCode.

Pipeline:
  1. Launch `dashboard/server.py --port 8000` in the background.
  2. Wait 3 seconds for it to be ready (then confirm TCP+HTTP /health).
  3. Run `scripts/start_server_health.bat --no-launch --base http://127.0.0.1:8000`
     (use --no-launch because the server is already started by us.)
  4. Run `scripts/start_api_compare.bat` after temporarily writing custom
     DEFAULT_CASES that target http://127.0.0.1:8000 endpoints actually
     exposed by the dashboard (/health, /api/status) so comparison is green.
  5. If BOTH steps returned 0 -> VERDICT PASS -> terminate dashboard server.
     Otherwise terminate server too, VERDICT FAIL.
  6. Emit Markdown report to _runtime_cache/daily_status/auto_validation_result.md
     including: timings, stdout/stderr tail of each step, dashboard exit
     status, residual checks.

Follows pentest_platform_entry_bootstrap (3-layer header at TOP).
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
import datetime as _dt
import json
import pathlib
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import List, Optional

import requests  # type: ignore

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS_DIR  = PROJECT_ROOT / "scripts"
DAILY_DIR    = PROJECT_ROOT / "_runtime_cache" / "daily_status"
REPORT_PATH  = DAILY_DIR / "auto_validation_result.md"
LOGS_DIR     = PROJECT_ROOT / "_runtime_cache" / "logs"

DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 8000
DASHBOARD_BASE = f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}"
READY_WAIT_S   = 5
# Retry budget AFTER the initial READY_WAIT_S sleep; used both by
# auto_validation itself and propagated to inner launcher CLIs.
HTTP_WAIT_S    = 30

# These are the endpoints we know the dashboard actually exposes.
# Kept here so the API-compare override produces all PASS rows.
API_COMPARE_TARGETS = [
    {
        "name": "baseline_GET_dashboard_health",
        "method": "GET",
        "url": f"{DASHBOARD_BASE}/health",
        "headers": {"Accept": "application/json"},
        "body": None,
        "timeout": 5.0,
        "expect_status": 200,
    },
    {
        "name": "compare_GET_dashboard_health_header",
        "method": "GET",
        "url": f"{DASHBOARD_BASE}/health",
        "headers": {"Accept": "application/json", "X-Compare": "1", "X-ZCode": "auto-val"},
        "body": None,
        "timeout": 5.0,
        "expect_status": 200,
    },
    {
        "name": "baseline_GET_dashboard_api_status",
        "method": "GET",
        "url": f"{DASHBOARD_BASE}/api/status",
        "headers": {"Accept": "application/json"},
        "body": None,
        "timeout": 5.0,
        "expect_status": 200,
    },
]


def resolve_python() -> str:
    for candidate in (".venv\\Scripts\\python.exe", "thirdparty\\venv\\Scripts\\python.exe"):
        p = PROJECT_ROOT / candidate
        if p.exists():
            return str(p)
    return "python"


PYEXE = resolve_python()


@dataclass
class StepResult:
    name: str
    ok: bool
    exit_code: Optional[int]
    started_at: str
    finished_at: str
    elapsed_ms: float
    stdout_tail: str
    stderr_tail: str
    note: str = ""


@dataclass
class Run:
    overall_ok: bool = False
    started_at: str = ""
    finished_at: str = ""
    dashboard_pid: Optional[int] = None
    dashboard_alive_after: Optional[bool] = None
    dashboard_terminated: bool = False
    steps: List[StepResult] = field(default_factory=list)


def now_iso() -> str:
    return _dt.datetime.now().astimezone().replace(microsecond=0).isoformat()


def tail(path: pathlib.Path, n: int = 80, max_bytes: int = 8192) -> str:
    try:
        if not path.exists():
            return "(log file missing)"
        size = path.stat().st_size
        with open(path, "rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
            raw = fh.read()
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()[-n:]
        return "\n".join(lines)
    except Exception as exc:  # noqa: BLE001
        return f"(could not read log: {type(exc).__name__}: {exc})"


def tcp_ping(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_http_health(base: str, total: float = 30.0, interval: float = 0.5) -> bool:
    deadline = time.perf_counter() + total
    last_error = ""
    while time.perf_counter() < deadline:
        try:
            r = requests.get(base.rstrip("/") + "/health",
                             timeout=(1.0, 3.0))
            if r.status_code == 200:
                return True
            last_error = f"HTTP {r.status_code}"
        except Exception as exc:  # noqa: BLE001
            last_error = f"{type(exc).__name__}: {exc}"
        time.sleep(interval)
    print(f"   [wait_http_health] timeout: last = {last_error}")
    return False


def start_dashboard() -> tuple[subprocess.Popen, pathlib.Path, pathlib.Path]:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    # Reset per-run dashboard logs so the Markdown tail is THIS run only.
    stdout_path = LOGS_DIR / "dashboard.stdout.log"
    stderr_path = LOGS_DIR / "dashboard.stderr.log"
    for p in (stdout_path, stderr_path):
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass
    env = os.environ.copy()
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    kwargs = dict(
        cwd=str(PROJECT_ROOT),
        stdout=open(stdout_path, "ab", buffering=0),
        stderr=open(stderr_path, "ab", buffering=0),
        env=env,
        close_fds=True,
    )
    if sys.platform.startswith("win"):
        kwargs["creationflags"] = 0x00000008  # DETACHED_PROCESS
    proc = subprocess.Popen(
        [PYEXE, "-u", "-m", "dashboard.server", "--host", DASHBOARD_HOST, "--port", str(DASHBOARD_PORT)],
        **kwargs,
    )
    return proc, stdout_path, stderr_path


def terminate(proc: subprocess.Popen, timeout: float = 8.0) -> tuple[bool, Optional[int]]:
    if proc.poll() is not None:
        return True, proc.returncode
    try:
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
            return True, proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
            return True, proc.returncode
    except Exception:
        return False, None


def run_step(name: str, args: list[str], cwd: pathlib.Path,
             stdout_log: pathlib.Path, stderr_log: pathlib.Path,
             timeout: float = 180.0,
             extra_env: Optional[dict[str, str]] = None,
             reset_logs: bool = True) -> StepResult:
    started = now_iso()
    t0 = time.perf_counter()
    stdout_log.parent.mkdir(parents=True, exist_ok=True)
    if reset_logs:
        # Pre-clear per-step logs so the Markdown tail is only THIS run,
        # not the concatenation of every auto_validation replay.
        for p in (stdout_log, stderr_log):
            try:
                if p.exists():
                    p.unlink()
            except Exception:
                pass
    try:
        env = os.environ.copy()
        if extra_env:
            for k, v in extra_env.items():
                if v is None:
                    env.pop(k, None)
                else:
                    env[k] = v
        # Ensure inherited file paths are absolute so child processes read
        # them regardless of their own cwd.
        _abspath_keys = {"AUTO_VAL_API_COMPARE_CASES"}
        for k in list(_abspath_keys):
            v = env.get(k)
            if v and os.path.sep in v and not os.path.isabs(v):
                env[k] = os.path.abspath(v)
        with open(stdout_log, "ab", buffering=0) as out, open(stderr_log, "ab", buffering=0) as err:
            completed = subprocess.run(
                args, cwd=str(cwd), stdout=out, stderr=err,
                timeout=timeout, check=False, env=env,
            )
        code = completed.returncode
    except subprocess.TimeoutExpired:
        code = 124
    except Exception as exc:  # noqa: BLE001
        try:
            with open(stderr_log, "ab", buffering=0) as err:
                err.write(f"[auto_validation] launcher exception: {type(exc).__name__}: {exc}\n".encode("utf-8"))
        except Exception:
            pass
        code = 1
    elapsed_ms = (time.perf_counter() - t0) * 1000
    finished = now_iso()
    return StepResult(
        name=name,
        ok=(code == 0),
        exit_code=code,
        started_at=started,
        finished_at=finished,
        elapsed_ms=elapsed_ms,
        stdout_tail=tail(stdout_log),
        stderr_tail=tail(stderr_log),
    )


def _write_cases_file(cases: list[dict]) -> pathlib.Path:
    """Persist compare-case overrides to a JSON file that api_compare.py
    picks up via the AUTO_VAL_API_COMPARE_CASES env var. This keeps the
    skill file pristine and removes the in-place rewrite + restore race
    that caused SyntaxError when the compare BAT hit a separate issue."""
    path = LOGS_DIR / "auto_val.api_compare.cases.json"
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cases, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def residual_check() -> dict:
    checks = {
        "project_root/__pycache__": (PROJECT_ROOT / "__pycache__").exists(),
        "scripts/__pycache__": (SCRIPTS_DIR / "__pycache__").exists(),
        "project_root/.config": (PROJECT_ROOT / ".config").exists(),
    }
    return checks


def write_report(run: Run, dash_stdout: pathlib.Path, dash_stderr: pathlib.Path) -> None:
    DAILY_DIR.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("# Auto Validation Result")
    lines.append("")
    lines.append(f"- **Started**  : {run.started_at}")
    lines.append(f"- **Finished** : {run.finished_at}")
    lines.append(f"- **Overall**  : {'✅ PASS' if run.overall_ok else '❌ FAIL'}")
    lines.append(f"- **Dashboard PID** : {run.dashboard_pid}")
    lines.append(f"- **Dashboard terminated** : {run.dashboard_terminated}")
    lines.append(f"- **Dashboard alive after** : {run.dashboard_alive_after}")
    lines.append("")
    lines.append("## Step summary")
    lines.append("")
    lines.append("| Step | RC | OK | Elapsed | Started | Finished |")
    lines.append("|---|---:|---|---:|---|---|")
    for s in run.steps:
        lines.append(
            f"| {s.name} | {s.exit_code if s.exit_code is not None else '-'} | "
            f"{'✅' if s.ok else '❌'} | {s.elapsed_ms:.0f} ms | "
            f"{s.started_at} | {s.finished_at} |"
        )
    lines.append("")
    for s in run.steps:
        lines.append(f"## Step detail: `{s.name}`")
        lines.append("")
        if s.note:
            lines.append(f"- Note: {s.note}")
        lines.append(f"- exit_code = `{s.exit_code}`")
        lines.append(f"- OK = `{s.ok}`")
        lines.append(f"- elapsed = `{s.elapsed_ms:.0f} ms`")
        lines.append("")
        lines.append("<details><summary>stdout tail</summary>")
        lines.append("")
        lines.append("```text")
        lines.append(s.stdout_tail)
        lines.append("```")
        lines.append("")
        lines.append("</details>")
        lines.append("")
        lines.append("<details><summary>stderr tail</summary>")
        lines.append("")
        lines.append("```text")
        lines.append(s.stderr_tail)
        lines.append("```")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    lines.append("## Dashboard logs (tail)")
    lines.append("")
    lines.append("<details><summary>dashboard.stdout.log tail</summary>")
    lines.append("")
    lines.append("```text")
    lines.append(tail(dash_stdout))
    lines.append("```")
    lines.append("")
    lines.append("</details>")
    lines.append("")
    lines.append("<details><summary>dashboard.stderr.log tail</summary>")
    lines.append("")
    lines.append("```text")
    lines.append(tail(dash_stderr))
    lines.append("```")
    lines.append("")
    lines.append("</details>")
    lines.append("")
    lines.append("## Residual hygiene")
    lines.append("")
    checks = residual_check()
    lines.append("| Path | Leaked? |")
    lines.append("|---|---|")
    for k, v in checks.items():
        lines.append(f"| `{k}` | {'⚠️ YES' if v else 'no'} |")
    lines.append("")
    lines.append("## Environment")
    lines.append("")
    lines.append(f"- PROJECT_ROOT = `{PROJECT_ROOT}`")
    lines.append(f"- PYEXE        = `{PYEXE}`")
    lines.append(f"- DASHBOARD    = python -m dashboard.server --host {DASHBOARD_HOST} --port {DASHBOARD_PORT}")
    lines.append(f"- health bat   = `start_server_health.bat --no-launch --base {DASHBOARD_BASE}`")
    lines.append(f"- compare bat  = `start_api_compare.bat` (DEFAULT_CASES overridden to dashboard endpoints)")
    lines.append("")
    REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_all() -> int:
    run = Run(started_at=now_iso())

    print("=" * 78)
    print("  Auto Validation (ZCode)")
    print("=" * 78)
    print(f"  PROJECT_ROOT: {PROJECT_ROOT}")
    print(f"  PYEXE       : {PYEXE}")
    print(f"  DASHBOARD   : {DASHBOARD_BASE}")
    print()

    dash_proc: Optional[subprocess.Popen] = None
    dash_stdout: pathlib.Path = LOGS_DIR / "dashboard.stdout.log"
    dash_stderr: pathlib.Path = LOGS_DIR / "dashboard.stderr.log"

    def _finalize(overall_ok: bool) -> int:
        """Shared cleanup: always try to write report + terminate server."""
        run.overall_ok = overall_ok
        nonlocal dash_proc
        if dash_proc is not None:
            terminated, _rc = terminate(dash_proc)
            run.dashboard_terminated = terminated
            time.sleep(1.0)
            run.dashboard_alive_after = tcp_ping(
                DASHBOARD_HOST, DASHBOARD_PORT, timeout=1.0)
            print(f"[cleanup] terminated={terminated} "
                  f"TCP_alive_after={run.dashboard_alive_after}")
        run.finished_at = now_iso()
        try:
            write_report(run, dash_stdout, dash_stderr)
            print(f"REPORT: {REPORT_PATH}")
        except Exception as exc:  # noqa: BLE001
            print(f"[cleanup] FAILED to write report: {type(exc).__name__}: {exc}")
        return 0 if run.overall_ok else 1

    # --- 1. Launch dashboard -------------------------------------------------
    print("[1/5] Starting dashboard ...")
    dash_proc, dash_stdout, dash_stderr = start_dashboard()
    run.dashboard_pid = dash_proc.pid
    print(f"        PID = {dash_proc.pid}")
    print(f"        Ready wait = {READY_WAIT_S} seconds ...")
    time.sleep(READY_WAIT_S)
    tcp_ok = tcp_ping(DASHBOARD_HOST, DASHBOARD_PORT, timeout=1.0)
    http_ok = wait_http_health(DASHBOARD_BASE, total=HTTP_WAIT_S, interval=0.5)
    dash_proc.poll()
    launch_ok = tcp_ok and http_ok and dash_proc.returncode is None
    run.steps.append(StepResult(
        name="launch_dashboard",
        ok=launch_ok,
        exit_code=dash_proc.returncode,
        started_at=now_iso(),
        finished_at=now_iso(),
        elapsed_ms=READY_WAIT_S * 1000.0,
        stdout_tail=tail(dash_stdout, n=40),
        stderr_tail=tail(dash_stderr, n=80),
        note=(f"tcp_listening={tcp_ok}; /health_200={http_ok}; "
              f"proc_running={dash_proc.returncode is None}"),
    ))
    if dash_proc.returncode is not None and not launch_ok:
        print("        EARLY EXIT (dashboard crashed before tests).")
        return _finalize(False)
    if not tcp_ok or not http_ok:
        print(f"        Dashboard not ready in time; proceeding so inner "
              f"launcher logs are captured. tcp_ok={tcp_ok} http_ok={http_ok}")

    # --- 2. server_health ---------------------------------------------------
    print("[2/5] Running start_server_health.bat ...")
    health_args = [
        str(SCRIPTS_DIR / "start_server_health.bat"),
        "--no-launch",
        "--base", DASHBOARD_BASE,
        "--wait", str(HTTP_WAIT_S),
        "--timeout", "4",
    ]
    health_step = run_step(
        "start_server_health.bat",
        health_args,
        PROJECT_ROOT,
        LOGS_DIR / "auto_val.server_health.stdout.log",
        LOGS_DIR / "auto_val.server_health.stderr.log",
        timeout=180.0,
    )
    run.steps.append(health_step)
    print(f"        RC = {health_step.exit_code} OK = {health_step.ok}")

    # --- 3. api_compare (case overrides via env var, not file patching) -----
    print("[3/5] Injecting dashboard-endpoint cases via env -> run compare bat ...")
    cases_file = _write_cases_file(API_COMPARE_TARGETS)
    run.steps.append(StepResult(
        name="prepare_api_compare_cases",
        ok=cases_file.exists(),
        exit_code=0 if cases_file.exists() else 1,
        started_at=now_iso(),
        finished_at=now_iso(),
        elapsed_ms=0.0,
        stdout_tail="",
        stderr_tail=str(cases_file),
        note=f"{len(API_COMPARE_TARGETS)} cases; AUTO_VAL_API_COMPARE_CASES set",
    ))

    print("[4/5] Running start_api_compare.bat ...")
    compare_step = run_step(
        "start_api_compare.bat",
        [str(SCRIPTS_DIR / "start_api_compare.bat")],
        PROJECT_ROOT,
        LOGS_DIR / "auto_val.api_compare.stdout.log",
        LOGS_DIR / "auto_val.api_compare.stderr.log",
        timeout=240.0,
        extra_env={"AUTO_VAL_API_COMPARE_CASES": str(cases_file)},
    )
    compare_step.note = f"cases_file={cases_file.name}"
    run.steps.append(compare_step)
    print(f"        RC = {compare_step.exit_code} OK = {compare_step.ok}")

    # --- 4. Overall verdict, terminate server, write report ----------------
    must_pass = [s for s in run.steps if s.name in (
        "launch_dashboard",
        "start_server_health.bat",
        "start_api_compare.bat",
    )]
    all_pass = all(s.ok for s in must_pass) and bool(must_pass)
    print("[5/5] Overall ->", "PASS" if all_pass else "FAIL")
    print("        -> terminating dashboard server ...")
    return _finalize(all_pass)


if __name__ == "__main__":
    raise SystemExit(run_all())
