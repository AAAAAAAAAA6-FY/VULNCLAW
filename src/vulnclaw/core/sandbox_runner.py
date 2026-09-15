# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/sandbox_runner.py
"""SP1 无 Docker 自动降级沙箱链：进程级隔离执行 PoC/利用脚本。

融合 strix runtime 思路时的本机兜底（对面若提供 Docker 沙箱，本模块自动优先：
Docker 可用 -> level-0 容器沙箱；不可用 -> level-1 进程隔离）。

level-1 进程隔离规则：
  - 无 shell：直接 asyncio.create_subprocess_exec(argv)，杜绝 shell 注入
  - 环境净化：PATH 白名单 + 剥离敏感变量，仅保留运行必需项
  - 独立工作目录：_runtime_cache/sandbox/<token>/，脚本不得触达项目目录
  - 超时强制 kill + 输出截断（双上限）
  - 执行前置门：PoC 目标 URL 必须命中 allowed_scope（复用 E5.1 白名单 + 默认 aiohttp
    出口拦截）；越界一律拒绝执行，防沙箱成为出网跳板

verdict -> 执行后端策略（E1 verdict 三档复用）：
  confirm     -> Docker 优先，无则进程隔离
  likely      -> 进程隔离
  suspicious  -> 不执行真实 PoC（启发式 + 人工复核），返回 heuristic_only
"""
import asyncio
import os
import shlex
import shutil
import sys
import tempfile
import time
import uuid
from typing import Any, Dict, List, Optional

from vulnclaw.core.logger import logger

# 进程隔离工作目录根（落盘收敛到 _runtime_cache）
SBOX_ROOT = os.path.join("_runtime_cache", "sandbox")
# 默认超时 / 输出上限（可按调用覆盖）
SBOX_TIMEOUT = int(os.getenv("VULNCLAW_SBOX_TIMEOUT", "30"))
SBOX_MAX_OUTPUT = int(os.getenv("VULNCLAW_SBOX_MAX_OUTPUT", "8192"))

# 危险命令前缀：PoC 脚本本身可执行任意语言代码（隔离保证安全），但若载荷是
# 命令行字符串，直接禁止高危外壳命令族（横向/破坏类），仅允许脚本解释器类。
# 判定时忽略平台扩展名（python.exe / py.exe 与 python 等同）。
_ALLOWED_SCRIPT_BINS = {"python", "python3", "py", "pythonw", "bash", "sh", "node", "php", "perl", "ruby"}

_docker_cache: Dict[str, Any] = {"checked": False, "ok": None, "ts": 0.0}
_DOCKER_CACHE_TTL = 60.0


async def _probe_docker_async(docker_bin: str, timeout: int) -> bool:
    """单一事件循环内完成 create + communicate（P0-5：不再跨 loop 使用 transport）。"""
    proc = await asyncio.create_subprocess_exec(
        docker_bin, "version", "--format", "{{.Server.Version}}",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        out, _err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return False
    return proc.returncode == 0 and bool(out and out.strip())


def docker_available(timeout: int = 5) -> bool:
    """探测本机 Docker 是否可用（TTL 缓存 60s；探测失败视为不可用）。

    P0-5 修复：旧实现用**两个** `new_event_loop()`——先在一个 loop 建子进程、
    再在另一个 loop 调 `communicate()`，transport 与 loop 不一致必然抛错被吞，
    导致"Docker 装了也永远判不可用"，且两个 loop 从不关闭。现在统一为
    单个 `asyncio.run`；已在事件循环内时落到独立线程 loop 并完整关闭。
    """
    now = time.time()
    if _docker_cache["checked"] and (now - float(_docker_cache.get("ts") or 0.0)) < _DOCKER_CACHE_TTL:
        return bool(_docker_cache["ok"])
    docker_bin = shutil.which("docker")
    ok = False
    if docker_bin:
        try:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                ok = asyncio.run(_probe_docker_async(docker_bin, timeout))
            else:
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    ok = bool(ex.submit(
                        asyncio.run, _probe_docker_async(docker_bin, timeout)).result())
        except Exception as exc:  # noqa: BLE001 - 探测失败一律"不可用"，不进主流程
            logger.debug(f"Docker 探测失败（视为不可用）: {exc}")
            ok = False
    _docker_cache["checked"] = True
    _docker_cache["ok"] = ok
    _docker_cache["ts"] = now
    return ok


def sandbox_policy_for(verdict: str) -> Dict[str, Any]:
    """verdict 三档 -> 沙箱策略（confirm/likely 真实执行，suspicious 不执行）。"""
    v = str(verdict or "suspicious").lower()
    if v in ("confirm", "confirmed", "high_confidence"):
        return {"backend": "docker" if docker_available() else "process", "execute": True}
    if v in ("likely", "medium_confidence"):
        return {"backend": "process", "execute": True}
    return {"backend": "heuristic", "execute": False, "reason": "suspicious 不执行真实 PoC，走启发式+人工复核"}


def _target_in_scope(url: str) -> bool:
    """复用 E5.1 出口白名单：allowed_scope 未配置 → 放行；配置后越界拒绝。

    P0-4 修复：旧实现把"校验异常"也 `return True`，等于**安全边界反向默认**——
    白名单解析器/DNS/配置一异常就全放行越界 PoC。现在严格区分：
      - 未配置 allowed_scope   → True（边界未启用，显式语义）
      - 校验抛异常/解析失败    → **False（fail-closed）** 并留可诊断日志
    """
    from vulnclaw.config.settings import settings
    scope = getattr(settings, "allowed_scope", "")
    if not scope:
        return True
    try:
        from vulnclaw.core.http_client import url_in_scope
        return bool(url_in_scope(url))  # 支持域名/子域/通配/CIDR/IP
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            f"🚫 [Sandbox] allowed_scope 校验异常 → fail-closed 拒绝执行: "
            f"{type(exc).__name__}: {exc}"
        )
        return False


def _sanitized_env(cwd: str) -> Dict[str, str]:
    """净化环境：仅保留运行必需项，并保证 UTF-8 输出（Windows GBK 防乱码）。"""
    keep = ("PATH", "SystemRoot", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT",
            "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS")
    env = {k: v for k, v in os.environ.items() if k in keep}
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["TMP"] = env["TEMP"] = cwd
    env["HOME"] = cwd
    env["CI"] = "1"
    return env


def _make_workdir() -> str:
    root = os.path.abspath(os.path.join(SBOX_ROOT, uuid.uuid4().hex[:12]))
    os.makedirs(root, exist_ok=True)
    return root


async def run_isolated(
    argv: List[str],
    *,
    workdir: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    timeout: int = SBOX_TIMEOUT,
    max_output: int = SBOX_MAX_OUTPUT,
) -> Dict[str, Any]:
    """执行隔离子进程（无 shell）。argv 为完整命令向量；返回结构化结果。"""
    if not argv or not argv[0]:
        return {"success": False, "blocked": True, "error": "空命令"}
    workdir = os.path.abspath(workdir or _make_workdir())
    env = env if env is not None else _sanitized_env(workdir)
    os.makedirs(workdir, exist_ok=True)
    started = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=workdir,
            env=env,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"success": False, "timeout": True, "backend": "process",
                    "error": f"isolated 执行超时 ({timeout}s)", "cmd": " ".join(argv),
                    "duration": round(time.time() - started, 2)}
        stdout = out.decode("utf-8", "ignore")
        stderr = err.decode("utf-8", "ignore")
        if len(stdout) > max_output:
            stdout = stdout[:max_output] + "\n...[output truncated]"
        if len(stderr) > 2048:
            stderr = stderr[:2048] + "\n...[stderr truncated]"
        return {
            "success": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "cmd": " ".join(argv),
            "backend": "process",
            "duration": round(time.time() - started, 2),
        }
    except Exception as exc:  # noqa: BLE001
        logger.debug("isolated 执行异常: %s", exc)
        return {"success": False, "error": str(exc), "backend": "process"}


async def run_python_script(
    code: str,
    *,
    target: str = "",
    verdict: str = "likely",
    timeout: int = SBOX_TIMEOUT,
    max_output: int = SBOX_MAX_OUTPUT,
) -> Dict[str, Any]:
    """把 PoC 作为临时 py 脚本在隔离区执行（SP1 主入口）。

    - 目标 URL 越界（allowed_scope）-> 拒绝执行
    - verdict=suspicious -> 不执行，返回 heuristic_only
    """
    if target and not _target_in_scope(target):
        return {"success": False, "blocked": True, "backend": "policy",
                "error": f"PoC 目标越界（allowed_scope 白名单外）: {target}"}
    policy = sandbox_policy_for(verdict)
    if not policy.get("execute"):
        return {"success": False, "blocked": True, "backend": "heuristic",
                "reason": policy.get("reason", ""), "heuristic_only": True}
    workdir = _make_workdir()
    script = os.path.join(workdir, "poc_" + uuid.uuid4().hex[:8] + ".py")
    with open(script, "w", encoding="utf-8") as f:
        f.write(code)
    argv = [sys.executable, script]
    return await run_isolated(argv, workdir=workdir, timeout=timeout, max_output=max_output)


async def run_command_argv(
    argv: List[str],
    *,
    target: str = "",
    verdict: str = "likely",
    timeout: int = SBOX_TIMEOUT,
    max_output: int = SBOX_MAX_OUTPUT,
) -> Dict[str, Any]:
    """命令向量版（无 shell）：仅允许脚本解释器类入口，其他一律拒绝。"""
    if target and not _target_in_scope(target):
        return {"success": False, "blocked": True, "backend": "policy",
                "error": f"PoC 目标越界（allowed_scope 白名单外）: {target}"}
    policy = sandbox_policy_for(verdict)
    if not policy.get("execute"):
        return {"success": False, "blocked": True, "backend": "heuristic",
                "reason": policy.get("reason", ""), "heuristic_only": True}
    if not argv:
        return {"success": False, "blocked": True, "error": "空命令"}
    base = os.path.splitext(os.path.basename(str(argv[0])))[0].lower()
    if base not in _ALLOWED_SCRIPT_BINS:
        return {"success": False, "blocked": True,
                "error": f"命令入口不在脚本解释器白名单: {base}"}
    workdir = _make_workdir()
    return await run_isolated(argv, workdir=workdir, timeout=timeout, max_output=max_output)


__all__ = [
    "docker_available", "sandbox_policy_for", "run_isolated",
    "run_python_script", "run_command_argv",
    "SBOX_TIMEOUT", "SBOX_MAX_OUTPUT",
]