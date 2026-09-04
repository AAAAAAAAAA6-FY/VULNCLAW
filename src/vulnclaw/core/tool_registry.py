# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/tool_registry.py
"""
统一工具注册表 - 基于 thirdparty/tools.yaml 配置
"""
import asyncio
import json
import re
import subprocess
import os
import shutil
import time
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional

from vulnclaw.config.settings import settings
from vulnclaw.core.logger import logger
from vulnclaw.core.utils import get_tool_path

TOOLS_CONFIG_PATH = Path(settings.thirdparty_dir) / "tools.yaml"
TOOLS_AUTO_CONFIG_PATH = TOOLS_CONFIG_PATH.with_name("tools_auto.yaml")
THIRDPARTY_PATH = TOOLS_CONFIG_PATH.parent
CONFIG_TTL = 60
_CONFIG_CACHE: Dict[str, Any] = {}
_PATH_CACHE: Dict[str, Optional[str]] = {}
_CAPABILITY_CACHE: Dict[str, Dict[str, Any]] = {}

# A5.5: 工具失败替代链——主工具缺失/失败时附降级路径（信息性，不改变 success 语义）
_TOOL_FALLBACKS: Dict[str, str] = {
    "nuclei": "本地规则引擎（vulnclaw 30 检测引擎）",
    "ffuf": "本地目录枚举（engines 目录引擎）",
    "subfinder": "本地被动子域（crt.sh / DNS 查询）",
    "waybackurls": "本地 URL 收集（gau/wayback API 直连）",
    "gau": "本地 URL 收集（Wayback CDX API 直连）",
    "naabu": "本地端口扫描（python-socket 探测）",
    "nmap": "本地端口扫描（python-socket 探测）",
    "katana": "本地爬虫（aiohttp 链接提取）",
    "dalfox": "本地 XSS 引擎（xss_echo 规则）",
}
# 工具调用统计（成功/失败/降级），供 Agent 成功率排序与审计
_TOOL_CALL_STATS: Dict[str, Dict[str, int]] = {}

# G5: 危险操作三级分级（read 只读 / write 写 / destructive 破坏性）
# 默认所有工具为 read（不阻断正常扫描）；仅显式标记的高危工具升级级别。
# deny 模式下 write/destructive 默认拦截，需对应开关（DANGER_LEVEL_WRITE_ALLOW /
# DANGER_LEVEL_DESTRUCTIVE_ALLOW）或 DANGEROUS_MODE=allow 才放行。
_DANGER_LEVELS: Dict[str, str] = {
    "msf": "destructive",
    "msfconsole": "destructive",
    "metasploit": "destructive",
    "exploit": "destructive",
}
_LEVEL_RANK = {"read": 0, "write": 1, "destructive": 2}


def grade_danger_op(op_name: str) -> str:
    """G5: 返回操作危险级别（read/write/destructive）。未知工具默认 read（不阻断扫描）。"""
    return _DANGER_LEVELS.get((op_name or "").lower(), "read")


def is_danger_allowed(level: str) -> bool:
    """G5: 依据 settings 判断该危险级别当前是否允许执行。"""
    if level == "read":
        return True
    if level == "write":
        return bool(settings.danger_level_write_allow or settings.dangerous_mode == "allow")
    if level == "destructive":
        return bool(settings.danger_level_destructive_allow or settings.dangerous_mode == "allow")
    return True


def record_tool_result(name: str, success: bool, degraded: bool = False) -> None:
    """A5.5: 记录工具调用结果（成功/失败/降级）。"""
    stats = _TOOL_CALL_STATS.setdefault(name, {"success": 0, "failure": 0, "degraded": 0})
    stats["success" if success else "failure"] += 1
    if degraded:
        stats["degraded"] += 1


def get_tool_stats(name: str = None) -> Dict[str, Any]:
    """A5.5: 读取工具调用统计。"""
    if name:
        return dict(_TOOL_CALL_STATS.get(name, {}))
    return {k: dict(v) for k, v in _TOOL_CALL_STATS.items()}


def _attach_fallback(name: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """A5.5: 失败结果附降级说明（信息性提示，不改变 success 语义）。"""
    fb = _TOOL_FALLBACKS.get(name)
    if fb:
        result["fallback"] = fb
        result["fallback_hint"] = f"{name} 不可用时降级为: {fb}"
    return result


def _finalize_failure(name: str, error: str, returncode: int = -1, cmd: str = "") -> Dict[str, Any]:
    """A5.5: 统一构造失败结果：记录统计 + 附降级说明。"""
    record_tool_result(name, False)
    result = {"success": False, "error": error, "returncode": returncode, "cmd": cmd}
    return _attach_fallback(name, result)


def _read_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.warning(f"⚠️ 加载工具配置失败 {path.name}: {exc}")
        return {}


def _write_auto_config(tools: Dict[str, Any]) -> None:
    try:
        with open(TOOLS_AUTO_CONFIG_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump({"tools": tools}, f, allow_unicode=True, sort_keys=True)
    except OSError as exc:
        logger.warning(f"⚠️ 写入自动工具配置失败: {exc}")


def _executable_candidates(path: Path) -> bool:
    if not path.is_file():
        return False
    if os.name == "nt":
        return path.suffix.lower() in {".exe", ".bat", ".cmd", ".com"}
    return path.suffix == "" and os.access(path, os.X_OK)


def discover_auto_tools() -> Dict[str, Any]:
    """扫描 thirdparty 并合并新增/变动的可执行文件，不覆盖 tools.yaml 条目。"""
    auto_data = _read_yaml(TOOLS_AUTO_CONFIG_PATH)
    auto_tools = auto_data.get("tools", {})
    configured = _read_yaml(TOOLS_CONFIG_PATH).get("tools", {})
    changed = False

    if THIRDPARTY_PATH.exists():
        for executable in THIRDPARTY_PATH.rglob("*"):
            if not _executable_candidates(executable):
                continue
            name = executable.stem
            if name in configured:
                continue
            fingerprint = f"{executable.stat().st_size}:{executable.stat().st_mtime_ns}"
            current = auto_tools.get(name, {})
            if current.get("executable") != str(executable) or current.get("fingerprint") != fingerprint:
                auto_tools[name] = {
                    "executable": str(executable),
                    "default_args": "",
                    "timeout": 60,
                    "output_format": "text",
                    "output_file": False,
                    "fingerprint": fingerprint,
                }
                changed = True

    if changed or not TOOLS_AUTO_CONFIG_PATH.exists():
        _write_auto_config(auto_tools)
    return auto_tools


def _load_config_file(path: Path) -> Dict[str, Any]:
    key = str(path)
    now = time.monotonic()
    cached = _CONFIG_CACHE.get(key)
    if cached and now - cached["time"] < CONFIG_TTL:
        return cached["data"]
    data = _read_yaml(path).get("tools", {})
    _CONFIG_CACHE[key] = {"time": now, "data": data}
    return data


def load_tool_config(name: str) -> Optional[Dict[str, Any]]:
    """优先从 tools.yaml 读取，未找到时读取 tools_auto.yaml。"""
    config = _load_config_file(TOOLS_CONFIG_PATH).get(name)
    if config is not None:
        return config
    return _load_config_file(TOOLS_AUTO_CONFIG_PATH).get(name)


def resolve_tool_path(name: str) -> Optional[str]:
    """解析工具路径，并缓存结果。"""
    if name in _PATH_CACHE:
        return _PATH_CACHE[name]
    path = name if os.path.isabs(name) and os.path.isfile(name) else get_tool_path(name)
    if not path and os.path.isfile(str(THIRDPARTY_PATH / name)):
        path = str(THIRDPARTY_PATH / name)
    _PATH_CACHE[name] = path
    return path


def _probe_capabilities(tool_path: str) -> Optional[Dict[str, Any]]:
    """通过帮助/version 输出建立轻量能力指纹。"""
    fingerprint = f"{tool_path}:{os.path.getmtime(tool_path)}"
    cached = _CAPABILITY_CACHE.get(fingerprint)
    if cached is not None:
        return cached
    for probe in (["-help"], ["-h"], ["-version"]):
        try:
            proc = subprocess.run(
                [tool_path] + probe,
                capture_output=True,
                text=True,
                timeout=5,
                encoding="utf-8",
                errors="ignore",
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        output = f"{proc.stdout}\n{proc.stderr}".lower()
        if proc.returncode == 0 or output.strip():
            capabilities = {
                "json": "json" in output,
                "silent": "silent" in output or "quiet" in output,
                "timeout": "timeout" in output,
                "output_file": any(v in output for v in ("output", " -o", "outfile")),
                "probe": probe[0],
            }
            _CAPABILITY_CACHE[fingerprint] = capabilities
            return capabilities
    return None


async def _discover_tool(name: str) -> Optional[Dict[str, Any]]:
    """发现并登记未配置工具（探针 subprocess 已 offload 到线程池，不阻塞事件循环）。"""
    tool_path = resolve_tool_path(name)
    if not tool_path:
        return None
    # 无损加速：-help/-version 探针是同步 subprocess（最坏 3×5s），
    # 直接在 async 上下文里跑会阻塞整个事件循环，这里扔进线程池。
    capabilities = await asyncio.to_thread(_probe_capabilities, tool_path)
    if capabilities is None:
        return None
    config = {
        "executable": tool_path,
        "default_args": "",
        "timeout": 60,
        "output_format": "json" if capabilities["json"] else "text",
        "output_file": capabilities["output_file"],
        "capabilities": capabilities,
    }
    auto_tools = _load_config_file(TOOLS_AUTO_CONFIG_PATH)
    auto_tools[name] = config
    _write_auto_config(auto_tools)
    _CONFIG_CACHE.pop(str(TOOLS_AUTO_CONFIG_PATH), None)
    return config


def _raw_command(name: str, args: List[str], timeout: int) -> Dict[str, Any]:
    tool_path = resolve_tool_path(name) or shutil.which(name)
    cmd = [tool_path or name] + args
    cmd_str = " ".join(cmd)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="ignore",
        )
        return {
            "success": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "cmd": cmd_str,
            "output": proc.stdout or "",
            "output_file": None,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Timeout after {timeout}s", "returncode": -1, "cmd": cmd_str}
    except OSError as exc:
        return {"success": False, "error": str(exc), "returncode": -1, "cmd": cmd_str}


# ============================================================
# P3-1: 沙箱执行层（strix 式 run_in_sandbox）—— 高危动作隔离执行
# 默认 local 后端（等同原 run_tool 行为，零隔离但集中审计）；配置
# sandbox_backend=docker 且 Docker 可用时，write/destructive 工具改走容器隔离执行。
# 默认关闭，开启即生效；docker 后端不可用时明确告警并降级 local。
# ============================================================

class SandboxUnavailableError(RuntimeError):
    """docker 后端不可用（未装 SDK / 守护进程未起 / 执行失败）。"""


async def _sandbox_local(cmd: List[str], timeout: int, stdin_text: Optional[str]):
    """local 后端：直接子进程执行（等价于原 run_tool 行为）。"""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin_text is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    if stdin_text is not None:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(stdin_text.encode("utf-8", errors="ignore")), timeout=timeout
        )
    else:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    return proc.returncode, stdout.decode("utf-8", errors="ignore"), stderr.decode("utf-8", errors="ignore")


async def _sandbox_docker(cmd: List[str], timeout: int, stdin_text: Optional[str],
                          image: Optional[str] = None):
    """docker 后端：一次性容器内执行（network_mode=none、无持久化），命令退出即销毁。"""
    try:
        import docker
    except ImportError:
        raise SandboxUnavailableError("未安装 docker SDK（pip install docker）")
    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:
        raise SandboxUnavailableError(f"Docker 守护进程不可用: {exc}")
    image = image or getattr(settings, "sandbox_image", "alpine:latest")
    try:
        container = client.containers.run(
            image,
            ["sh", "-c", " ".join(cmd)],
            network_mode="none",
            remove=True,
            detach=True,
            mem_limit=getattr(settings, "sandbox_mem_limit", "512m"),
        )
        exit_status = await asyncio.wait_for(
            asyncio.to_thread(container.wait, timeout=timeout), timeout=timeout
        )
        stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="ignore")
        stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="ignore")
        return exit_status, stdout, stderr
    except SandboxUnavailableError:
        raise
    except Exception as exc:
        raise SandboxUnavailableError(f"Docker 执行失败: {exc}")
    finally:
        try:
            client.containers.get(container.id).remove(force=True)
        except Exception:
            pass


async def sandbox_run(cmd: List[str], timeout: int, stdin_text: Optional[str] = None,
                     level: str = "read", backend: Optional[str] = None) -> tuple:
    """统一沙箱执行入口。

    - level=read：直接 local（无需隔离，省开销）。
    - level in (write,destructive)：若 settings.sandbox_enabled 且后端可用则隔离执行，
      否则退回 local。docker 后端不可用时明确告警并降级。
    backend 可显式指定（测试/未来协调器复用），None 时按 settings 推导。
    返回 (returncode, stdout, stderr)。
    """
    if backend is None:
        backend = "local"
        if level in ("write", "destructive") and getattr(settings, "sandbox_enabled", False):
            backend = getattr(settings, "sandbox_backend", "local")
    if backend == "docker":
        try:
            return await _sandbox_docker(cmd, timeout, stdin_text)
        except SandboxUnavailableError as exc:
            logger.warning(f"⚠️ [Sandbox] Docker 隔离不可用，降级 local: {exc}")
    return await _sandbox_local(cmd, timeout, stdin_text)


async def run_tool(
    name: str,
    args: Optional[List[str]] = None,
    timeout: Optional[int] = None,
    extra_args: Optional[List[str]] = None,
    stdin_text: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """统一工具调用入口（含工具治理层钩子）。

    治理三件事：运行前完整性抽检（供应链） / 运行后健康记录（降级依据）
    / 每次调用审计（tool_usage.jsonl）。所有治理钩子吞异常——
    治理层故障绝不影响工具执行本身。
    """
    import time

    started = time.time()
    gov = None
    try:
        from vulnclaw.core.tool_governance import get_governance

        gov = get_governance()
        gov.pre_run(name)
    except Exception:  # noqa: BLE001
        gov = None

    ok = False
    error = ""
    try:
        result = await _run_tool_impl(
            name, args=args, timeout=timeout, extra_args=extra_args,
            stdin_text=stdin_text, **kwargs
        )
        ok = bool(result.get("success"))
        error = str(result.get("error") or "")
        return result
    finally:
        if gov is not None:
            try:
                gov.post_run(
                    name, success=ok,
                    duration_ms=int((time.time() - started) * 1000),
                    error=error,
                )
            except Exception:  # noqa: BLE001
                pass


async def _run_tool_impl(
    name: str,
    args: Optional[List[str]] = None,
    timeout: Optional[int] = None,
    extra_args: Optional[List[str]] = None,
    stdin_text: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    统一工具调用入口

    Args:
        name: 工具名称（tools.yaml 中的 key）
        args: 自定义参数列表（覆盖默认）
        timeout: 超时时间（覆盖配置）
        extra_args: 额外追加的参数
        stdin_text: 需要写入子进程 stdin 的文本内容（如 httprobe 的域列表）

    Returns:
        {
            "success": bool,
            "stdout": str,
            "stderr": str,
            "returncode": int,
            "output": Any,  # 如果是 JSON 格式，自动解析
            "output_file": Optional[str],  # 输出文件路径
            "cmd": str  # 完整命令
        }
    """
    config = load_tool_config(name)

    # ===== G5: 危险操作三级分级（read/write/destructive）=====
    # write/destructive 在 deny 模式下默认拦截，需对应开关或 DANGEROUS_MODE=allow 放行。
    _op_level = grade_danger_op(name)
    if not is_danger_allowed(_op_level):
        return {
            "success": False,
            "error": (
                f"DangerGuard(G5) 拦截 {_op_level} 级操作: {name} "
                f"（需开启 DANGER_LEVEL_WRITE_ALLOW / DANGER_LEVEL_DESTRUCTIVE_ALLOW 或 DANGEROUS_MODE=allow）"
            ),
            "cmd": name,
            "returncode": -1,
        }

    # ===== 远程任务委派路由 =====
    # 若 .env 里 REMOTE_TASK_ROUTING 配置了该工具，优先尝试交给远程 AI Agent 执行。
    # 远程 Agent 执行等同于本地执行危险载荷，必须显式过 DangerGuard（默认 deny）。
    remote_agent_name = settings.remote_task_routing.get(name)
    if remote_agent_name is not None:
        from vulnclaw.core.danger_guard import guard
        detail = f"tool={name}, agent={remote_agent_name or '(first available)'}"
        if not guard.require_approval("remote_task_execution", detail):
            return {
                "success": False,
                "error": f"DangerGuard 拒绝远程任务委派: {detail}",
                "cmd": f"remote://{name}",
                "returncode": -1,
            }
        from vulnclaw.ai.remote_agents import delegate_task
        remote_payload = {
            "args": args,
            "extra_args": extra_args,
            "stdin_text": stdin_text,
            "kwargs": kwargs,
        }
        remote_result = await delegate_task(
            name=name, arguments=remote_payload, agent_name=remote_agent_name or None
        )
        if remote_result is not None:
            remote_result.setdefault("success", True)
            remote_result.setdefault("cmd", f"remote://{name}")
            return remote_result
        logger.info(f"🔁 [Tool] {name} 远程委派失败，回退本地执行")

    primary_config = _load_config_file(TOOLS_CONFIG_PATH).get(name)
    if config is None:
        config = await _discover_tool(name)
    if not config:
        # A5.5: 无配置（工具未安装）→ 附降级说明
        return _attach_fallback(name, await asyncio.to_thread(_raw_command, name, args or [], timeout or 60))

    # 解析工具路径
    tool_path = resolve_tool_path(config.get("executable", name))
    if not tool_path:
        # A5.5: 工具缺失 → 统一失败构造（记录统计 + 降级说明）
        return _finalize_failure(name, f"未找到工具: {name}")

    # 自动扫描得到的条目在首次调用时补充能力指纹（offload 线程池，不阻塞事件循环）。
    if primary_config is None and "capabilities" not in config:
        capabilities = await asyncio.to_thread(_probe_capabilities, tool_path)
        if capabilities is None:
            return _attach_fallback(
                name,
                await asyncio.to_thread(
                    _raw_command, name, (args or []) + (extra_args or []), timeout or 60
                ),
            )
        config["capabilities"] = capabilities
        config["output_format"] = "json" if capabilities["json"] else "text"
        config["output_file"] = capabilities["output_file"]
        auto_tools = _load_config_file(TOOLS_AUTO_CONFIG_PATH)
        auto_tools[name] = config
        _write_auto_config(auto_tools)
        _CONFIG_CACHE.pop(str(TOOLS_AUTO_CONFIG_PATH), None)

    # 合并参数
    default_args = config.get("default_args", "").split()
    if args is None:
        args = default_args.copy()
    else:
        args = default_args + args

    if extra_args:
        args.extend(extra_args)

    timeout = timeout or config.get("timeout", 60)
    output_format = config.get("output_format", "text")
    output_file_enabled = config.get("output_file", False)

    # 构建命令
    cmd = [tool_path] + args
    cmd_str = " ".join(cmd)

    logger.debug(f"🔧 [Tool] {name}: {cmd_str}")

    try:
        try:
            returncode, stdout_text, stderr_text = await sandbox_run(cmd, timeout, stdin_text, level=_op_level)
        except asyncio.TimeoutError:
            logger.warning(f"⏰ [Tool] {name} 超时 ({timeout}s)")
            return _finalize_failure(name, f"Timeout after {timeout}s", -1, cmd_str)

        result = {
            "success": returncode == 0,
            "returncode": returncode,
            "stdout": stdout_text[:5000] if len(stdout_text) > 5000 else stdout_text,
            "stderr": stderr_text[:500] if len(stderr_text) > 500 else stderr_text,
            "cmd": cmd_str,
            "output": None,
            "output_file": None
        }
        # A5.5: 统一记录调用结果；失败时附降级路径
        record_tool_result(name, result["success"])
        if not result["success"]:
            _attach_fallback(name, result)

        # 解析输出
        if output_format == "json" and stdout_text.strip():
            try:
                # 支持多行 JSON（每行一个 JSON 对象）
                if "\n" in stdout_text.strip():
                    result["output"] = [json.loads(line) for line in stdout_text.strip().split("\n") if line.strip()]
                else:
                    result["output"] = json.loads(stdout_text)
            except json.JSONDecodeError:
                logger.debug(f"⚠️ [Tool] {name} JSON 解析失败，按文本处理")
                result["output"] = stdout_text

        elif output_format == "text":
            result["output"] = stdout_text

        # 如果输出文件模式，尝试从 stderr 或命令行提取文件路径
        if output_file_enabled and not result["success"]:
            # 某些工具会把输出文件路径打印到 stderr
            file_match = re.search(r'[A-Za-z]:\\.+\.(json|txt|log)', stderr_text)
            if file_match:
                result["output_file"] = file_match.group(0)

        return result

    except Exception as e:
        logger.error(f"❌ [Tool] {name} 执行失败: {e}")
        return _finalize_failure(name, str(e), cmd=cmd_str)


def list_tools() -> List[str]:
    """列出所有已注册的工具"""
    tools = dict(_load_config_file(TOOLS_CONFIG_PATH))
    tools.update(_load_config_file(TOOLS_AUTO_CONFIG_PATH))
    return list(tools.keys())


discover_auto_tools()
