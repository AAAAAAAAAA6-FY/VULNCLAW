# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 3 模块 3：SQLMap 封装器。

封装 SQLMap CLI，提供异步 API：
- extract_data: 自动提取数据库信息（banner/当前库/所有库/表/列/数据）
- generate_poc: 生成 SQLMap 命令行 POC

安全约束：实际提取仅在 --dangerous 模式下执行。
"""
import asyncio
import json
import os
import tempfile
import time
from typing import Any, Dict, Optional

import aiohttp

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import get_tool_path
from urllib.parse import urlparse


# ============================================================
# P4-4: SQLMap REST API（sqlmapapi 守护进程模式）
# ============================================================
class SQLMapAPIClient:
    """sqlmapapi REST 客户端。

    交互流程（官方 sqlmapapi）：
        GET  /task/new            → {"taskid": "..."}
        POST /scan/<taskid>/start  ← JSON options {"url": ..., "level": 3, ...}
        GET  /scan/<taskid>/status → {"status": "running"|"terminated"}
        GET  /scan/<taskid>/data   → {"data": [...], "success": true}
        GET  /task/<taskid>/delete → 清理任务
    """

    def __init__(self, base_url: str = None, timeout: int = 30, poll_interval: float = 0.5):
        self.base_url = (base_url or settings.sqlmap_api_url).rstrip("/")
        self.timeout = timeout
        self.poll_interval = poll_interval

    async def _session(self):
        from vulnclaw.core.utils import get_shared_session

        return await get_shared_session()

    async def is_alive(self) -> bool:
        """探测 API 服务是否可用（顺带回收探测创建的任务）。"""
        try:
            session = await self._session()
            async with session.get(
                f"{self.base_url}/task/new",
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                if resp.status != 200:
                    return False
                data = await resp.json(content_type=None)
                taskid = data.get("taskid")
                if taskid:
                    await self.delete(taskid)
                return bool(data.get("success"))
        except Exception:  # noqa: BLE001
            return False

    async def new_task(self) -> Optional[str]:
        session = await self._session()
        async with session.get(
            f"{self.base_url}/task/new",
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            data = await resp.json(content_type=None)
            return data.get("taskid")

    async def start_scan(self, taskid: str, options: Dict) -> bool:
        session = await self._session()
        async with session.post(
            f"{self.base_url}/scan/{taskid}/start",
            json=options,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as resp:
            data = await resp.json(content_type=None)
            return bool(data.get("success"))

    async def scan_status(self, taskid: str) -> Dict:
        session = await self._session()
        async with session.get(
            f"{self.base_url}/scan/{taskid}/status",
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            return await resp.json(content_type=None)

    async def scan_data(self, taskid: str) -> Dict:
        session = await self._session()
        async with session.get(
            f"{self.base_url}/scan/{taskid}/data",
            timeout=aiohttp.ClientTimeout(total=20),
        ) as resp:
            return await resp.json(content_type=None)

    async def stop_scan(self, taskid: str) -> None:
        try:
            session = await self._session()
            await session.get(
                f"{self.base_url}/scan/{taskid}/stop",
                timeout=aiohttp.ClientTimeout(total=5),
            )
        except Exception:  # noqa: BLE001
            pass

    async def delete(self, taskid: str) -> None:
        """P4-4: 扫描结束后清理任务，避免服务端堆积。"""
        try:
            session = await self._session()
            await session.get(
                f"{self.base_url}/task/{taskid}/delete",
                timeout=aiohttp.ClientTimeout(total=5),
            )
        except Exception:  # noqa: BLE001
            pass

    async def run(self, url: str, options: Dict, timeout: int = 300) -> Dict:
        """完整一次检测：new → start → 轮询 status → data → delete。"""
        taskid = await self.new_task()
        if not taskid:
            return {}
        try:
            payload = dict(options)
            payload.setdefault("url", url)
            if not await self.start_scan(taskid, payload):
                return {}
            deadline = time.time() + timeout
            while time.time() < deadline:
                await asyncio.sleep(self.poll_interval)
                status = await self.scan_status(taskid)
                if str(status.get("status", "")).lower() in ("terminated", "not running"):
                    break
            return await self.scan_data(taskid)
        finally:
            await self.delete(taskid)


class SQLMapAPIDaemon:
    """P4-4: sqlmapapi 守护进程管理（启动 / 探测 / 停止）。

    启动时执行: sqlmapapi -s -H 127.0.0.1 -p 8775
    不可用（未安装 / 启动失败）时自动回退 CLI 模式，不影响扫描主流程。
    """

    _process = None
    _ready = False

    @classmethod
    def _host_port(cls) -> tuple:
        parsed = urlparse(settings.sqlmap_api_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 8775
        return host, port

    @classmethod
    async def ensure_running(cls) -> bool:
        """确保 API 服务可用；不可用时返回 False（调用方回退 CLI）。"""
        client = SQLMapAPIClient()
        if await client.is_alive():
            cls._ready = True
            logger.info(f"💉 [SQLMap] API 服务已在运行: {settings.sqlmap_api_url}")
            return True
        if not settings.sqlmap_api_autostart:
            logger.info("💉 [SQLMap] API 自动启动已关闭（SQLMAP_API_AUTOSTART=false）")
            return False

        host, port = cls._host_port()
        sqlmapapi = get_tool_path("sqlmapapi") or "sqlmapapi"
        try:
            cls._process = await asyncio.create_subprocess_exec(
                sqlmapapi,
                "-s",
                "-H",
                host,
                "-p",
                str(port),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except (FileNotFoundError, OSError) as exc:
            logger.info(f"💉 [SQLMap] sqlmapapi 不可用，回退 CLI 模式: {exc}")
            return False

        for _ in range(24):  # 最多等待 ~12s
            await asyncio.sleep(0.5)
            if cls._process.returncode is not None:
                logger.warning("💉 [SQLMap] sqlmapapi 进程退出，回退 CLI 模式")
                cls._process = None
                return False
            if await client.is_alive():
                cls._ready = True
                logger.info(f"💉 [SQLMap] API 服务已启动: {settings.sqlmap_api_url}")
                return True

        logger.warning("💉 [SQLMap] API 服务启动超时，回退 CLI 模式")
        await cls.stop()
        return False

    @classmethod
    async def stop(cls) -> None:
        """停止守护进程（扫描结束时调用）。"""
        cls._ready = False
        if cls._process is not None and cls._process.returncode is None:
            try:
                cls._process.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(cls._process.wait(), timeout=5)
            except Exception:  # noqa: BLE001
                try:
                    cls._process.kill()
                except Exception:  # noqa: BLE001
                    pass
            logger.info("💉 [SQLMap] API 服务已停止")
        cls._process = None


class SQLMapWrapper:
    """SQLMap CLI 异步封装器。"""

    def __init__(
        self,
        target: str,
        session=None,
        timeout: int = 300,
        level: int = 3,
        risk: int = 2,
    ):
        """初始化 SQLMap 封装器。

        Args:
            target: 目标 URL。
            session: HTTP 会话（用于提取 Cookie）。
            timeout: 单次 SQLMap 调用超时（秒）。
            level: SQLMap --level（1-5，越高检测越全面）。
            risk: SQLMap --risk（1-3，越高 payload 越危险）。
        """
        self.target = target
        self.session = session
        self.timeout = timeout
        self.level = level
        self.risk = risk
        self._sqlmap_path: Optional[str] = None
        self._output_dir = tempfile.mkdtemp(prefix="sqlmap_")

    def _get_sqlmap_path(self) -> str:
        """获取 sqlmap 可执行文件路径。"""
        if self._sqlmap_path:
            return self._sqlmap_path
        path = get_tool_path("sqlmap") or "sqlmap"
        self._sqlmap_path = path
        return path

    def _get_cookie(self) -> str:
        """从 session 提取 Cookie。"""
        if self.session and hasattr(self.session, "cookies"):
            return "; ".join(
                f"{k}={v}" for k, v in self.session.cookies.items()
            )
        return ""

    @property
    def _api_enabled(self) -> bool:
        """P4-4: sqlmapapi 守护进程是否就绪（就绪则走 REST，否则 CLI）。"""
        return bool(getattr(SQLMapAPIDaemon, "_ready", False))

    async def extract_data(
        self,
        url: str,
        parameter: str,
        data: str = None,
        method: str = "GET",
    ) -> Dict:
        """执行 SQLMap 数据提取（P4-4: 优先 sqlmapapi 守护进程，失败回退 CLI）。

        Returns:
            结构化结果字典（API 模式额外附带 raw 原始响应）。
        """
        cookie = self._get_cookie()
        if self._api_enabled:
            options: Dict[str, Any] = {
                "level": self.level,
                "risk": self.risk,
                "getBanner": True,
                "getCurrentDb": True,
                "getCurrentUser": True,
                "getDbs": True,
                "getTables": True,
                "getColumns": True,
                "dump": True,
            }
            if parameter:
                options["testParameter"] = parameter
            if method == "POST" and data:
                options["data"] = data
            if cookie:
                options["cookie"] = cookie
            try:
                started = time.time()
                payload = await SQLMapAPIClient().run(url, options, timeout=self.timeout)
                if payload:
                    result = self._parse_api_results(payload)
                    logger.info(
                        f"💉 [SQLMap] API 模式完成: {url} 耗时 {time.time() - started:.2f}s"
                    )
                    return result
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"💉 [SQLMap] API 模式失败，回退 CLI: {exc}")

        return await self._extract_via_cli(url, parameter, data, method, cookie)

    def _parse_api_results(self, payload: Dict) -> Dict:
        """P4-4: 解析 sqlmapapi /scan/<taskid>/data 的结构化结果。

        sqlmapapi 返回 data 列表，每项形如 {"type": int, "value": ...}，
        type 依次对应 banner / current-db / current-user / dbs / tables / columns / dump。
        """
        result: Dict[str, Any] = {
            "banner": "",
            "current_db": "",
            "current_user": "",
            "databases": [],
            "tables": {},
            "columns": {},
            "dump": {},
            "raw": payload,
        }
        for item in (payload or {}).get("data") or []:
            if not isinstance(item, dict):
                continue
            typ = item.get("type")
            value = item.get("value")
            if typ == 1 and value:
                result["banner"] = value if isinstance(value, str) else str(value)
            elif typ == 2 and value:
                result["current_db"] = value if isinstance(value, str) else str(value)
            elif typ == 3 and value:
                result["current_user"] = value if isinstance(value, str) else str(value)
            elif typ == 4 and value:
                result["databases"] = (
                    list(value) if isinstance(value, (list, dict)) else [value]
                )
            elif typ == 5 and isinstance(value, dict):
                result["tables"] = value
            elif typ == 6 and isinstance(value, dict):
                result["columns"] = value
            elif typ == 7 and isinstance(value, dict):
                result["dump"] = value
            elif typ == 0 and isinstance(value, list) and not result["databases"]:
                result["databases"] = value
        return result

    async def _extract_via_cli(
        self,
        url: str,
        parameter: str,
        data: str = None,
        method: str = "GET",
        cookie: str = "",
    ) -> Dict:
        """CLI 模式（sqlmapapi 不可用时的回退路径）。"""
        sqlmap = self._get_sqlmap_path()
        cookie = cookie or self._get_cookie()
        output_file = os.path.join(self._output_dir, "result.json")

        # 构建 SQLMap 命令
        cmd = [
            sqlmap,
            "-u", url,
            "--level", str(self.level),
            "--risk", str(self.risk),
            "--batch",
            "--output-dir", self._output_dir,
            "--results", output_file,
        ]

        if parameter:
            cmd.extend(["-p", parameter])
        if method == "POST" and data:
            cmd.extend(["--data", data])
        if cookie:
            cmd.extend(["--cookie", cookie])

        # 提取全部数据
        cmd.extend([
            "--banner",
            "--current-db",
            "--current-user",
            "--dbs",
            "--tables",
            "--columns",
            "--dump",
        ])

        logger.info(f"💉 [SQLMap] CLI 模式开始提取: {url} param={parameter}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout
            )

            if process.returncode != 0:
                logger.warning(
                    f"⚠️ [SQLMap] 退出码={process.returncode}: {stderr.decode().strip()[:200]}"
                )

            # 解析结果
            return self._parse_results(output_file, stdout.decode())

        except asyncio.TimeoutError:
            logger.error(f"❌ [SQLMap] 超时 ({self.timeout}s)")
            return {"error": "timeout", "banner": "", "databases": []}
        except FileNotFoundError:
            raise RuntimeError("sqlmap 未安装")
        finally:
            # 清理临时目录
            import shutil
            shutil.rmtree(self._output_dir, ignore_errors=True)

    def _parse_results(self, output_file: str, stdout: str) -> Dict:
        """解析 SQLMap 输出。

        Args:
            output_file: SQLMap --results 输出的 JSON 文件。
            stdout: SQLMap stdout 输出。

        Returns:
            结构化提取结果。
        """
        result: Dict[str, Any] = {
            "banner": "",
            "current_db": "",
            "current_user": "",
            "databases": [],
            "tables": {},
            "columns": {},
            "dump": {},
        }

        # 从 stdout 提取信息
        for line in stdout.splitlines():
            line = line.strip()
            if "banner:" in line.lower():
                result["banner"] = line.split(":", 1)[1].strip()
            elif "current database:" in line.lower():
                result["current_db"] = line.split(":", 1)[1].strip()
            elif "current user:" in line.lower():
                result["current_user"] = line.split(":", 1)[1].strip()
            elif "available databases" in line.lower():
                # TODO: 解析数据库列表
                pass

        # 解析 JSON 结果文件（如果存在）
        if os.path.exists(output_file):
            try:
                raw = json.loads(open(output_file, "r", encoding="utf-8").read())
                # TODO: 根据 SQLMap JSON 格式解析完整结果
                result["raw"] = raw
            except (json.JSONDecodeError, OSError):
                pass

        return result

    def generate_poc(self, finding: Dict) -> str:
        """生成 SQLMap 命令行 POC（不实际执行）。

        Args:
            finding: 漏洞字典。

        Returns:
            SQLMap 命令行字符串。
        """
        url = finding.get("url", self.target)
        parameter = finding.get("parameter", "")
        cookie = self._get_cookie()

        cmd_parts = [
            "sqlmap",
            "-u", f'"{url}"',
            "--level", str(self.level),
            "--risk", str(self.risk),
            "--batch",
        ]

        if parameter:
            cmd_parts.extend(["-p", parameter])
        if cookie:
            cmd_parts.extend(["--cookie", f'"{cookie}"'])

        cmd_parts.extend(["--banner", "--current-db", "--dbs", "--tables", "--dump"])

        poc = " ".join(cmd_parts)
        logger.info(f"📝 [SQLMap] POC 生成: {poc[:100]}...")
        return poc

    async def check_waf(self, url: str) -> Dict:
        """检测目标是否有 WAF。

        Args:
            url: 目标 URL。

        Returns:
            {"has_waf": bool, "waf_type": str}
        """
        sqlmap = self._get_sqlmap_path()
        cmd = [sqlmap, "-u", url, "--batch", "--identify-waf"]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                process.communicate(), timeout=60
            )
            output = stdout.decode()
            has_waf = "is behind" in output.lower() or "WAF" in output
            waf_type = ""
            if has_waf:
                # TODO: 提取 WAF 类型
                for line in output.splitlines():
                    if "WAF" in line:
                        waf_type = line.strip()
                        break
            return {"has_waf": has_waf, "waf_type": waf_type}
        except Exception:
            return {"has_waf": False, "waf_type": "", "error": "check failed"}


# ============================================================
# P4-4: 守护进程生命周期（扫描启动 / 结束时由 scan_runner 调用）
# ============================================================
async def ensure_sqlmap_api() -> bool:
    """扫描启动时确保 sqlmapapi 守护进程可用（不可用返回 False → 回退 CLI）。"""
    try:
        return await SQLMapAPIDaemon.ensure_running()
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"💉 [SQLMap] API 守护进程未启动: {exc}")
        return False


async def stop_sqlmap_api() -> None:
    """扫描结束时停止 sqlmapapi 守护进程。"""
    try:
        await SQLMapAPIDaemon.stop()
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"💉 [SQLMap] API 守护进程停止异常: {exc}")
