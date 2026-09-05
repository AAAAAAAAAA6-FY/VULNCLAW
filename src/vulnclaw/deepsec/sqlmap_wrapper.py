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
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

import aiohttp

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import get_tool_path
from urllib.parse import urlparse


def _invoke(tool_path: str) -> List[str]:
    """构造调用命令：.py 脚本用 python 解释器，否则直接可执行。

    get_tool_path 现在会把目录型 Python 工具（如 thirdparty/sqlmap/sqlmap.py）
    解析为脚本路径；Windows 下直接 exec .py 会失败，必须前置 python。
    """
    if tool_path and str(tool_path).endswith(".py"):
        return [sys.executable, tool_path]
    return [tool_path] if tool_path else []


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
            logger.debug("suppressed exception (core audit)")

    async def delete(self, taskid: str) -> None:
        """P4-4: 扫描结束后清理任务，避免服务端堆积。"""
        try:
            session = await self._session()
            await session.get(
                f"{self.base_url}/task/{taskid}/delete",
                timeout=aiohttp.ClientTimeout(total=5),
            )
        except Exception:  # noqa: BLE001
            logger.debug("suppressed exception (core audit)")

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
            inv = _invoke(sqlmapapi) or ["sqlmapapi"]
            cls._process = await asyncio.create_subprocess_exec(
                *inv,
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
                logger.debug("suppressed exception (core audit)")
            try:
                await asyncio.wait_for(cls._process.wait(), timeout=5)
            except Exception:  # noqa: BLE001
                try:
                    cls._process.kill()
                except Exception:  # noqa: BLE001
                    logger.debug("suppressed exception (core audit)")
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
        cmd = _invoke(sqlmap) + [
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
                # 解析数据库列表：优先本行内联（"available databases [N]: db1, db2"），
                # 否则收集后续形如 "[*] db1" / "[x] db2" / 2-3 空格缩进 + 名称 的行。
                _dbs: list[str] = []
                _, _, _inline = line.partition(":")
                if _inline.strip():
                    _dbs = [d.strip() for d in _inline.split(",") if d.strip()]
                else:
                    _lines = stdout.splitlines()
                    _idx = next(
                        (i for i, l in enumerate(_lines) if l.strip() == line),
                        -1,
                    )
                    for _nxt in _lines[_idx + 1:]:
                        _raw = _nxt
                        _s = _raw.strip()
                        if not _s or "available databases" in _s.lower():
                            continue
                        if _s.startswith(("[*] ", "[x] ")):
                            _dbs.append(_s.split("]", 1)[1].strip())
                        elif (
                            len(_raw) - len(_raw.lstrip()) in (2, 3)
                            and not _s.startswith("[")
                        ):
                            _dbs.append(_s)
                        else:
                            break
                if _dbs:
                    # 去重保序合并到结果
                    _seen = set(result["databases"])
                    for _d in _dbs:
                        if _d not in _seen:
                            _seen.add(_d)
                            result["databases"].append(_d)

        # 解析 JSON 结果文件（如果存在）
        raw = None
        if os.path.exists(output_file):
            try:
                raw = json.loads(open(output_file, "r", encoding="utf-8").read())
                result["raw"] = raw
            except (json.JSONDecodeError, OSError):
                raw = None
                logger.debug("suppressed exception (core audit)")

        # 解析 SQLMap JSON 结果。结构一：{"data": [{"url": ..., "value": {...}}]}；
        # 结构二：{db_name: {"tables": {tb: {"entries": [...]}}}}。缺失键/异常一律
        # 优雅降级：不抛异常、不破坏返回结构、不覆盖已有字段值。
        if isinstance(raw, dict):
            try:
                _items = raw.get("data") if isinstance(raw.get("data"), list) else None
                if _items:
                    for _item in _items:
                        _value = _item.get("value") if isinstance(_item, dict) else None
                        if not isinstance(_value, dict):
                            continue
                        if not result["banner"] and _value.get("banner"):
                            result["banner"] = str(_value["banner"])
                        _db = _value.get("current_db") or _value.get("db")
                        if not result["current_db"] and _db:
                            result["current_db"] = str(_db)
                        _user = _value.get("current_user") or _value.get("user")
                        if not result["current_user"] and _user:
                            result["current_user"] = str(_user)
                        _dbs = _value.get("databases")
                        if isinstance(_dbs, dict):
                            _dbs = list(_dbs)
                        if isinstance(_dbs, list):
                            for _d in _dbs:
                                if (
                                    isinstance(_d, str)
                                    and _d
                                    and _d not in result["databases"]
                                ):
                                    result["databases"].append(_d)
                        if not result["tables"] and isinstance(_value.get("tables"), dict):
                            result["tables"] = _value["tables"]
                        if not result["columns"] and isinstance(_value.get("columns"), dict):
                            result["columns"] = _value["columns"]
                        if not result["dump"]:
                            _dump = _value.get("dump")
                            if isinstance(_dump, list):
                                result["dump"] = _dump[:5]
                            elif isinstance(_dump, dict) and _dump:
                                result["dump"] = _dump
                            elif isinstance(_value.get("entries"), list):
                                result["dump"] = _value["entries"][:5]
                else:
                    # 结构二：顶层键即库名（含 tables / entries 元数据的键）
                    for _dbname, _meta in raw.items():
                        if not isinstance(_dbname, str) or not isinstance(_meta, dict):
                            continue
                        if "tables" not in _meta and "entries" not in _meta:
                            continue
                        if _dbname not in result["databases"]:
                            result["databases"].append(_dbname)
                        if not result["tables"] and isinstance(_meta.get("tables"), dict):
                            result["tables"] = _meta["tables"]
                        for _tb, _tmeta in (_meta.get("tables") or {}).items():
                            if (
                                isinstance(_tmeta, dict)
                                and isinstance(_tmeta.get("entries"), list)
                            ):
                                result["dump"][_tb] = _tmeta["entries"][:5]
            except Exception:  # noqa: BLE001
                logger.debug("suppressed exception (core audit)")

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
        import re as _re

        sqlmap = self._get_sqlmap_path()
        cmd = _invoke(sqlmap) + ["-u", url, "--batch", "--identify-waf"]

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
                # 用常见 WAF 特征关键词识别类型；无匹配时回退首个含 "WAF" 的行。
                _waf_kws = (
                    ("cloudflare", "cloudflare"),
                    ("akamai", "akamai"),
                    ("modsecurity", "modsecurity"),
                    ("big-ip", "f5 big-ip"),
                    ("f5", "f5"),
                    ("aws waf", "aws waf"),
                    ("amazon", "aws waf"),
                    ("imperva", "imperva"),
                    ("barracuda", "barracuda"),
                    ("safedog", "safedog"),
                    ("安全狗", "safedog"),
                    ("宝塔", "baota"),
                    ("btwaf", "baota"),
                    ("阿里云", "aliyun waf"),
                    ("aliyun", "aliyun waf"),
                    ("腾讯云", "tencent waf"),
                    ("tencent", "tencent waf"),
                    ("qianxin", "360 waf"),
                    ("360", "360 waf"),
                )
                _lower = output.lower()
                for _kw, _typ in _waf_kws:
                    if _kw.isascii():
                        _hit = _re.search(r"\b" + _re.escape(_kw) + r"\b", _lower)
                    else:
                        _hit = _kw in _lower
                    if _hit:
                        waf_type = _typ
                        break
                if not waf_type:
                    for line in output.splitlines():
                        if "WAF" in line:
                            waf_type = line.strip()
                            break
            return {"has_waf": has_waf, "waf_type": waf_type}
        except Exception:
            return {"has_waf": False, "waf_type": "", "error": "check failed"}

    async def confirm(
        self,
        url: str,
        parameter: str,
        data: str = None,
        method: str = "GET",
        level: int = 2,
        risk: int = 1,
        timeout: int = 120,
    ) -> Dict:
        """轻量注入确认（POC 级，不提取数据）：仅验证注入点是否存在。

        用于把引擎检出的 SQLi 升级为 sqlmap 实锤；失败不影响原检测结果。
        """
        sqlmap = self._get_sqlmap_path()
        cookie = self._get_cookie()
        cmd = _invoke(sqlmap) + [
            "-u", url,
            "--level", str(level),
            "--risk", str(risk),
            "--batch",
            "--timeout", "30",
        ]
        if parameter:
            cmd.extend(["-p", parameter])
        if method == "POST" and data:
            cmd.extend(["--data", data])
        if cookie:
            cmd.extend(["--cookie", cookie])
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
            out = (stdout or b"").decode(errors="replace")
            confirmed = ("is vulnerable" in out.lower()) or ("appears to be" in out.lower())
            return {
                "confirmed": confirmed,
                "parameter": parameter,
                "evidence": (out[-500:] if not confirmed else "sqlmap 确认注入点存在"),
            }
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"💉 [SQLMap] 轻量确认失败: {exc}")
            return {"confirmed": False, "parameter": parameter, "evidence": str(exc)}

    async def extract(
        self,
        url: str,
        parameter: str,
        data: str = None,
        method: str = "GET",
        timeout: int = 180,
    ) -> Dict:
        """SQLi 实锤后的最小化数据提取（只取数据库指纹，不导出业务数据表）。

        获取 DBMS banner / 当前库名 / 当前用户 / 是否 DBA，
        用于把“疑似注入”升级为“已验证可利用”，不做表数据 dump。
        """
        import re as _re

        sqlmap = self._get_sqlmap_path()
        cookie = self._get_cookie()
        cmd = _invoke(sqlmap) + [
            "-u", url,
            "--batch",
            "--level", "2",
            "--risk", "1",
            "--timeout", "30",
            "--banner",
            "--current-db",
            "--current-user",
            "--is-dba",
            "--union-check",
            "--tables",
        ]
        if parameter:
            cmd.extend(["-p", parameter])
        if method == "POST" and data:
            cmd.extend(["--data", data])
        if cookie:
            cmd.extend(["--cookie", cookie])

        def _grab(text: str, label: str) -> str:
            match = _re.search(label + r"\s*:?\s*'?([^\n']+)'?", text, _re.IGNORECASE)
            return match.group(1).strip() if match else ""

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
            out = (stdout or b"").decode(errors="replace")
            banner = _grab(out, "banner")
            current_db = _grab(out, "current database")
            current_user = _grab(out, "current user")
            is_dba = (
                "current user is dba: true" in out.lower()
                or "is dba: true" in out.lower()
            )
            # B4: --tables 仅取表名（不分页 dump 业务数据），并解析 UNION 回显位
            tables = self._parse_tables_only(out, current_db)
            union_pos = self._parse_union_position(out)
            return {
                "extracted": bool(banner or current_db or current_user),
                "banner": banner,
                "current_db": current_db,
                "current_user": current_user,
                "is_dba": is_dba,
                "tables": tables,
                "union_position": union_pos,
                "raw_tail": out[-600:],
            }
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[SQLMap] 数据提取失败: {exc}")
            return {"extracted": False, "evidence": str(exc)}




    def _parse_tables_only(self, out: str, current_db: str) -> List[str]:
        """从 sqlmap 输出解析数据库表名列表（仅表名，不涉及行/列数据）。"""
        import re as _re
        names: List[str] = []
        # sqlmap 表格输出形如: | Table      | ... 或 `[x table(s)]`
        for line in out.splitlines():
            if "table" not in line.lower():
                continue
            # 匹配 " | tablename | " 单元格
            cells = [c.strip() for c in line.split("|") if c.strip()]
            for cell in cells:
                if _re.fullmatch(r"[A-Za-z0-9_\-]+", cell) and len(cell) <= 64:
                    names.append(cell)
        # 去重保序
        seen = set()
        uniq = []
        for n in names:
            if n not in seen:
                seen.add(n)
                uniq.append(n)
        return uniq[:50]

    def _parse_union_position(self, out: str) -> str:
        """从 sqlmap 输出提取 UNION 回显位（如 'position: 2'）。"""
        import re as _re
        m = _re.search(r"position[^0-9]{0,4}([0-9]+)", out, _re.IGNORECASE)
        if m:
            return m.group(1)
        m = _re.search(r"column[^0-9]{0,4}([0-9]+)", out, _re.IGNORECASE)
        if m:
            return m.group(1)
        return ""

    async def enumerate_columns(
        self,
        url: str,
        parameter: str,
        data: str = None,
        method: str = "GET",
        db: str = "",
        timeout: int = 180,
    ) -> Dict:
        """B4: 列枚举 —— ORDER BY 二分探测列数 + UNION 冒烟回显位，不 dump 任何业务数据。

        验证注入面：通过 sqlmap 的 --columns -D <db> 仅枚举表列名（structure 而非数据）。
        为控制时间与流量，默认由调用方在已确认注入后主动触发（extract 不做 --columns，
        extract 只做 --tables 表名）。本方法供上层按需调用。
        """
        import re as _re
        sqlmap = self._get_sqlmap_path()
        cookie = self._get_cookie()
        cmd = _invoke(sqlmap) + [
            "-u", url,
            "--batch",
            "--level", "2",
            "--risk", "1",
            "--timeout", "30",
            "--columns",
            "--union-check",
        ]
        if db:
            cmd.extend(["-D", db])
        else:
            cmd.extend(["--current-db"])
        if parameter:
            cmd.extend(["-p", parameter])
        if method == "POST" and data:
            cmd.extend(["--data", data])
        if cookie:
            cmd.extend(["--cookie", cookie])

        def _grab_cols(text: str) -> List[str]:
            names: List[str] = []
            for line in text.splitlines():
                if "column" not in line.lower():
                    continue
                cells = [c.strip() for c in line.split("|") if c.strip()]
                for cell in cells:
                    if _re.fullmatch(r"[A-Za-z0-9_\-]+", cell) and len(cell) <= 64:
                        names.append(cell)
            seen = set()
            out = []
            for n in names:
                if n not in seen:
                    seen.add(n)
                    out.append(n)
            return out[:50]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
            out = (stdout or b"").decode(errors="replace")
            return {
                "extracted": bool(out.strip()),
                "columns": _grab_cols(out),
                "union_position": self._parse_union_position(out),
                "raw_tail": out[-800:],
            }
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[SQLMap] 列枚举失败: {exc}")
            return {"extracted": False, "evidence": str(exc)}


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
