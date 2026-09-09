# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 4 模块 5：实时监控 Dashboard。

FastAPI + WebSocket 实现：
- REST API: 获取扫描状态、漏洞列表、DAG 节点进度
- WebSocket: 实时推送扫描进度（延迟 < 1s）
- 静态文件: Vue.js 单页应用

启动: python -m dashboard.server --port 8080
"""
import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from vulnclaw.core.logger import logger
from enum import Enum
from vulnclaw.core.settings import PROJECT_CACHE_DIR, settings


class ScanEvent(str, Enum):
    """PGEN-EVENT: 状态总线事件类型——对齐 PentAGI 10 类事件模型
    (Flow/Task/AgentLog/TerminalLog/SearchLog/VectorStoreLog/ToolCallLog/Screenshot/AssistantLog/MessageLog)。

    VULNCLAW 本地无 Docker 终端/截图场景，terminal_log/screenshot 保留占位便于未来对齐；
    其余类型为扫描链路（ReAct 思考、工具调用、记忆读写、情报查询）按类型推送，TUI/Web/Tauri 共用。
    """
    FLOW = "flow"
    TASK = "task"
    AGENT_LOG = "agent_log"
    TERMINAL_LOG = "terminal_log"
    SEARCH_LOG = "search_log"
    VECTOR_STORE_LOG = "vector_store_log"
    TOOL_CALL_LOG = "tool_call_log"
    SCREENSHOT = "screenshot"
    ASSISTANT_LOG = "assistant_log"
    MESSAGE_LOG = "message_log"


_bus: Optional["DashboardServer"] = None


def set_event_bus(bus: "DashboardServer") -> None:
    """PGEN-EVENT: 注入全局状态总线实例（DashboardServer.start 时调用）。"""
    global _bus
    _bus = bus


async def emit_event(event_type: str, payload: Dict) -> None:
    """PGEN-EVENT: 扫描链路发射事件到状态总线。

    无 bus 实例（Dashboard 未启动）时静默 no-op，绝不阻塞/影响主扫描流程
    （对齐审计增强项"增强项绝不影响主流程"原则）。
    """
    if _bus is None:
        return
    try:
        await _bus.broadcast_event(event_type, payload)
    except Exception:  # noqa: BLE001
        pass


class DashboardServer:
    """FastAPI Dashboard 服务器。

    提供 REST API + WebSocket 实时推送。
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        redis_url: str = "redis://localhost:6379/0",
        prefix: str = "vulnclaw",
    ):
        """初始化 Dashboard 服务器。

        Args:
            host: 监听地址。
            port: 监听端口。
            redis_url: Redis 连接 URL（读取扫描状态）。
            prefix: Redis Key 前缀。
        """
        self.host = host
        self.port = port
        self._redis_url = redis_url
        self._prefix = prefix
        self._app = None
        self._ws_clients: Set[Any] = set()  # WebSocket 客户端集合
        self._broadcast_task = None
        self._redis = None
        self._token = getattr(settings, "dashboard_token", "") or ""
        # 合规收口：非回环绑定且未配置 token 时醒目告警
        _loopback = host in ("127.0.0.1", "localhost", "::1")
        if not _loopback and not self._token:
            logger.warning("🚨 [Dashboard] 绑定非回环地址且未配置 DASHBOARD_TOKEN，局域网内任何主机"
                           "都可查看扫描结果并远程发起扫描；建议仅本地使用或配置 token（.env DASHBOARD_TOKEN=xxx）")
        # Avoid re-attempting a broken Redis connection on every single
        # broadcast tick; the event loop gets blocked when each attempt
        # spends 1s on TCP RST. Backoff is reset as soon as any attempt
        # succeeds, so recovery is still fast.
        self._redis_backoff_until: float = 0.0
        self._redis_backoff_seconds: float = 10.0

        logger.info(f"📊 [Dashboard] 初始化: {host}:{port}")

    def _auth_ok(self, request) -> bool:
        """Token 鉴权：未配置 DASHBOARD_TOKEN 时全部放行（默认回环绑定）；配置后校验 header。"""
        if not self._token:
            return True
        return request.headers.get("X-Dashboard-Token", "") == self._token

    def create_app(self):
        """创建 FastAPI 应用。"""
        from fastapi import Body, FastAPI, Request, WebSocket, WebSocketDisconnect
        from fastapi.staticfiles import StaticFiles
        from fastapi.responses import HTMLResponse, JSONResponse

        app = FastAPI(title="VULNCLAW Dashboard", version="1.0.0")
        self._app = app

        # --- 静态文件 ---
        static_dir = Path(__file__).parent / "static"
        if static_dir.exists():
            app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

        # --- REST API ---

        @app.get("/", response_class=HTMLResponse)
        async def index():
            """首页：返回 Vue 单页应用。"""
            index_path = static_dir / "index.html"
            if index_path.exists():
                return index_path.read_text(encoding="utf-8")
            return "<h1>VULNCLAW Dashboard</h1><p>static/index.html not found</p>"

        @app.get("/api/status")
        async def api_status(request: Request):
            """获取集群状态。"""
            if not self._auth_ok(request):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            return await self._get_cluster_status()

        @app.get("/api/scans")
        async def api_scans(request: Request):
            """获取扫描列表。"""
            if not self._auth_ok(request):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            return await self._get_scans()

        @app.post("/api/scans")
        async def api_scans_create(request: Request, payload: Dict = Body(default={})):
            """发起新的扫描任务。"""
            if not self._auth_ok(request):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            return await self._start_scan(payload)

        @app.get("/api/scans/{scan_id}")
        async def api_scan_detail(request: Request, scan_id: str):
            """获取扫描详情。"""
            if not self._auth_ok(request):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            return await self._get_scan_detail(scan_id)

        @app.get("/api/findings")
        async def api_findings(request: Request, scan_id: str = None):
            """获取漏洞列表。"""
            if not self._auth_ok(request):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            return await self._get_findings(scan_id)

        @app.get("/api/dag/{scan_id}")
        async def api_dag(request: Request, scan_id: str):
            """获取 DAG 节点状态。"""
            if not self._auth_ok(request):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            return await self._get_dag_status(scan_id)

        @app.get("/api/workers")
        async def api_workers(request: Request):
            """获取 Worker 状态。"""
            if not self._auth_ok(request):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            return await self._get_workers()

        @app.get("/health")
        async def health() -> Dict[str, Any]:
            """Health endpoint used by health probes.

            Does NOT require Redis to be up: if Redis is unreachable the
            server itself is still considered live. Callers that need to
            assert Redis readiness should look at /api/status instead.
            """
            cluster = await self._get_cluster_status()
            workers_ok = cluster.get("status") != "redis_unavailable"
            return {
                "status": "ok",
                "service": "dashboard",
                "version": getattr(app, "version", "1.0.0"),
                "redis": "ok" if workers_ok else "unavailable",
                # NOTE: intentionally NOT time.time() here — the ZCode
                # auto-validation API compare uses byte-stable JSON bodies
                # across clients/cases; volatile timestamps would otherwise
                # cascade into spurious "body differs" reports.
                "ping": "pong",
            }

        @app.get("/metrics")
        async def metrics() -> str:
            """Minimal Prometheus-style metrics endpoint (text/plain)."""
            from fastapi import Response as _Resp

            cluster = await self._get_cluster_status()
            pending = int(cluster.get("pending_tasks", 0) or 0)
            completed = int(cluster.get("completed_tasks", 0) or 0)
            workers = int(len(cluster.get("worker_ids") or ()) if isinstance(
                cluster.get("worker_ids"), (list, tuple, set)) else 0)
            redis_up = 0 if cluster.get("status") == "redis_unavailable" else 1
            body = (
                "# HELP dashboard_workers Number of registered workers.\n"
                "# TYPE dashboard_workers gauge\n"
                f"dashboard_workers {workers}\n"
                "# HELP dashboard_pending_tasks Tasks waiting in queue.\n"
                "# TYPE dashboard_pending_tasks gauge\n"
                f"dashboard_pending_tasks {pending}\n"
                "# HELP dashboard_completed_tasks Completed tasks in result queue.\n"
                "# TYPE dashboard_completed_tasks gauge\n"
                f"dashboard_completed_tasks {completed}\n"
                "# HELP dashboard_redis_up Whether Redis backend is reachable.\n"
                "# TYPE dashboard_redis_up gauge\n"
                f"dashboard_redis_up {redis_up}\n"
            )
            return _Resp(content=body, media_type="text/plain; charset=utf-8")

        # --- WebSocket ---

        @app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket 实时推送端点。"""
            if self._token and websocket.query_params.get("token") != self._token:
                await websocket.close(code=4401)
                return
            await websocket.accept()
            self._ws_clients.add(websocket)
            logger.info(f"🔌 [Dashboard] WebSocket 客户端连接 (total={len(self._ws_clients)})")

            try:
                while True:
                    # 保持连接，接收客户端心跳
                    data = await websocket.receive_text()
                    if data == "ping":
                        await websocket.send_text("pong")
            except WebSocketDisconnect:
                self._ws_clients.discard(websocket)
                logger.info(f"🔌 [Dashboard] WebSocket 客户端断开 (total={len(self._ws_clients)})")

        return app

    async def broadcast_update(self, data: Dict) -> None:
        """向所有 WebSocket 客户端推送更新。

        Args:
            data: 要推送的数据字典。
        """
        if not self._ws_clients:
            return

        message = json.dumps(data, default=str, ensure_ascii=False)
        disconnected = set()

        for client in self._ws_clients:
            try:
                await client.send_text(message)
            except Exception:
                disconnected.add(client)

        # 清理断开的连接
        self._ws_clients -= disconnected

    async def broadcast_event(self, event_type: str, payload: Dict) -> None:
        """PGEN-EVENT: 结构化事件广播（对齐 PentAGI 事件模型）。

        封装 broadcast_update，统一带 event_type/timestamp，供扫描链路（ReAct 思考、
        工具调用、记忆读写、情报查询等）按 ScanEvent 类型推送，TUI/Web/Tauri 共用。
        """
        await self.broadcast_update({
            "type": str(event_type),
            "timestamp": time.time(),
            "data": payload,
        })

    async def _broadcast_loop(self) -> None:
        """定时推送扫描进度（每 500ms）。"""
        while True:
            try:
                status = await self._get_cluster_status()
                await self.broadcast_update({
                    "type": "status",
                    "timestamp": time.time(),
                    "data": status,
                })
            except Exception as exc:
                logger.warning(f"⚠️ [Dashboard] 推送异常: {exc}")

            await asyncio.sleep(0.5)  # 500ms 推送间隔，延迟 < 1s

    # --- 数据读取 ---

    async def _connect_redis(self):
        """连接 Redis。

        Uses explicit 1s socket+connect timeouts plus connection backoff so
        a missing local Redis never starves the event loop. Without this, the
        /health and /metrics endpoints (and every broadcast tick) kept
        re-triggering a 1s blocking-connect attempt, producing cascading
        read-timeouts on the HTTP side.
        """
        if self._redis is not None:
            return self._redis
        now = time.monotonic()
        if now < self._redis_backoff_until:
            return None
        try:
            import redis.asyncio as aioredis
            socket_timeout = 1.0  # fast-fail: Redis optional
            self._redis = aioredis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_timeout=socket_timeout,
                socket_connect_timeout=socket_timeout,
                retry_on_timeout=False,
                socket_keepalive=False,
                health_check_interval=0,
                single_connection_client=True,
            )
            await asyncio.wait_for(self._redis.ping(), timeout=socket_timeout)
        except Exception:
            self._redis = None
            self._redis_backoff_until = now + self._redis_backoff_seconds
            return None
        # Success: clear backoff so a later transient blip is retried promptly.
        self._redis_backoff_until = 0.0
        return self._redis

    async def _get_cluster_status(self) -> Dict:
        """获取集群状态。"""
        await self._connect_redis()
        if self._redis is None:
            return {"status": "redis_unavailable"}

        try:
            workers = await self._redis.smembers(f"{self._prefix}:workers")
            task_queue_len = await self._redis.llen(f"{self._prefix}:tasks")
            result_queue_len = await self._redis.llen(f"{self._prefix}:results")

            return {
                "workers": len(workers),
                "worker_ids": list(workers),
                "pending_tasks": task_queue_len,
                "completed_tasks": result_queue_len,
                "timestamp": time.time(),
            }
        except Exception as exc:
            return {"error": str(exc)}

    @staticmethod
    def _reports_dir() -> Path:
        """报告目录。"""
        return Path(PROJECT_CACHE_DIR) / "reports"

    def _load_report(self, scan_id: str) -> Optional[Dict]:
        """按 scan_id 加载报告 JSON。兼容带/不带 .json 后缀及 report_ 前缀。"""
        if not scan_id:
            return None
        reports_dir = self._reports_dir()
        candidates = [
            reports_dir / scan_id,
            reports_dir / f"{scan_id}.json",
            reports_dir / f"report_{scan_id}.json",
        ]
        path = next((c for c in candidates if c.is_file()), None)
        if path is None:
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.warning(f"⚠️ [Dashboard] 报告解析失败 {path.name}: {exc}")
            return None

    def _save_report(self, report: Dict, target: str, scan_id: str) -> Optional[Path]:
        """把扫描结果落盘为报告 JSON（供 /api/scans 等接口读取）。"""
        try:
            reports_dir = self._reports_dir()
            reports_dir.mkdir(parents=True, exist_ok=True)
            path = reports_dir / f"{scan_id}.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            return path
        except Exception as exc:
            logger.warning(f"⚠️ [Dashboard] 报告保存失败: {exc}")
            return None

    async def _get_scans(self) -> List[Dict]:
        """获取扫描列表（按报告文件修改时间倒序）。"""
        scans = []
        reports_dir = self._reports_dir()
        if not reports_dir.is_dir():
            return scans

        files = list(reports_dir.glob("report_*.json"))
        files += list(reports_dir.glob("web_*.json"))
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)

        for path in files[:100]:
            report = self._load_report(path.stem)
            if report is None:
                continue
            findings = report.get("vulnerabilities", [])
            scans.append({
                "scan_id": path.stem,
                "target": report.get("target", ""),
                "scan_time": report.get("scan_time", ""),
                "status": "completed",
                "elapsed_seconds": report.get("elapsed_seconds"),
                "total_tasks": report.get("total_tasks"),
                "processed_tasks": report.get("processed_tasks"),
                "findings_count": len(findings),
                "verified_findings": report.get("verified_findings", 0),
                "severity_stats": report.get("severity_stats", {}),
                "report_file": path.name,
            })
        return scans

    async def _get_scan_detail(self, scan_id: str) -> Dict:
        """获取扫描详情。"""
        report = self._load_report(scan_id)
        if report is None:
            return {"scan_id": scan_id, "status": "not_found",
                    "error": "报告不存在，扫描可能尚未完成"}
        return {
            "scan_id": scan_id,
            "target": report.get("target", ""),
            "status": "completed",
            "scan_time": report.get("scan_time", ""),
            "elapsed_seconds": report.get("elapsed_seconds"),
            "total_tasks": report.get("total_tasks"),
            "processed_tasks": report.get("processed_tasks"),
            "verified_findings": report.get("verified_findings", 0),
            "findings_count": len(report.get("vulnerabilities", [])),
            "severity_stats": report.get("severity_stats", {}),
            "tech_stack": report.get("tech_stack", []),
            "summary": report.get("summary", {}),
            "has_dag": "dag_profile" in report,
        }

    async def _get_findings(self, scan_id: str = None) -> List[Dict]:
        """获取漏洞列表。

        指定 scan_id 时返回该扫描的全部漏洞；
        未指定时聚合最近报告中的漏洞（每个条目补充 scan_id / id）。
        """
        if scan_id:
            report = self._load_report(scan_id)
            if report is None:
                return []
            findings = report.get("vulnerabilities", [])
            for i, finding in enumerate(findings):
                finding.setdefault("id", f"{scan_id}:{i}")
                finding.setdefault("scan_id", scan_id)
            return findings

        findings = []
        for scan in (await self._get_scans())[:20]:
            report = self._load_report(scan["scan_id"])
            if report is None:
                continue
            for i, finding in enumerate(report.get("vulnerabilities", [])):
                item = dict(finding)
                item.setdefault("id", f"{scan['scan_id']}:{i}")
                item.setdefault("scan_id", scan["scan_id"])
                findings.append(item)
        return findings

    async def _get_dag_status(self, scan_id: str) -> Dict:
        """获取 DAG 节点状态（优先读报告内 dag_profile，Redis 为扩展点）。"""
        report = self._load_report(scan_id)
        if report is None or "dag_profile" not in report:
            return {"scan_id": scan_id, "available": False, "nodes": []}

        dag = report["dag_profile"]
        nodes = []
        for node_id, info in (dag.get("nodes") or {}).items():
            nodes.append({
                "id": node_id,
                "type": info.get("type", node_id),
                "status": info.get("status", "unknown"),
                "retries": info.get("retries", 0),
                "duration_ms": info.get("duration_ms", 0),
            })
        return {
            "scan_id": scan_id,
            "available": True,
            "total_nodes": dag.get("total_nodes", len(nodes)),
            "status_counts": dag.get("status_counts", {}),
            "elapsed_seconds": dag.get("elapsed_seconds"),
            "nodes": nodes,
            "slowest_3_nodes": dag.get("slowest_3_nodes", []),
        }

    async def _start_scan(self, payload: Dict) -> Dict:
        """发起新的扫描任务（后台执行，完成后自动落盘报告）。"""
        target = (payload.get("target") or "").strip()
        if not target:
            return {"success": False, "error": "target 参数不能为空"}
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        max_tasks = payload.get("max_tasks")
        initial_qps = payload.get("initial_qps")
        scan_id = f"web_{int(time.time())}"

        async def _run():
            from vulnclaw.ai.v100 import run_v100_scan
            from vulnclaw.core.utils import get_shared_session, close_shared_session
            session = await get_shared_session(target=target)
            try:
                report = await run_v100_scan(
                    target=target,
                    session=session,
                    max_tasks=max_tasks,
                    initial_qps=initial_qps,
                )
            except Exception as exc:
                logger.error(f"❌ [Dashboard] 扫描失败 {scan_id} ({target}): {exc}")
                return
            finally:
                await close_shared_session()
            if isinstance(report, dict):
                saved = self._save_report(report, target, scan_id)
                logger.info(f"📄 [Dashboard] 扫描完成: {scan_id} → {saved or '报告保存失败'}")

        asyncio.create_task(_run())
        logger.info(f"📊 [Dashboard] 已提交扫描任务: {scan_id} → {target}")
        return {
            "success": True,
            "scan_id": scan_id,
            "target": target,
            "status": "running",
            "message": "扫描已后台启动，完成后的报告将出现在扫描列表中",
        }

    async def _get_workers(self) -> List[Dict]:
        """获取 Worker 状态列表。"""
        await self._connect_redis()
        if self._redis is None:
            return []

        try:
            worker_ids = await self._redis.smembers(f"{self._prefix}:workers")
            workers = []
            for wid in worker_ids:
                info = await self._redis.hgetall(f"{self._prefix}:worker:{wid}")
                workers.append({
                    "id": wid,
                    "status": info.get("status", "unknown"),
                    "last_heartbeat": info.get("last_heartbeat", ""),
                    "tasks_completed": info.get("tasks_completed", "0"),
                })
            return workers
        except Exception:
            return []

    async def start(self) -> None:
        """启动 Dashboard 服务器。"""
        import uvicorn

        app = self.create_app()

        # 启动推送循环
        self._broadcast_task = asyncio.create_task(self._broadcast_loop())

        logger.info(f"📊 [Dashboard] 启动: http://{self.host}:{self.port}")

        config = uvicorn.Config(
            app,
            host=self.host,
            port=self.port,
            log_level="info",
        )
        server = uvicorn.Server(config)
        await server.serve()

    async def stop(self) -> None:
        """停止 Dashboard。"""
        if self._broadcast_task:
            self._broadcast_task.cancel()
        if self._redis:
            await self._redis.close()
        logger.info("🛑 [Dashboard] 已停止")


def run_dashboard(host: str = "127.0.0.1", port: int = 8080):
    """CLI 入口：启动 Dashboard。"""
    server = DashboardServer(host=host, port=port)
    asyncio.run(server.start())


if __name__ == "__main__":
    import argparse

    _parser = argparse.ArgumentParser(description="VULNCLAW Dashboard server")
    _parser.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    _parser.add_argument("--port", type=int, default=8080, help="Bind port (default 8080)")
    _args = _parser.parse_args()
    run_dashboard(host=_args.host, port=_args.port)

