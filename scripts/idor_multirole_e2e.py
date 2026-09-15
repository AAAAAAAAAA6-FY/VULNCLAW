#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IDOR/BOLA 多账号 E2E —— 双账号 mock 后端 + 多角色会话 + IDOREngine 检测。

合规与背景
----------
完全离线：mock 服务只起在 127.0.0.1 随机端口，模拟"跨账号水平越权(BOLA)"，
不触碰任何真实目标，因此无需 --authorized。服务端不落盘任何敏感数据，用完即关。

模拟语义
--------
  账号 alice(id=1)、bob(id=2)，各自持 `Authorization: Bearer <token>`。
  /api/profile/{id}：鉴权中间件校验 Bearer 令牌归属（无效令牌 → 401）。
    错误版(默认)：跨号访问 `/api/profile/{other_id}` 仍 200 返回对方资料
                  → 越权漏洞（模拟后端未做属主校验）。
    正确版(-c)   ：跨号访问返回 403 → 无越权（负例，验证不误报）。

检测链路
--------
  调用 IDOREngine 的顺序 ID 相邻越权(BOLA)证明入口 `scan()`：用 alice 会话
  请求 id=2（bob）资源，`_idor_other_user` 纯技术判定（无 LLM）比较"自己 vs
  对方"响应内容 → 检出跨账号越权。该入口天然离线，--no-ai 恒满足。
  另经 orchestrator.build_multi_role_sessions 装载 alice+bob 两个会话注入
  session_manager，验证多角色链路可跑（--roles 时补充跑 scan_with_roles）。

用法
----
  python scripts/idor_multirole_e2e.py        # 越权 mock → 应检出，退出码 0
  python scripts/idor_multirole_e2e.py -c     # 正确 mock → 不误报
  python scripts/idor_multirole_e2e.py --no-ai # CI 离线：跳过 LLM 验证分支
退出码：检出成功 0 / 检出失败 1；正确场景误报也返回 1。
"""
import argparse
import asyncio
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiohttp

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from vulnclaw.engines.auth_engines import IDOREngine  # noqa: E402


# ---------------------------------------------------------------------------
# 双账号 mock 资源服务
# ---------------------------------------------------------------------------
PROFILES = {
    "1": {"id": 1, "username": "alice", "email": "alice@example.com", "name": "Alice"},
    "2": {"id": 2, "username": "bob", "email": "bob@example.com", "name": "Bob"},
}
TOKENS = {"alice": "tok-alice-0001", "bob": "tok-bob-0002"}
OWNER = {"1": "alice", "2": "bob"}


class _MockHandler(BaseHTTPRequestHandler):
    correct = False  # 由 start_mock_server 覆盖

    def log_message(self, *args):  # 抑制握手/访问日志
        pass

    def _auth(self) -> Optional[str]:
        header = self.headers.get("Authorization") or ""
        if header.startswith("Bearer "):
            token = header[7:].strip()
            for uname, tok in TOKENS.items():
                if tok == token:
                    return uname
        return None

    def _send(self, status: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False)
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        m = re.match(r"^/api/profile/(\d+)/?$", self.path)
        if not m:
            self._send(404, {"error": "not found"})
            return
        uid = m.group(1)
        me = self._auth()
        if not me:
            self._send(401, {"error": "unauthorized"})
            return
        if uid not in PROFILES:
            self._send(404, {"error": "profile not found"})
            return
        if self.correct and OWNER[uid] != me:  # 正确版：跨号访问 → 403
            self._send(403, {"error": "forbidden"})
            return
        self._send(200, PROFILES[uid])  # 错误版：不做属主校验 → 越权


def start_mock_server(correct: bool = False, port: int = 0) -> Tuple[ThreadingHTTPServer, int]:
    """启动双账号 mock 服务，返回 (server, port)。调用方负责 shutdown。"""
    server = ThreadingHTTPServer(("127.0.0.1", port), _MockHandler)
    _MockHandler.correct = correct
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def mock_base_url(port: int) -> str:
    return f"http://127.0.0.1:{port}/api/profile/1"


# ---------------------------------------------------------------------------
# IDOR 检测
# ---------------------------------------------------------------------------
async def _run_seq_detect(base_url: str, token: str) -> List[Dict]:
    """顺序 ID 相邻越权(BOLA)证明：alice 会话请求 id=2（bob）资源 → 纯技术判定。"""
    engine = IDOREngine()
    async with aiohttp.ClientSession(headers={"Authorization": f"Bearer {token}"}) as sess:
        return await engine.scan(base_url, sess)


async def _run_with_roles(base_url: str, role_tokens: Dict[str, Dict], no_ai: bool = False) -> List[Dict]:
    """多角色链路补充：build_multi_role_sessions 装载 ≥2 会话 → scan_with_roles。"""
    from vulnclaw.core.auth.session_manager import SessionManager
    from vulnclaw.ai.v100.orchestrator import build_multi_role_sessions
    sm = SessionManager()
    sm._enabled_reload = False      # 本地 mock 不需要后台 Cookie 保鲜
    sm.set_auto_refresh(False)      # 401 不触发 Cookie 文件重载/重试
    build_multi_role_sessions(sm, role_tokens, domain="127.0.0.1")
    roles = sm.get_roles()
    engine = IDOREngine()
    if no_ai:
        # 离线确定性验证器：差异分数 + 敏感字段即判真（引擎同款 no-LLM 兜底）。
        async def _fake(url, roles, responses, diff, sensitive, rp=None):
            if diff > 0.4 and sensitive:
                return {"is_idor": True, "confidence": "中", "severity": "High",
                        "evidence": "离线判定：差异大且含敏感数据", "privilege_violation": "水平越权",
                        "recommendation": "服务端校验属主关系"}
            return {"is_idor": False, "confidence": "低", "evidence": "离线未确认",
                    "privilege_violation": "无"}
        engine._ai_verify_idor = _fake  # type: ignore[assignment]
    try:
        return await engine.scan_with_roles(base_url, roles, sm)
    finally:
        await sm.close_all()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="IDOR/BOLA 多账号 E2E（本地 mock，离线）")
    ap.add_argument("--port", type=int, default=0, help="mock 端口（默认随机）")
    ap.add_argument("-c", "--correct", action="store_true", help="启用正确版对比（负例）")
    ap.add_argument("--no-ai", action="store_true", help="跳过 LLM 验证分支（CI 离线）")
    ap.add_argument("--roles", action="store_true", help="补充跑 scan_with_roles 多角色链路")
    args = ap.parse_args(argv)

    server, port = start_mock_server(correct=args.correct, port=args.port)
    base = mock_base_url(port)
    role_tokens = {"alice": {"authorization": TOKENS["alice"]},
                   "bob": {"authorization": TOKENS["bob"]}}
    try:
        findings = asyncio.run(_run_seq_detect(base, TOKENS["alice"]))
        roles_findings: List[Dict] = []
        if args.roles:
            roles_findings = asyncio.run(_run_with_roles(base, role_tokens, no_ai=args.no_ai))

        print("=" * 60)
        print(f"  target : {base}")
        print(f"  roles  : alice(id=1) / bob(id=2)")
        print(f"  mode   : {'正确版(负例)' if args.correct else '越权mock(正例)'}")
        if not args.correct:
            print("  finding: " + (findings[0]['type'] if findings else "<无>"))
            for f in findings:
                print(f"    · {f['type']} @ {f['url']}  parm={f['parameter']} "
                      f"sev={f['severity']} conf={f['confidence']}")
                print(f"      evidence: {f['evidence'][:120]}")
        if args.roles:
            print(f"  scan_with_roles finding: {len(roles_findings)}"
                  + (f"（type={roles_findings[0]['type']}）" if roles_findings else "（无，水平隔离响应趋同）"))
        print("=" * 60)

        found = len(findings) > 0
        if args.correct:
            ok = not found            # 正确版：不误报才成功
        else:
            ok = found                # 越权版：检出才成功
        print(f"  结果: {'✅ 符合预期' if ok else '❌ 不符合预期'} "
              f"({'检出' if found else '无finding'})")
        return 0 if ok else 1
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())