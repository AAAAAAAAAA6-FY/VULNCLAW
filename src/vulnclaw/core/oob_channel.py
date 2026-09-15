# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/oob_channel.py  (Z2.1)
"""
统一 OOB（Out-of-Band）带外通道客户端。

背景：0day/复杂漏洞的「盲打」判定需要可靠的带外回调证据。框架引擎（log4shell/
fastjson/struts2 等）此前只做带内回显判定，目标不回显就漏检。本模块把这些引擎
统一接入外带通道，提供：

  - token 申请：为每次注入生成唯一随机 token，可拼接成 OOB 地址
  - 通道分配：interactsh（DNS+HTTP）为主，dnslog.cn（HTTP）为备，均不可用返回 None
  - 回调查询：按 token 过滤，返回匹配的交互记录
  - 盲打判定：wait_for_interaction() 轮询直到出现该 token 的 DNS/HTTP 回调

设计原则（低误报）：
  - 只认「注册过的真实带外域名」发来的回调，绝不使用假域名（fake oast 域名会堵死降级链）。
  - 交互须精确匹配本次 token 才判定命中，避免历史/串台回调解读。
  - 纯本地驱动，interactsh-client 缺失时静默降级，不抛异常。
"""
import asyncio
import atexit
import json
import os
import re
import secrets
import tempfile
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

from vulnclaw.core.logger import logger
from vulnclaw.core.tool_registry import run_tool, load_tool_config, resolve_tool_path

# 缓存已申请的域名，避免同一 agent 反复申请
_DOMAIN_CACHE: Dict[str, str] = {}

# interactsh-client v1.3.x：会话文件缓存（域名 -> 会话文件），跨调用轮询复用
_INTERACTSH_SESSION: Dict[str, str] = {}

# interactsh 默认公共服务器后缀，用于从 payload/session/输出里揪出注册域名
_OAST_DOMAIN_RE = re.compile(
    r"([a-zA-Z0-9_-]{3,63}(?:\.[a-zA-Z0-9_-]+)*\."
    r"oast\.(?:pro|live|site|online|fun|me))"
)

# A1.2：自部署 interactsh server 作为第二主通道。
# 设置 OOB_INTERACTSH_SERVER（如 https://oob.example.com）后，所有 interactsh
# 注册/轮询均走该私有服务，摆脱公共 oast.me 的限流与单点故障；未设置则用公共服务器。
_OOB_INTERACTSH_SERVER = (os.environ.get("OOB_INTERACTSH_SERVER") or "").strip()


def validate_interactsh_server(server: Optional[str] = None) -> Dict[str, object]:
    """Validate the configured interactsh endpoint without making a network call.

    This is deliberately only a syntax/safety check.  A valid URL does not prove
    that an interactsh deployment is reachable or that callbacks will arrive.
    """
    from urllib.parse import urlsplit

    value = (server if server is not None else os.environ.get(
        "OOB_INTERACTSH_SERVER", "")).strip()
    if not value:
        return {"configured": False, "valid": True, "server": "", "error": ""}
    parsed = urlsplit(value)
    error = ""
    if parsed.scheme not in ("http", "https"):
        error = "must use http:// or https://"
    elif not parsed.hostname:
        error = "missing hostname"
    elif parsed.username or parsed.password:
        error = "credentials are not allowed"
    elif parsed.query or parsed.fragment:
        error = "query strings and fragments are not allowed"
    elif parsed.path not in ("", "/"):
        error = "path component is not supported"
    return {
        "configured": True,
        "valid": not error,
        "server": value,
        "error": error,
    }


def get_oob_diagnostics() -> Dict[str, object]:
    """Return offline OOB readiness information; never contacts an OOB service."""
    config = validate_interactsh_server()
    client = resolve_tool_path("interactsh-client")
    return {
        **config,
        "provider": "interactsh",
        "client_available": bool(client),
        "client_path": client or "",
        "network_checked": False,
        "callback_verified": False,
    }

# A1.3：支持的带外回调协议（LDAP/RMI/SMB/SMTP + 既有 DNS/HTTP）
_OOB_PROTOCOLS = ("ldap", "rmi", "smb", "smtp", "dns", "http", "https")


# ----------------------------------------------------------
# 本地 OOB 回环（reproduced 闭环，2026-09-14）
# ----------------------------------------------------------
# 场景：目标是本机/私网（自建靶场/内网演练）时，目标能回连 127.0.0.1——
# 本地监听器让"盲 SSRF / 盲命令注入"等 OOB 声明从"恒 0"变成可闭环证伪。
# 仅 HTTP 型回调（payload 形如 http://127.0.0.1:PORT/{token}）；外部目标回连
# 不到本机 → 调用方必须先用 maybe_enable_local_oob_for_target 判断来源。
class LocalOOBListener:
    """本机 HTTP 回调监听器：请求路径逐行写入 hits 文件，供 oracle 轮询。"""

    def __init__(self, hits_file: str):
        self.hits_file = hits_file
        self.port = 0
        self._srv = None

    def start(self) -> int:
        import http.server
        import threading
        hits = self.hits_file

        class _H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                try:
                    with open(hits, "a", encoding="utf-8") as fh:
                        fh.write(self.path + "\n")
                except OSError:
                    pass
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                try:
                    self.wfile.write(b"ok")
                except OSError:
                    pass

            def log_message(self, *args):
                return

        self._srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
        self.port = int(self._srv.server_address[1])
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self.port

    def stop(self) -> None:
        try:
            if self._srv is not None:
                self._srv.shutdown()
                self._srv.server_close()
        except Exception:  # noqa: BLE001
            pass


class LocalLDAPListener:
    """本机 LDAP/TCP 回调监听器（2026-09-15）：JNDI 型盲打回连闭环。

    Log4Shell / Fastjson 的 jndi:ldap://127.0.0.1:PORT/{token} 注入后，目标侧
    JNDI 解析会以原始 TCP 回连该端口并携带 token。监听器把连接首包（含 token）
    逐行写入与 HTTP 监听器共用的 hits 文件，`_oob_token_seen` 子串匹配即可闭环
    ——无需完整 LDAP 协议解码（低误报铁律：只有"目标真回连了本机端口"才算实锤）。
    """

    def __init__(self, hits_file: str):
        self.hits_file = hits_file
        self.port = 0
        self._srv = None

    def start(self) -> int:
        import socketserver
        import threading
        hits = self.hits_file

        class _H(socketserver.BaseRequestHandler):
            def handle(self):  # noqa: D401
                # JNDI LDAP 回连时序：首包是匿名 bind（不含 token），随后才是携带
                # 搜索 DN=token 的 search 请求。只读首包会漏 token → 累积读取至
                # 短窗口结束或连接关闭，把整段会话文本写入 hits 供子串匹配。
                import socket as _socket
                chunks = []
                try:
                    self.request.settimeout(0.6)
                    deadline = time.monotonic() + 1.5
                    while time.monotonic() < deadline and sum(len(c) for c in chunks) < 4096:
                        try:
                            data = self.request.recv(1024)
                        except _socket.timeout:
                            break
                        if not data:
                            break
                        chunks.append(data)
                except OSError:
                    pass
                try:
                    raw = b"".join(chunks)
                    line = raw.decode("utf-8", errors="replace").strip()
                    if line:
                        with open(hits, "a", encoding="utf-8") as fh:
                            fh.write("ldap " + line[:800] + "\n")
                except OSError:
                    pass
                finally:
                    try:
                        self.request.close()
                    except OSError:
                        pass

        self._srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _H)
        self.port = int(self._srv.server_address[1])
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self.port

    def stop(self) -> None:
        try:
            if self._srv is not None:
                self._srv.shutdown()
                self._srv.server_close()
        except Exception:  # noqa: BLE001
            pass


_LOCAL_LISTENER: Optional["LocalOOBListener"] = None
_LOCAL_LDAP_LISTENER: Optional["LocalLDAPListener"] = None
_LOCAL_HITS_FILE: str = ""
_LOCAL_LDAP_BASE: str = ""


def enable_local_oob() -> Optional[str]:
    """启动本地 OOB 监听并写入 settings.oob_base_url / oob_hits_file。

    幂等：重复调用复用同一监听器。返回 base_url（如 http://127.0.0.1:54321）。
    LDAP 监听器与 HTTP 共享 hits 文件；JNDI 盲打地址通过 `local_oob_ldap_base()`
    获取，外部目标回连不到本机 → 调用方必须先用 maybe_enable_local_oob_for_target
    判断来源（与 HTTP 回环同一约束）。
    """
    global _LOCAL_LISTENER, _LOCAL_LDAP_LISTENER, _LOCAL_HITS_FILE, _LOCAL_LDAP_BASE
    try:
        from vulnclaw.config import settings as _st
        if _LOCAL_LISTENER is None:
            fd, hits = tempfile.mkstemp(prefix="oob_hits_", suffix=".txt")
            os.close(fd)
            _LOCAL_LISTENER = LocalOOBListener(hits)
            _LOCAL_LISTENER.start()
            _LOCAL_HITS_FILE = hits
        if _LOCAL_LDAP_LISTENER is None:
            _LOCAL_LDAP_LISTENER = LocalLDAPListener(_LOCAL_HITS_FILE)
            _LOCAL_LDAP_LISTENER.start()
            _LOCAL_LDAP_BASE = f"ldap://127.0.0.1:{_LOCAL_LDAP_LISTENER.port}"
        base = f"http://127.0.0.1:{_LOCAL_LISTENER.port}"
        _st.oob_base_url = base
        _st.oob_hits_file = _LOCAL_HITS_FILE
        return base
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[OOB] 本地监听启动失败: {exc}")
        return None


def local_oob_ldap_base() -> str:
    """本地 LDAP 回环基址（如 ldap://127.0.0.1:54322）；未启用返回空串。"""
    return _LOCAL_LDAP_BASE


def local_oob_token_seen(token: str) -> bool:
    """本地回环命中判定：hits 文件逐行子串匹配 token（HTTP 路径 / LDAP 会话）。

    本地监听器把回调路径/会话文本逐行写入 settings.oob_hits_file；
    token 为随机 hex（≥8 字符），子串匹配无串台风险。
    """
    token = (token or "").strip().lower()
    if not token:
        return False
    try:
        from vulnclaw.config import settings as _st
        hits = str(getattr(_st, "oob_hits_file", "") or "").strip()
    except Exception:  # noqa: BLE001
        return False
    if not hits:
        return False
    try:
        with open(hits, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if token in line.lower():
                    return True
    except OSError:
        pass
    return False


async def wait_local_oob(token: str, timeout: int = 12) -> bool:
    """本地回环轮询等待：token 出现在 hits 文件即命中（零网络、纯本机）。"""
    deadline = time.monotonic() + max(1, timeout)
    while time.monotonic() < deadline:
        if local_oob_token_seen(token):
            return True
        await asyncio.sleep(0.5)
    return False


def local_oob_channel(token: str) -> str:
    """返回本地回环命中通道：'ldap'（TCP/JNDI 会话）/'http'（HTTP 路径）/''（未命中）。"""
    token = (token or "").strip().lower()
    if not token:
        return ""
    try:
        from vulnclaw.config import settings as _st
        hits = str(getattr(_st, "oob_hits_file", "") or "").strip()
    except Exception:  # noqa: BLE001
        return ""
    if not hits:
        return ""
    try:
        with open(hits, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if token not in line.lower():
                    continue
                return "ldap" if line.lstrip().lower().startswith("ldap") else "http"
    except OSError:
        pass
    return ""


def disable_local_oob() -> None:
    """停止本地 OOB 监听（hits 文件保留供事后审计）。"""
    global _LOCAL_LISTENER, _LOCAL_LDAP_LISTENER, _LOCAL_LDAP_BASE
    try:
        if _LOCAL_LDAP_LISTENER is not None:
            _LOCAL_LDAP_LISTENER.stop()
    except Exception:  # noqa: BLE001
        pass
    _LOCAL_LDAP_LISTENER = None
    _LOCAL_LDAP_BASE = ""
    try:
        if _LOCAL_LISTENER is not None:
            _LOCAL_LISTENER.stop()
    except Exception:  # noqa: BLE001
        pass
    _LOCAL_LISTENER = None


def maybe_enable_local_oob_for_target(target: str) -> Optional[str]:
    """目标为本机/私网时启用本地 OOB 回环；否则返回 None（绝不启用）。

    外部目标回连不到 127.0.0.1，启用只会让每个 OOB 声明白等等待秒数。
    """
    try:
        from urllib.parse import urlparse
        h = (urlparse(str(target or "")).hostname or "").lower()
        if not h:
            return None
        _local = h in ("localhost", "::1", "0.0.0.0") or h.startswith("127.")
        if not _local and (h.startswith("10.") or h.startswith("192.168.")):
            _local = True
        if not _local and h.startswith("172."):
            try:
                _local = 16 <= int(h.split(".")[1]) <= 31
            except Exception:  # noqa: BLE001
                _local = False
        if not _local:
            return None
        base = enable_local_oob()
        if base:
            logger.info(f"[OOB] 本地目标 → 启用本地 OOB 回环: {base}")
        return base
    except Exception:  # noqa: BLE001
        return None

# A1.4：OOB 回调证据链审计（进程内持久化 + 去重）
# 满足「token→interaction 落库，支持跨轮次复核、去重与事后审计」——
# 在单次扫描进程内累积全部回调，按 (token,protocol,time,from,raw) 去重，
# 供引擎/verify/报告侧事后审计，避免重复计数与串台误读。进程级单例，无需新建文件。
# 内存审计链封顶（P3-13，2026-09-15）：回调已逐条落盘 JSONL
# （_append_oob_evidence_jsonl），**磁盘是审计完整性的真源**；内存只保留最近
# N 条，防长时间扫大网时无界增长（不改审计语义，证据一条不丢）。
_OOB_AUDIT_MAX = 10000
_OOB_AUDIT: List["OOBInteraction"] = []
_OOB_AUDIT_SEEN: set = set()


# ----------------------------------------------------------
# P0：OOB 熔断器（通道级 + 目标级两层）
# ----------------------------------------------------------
# 问题：目标无出网能力 / 外发域被封禁（403）时，引擎仍逐个等待带外回调
# （framework 引擎 oob_wait=12s、wait_for_interaction 默认 15s，且每次
# poll 内部再挂 6s），大量任务空等占满 worker——实测一次 attack 阶段
# 545s 仅产出 2 个 finding，355 个任务被超时清空。
# 策略：
#   通道级：域名申请失败后短期熔断，避免每个引擎重复走 8s 注册流程；
#   目标级：连续 N 次「已注入 payload 但零回调」→ 判定外发被封禁，
#           后续跳过等待（返回空），把时间还给确定性检测。
# 熔断只影响"等待"，不写 finding、不断言漏洞——低误报铁律不变。
_OOB_CHANNEL_DOWN_UNTIL: float = 0.0      # 通道熔断截止（monotonic 秒）
_OOB_CHANNEL_DOWN_TTL: float = 300.0      # 通道熔断时长（秒）
_OOB_MISS_STREAK: Dict[str, int] = {}     # target -> 连续零回调次数
_OOB_HIT_COUNT: Dict[str, int] = {}       # target -> 历史回调命中次数
_OOB_MISS_THRESHOLD: int = 6              # 连续零回调触发阈值
_OOB_GLOBAL_TARGET = "*"                  # 无目标上下文时的兜底键

# 审计Q：interactsh 通道独立熔断。
# 国内网络常常连不上 oast 公共服务器，注册必然超时；而 request_domain 每次都
# 先试 interactsh 再降级 dnslog，等于每次白等 8s——真扫实证单次扫描累计失败
# 394 次 ≈ 空耗 3152s，比 nuclei 超时还狠。故连续失败达阈值即短期熔断。
_ITSH_DOWN_UNTIL: float = 0.0
_ITSH_FAIL_STREAK: int = 0
_ITSH_FAIL_THRESHOLD: int = 2
_ITSH_DOWN_TTL: float = 300.0


def _mark_itsh_failure() -> None:
    """审计Q：interactsh 注册失败累计 → 短期熔断，期间直接走 dnslog。"""
    global _ITSH_FAIL_STREAK, _ITSH_DOWN_UNTIL
    _ITSH_FAIL_STREAK += 1
    if _ITSH_FAIL_STREAK >= _ITSH_FAIL_THRESHOLD and time.monotonic() >= _ITSH_DOWN_UNTIL:
        _ITSH_DOWN_UNTIL = time.monotonic() + _ITSH_DOWN_TTL
        logger.info(
            f"[OOB] interactsh 连续失败 {_ITSH_FAIL_STREAK} 次 → 熔断 "
            f"{_ITSH_DOWN_TTL:.0f}s，期间直接走 dnslog（不再每次白等 8s）"
        )


def mark_channel_down(reason: str = "") -> None:
    """通道级熔断：带外通道不可用，TTL 内不再尝试申请域名。"""
    global _OOB_CHANNEL_DOWN_UNTIL
    _OOB_CHANNEL_DOWN_UNTIL = time.monotonic() + _OOB_CHANNEL_DOWN_TTL
    logger.info(f"[OOB] 通道熔断 {_OOB_CHANNEL_DOWN_TTL:.0f}s（{reason or '通道不可用'}）")


def is_channel_down() -> bool:
    """通道是否处于熔断期（熔断期间 request_domain 直接返回 None）。"""
    return time.monotonic() < _OOB_CHANNEL_DOWN_UNTIL


def channel_down_remaining() -> float:
    """通道熔断剩余秒数（0 = 未熔断）。"""
    return max(0.0, _OOB_CHANNEL_DOWN_UNTIL - time.monotonic())


def record_oob_result(target: str, hit: bool) -> None:
    """记录一次带外探测结果（hit=是否收到回调），驱动目标级熔断。"""
    key = (target or _OOB_GLOBAL_TARGET).strip().lower() or _OOB_GLOBAL_TARGET
    # 工作流8：OOB 命中率指标（hit/miss）
    try:
        from vulnclaw.core_modules.metrics import get_metrics
        get_metrics().inc_oob_event("hit" if hit else "miss")
    except Exception:  # noqa: BLE001 - 指标是增强项
        pass
    if hit:
        _OOB_HIT_COUNT[key] = _OOB_HIT_COUNT.get(key, 0) + 1
        _OOB_MISS_STREAK[key] = 0
        return
    _OOB_MISS_STREAK[key] = _OOB_MISS_STREAK.get(key, 0) + 1
    if _OOB_MISS_STREAK[key] == _OOB_MISS_THRESHOLD:
        logger.info(
            f"[OOB] 目标 {key} 连续 {_OOB_MISS_THRESHOLD} 次零回调 → 判定外发被封禁，"
            f"后续跳过带外等待（不影响确定性检测）"
        )


def is_oob_blocked(target: str) -> bool:
    """目标级熔断：该目标的外发回连是否已被判定为不可达。"""
    if is_channel_down():
        return True
    key = (target or _OOB_GLOBAL_TARGET).strip().lower() or _OOB_GLOBAL_TARGET
    if _OOB_MISS_STREAK.get(key, 0) >= _OOB_MISS_THRESHOLD:
        return True
    # 无目标上下文时以全局键兜底，避免漏判
    return _OOB_MISS_STREAK.get(_OOB_GLOBAL_TARGET, 0) >= _OOB_MISS_THRESHOLD


def oob_state_snapshot() -> Dict:
    """熔断器状态快照（供报告 / 覆盖账本 / 排障使用）。"""
    return {
        "channel_down": is_channel_down(),
        "channel_down_remaining_s": round(channel_down_remaining(), 1),
        "miss_threshold": _OOB_MISS_THRESHOLD,
        "miss_streak": dict(_OOB_MISS_STREAK),
        "hit_count": dict(_OOB_HIT_COUNT),
    }


def target_key_from_url(url: str) -> str:
    """从 URL 提取熔断用的目标键（netloc 小写；解析失败退化为整串小写）。

    粒度取 origin 级别：同一主机的不同路径共享熔断状态，否则每个 URL
    独立计数会导致熔断器永远达不到阈值。
    """
    try:
        from urllib.parse import urlparse
        return (urlparse(str(url or "")).netloc or str(url or "")).strip().lower()
    except Exception:  # noqa: BLE001 - URL 形态异常时按整串兜底
        return str(url or "").strip().lower()


def reset_oob_breaker() -> None:
    """重置 OOB 全部进程级状态（每次扫描开场调用）。

    清除目标级熔断计数、通道熔断、域名/会话缓存，避免跨扫描复用
    失效的 interactsh session 或残留 miss_streak 导致带外验证永久跳过。
    证据链 _OOB_AUDIT 保留（审计不可变原则），仅靠 token 去重防串台。
    """
    _OOB_MISS_STREAK.clear()
    _OOB_HIT_COUNT.clear()
    _DOMAIN_CACHE.clear()
    _INTERACTSH_SESSION.clear()
    global _OOB_CHANNEL_DOWN_UNTIL
    _OOB_CHANNEL_DOWN_UNTIL = 0.0


@dataclass
class OOBInteraction:
    """一条带外回调交互。"""
    token: str              # 触发方标识（子域名前缀）
    protocol: str           # dns / http / https
    tag: str = ""           # interactsh 返回的事件类型，如 dns / http
    time: str = ""          # 回调时间
    from_addr: str = ""     # 来源 IP（HTTP）
    raw_protocol: str = ""  # 原始协议首行
    extra: Dict = None      # 原始 JSON
    channel: str = ""       # SP14.3-B：解析出的通道 provider（interactsh/dnslog），随证据链传递

    def __post_init__(self):
        if self.extra is None:
            self.extra = {}
        if not self.time:
            self.time = time.strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self):
        return asdict(self)

    def evidence_view(self, channel: str = "") -> Dict:
        """SP14.3-B：结构化证据视图（接口约定，消费方 = A 线 evidence 组装）。

        返回固定四键，A 侧按 evidence.oob_* 直接展开写入 finding/报告：
          oob_ts      回调时间（ISO 风格字符串）
          oob_channel 通道标识 "provider:protocol"（provider ∈ interactsh/dnslog，
                      未解析时退化为 protocol）
          oob_token   触发回调的唯一 token（串台防护的关键字段）
          oob_detail  人读证据串（协议/来源/原始首行/extra 摘要，截断防膨胀）
        """
        chan = str(channel or "").strip() or self.channel or self.protocol
        return {
            "oob_ts": self.time,
            "oob_channel": f"{chan}:{self.protocol}",
            "oob_token": self.token,
            "oob_detail": self._detail_text(),
        }

    def _detail_text(self, max_chars: int = 200) -> str:
        parts = [f"{self.protocol} 回调", f"time={self.time}"]
        if self.from_addr:
            parts.append(f"from={self.from_addr}")
        if self.raw_protocol:
            parts.append(f"raw={self.raw_protocol}")
        if self.extra:
            try:
                parts.append(f"extra={json.dumps(self.extra, ensure_ascii=False)[:80]}")
            except (TypeError, ValueError):
                pass
        text = " | ".join(p for p in parts if p)
        return text[:max_chars]


def _new_token() -> str:
    """生成唯一 token（小写十六进制，14 位）。"""
    return secrets.token_hex(7)


class OOBChannel:
    """统一带外通道。

    用法（引擎内）：
        ch = OOBChannel()
        domain = await ch.request_domain()          # 获取带外根域名
        if not domain: return                      # 通道不可用 → 引擎自行降级/跳过
        token = ch.new_token()
        url = ch.interaction_url(token, "https")    # https://<token>.<domain>
        # ... 把 url 注入 payload ...
        await asyncio.sleep(1)
        if await ch.wait_for_interaction(token, timeout=15):
            # 实锤：收到该 token 的回调
    """

    def __init__(self, provider: str = "auto"):
        """
        provider:
          auto       = 自动选择：interactsh 可用则用它，否则 dnslog，否则 None
          interactsh = 强制 interactsh
          dnslog     = 强制 dnslog.cn
        """
        self.provider = provider
        # 审计N：记录上次轮询是否故障（超时/异常/通道错）。用于区分
        # "我们没问到（轮询失败）"与"目标确实没回连"——前者绝不能累加目标级
        # miss，否则通道故障会被误判成"目标外发被封禁"，在真实目标上会错误地
        # 永久关闭 OOB 检测（真扫实证：interactsh 参数不匹配 → 全部走 dnslog →
        # 连续 6 次零回调 → 误判封禁）。
        self._last_poll_error: Optional[str] = None
        # 审计O：interactsh 常驻订阅进程（该 client 无 -sf，无法"重启续会话"）
        self._itsh_proc = None
        self._itsh_buffer: List[OOBInteraction] = []
        self._itsh_reader_task = None
        self._itsh_payload_file: str = ""
        self._domain: Optional[str] = None
        self._resolved_provider: Optional[str] = None
        self._itsh_session_file: Optional[str] = None

    # ----------------------------------------------------------
    # 域名申请
    # ----------------------------------------------------------
    async def request_domain(self) -> Optional[str]:
        """申请一个带外根域名（线程安全，缓存复用）。"""
        if self._domain:
            return self._domain
        # P0 熔断：通道熔断期内不再重复申请（注册本身要 8s，失败会拖死 worker）
        if is_channel_down():
            return None
        if self.provider in ("auto", "interactsh"):
            d = await self._request_interactsh_domain()
            if d:
                self._domain, self._resolved_provider = d, "interactsh"
                _DOMAIN_CACHE["interactsh"] = d
                return d
            if self.provider == "interactsh":
                logger.warning("[OOB] interactsh 通道不可用，无降级。")
                return None
        if self.provider in ("auto", "dnslog"):
            d = await self._request_dnslog_domain()
            if d:
                self._domain, self._resolved_provider = d, "dnslog"
                return d
        logger.warning("[OOB] 所有带外通道均不可用（无 interactsh-client 且 dnslog 失败）。")
        # P0 熔断：全部通道申请失败 → 通道级熔断，避免后续每个引擎各走一遍 8s 注册
        mark_channel_down("所有带外通道申请失败")
        return None

    @staticmethod
    def _interactsh_server_args() -> List[str]:
        """A1.2：自部署 server 参数；未配置返回空列表（走公共服务器）。"""
        if _OOB_INTERACTSH_SERVER:
            return ["-server", _OOB_INTERACTSH_SERVER]
        return []

    async def _request_interactsh_domain(self) -> Optional[str]:
        """interactsh-client v1.3.x 注册带外域名（会话文件跨调用复用）。

        该版本无 print-and-exit / -poll/-domain 子命令：以「-json -sf <session> -psf
        <payload_store>」短超时启动，注册结果写入会话文件与 payload 文件；随后同一会话
        文件可再次启动以轮询回调。注册完成即返回 oast 域名。
        """
        # 审计Q：熔断期内不再尝试（避免每次注册白等 8s）
        if time.monotonic() < _ITSH_DOWN_UNTIL:
            logger.debug("[OOB] interactsh 短期熔断中，直接跳过（走 dnslog）")
            return None
        cached = _DOMAIN_CACHE.get("interactsh")
        if cached:
            self._itsh_session_file = _INTERACTSH_SESSION.get("interactsh")
            return cached
        if not resolve_tool_path("interactsh-client"):
            logger.info("[OOB] interactsh-client 未安装，跳过 interactsh 通道。")
            return None
        try:
            tag = secrets.token_hex(4)
            sf = os.path.join(tempfile.gettempdir(), f"itsh_{tag}.yaml")
            ps = os.path.join(tempfile.gettempdir(), f"itsh_{tag}_payload.txt")
            server_note = f" (server={_OOB_INTERACTSH_SERVER})" if _OOB_INTERACTSH_SERVER else ""
            logger.info(f"[OOB] 注册 interactsh 域名{server_note}")
            # 短超时注册：即便 8s 后被 kill，注册与会话在服务端持续有效
            # 审计O：去掉本机 client 不支持的 -sf / -nf（实测其 -h 只有
            # -server/-pi/-json/-psf；传 -sf/-nf 会打印 usage 并 exit 1，
            # 导致注册永远失败、OOB 被迫降级明文 dnslog）。
            result = await run_tool(
                "interactsh-client",
                args=self._interactsh_server_args()
                + ["-json", "-psf", ps, "-pi", "3"],
                timeout=8,
            )
            domain = self._extract_itsh_domain("", ps, result.get("stdout", ""))
            if domain:
                global _ITSH_FAIL_STREAK
                _ITSH_FAIL_STREAK = 0
                self._itsh_payload_file = ps
                _DOMAIN_CACHE["interactsh"] = domain
                logger.info(f"[OOB] 已注册 interactsh 域名: {domain}")
                # 该 client 无 -sf，回调只能靠常驻子进程订阅（见 _start_itsh_stream）
                await self._start_itsh_stream(ps)
                return domain
            err = result.get("stderr") or result.get("error") or ""
            logger.warning(f"[OOB] interactsh 注册未取到域名 rc={result.get('returncode', -1)} err={err[:200]}")
            _mark_itsh_failure()
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[OOB] interactsh 申请域名失败: {e}")
            _mark_itsh_failure()
        return None

    @staticmethod
    def _extract_itsh_domain(session_file: str, payload_file: str, stdout: str) -> Optional[str]:
        """从 payload 文件 / 会话文件 / 标准输出三处揪出注册的 oast 根域名。"""
        candidates = [stdout]
        for path in (payload_file, session_file):
            if path and os.path.exists(path):
                try:
                    with open(path, encoding="utf-8", errors="replace") as f:
                        candidates.append(f.read()[:2000])
                except OSError:
                    logger.debug("suppressed exception (core audit)")
        for text in candidates:
            m = _OAST_DOMAIN_RE.search(text or "")
            if m:
                return m.group(1)
        return None

    async def _request_dnslog_domain(self) -> Optional[str]:
        """dnslog.cn 备选通道（HTTP，无二进制依赖）。

        会话语义：dnslog.cn 用 cookie 把「session ↔ 当前域名」绑定，重复调用
        getdomain.php 会切换绑定并使旧域名下的记录不可查。故域名必须缓存复用
        （与 interactsh 通道一致）：否则引擎侧 get_interactsh_poll 新建 channel
        时会反复重新申请 → 共享 session 的 cookie 漂移 → 已注入 token 的回调
        永远查不到（真扫实证：auto 降级链 0 hits，显式 dnslog 3 hits）。
        """
        cached = _DOMAIN_CACHE.get("dnslog")
        if cached:
            return cached
        try:
            from vulnclaw.core.utils import get_shared_session
            import aiohttp
            session = await get_shared_session()
            url = "http://www.dnslog.cn/getdomain.php"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                text = await resp.text()
            text = (text or "").strip()
            if text and "." in text and " " not in text:
                _DOMAIN_CACHE["dnslog"] = text
                logger.info(f"[OOB] 已申请 dnslog 域名: {text}")
                return text
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[OOB] dnslog 申请失败: {e}")
        return None

    # ----------------------------------------------------------
    # token 与地址拼接
    # ----------------------------------------------------------
    @staticmethod
    def new_token() -> str:
        return _new_token()

    def require_domain(self) -> Optional[str]:
        return self._domain

    def interaction_url(self, token: str, scheme: str = "https") -> Optional[str]:
        """返回触发回调的 URL：<scheme>://<token>.<domain>/。无域名返回 None。"""
        if not self._domain:
            return None
        return f"{scheme}://{token}.{self._domain}/"

    def dns_label(self, token: str) -> Optional[str]:
        """返回用于 DNS 类注入的完整子域：<token>.<domain>。"""
        if not self._domain:
            return None
        return f"{token}.{self._domain}"

    # ----------------------------------------------------------
    # A1.3：多协议回调构造（LDAP/RMI/SMB/SMTP + 既有 DNS/HTTP）
    # 通道层统一支持这些协议的回调目标串；引擎据此构造对应 payload，
    # 目标一旦以任一协议回连 <token>.<domain>，interactsh 即记录该协议回调。
    # ----------------------------------------------------------
    def protocol_callback(self, token: str, proto: str) -> Optional[str]:
        """返回指定协议的带外回调目标串（供引擎构造 payload）。无域名返回 None。"""
        if not self._domain or not token:
            return None
        proto = str(proto).lower()
        if proto == "dns":
            return f"{token}.{self._domain}"
        if proto in ("http", "https"):
            return f"{proto}://{token}.{self._domain}/"
        if proto == "ldap":
            return f"ldap://{token}.{self._domain}/"
        if proto == "rmi":
            return f"rmi://{token}.{self._domain}/"
        if proto == "smtp":
            return f"{token}.{self._domain}"
        if proto == "smb":
            # UNC 路径形式：\\<token>.<domain>\share
            return f"\\\\{token}.{self._domain}\\share"
        return f"{token}.{self._domain}"

    def protocol_probes(self, token: str) -> Dict[str, str]:
        """返回全部支持协议的回调目标串，用于一次性发起多协议盲打。"""
        out: Dict[str, str] = {}
        for proto in _OOB_PROTOCOLS:
            cb = self.protocol_callback(token, proto)
            if cb:
                out[proto] = cb
        return out

    # ----------------------------------------------------------
    # 回调查询
    # ----------------------------------------------------------
    async def poll(self, timeout: int = 15) -> List[OOBInteraction]:
        """拉取所有回调（未过滤），并落入进程内审计链（A1.4）。无通道或失败返回空列表。"""
        items: List[OOBInteraction] = []
        if not self._domain:
            return items
        try:
            if self._resolved_provider == "interactsh":
                items = await self._poll_interactsh(timeout)
            elif self._resolved_provider == "dnslog":
                items = await self._poll_dnslog(timeout)
        except Exception as exc:  # noqa: BLE001
            # SP15-B 自证口径：任何回查异常（含超时/网络抖动）一律返回空，绝不抛错
            logger.debug(f"[OOB] poll 异常（忽略，返回空）: {exc}")
            # 审计N：标记轮询故障（见 wait_for_interaction 的统计口径）
            self._last_poll_error = str(exc)[:200]
            items = []
        if items:
            for _it in items:  # SP14.3-B：通道 provider 随证据链传递
                _it.channel = self._resolved_provider or _it.channel
        self.record_interactions(items)  # A1.4：回调证据链持久化 + 去重
        return items

    async def _poll_interactsh(self, timeout: int) -> List[OOBInteraction]:
        if not load_tool_config("interactsh-client"):
            return []
        if not self._itsh_session_file:
            self._itsh_session_file = _INTERACTSH_SESSION.get("interactsh")
        # 审计O：本机 interactsh-client 不支持 -sf（传它只会打印 usage 并 exit 1），
        # 旧"重启进程续会话"轮询彻底失效 → 改为消费常驻子进程累积的回调缓冲。
        if self._itsh_proc is None and not self._itsh_buffer:
            await self._start_itsh_stream(self._itsh_payload_file)
        if self._itsh_proc is None and not self._itsh_buffer:
            logger.debug("[OOB] interactsh 常驻订阅未就绪，本次无回调")
            return []
        if not self._itsh_buffer:
            # 给常驻进程一点时间收回调（受 timeout 约束，绝不空转）
            await asyncio.sleep(min(1.5, max(0.3, timeout * 0.2)))
        out = list(self._itsh_buffer)
        self._itsh_buffer.clear()
        return out

    # ----------------------------------------------------------
    # 审计O：interactsh 常驻订阅（替代不支持的 -sf 续会话机制）
    # ----------------------------------------------------------
    async def _start_itsh_stream(self, payload_file: str) -> None:
        """以常驻子进程订阅回调。

        该 client 没有 -sf，无法"短超时注册 → 重启续轮询"，只能常驻并持续把
        交互以 JSONL 打到 stdout；这里起后台读取协程累积到缓冲，poll 时取走。
        进程退出由 atexit 兜底 terminate，绝不泄漏。
        """
        if self._itsh_proc is not None:
            return
        exe = resolve_tool_path("interactsh-client")
        if not exe:
            return
        try:
            self._itsh_payload_file = payload_file or self._itsh_payload_file
            args = [exe] + self._interactsh_server_args() + [
                "-json", "-psf", self._itsh_payload_file, "-pi", "3"]
            self._itsh_proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            atexit.register(self._kill_itsh_sync)
            self._itsh_reader_task = asyncio.create_task(self._read_itsh_stream())
            logger.info("[OOB] interactsh 常驻订阅已启动")
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[OOB] interactsh 常驻订阅启动失败: {e}")
            self._itsh_proc = None

    async def _read_itsh_stream(self) -> None:
        """后台读取常驻进程 stdout，按行解析交互并入缓冲。"""
        proc = self._itsh_proc
        if proc is None or proc.stdout is None:
            return
        try:
            async for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").strip()
                if not line.startswith("{") or '"protocol"' not in line.lower():
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(data, dict):
                    continue
                proto = str(data.get("protocol") or data.get("type") or "unknown").lower()
                token = self._extract_itsh_token(data)
                if not token:
                    continue
                raw_req = str(data.get("raw_request") or "")
                self._itsh_buffer.append(OOBInteraction(
                    token=token, protocol=proto,
                    tag=str(data.get("type") or proto),
                    time=str(data.get("timestamp") or ""),
                    from_addr=str(data.get("remote_address") or ""),
                    raw_protocol=raw_req.split("\r\n", 1)[0][:120],
                    extra=data,
                ))
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[OOB] interactsh 流读取结束: {e}")


    def _extract_itsh_token(self, data: Dict) -> str:
        """从一条 interactsh 交互里解析「触发回调的 token」（子域首标签）。

        低误报铁律（A1.4 串台防护的落地）：模块头声明「只认注册过的真实带外
        域名发来的回调」，但旧实现直接取 fullId/subdomain 首标签，不校验该域名
        是否落在本次注册域名之下——任何 FQDN 形态的候选值都会被当成"我们的 token"
        绑定到 finding（自部署/异常服务端、或被篡改的交互记录即可制造误关联）。
        现要求 FQDN 候选值必须收口于本次注册域名，且不得就是根域名本身；
        裸标签（无点，如某些版本的 shorthost）无法判定归属，沿用旧行为。
        候选字段逐个尝试，命中即返回；全部不可信返回 ""（该条交互丢弃）。
        """
        domain = str(self._domain or _DOMAIN_CACHE.get("interactsh") or "")
        domain = domain.strip(".").lower()
        for key in ("fullId", "subdomain", "token", "dns_name", "shorthost"):
            val = str(data.get(key) or "").strip().strip(".")
            if not val:
                continue
            head = val.split(".", 1)[0]
            if not head or head == domain:
                continue
            if "." in val and domain:
                low = val.lower()
                if low == domain or not low.endswith("." + domain):
                    continue  # 非本通道注册域名 → 该字段不可信，试下一个候选字段
            return head
        return ""

    def _kill_itsh_sync(self) -> None:
        """同步兜底：进程退出前终止常驻子进程（atexit 注册）。"""
        proc = getattr(self, "_itsh_proc", None)
        if proc is not None and proc.returncode is None:
            try:
                proc.terminate()
            except Exception:
                logger.debug("suppressed exception (core audit)")
        self._itsh_proc = None

    async def aclose(self) -> None:
        """显式释放常驻订阅（扫描结束调用；atexit 为兜底）。"""
        if self._itsh_reader_task is not None:
            self._itsh_reader_task.cancel()
            try:
                await self._itsh_reader_task
            except (asyncio.CancelledError, Exception):
                logger.debug("suppressed exception (core audit)")
            self._itsh_reader_task = None
        self._kill_itsh_sync()

    async def _poll_dnslog(self, timeout: int) -> List[OOBInteraction]:
        try:
            from vulnclaw.core.utils import get_shared_session
            import aiohttp
            session = await get_shared_session()
            url = "http://www.dnslog.cn/getrecords.php"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                text = await resp.text()
            text = (text or "").strip()
            if not text:
                return []
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return []
            out = []
            # dnslog.cn 的记录可能为「对象(dict)」或「数组[hostname,IP,time]」两种形态，均兼容
            for rec in data if isinstance(data, list) else []:
                if isinstance(rec, dict):
                    raw = str(rec.get("data") or "")
                    ip = str(rec.get("remote_ip") or "")
                    t = str(rec.get("time") or "")
                elif isinstance(rec, list) and rec:
                    raw = str(rec[0] or "")
                    ip = str(rec[1]) if len(rec) > 1 else ""
                    t = str(rec[2]) if len(rec) > 2 else ""
                else:
                    continue
                head = str(raw).split(".", 1)[0]
                out.append(OOBInteraction(
                    token=head, protocol="dns", tag="dns",
                    time=t, from_addr=ip, extra={"data": raw, "time": t, "remote_ip": ip},
                ))
            return out
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[OOB] dnslog poll 异常: {e}")
            # 审计N：dnslog 为明文第三方、常被限流，其异常同样不计入目标熔断
            self._last_poll_error = f"dnslog poll error: {e}"[:200]
        return []

    # ----------------------------------------------------------
    # 按 token 判定
    # ----------------------------------------------------------
    async def interactions_for(self, token: str, timeout: int = 15) -> List[OOBInteraction]:
        """返回匹配指定 token 的回调（精确相等，大小写不敏感）。

        poll 取走缓冲后，未被本次过滤命中的其它 token 回调只留在审计链；
        本次未命中时按 token 兜底查审计链，避免"并发等待时回调被先行 token
        的 poll 取走"造成的漏绑定（token 每次注入随机生成，精确匹配无串台风险）。
        """
        token = token.strip().lower()
        if not token:
            return []
        fresh = [it for it in await self.poll(timeout=timeout)
                 if it.token and it.token.lower() == token]
        if fresh:
            return fresh
        return list(get_oob_audit(token))

    def _local_hits(self, token: str) -> List[OOBInteraction]:
        """纯内存查取：审计链 + 当前缓冲中匹配 token 的回调（零网络零等待）。

        熔断快速路径专用——熔断的设计目标是"不为注定无回连的等待买单"，但
        已经收到的回调是实锤，必须能在零成本的前提下发现并解除熔断。
        """
        token = token.strip().lower()
        if not token:
            return []
        out = list(get_oob_audit(token))
        for it in list(self._itsh_buffer):
            if it.token and it.token.lower() == token and it not in out:
                out.append(it)
        return out

    async def wait_for_interaction(self, token: str, timeout: int = 15,
                                   interval: float = 1.5,
                                   target: str = "") -> List[OOBInteraction]:
        """轮询等待该 token 出现回调。命中返回命中列表，超时/熔断返回空。

        P0：``target`` 传入当前扫描目标。若该目标已连续零回调达阈值（外发被封禁）
        或通道处于熔断期，则跳过等待直接返回空——不再为注定无回连的等待买单。
        熔断只跳过"等待"，不产生任何 finding，不影响误报率。
        """
        token = token.strip().lower()
        if not self._domain or not token:
            return []
        # 熔断快速路径：零网络、零等待地查一次内存（缓冲 + 审计链）——已收到的
        # 实锤不应因熔断被当成"无回连"漏掉（FN 防护）；内存无命中才真正跳过等待，
        # 保持熔断"不再为注定无回连的等待买单"的成本语义。
        if is_oob_blocked(target):
            hits = self._local_hits(token)
            if not hits:
                logger.debug(f"[OOB] 熔断生效，跳过 token={token} 的带外等待（target={target or '*'}）")
                return []
            logger.info(f"[OOB] 熔断中但缓冲/审计已有 token={token} 回调 → 命中并解除熔断")
            if not self._last_poll_error:
                record_oob_result(target, True)
            return hits
        deadline = time.monotonic() + timeout
        hits: List[OOBInteraction] = []
        while time.monotonic() < deadline:
            hits = await self.interactions_for(token, timeout=min(6, timeout))
            if hits:
                logger.info(f"[OOB] token={token} 捕获 {len(hits)} 条回调 → 实锤")
                break
            await asyncio.sleep(min(interval, max(0.5, deadline - time.monotonic())))
        else:
            logger.debug(f"[OOB] token={token} 在 {timeout}s 内未收到回调")
        # 驱动目标级熔断：命中清零、未命中累加。
        # 审计N：轮询本身故障（超时/异常/通道错）时**不**累加——那是"我们没问到"，
        # 不是"目标没回连"。否则通道故障会被误判成"目标外发被封禁"，在真实目标
        # 上永久关闭 OOB 检测（等于自废盲打能力）。
        if self._last_poll_error:
            logger.debug(
                f"[OOB] 轮询故障({self._last_poll_error[:80]})，"
                f"本次不计入目标熔断统计（target={target or '*'}）"
            )
        else:
            record_oob_result(target, bool(hits))
        return hits

    # ----------------------------------------------------------
    # 便捷：一次盲打探测（申请域名 + 生成 token + 地址）
    # ----------------------------------------------------------
    async def make_probe(self, scheme: str = "https") -> Optional[Dict]:
        """一步拿到探测所需信息；通道不可用返回 None。"""
        domain = await self.request_domain()
        if not domain:
            return None
        token = self.new_token()
        return {
            "domain": domain,
            "provider": self._resolved_provider,
            "token": token,
            "url": self.interaction_url(token, scheme),
            "dns": self.dns_label(token),
        }

    # ----------------------------------------------------------
    # A1.4：回调证据链审计 / 去重 / 复核
    # ----------------------------------------------------------
    def _record_interaction(self, it: "OOBInteraction") -> None:
        """单条回调去重入库（进程内 + JSONL 落盘跨进程审计）。"""
        key = (it.token, it.protocol, it.time, it.from_addr, it.raw_protocol)
        if key in _OOB_AUDIT_SEEN:
            return
        _OOB_AUDIT_SEEN.add(key)
        _OOB_AUDIT.append(it)
        # P3-13：内存审计链封顶（落盘在先，磁盘保完整；内存只留最近 N 条）。
        # 裁剪时同步重建去重集，避免 SEEN 无界增长。
        if len(_OOB_AUDIT) > _OOB_AUDIT_MAX:
            del _OOB_AUDIT[: len(_OOB_AUDIT) - _OOB_AUDIT_MAX]
            _OOB_AUDIT_SEEN.clear()
            for _it in _OOB_AUDIT:
                _OOB_AUDIT_SEEN.add(
                    (_it.token, _it.protocol, _it.time, _it.from_addr, _it.raw_protocol))
        _append_oob_evidence_jsonl(
            it.evidence_view(channel=self._resolved_provider or ""))

    def record_interactions(self, items: List["OOBInteraction"]) -> None:
        """批量入库（忽略非 OOBInteraction）。"""
        for it in (items or []):
            if isinstance(it, OOBInteraction):
                self._record_interaction(it)

    def get_audit(self, token: Optional[str] = None) -> List["OOBInteraction"]:
        """查询审计链：不传 token 返回全部；传 token 仅返回该 token 的回调。"""
        if not token:
            return list(_OOB_AUDIT)
        t = token.strip().lower()
        return [it for it in _OOB_AUDIT if it.token and it.token.lower() == t]

    @staticmethod
    def audit_size() -> int:
        """当前审计链条数。"""
        return len(_OOB_AUDIT)


async def make_oob_probe(scheme: str = "https") -> Optional[Dict]:
    """模块级便捷入口：engine 内一行拿到 OOB 探测地址。"""
    return await OOBChannel().make_probe(scheme)


def get_oob_audit(token: Optional[str] = None) -> List["OOBInteraction"]:
    """模块级审计查询：跨 OOBChannel 实例汇总（A1.4）。

    供非引擎侧（verify、报告聚合、事后审计）直接读取进程内累积的全部 OOB 回调，
    无需持有具体通道实例。
    """
    if not token:
        return list(_OOB_AUDIT)
    t = token.strip().lower()
    return [it for it in _OOB_AUDIT if it.token and it.token.lower() == t]


# ----------------------------------------------------------
# SP14.3-B：结构化证据落盘（跨进程审计 + A 线 evidence 组装的数据源）
# 每条回调入库时同步追加一行 evidence_view()（oob_ts/oob_channel/oob_token/
# oob_detail），写失败静默——落盘是增强项，绝不影响盲打主流程。
# ----------------------------------------------------------
_OOB_EVIDENCE_RELPATH = ("_runtime_cache", "metrics", "oob_interactions.jsonl")


def _oob_evidence_path() -> str:
    root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    return os.path.join(root, *_OOB_EVIDENCE_RELPATH)


def _append_oob_evidence_jsonl(view: Dict) -> None:
    try:
        path = _oob_evidence_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(view, ensure_ascii=False) + "\n")
    except OSError as exc:
        logger.debug(f"OOB 证据落盘失败（忽略）: {exc}")


def get_oob_evidence(token: Optional[str] = None) -> List[Dict]:
    """模块级结构化证据查询（SP14.3-B，A 线一行调用）：返回 evidence_view 列表。

    与 get_oob_audit 同源；A 侧按 evidence.oob_* 直接展开写入 finding/报告。
    """
    return [it.evidence_view() for it in get_oob_audit(token)]


__all__ = [
    "OOBChannel", "OOBInteraction", "make_oob_probe", "get_oob_audit",
    "get_oob_evidence", "validate_interactsh_server", "get_oob_diagnostics",
]