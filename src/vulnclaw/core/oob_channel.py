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

# A1.3：支持的带外回调协议（LDAP/RMI/SMB/SMTP + 既有 DNS/HTTP）
_OOB_PROTOCOLS = ("ldap", "rmi", "smb", "smtp", "dns", "http", "https")

# A1.4：OOB 回调证据链审计（进程内持久化 + 去重）
# 满足「token→interaction 落库，支持跨轮次复核、去重与事后审计」——
# 在单次扫描进程内累积全部回调，按 (token,protocol,time,from,raw) 去重，
# 供引擎/verify/报告侧事后审计，避免重复计数与串台误读。进程级单例，无需新建文件。
_OOB_AUDIT: List["OOBInteraction"] = []
_OOB_AUDIT_SEEN: set = set()


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

    def __post_init__(self):
        if self.extra is None:
            self.extra = {}
        if not self.time:
            self.time = time.strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self):
        return asdict(self)


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
        cached = _DOMAIN_CACHE.get("interactsh")
        if cached:
            self._itsh_session_file = _INTERACTSH_SESSION.get("interactsh")
            return cached
        if not load_tool_config("interactsh-client"):
            logger.info("[OOB] interactsh-client 未安装，跳过 interactsh 通道。")
            return None
        try:
            tag = secrets.token_hex(4)
            sf = os.path.join(tempfile.gettempdir(), f"itsh_{tag}.yaml")
            ps = os.path.join(tempfile.gettempdir(), f"itsh_{tag}_payload.txt")
            server_note = f" (server={_OOB_INTERACTSH_SERVER})" if _OOB_INTERACTSH_SERVER else ""
            logger.info(f"[OOB] 注册 interactsh 域名{server_note}")
            # 短超时注册：即便 8s 后被 kill，注册与会话在服务端持续有效
            result = await run_tool(
                "interactsh-client",
                args=self._interactsh_server_args()
                + ["-json", "-sf", sf, "-psf", ps, "-nf", "-pi", "3"],
                timeout=8,
            )
            domain = self._extract_itsh_domain(sf, ps, result.get("stdout", ""))
            if domain:
                self._itsh_session_file = sf
                _DOMAIN_CACHE["interactsh"] = domain
                _INTERACTSH_SESSION["interactsh"] = sf
                logger.info(f"[OOB] 已注册 interactsh 域名: {domain} (session={sf})")
                return domain
            err = result.get("stderr") or result.get("error") or ""
            logger.warning(f"[OOB] interactsh 注册未取到域名 rc={result.get('returncode', -1)} err={err[:200]}")
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[OOB] interactsh 申请域名失败: {e}")
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
                    pass
        for text in candidates:
            m = _OAST_DOMAIN_RE.search(text or "")
            if m:
                return m.group(1)
        return None

    async def _request_dnslog_domain(self) -> Optional[str]:
        """dnslog.cn 备选通道（HTTP，无二进制依赖）。"""
        try:
            from vulnclaw.core.utils import get_shared_session
            import aiohttp
            session = await get_shared_session()
            url = "http://www.dnslog.cn/getdomain.php"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                text = await resp.text()
            text = (text or "").strip()
            if text and "." in text and " " not in text:
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
        if self._resolved_provider == "interactsh":
            items = await self._poll_interactsh(timeout)
        elif self._resolved_provider == "dnslog":
            items = await self._poll_dnslog(timeout)
        self.record_interactions(items)  # A1.4：回调证据链持久化 + 去重
        return items

    async def _poll_interactsh(self, timeout: int) -> List[OOBInteraction]:
        if not load_tool_config("interactsh-client"):
            return []
        if not self._itsh_session_file:
            self._itsh_session_file = _INTERACTSH_SESSION.get("interactsh")
        if not self._itsh_session_file:
            logger.warning("[OOB] interactsh 轮询缺少会话文件，跳过。")
            return []
        result = None
        try:
            # 用同一会话文件重启 interactsh-client，重连并轮询该会话注册期间的回调
            result = await run_tool("interactsh-client",
                                    args=self._interactsh_server_args()
                                    + ["-json", "-sf", self._itsh_session_file],
                                    timeout=timeout)
        except asyncio.TimeoutError:
            logger.debug("[OOB] interactsh poll 超时")
            return []
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[OOB] interactsh poll 异常: {e}")
            return []
        if not result:
            return []
        out = result.get("stdout") or ""
        if not out:
            return []
        interactions = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            lc = line.lower()
            # 弹出版权横幅、未注册 payload 行等噪音；只认协议化的交互 JSON
            if not line.startswith("{") or '"protocol"' not in lc:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            proto = str(data.get("protocol") or data.get("type") or "unknown").lower()
            token = ""
            for key in ("fullId", "subdomain", "token", "dns_name", "shorthost"):
                val = str(data.get(key) or "")
                head = val.split(".", 1)[0]
                if head and head != self._domain:
                    token = head
                    break
            if not token:
                continue
            raw_req = str(data.get("raw_request") or "")
            interactions.append(OOBInteraction(
                token=token,
                protocol=proto,
                tag=str(data.get("type") or proto),
                time=str(data.get("timestamp") or ""),
                from_addr=str(data.get("remote_address") or ""),
                raw_protocol=raw_req.split("\r\n", 1)[0][:120],
                extra=data,
            ))
        return interactions

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
        return []

    # ----------------------------------------------------------
    # 按 token 判定
    # ----------------------------------------------------------
    async def interactions_for(self, token: str, timeout: int = 15) -> List[OOBInteraction]:
        """返回匹配指定 token 前缀的回调。"""
        token = token.strip().lower()
        if not token:
            return []
        return [it for it in await self.poll(timeout=timeout)
                if it.token and it.token.lower() == token]

    async def wait_for_interaction(self, token: str, timeout: int = 15,
                                   interval: float = 1.5) -> List[OOBInteraction]:
        """轮询等待该 token 出现回调。命中返回命中列表，超时返回空。"""
        token = token.strip().lower()
        if not self._domain or not token:
            return []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            hits = await self.interactions_for(token, timeout=min(6, timeout))
            if hits:
                logger.info(f"[OOB] token={token} 捕获 {len(hits)} 条回调 → 实锤")
                return hits
            await asyncio.sleep(min(interval, max(0.5, deadline - time.monotonic())))
        logger.debug(f"[OOB] token={token} 在 {timeout}s 内未收到回调")
        return []

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
        """单条回调去重入库（进程内）。"""
        key = (it.token, it.protocol, it.time, it.from_addr, it.raw_protocol)
        if key in _OOB_AUDIT_SEEN:
            return
        _OOB_AUDIT_SEEN.add(key)
        _OOB_AUDIT.append(it)

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


__all__ = [
    "OOBChannel", "OOBInteraction", "make_oob_probe", "get_oob_audit",
]