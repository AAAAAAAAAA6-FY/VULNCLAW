# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/burp.py
"""
Burp Suite 统一控制模块 - 修复版
修复：random→secrets，认证恢复机制
步骤0：移除伪造 oast.fun 假域名的降级（OOB 漏报复）；collaborator_poll 改走真实 interactsh
步骤1：实现 /v0.1/proxy/history 被动采集（get_history_since / Cookie / Token 提取）
"""

import asyncio
import json
import time
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse

import aiohttp

from vulnclaw.config.settings import settings
from vulnclaw.core.logger import logger
from vulnclaw.core.utils import get_shared_session


# Set-Cookie 属性名（出现在分号后，非 cookie 键值对）
_COOKIE_ATTRS = {"path", "domain", "expires", "max-age", "httponly", "secure", "samesite"}

# ---- Montoya 扩展桥（thirdparty/burp-bridge/vulnclaw-bridge.jar）----
# 精简 REST API 缺 /proxy/history 与 issue 详情，扩展桥以 JSONL 落盘补齐。
# 目录可由环境变量 VULNCLAW_BRIDGE_DIR 覆盖，默认 <项目根>/_runtime_cache/burp_bridge
_BRIDGE_DIR_ENV = os.environ.get("VULNCLAW_BRIDGE_DIR", "")


def _bridge_dir() -> str:
    if _BRIDGE_DIR_ENV:
        return _BRIDGE_DIR_ENV
    # burp.py 位于 <root>/src/vulnclaw/ai/ → 项目根为上三级
    root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    return os.path.join(root, "_runtime_cache", "burp_bridge")


# 请求头中视为 Token 的头名（小写）
_TOKEN_HEADERS = (
    "authorization", "x-auth-token", "x-api-key", "x-access-token",
    "x-csrf-token", "x-xsrf-token", "api-key", "access-token",
)


class BurpClient:
    CACHE_FILE = ".burp_cache.json"

    def __init__(
        self,
        base_url: str = None,
        api_key: str = "",
        max_retries: int = 3,
        connect_timeout: int = 10,
        read_timeout: int = 30
    ):
        from vulnclaw.config.settings import settings as _st
        env_url = _st.burp_api_url or ""
        self.base_url = (env_url or base_url or "http://127.0.0.1:1337").rstrip('/')
        self.api_key = api_key or _st.burp_api_key or ""
        self.max_retries = max_retries
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout

        self._api_prefix = self._load_from_cache()
        self._connection_status = None
        self._auth_attempted = False
        self._auth_failed = False

        self.headers = {"Content-Type": "application/json", "Accept": "application/json"}
        self._auth_headers = self._build_auth_headers(self.api_key)
        self._active_auth_header = self._auth_headers[0] if self._auth_headers else {}

        self._collaborator_domain = None
        self._session = None
        # 步骤3：记录所有已提交扫描的 scan_id（含 recon 阶段 import_to_burp
        # 的"发射后不管"提交），供 scan_and_collect 统一收结果。
        self._scan_ids: List = []
        # 实测部分版本（如 Burp 2026.7.3）的 /scan/{id}/issues 恒 500，
        # issue 详情仅存在于 Burp GUI；探测一次后跳过空耗轮询
        self._issues_endpoint_broken = False
        # 扩展桥 JSONL 增量读取位置（轮转感知：文件变短即重置）
        self._bridge_offsets: Dict[str, int] = {}
        self._bridge_checked = False

        if self._api_prefix is not None:
            logger.debug(f"使用缓存 Burp API 前缀: '{self._api_prefix}'")

    def _build_auth_headers(self, api_key: str) -> List[Dict[str, str]]:
        if not api_key:
            return [{}]
        return [
            {"Authorization": f"Bearer {api_key}"},
            {"X-API-Key": api_key},          # 修复：去掉花括号
            {"Authorization": f"ApiKey {api_key}"},
        ]

    def _load_from_cache(self) -> Optional[str]:
        """从缓存文件读取 - 保留读取功能，但不会写入新文件"""
        try:
            if os.path.exists(self.CACHE_FILE):
                with open(self.CACHE_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if data.get('base_url') == self.base_url:
                        # 检查缓存时间，超过7天则视为失效
                        if data.get('timestamp', 0) > time.time() - 7 * 24 * 3600:
                            return data.get('api_prefix')
                        else:
                            return None
        except BaseException:
            logger.debug("suppressed exception (core audit)")
        return None

    def _save_to_cache(self, prefix: str):
        # 已禁用缓存写入
        return

    async def _probe_prefix(self) -> Optional[str]:
        test_cases = [
            ("/v0.1", "/knowledge_base/issue_definitions"),
            ("/v0.1", "/issue_definitions"),
            ("", "/knowledge_base/issue_definitions"),
            ("", "/issue_definitions"),
            ("/api/v1", "/knowledge_base/issue_definitions"),
            ("/api", "/knowledge_base/issue_definitions"),
        ]
        logger.info("🔍 自动探测 Burp API 前缀...")
        async with aiohttp.ClientSession() as session:
            for prefix, path in test_cases:
                full_path = prefix + path
                url = self.base_url + full_path
                try:
                    async with session.get(url, timeout=5, ssl=False) as resp:
                        if resp.status == 200:
                            try:
                                data = await resp.json()
                                if data is not None:
                                    logger.info(f"✅ 发现可用前缀: '{prefix}'")
                                    return prefix
                            except BaseException:
                                logger.debug("suppressed exception (core audit)")
                except BaseException:
                    continue
        return None

    async def _ensure_prefix(self) -> bool:
        if self._api_prefix is not None:
            return True
        prefix = await self._probe_prefix()
        if prefix is not None:
            self._api_prefix = prefix
            return True
        self._api_prefix = ""
        return False

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = await get_shared_session()
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    async def _request(
        self,
        method: str,
        path: str,
        data: Optional[Dict] = None,
        operation: str = "default",
        retry_count: int = 0
    ) -> Optional[Any]:
        if self._auth_failed:
            logger.warning("⚠️ Burp 认证已失败，尝试恢复...")
            self._auth_failed = False
            self._auth_attempted = False

        if not await self._ensure_prefix():
            return None

        if not path.startswith('/'):
            path = '/' + path
        if path.startswith('/v0.1') or path.startswith('/api'):
            full_path = path
        else:
            full_path = self._api_prefix + path

        url = f"{self.base_url}{full_path}"
        headers = self.headers.copy()
        if self._active_auth_header:
            headers.update(self._active_auth_header)

        timeout = aiohttp.ClientTimeout(total=30)
        session = await self._get_session()

        try:
            async with session.request(
                method,
                url,
                headers=headers,
                json=data,
                timeout=timeout,
                ssl=False
            ) as resp:
                if resp.status in (200, 201, 202):
                    # Burp 2026.x 实测：POST /scan 返回 201 空 body，
                    # task_id 在 Location 响应头（如 "5"），必须透出
                    location = resp.headers.get("location") or ""
                    try:
                        body = await resp.json()
                    except BaseException:
                        text = await resp.text()
                        if text and text.strip():
                            return {"status": "success", "raw": text}
                        return {"status": "success", "_location": location}
                    if isinstance(body, dict) and location:
                        body.setdefault("_location", location)
                    return body
                elif resp.status == 401:
                    if self.api_key and not self._auth_attempted and len(self._auth_headers) > 1:
                        self._auth_attempted = True
                        for auth in self._auth_headers:
                            if auth != self._active_auth_header:
                                self._active_auth_header = auth
                                logger.info("🔄 尝试切换认证方式")
                                return await self._request(method, path, data, operation, retry_count + 1)
                        self._auth_failed = True
                        logger.error("❌ 所有 Burp API 认证方式均失败")
                        return None
                    return None
                # 其他 4xx/5xx：透出 code + body 方便排错（如特殊字符被 API 输入校验拒绝）
                try:
                    body_text = (await resp.text())[:1500]
                except Exception:
                    body_text = ""
                logger.debug(
                    f"Burp API HTTP {resp.status}: {method} {path[:80]} -> {body_text[:200]}"
                )
                return {
                    "status": f"http_{resp.status}",
                    "code": resp.status,
                    "body": body_text,
                    "_location": resp.headers.get("location") or "",
                }
        except Exception as e:
            logger.debug(f"Burp API 请求失败: {e}")
            return None

    async def get_status(self, force_refresh: bool = False) -> bool:
        if force_refresh:
            self._auth_failed = False
            self._api_prefix = None
            self._connection_status = None

        if not force_refresh and self._connection_status is not None:
            return self._connection_status

        result = await self._request("GET", "/knowledge_base/issue_definitions")
        if result is not None:
            self._connection_status = True
            logger.info(f"✅ Burp REST API 连接成功 (前缀: '{self._api_prefix}')")
            return True

        if os.path.exists(self.CACHE_FILE):
            try:
                os.remove(self.CACHE_FILE)
                logger.info("🔄 缓存失效，已清除，重新探测...")
            except BaseException:
                logger.debug("suppressed exception (core audit)")
        self._api_prefix = None
        self._connection_status = False

        if await self._ensure_prefix():
            result = await self._request("GET", "/knowledge_base/issue_definitions")
            if result is not None:
                self._connection_status = True
                logger.info(f"✅ Burp REST API 重新连接成功 (前缀: '{self._api_prefix}')")
                return True

        self._connection_status = False
        logger.warning("⚠️ Burp REST API 连接失败，将使用独立模式")
        return False

    # ================= Montoya 扩展桥（JSONL 文件读取） =================

    def _bridge_file(self, name: str) -> Optional[str]:
        """返回桥目录下指定文件的绝对路径（不存在则 None）。"""
        try:
            path = os.path.join(_bridge_dir(), name)
            return path if os.path.isfile(path) else None
        except Exception:
            return None

    def get_bridge_status(self) -> Optional[Dict]:
        """读取扩展心跳 status.json；扩展未加载返回 None。"""
        path = os.path.join(_bridge_dir(), "status.json")
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                hb = json.load(f)
            if isinstance(hb, dict):
                status = {
                    "ok": bool(hb.get("registered")) or hb.get("ok") is True,
                    "version": hb.get("version"),
                    "started": hb.get("started"),
                    "heartbeat": dict(hb),
                }
                for name, key in [("audit_issues.jsonl", "audit_issues_written"),
                                  ("proxy_history.jsonl", "proxy_events_written")]:
                    p = os.path.join(_bridge_dir(), name)
                    if os.path.isfile(p):
                        with open(p, "r", encoding="utf-8", errors="replace") as fh:
                            status["heartbeat"][key] = sum(1 for _ in fh if _.strip())
                    else:
                        status["heartbeat"][key] = 0
                return status
            return {"ok": False, "heartbeat": hb}
        except Exception:
            return None

    def _bridge_http_url(self) -> str:
        """扩展桥 mini HTTP server 地址（默认 127.0.0.1:18181，可 VULNCLAW_BRIDGE_URL 覆盖）。"""
        return (os.environ.get("VULNCLAW_BRIDGE_URL", "").strip().rstrip("/")
                or "http://127.0.0.1:18181")

    async def run_intruder(
        self,
        url: str,
        payloads: List[str],
        marker: str = "FUZZ",
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        concurrency: int = 4,
        timeout_s: int = 120,
    ) -> Optional[Dict]:
        """真 Intruder：经扩展桥 /vulnclaw/intruder 逐 payload 发送并收集结果表。

        桥（vulnclaw-bridge.jar 1.1.0+）未运行时返回 None（调用方降级或如实报
        不可用）。payload 数上限 200；payload 含逗号时请用 marker 多占位规避
        （桥端为极简数组解析器，与 urls 解析同款）。
        """
        payload_list = [str(p) for p in (payloads or []) if str(p).strip()]
        url = str(url or "").strip()
        if not url or not payload_list:
            return None
        payload = json.dumps({
            "url": url,
            "payloads": payload_list[:200],
            "marker": str(marker or "FUZZ"),
            "method": str(method or "GET").upper(),
            "headers": dict(headers or {}),
            "body": str(body or ""),
            "concurrency": max(1, min(int(concurrency or 4), 16)),
        }, ensure_ascii=False).encode("utf-8")
        try:
            session = await get_shared_session()
            async with session.post(
                self._bridge_http_url() + "/vulnclaw/intruder",
                data=payload,
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=max(30, int(timeout_s))),
            ) as resp:
                if resp.status != 200:
                    logger.debug(
                        f"[BurpBridge] intruder HTTP {resp.status}（桥版本过低或未加载）")
                    return None
                return await resp.json(content_type=None)
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[BurpBridge] intruder 调用失败（桥未运行？）: {exc}")
            return None

    def _read_new_lines(self, name: str) -> List[Dict]:
        """增量读取桥 JSONL（记住 offset；轮转后文件变小则重头读）。"""
        path = self._bridge_file(name)
        if not path:
            return []
        out: List[Dict] = []
        try:
            size = os.path.getsize(path)
            offset = self._bridge_offsets.get(name, 0)
            if size < offset:  # 轮转发生
                offset = 0
            if size == offset:
                return []
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        continue
                self._bridge_offsets[name] = f.tell()
        except Exception as e:
            logger.debug(f"扩展桥读取 {name} 失败: {e}")
        return out

    def get_history_from_bridge(self, limit: int = 50) -> List[Dict]:
        """从桥 proxy_history.jsonl 取增量流量（结构对齐 _normalize_history_event 输出）。"""
        entries: List[Dict] = []
        for ev in self._read_new_lines("proxy_history.jsonl"):
            try:
                url = ev.get("url") or ""
                if not url:
                    continue
                parsed = urlparse(url)
                resp_headers = ev.get("response_headers") or {}
                ts = ev.get("ts") or ""
                try:
                    ms = int(datetime.fromisoformat(ts.replace("Z", "+00:00"))
                             .timestamp() * 1000)
                except Exception:
                    ms = 0
                entries.append({
                    "url": url,
                    "method": ev.get("method") or "",
                    "host": ev.get("host") or parsed.netloc,
                    "path": parsed.path,
                    "status": ev.get("status"),
                    "timestamp": ms,
                    "request_headers": ev.get("request_headers") or {},
                    "response_headers": resp_headers,
                    "response_set_cookies": [v for k, v in resp_headers.items()
                                             if str(k).lower() == "set-cookie"],
                    "request_body": ev.get("request_body"),
                    "response_body": None,
                    "source": "burp_bridge",
                })
            except Exception:
                continue
        if entries:
            logger.info(f"🌉 扩展桥被动采集到 {len(entries)} 条流量")
        return entries[:limit] if limit else entries

    def get_issues_from_bridge(self, since_epoch: float = 0) -> List[Dict]:
        """从桥 audit_issues.jsonl 取增量 issue（since_epoch 过滤，秒级时间戳）。

        返回已对齐 normalize_issue 输入形态的列表。
        """
        out: List[Dict] = []
        seen = set()
        for ev in self._read_new_lines("audit_issues.jsonl"):
            try:
                ts = ev.get("ts") or ""
                if since_epoch > 0 and ts:
                    try:
                        epoch = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
                        if epoch < since_epoch - 5:
                            continue
                    except Exception:
                        logger.debug("suppressed exception (core audit)")
                name = ev.get("name") or "Unknown Issue"
                key = (name, ev.get("base_url") or "")
                if key in seen:
                    continue
                seen.add(key)
                url = ev.get("base_url") or ""
                if not url:
                    evd = ev.get("evidence") or []
                    if evd and isinstance(evd[0], dict):
                        url = evd[0].get("url") or ""
                sev = str(ev.get("severity") or "Medium").title()
                if sev == "Information":
                    sev = "Info"
                out.append({
                    "name": name,
                    "severity": sev,
                    "confidence": str(ev.get("confidence") or "").title(),
                    "url": url,
                    "issue_detail": ev.get("detail") or "",
                    "issue_remediation": ev.get("remediation") or "",
                    "issue_background": ev.get("issue_background") or "",
                    "evidence": ev.get("evidence") or [],
                    "source": "burp_bridge",
                })
            except Exception:
                continue
        if out:
            logger.info(f"🌉 扩展桥收割到 {len(out)} 条 issue 详情")
        return out

    async def get_issue_definitions(self, severity: List[str] = None, limit: int = 50) -> List[Dict]:
        """获取 Burp 知识库的 issue 类型定义（步骤2 修正语义）。

        这是所有漏洞类型的静态目录描述，不是对目标的扫描结果。
        目标扫描结果请用 get_scan_issues(scan_id)。
        """
        if not await self.get_status():
            return []
        result = await self._request("GET", "/knowledge_base/issue_definitions")
        if result:
            issues = result if isinstance(result, list) else result.get('issue_definitions', []) or result.get('issues', [])
            if severity:
                issues = [i for i in issues if i.get('severity', '').lower() in [s.lower() for s in severity]]
            if limit:
                issues = issues[:limit]
            logger.info(f"📥 Burp 知识库 issue 类型定义: {len(issues)} 种")
            return issues
        return []

    async def send_to_scanner(self, url: str) -> Dict:
        """提交主动扫描（步骤2 重写）：捕获 scan_id 供后续轮询。

        _request 对 200 但非 JSON 的响应会返回 {"status": "success", "raw": ...}，
        因此必须校验响应中确实存在 scan_id 字段才算成功，
        避免 Burp 返回 HTML 错误页时被误判为提交成功（发射后不管）。
        """
        result = await self._request("POST", "/scan", {"urls": [url]})
        scan_id = None
        if isinstance(result, dict):
            for key in ("scan_id", "scanId", "id"):
                if result.get(key) is not None:
                    scan_id = result.get(key)
                    break
        if scan_id is None and isinstance(result, dict):
            # Burp 2026.x：201 空 body，task_id 在 Location 头（"5" 或 "/v0.1/scan/5"）
            loc = str(result.get("_location") or "").strip()
            if loc:
                scan_id = loc.rstrip("/").split("/")[-1]
        if scan_id is None:
            code = (result or {}).get("code")
            body = (result or {}).get("body") if isinstance(result, dict) else None
            logger.warning(
                f"⚠️ Burp 提交扫描未返回 scan_id: {url[:160]}  "
                f"http_code={code}  detail={((body or str(result or ''))[:200])!r}"
            )
            return {"status": "error", "url": url, "code": code, "detail": body}
        logger.info(f"🔍 Burp 开始扫描: {url} (scan_id={scan_id})")
        self._scan_ids.append(scan_id)
        return {"status": "success", "url": url, "scan_id": scan_id}

    async def get_scan_status(self, scan_id) -> Optional[Dict]:
        """查询扫描状态（GET /v0.1/scan/{id}）。"""
        if not await self.get_status():
            return None
        return await self._request("GET", f"/scan/{scan_id}")

    async def get_scan_issues(self, scan_id) -> List[Dict]:
        """获取该次扫描发现的目标漏洞（GET /v0.1/scan/{id}/issues，步骤2 新增）。"""
        if not await self.get_status():
            return []
        result = await self._request("GET", f"/scan/{scan_id}/issues")
        if result is None:
            if not self._issues_endpoint_broken:
                self._issues_endpoint_broken = True
                logger.warning(
                    "⚠️ Burp /scan/{id}/issues 不可用（部分版本未实现或损坏），"
                    "issue 详情仅能在 Burp GUI 查看；后续将只提交不等待"
                )
            return []
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            issues = result.get('issues') or result.get('issue_details') or result.get('results') or []
            return issues if isinstance(issues, list) else []
        return []

    async def cancel_scan(self, scan_id) -> bool:
        """取消扫描（POST /v0.1/scan/{id}/cancel，步骤2 新增）。"""
        if not await self.get_status():
            return False
        result = await self._request("POST", f"/scan/{scan_id}/cancel")
        return result is not None

    async def wait_for_scan(
        self, scan_id, timeout: int = 600, interval: int = 10
    ) -> Optional[str]:
        """轮询扫描直到终态（步骤2 新增）。

        返回终态字符串（completed/succeeded/aborted/canceled/failed），
        超时返回 None。调用方随后可用 get_scan_issues() 拉取结果。
        """
        start = time.time()
        terminal = ("completed", "succeeded", "aborted", "cancelled",
                    "canceled", "failed", "paused", "paused_by_user")
        succeeded = ("succeeded", "completed")
        last_seen = ""
        while time.time() - start < timeout:
            status = await self.get_scan_status(scan_id)
            if isinstance(status, dict):
                s = str(
                    status.get("scan_status")
                    or status.get("scanStatus")
                    or status.get("status")
                    or ""
                ).lower()
                last_seen = s
                if s in terminal:
                    return s
                # 若 scan_metrics 或 issue_events 显示扫描不再推进 (audit queue 0 & crawl 0)，提前判完成
                try:
                    metrics = status.get("scan_metrics") or {}
                    audit_q = (metrics.get("audit_queue_items")
                               if isinstance(metrics, dict) else None)
                    crawl_q = (metrics.get("crawl_queue_items")
                               if isinstance(metrics, dict) else None)
                    if (audit_q is not None and audit_q <= 0
                            and crawl_q is not None and crawl_q <= 0):
                        # 队列空 + 最近 scan_status 非 crawling/pending
                        if last_seen and last_seen in succeeded:
                            return last_seen
                        if last_seen in ("auditing", "crawling_and_auditing", "scanning",
                                         "running", "processing") and s in succeeded:
                            return s
                except Exception:
                    logger.debug("suppressed exception (core audit)")
            elif isinstance(status, str) and status.lower() in terminal:
                return status.lower()
            await asyncio.sleep(interval)
        logger.warning(f"⏱️ Burp 扫描 {scan_id} 轮询超时 ({timeout}s)")
        return None

    def drain_scan_ids(self) -> List:
        """取出并清空已记录的 scan_id（步骤3）。"""
        ids = list(self._scan_ids)
        self._scan_ids.clear()
        return ids

    @staticmethod
    def normalize_issue(issue: Any, fallback_url: str = "") -> Optional[Dict]:
        """把 Burp scan issue 归一化为标准 finding 结构（步骤3）。

        兼容 issue name/issueName、severity、url/issueDetail/issueBackground
        等常见字段形态；Burp 的 "Information" 级别归为 "Info"。
        """
        if not isinstance(issue, dict):
            return None
        name = (
            issue.get("issue_name") or issue.get("issueName")
            or issue.get("name") or issue.get("issue_type")
            or issue.get("type") or "Unknown Issue"
        )
        sev = str(
            issue.get("severity") or issue.get("issue_severity") or "Medium"
        ).strip().title()
        if sev in ("Information", "Info"):
            sev = "Info"
        url = (
            issue.get("url") or issue.get("origin") or issue.get("host")
            or fallback_url
        )
        if url and not str(url).startswith(("http://", "https://")):
            # host-only（如 "t.com"）或 host:port 一律补 https:// 前缀
            url = f"https://{url}"
        detail = (
            issue.get("detail") or issue.get("issue_detail")
            or issue.get("issueDetail") or issue.get("description") or ""
        )
        return {
            "type": f"Burp: {name}",
            "severity": sev if sev in ("Info", "Low", "Medium", "High", "Critical") else "Medium",
            "url": str(url) if url else fallback_url,
            "evidence": str(detail)[:300],
            "source": "burp_scanner",
            "confidence": "high",
        }

    async def scan_and_collect(
        self,
        urls: Optional[List[str]] = None,
        wait_timeout: int = 240,
        poll_interval: int = 10,
    ) -> List[Dict]:
        """一站式：提交扫描 → 轮询到终态 → 拉取 issues（步骤3）。

        会顺带收集此前提交（如 recon 阶段 import_to_burp）已记录的 scan_id，
        避免那些"发射后不管"的扫描结果永远丢失。
        urls 为空且无已记录 scan_id 时返回 []。
        """
        if not await self.get_status():
            return []

        scan_ids = self.drain_scan_ids()
        submitted = 0
        for url in (urls or []):
            result = await self.send_to_scanner(str(url))
            if result.get("status") == "success":
                submitted += 1
        # send_to_scanner 已把新 scan_id 记入 self._scan_ids
        scan_ids.extend(self.drain_scan_ids())
        if not scan_ids:
            logger.info("🔍 [Burp] 无待收集的扫描任务")
            return []

        # 统一流程（不区分 _issues_endpoint_broken）：
        #   1. 先等所有 scan 到终态
        #   2. 优先：扩展桥 audit_issues.jsonl（因为 REST /scan/id/issues 2026.7.3 常为空）
        #   3. 其次：scan_status.issue_events REST 回退合成
        #   4. 最后：get_scan_issues() 再兜底一次
        logger.info(
            f"🔍 [Burp] 等待 {len(scan_ids)} 个扫描完成 "
            f"(本轮新提交 {submitted}，历史遗留 {len(scan_ids) - submitted})"
        )
        start_ts = time.time() - 5
        states = await asyncio.gather(
            *[self.wait_for_scan(sid, timeout=wait_timeout,
                                 interval=poll_interval)
              for sid in scan_ids],
            return_exceptions=True,
        )
        ok_ids = [sid for sid, st in zip(scan_ids, states)
                  if isinstance(st, str) and st not in (None,)]
        if not ok_ids:
            logger.warning("⚠️ [Burp] 所有扫描终态异常，仅依赖扩展桥收割（不跳过）")

        findings: List[Dict] = []
        bridge_issues = []
        # --- 层级 1：扩展桥 ---
        bridge_retry = 0
        while bridge_retry < 4:
            bridge_issues = self.get_issues_from_bridge(since_epoch=start_ts)
            if bridge_issues:
                break
            await asyncio.sleep(3)
            bridge_retry += 1
        for issue in bridge_issues:
            normalized = self.normalize_issue(issue)
            if normalized:
                normalized["source"] = "burp_scanner"
                normalized["bridge_confirmed"] = True
                if issue.get("issue_remediation"):
                    normalized.setdefault("remediation", issue["issue_remediation"])
                if issue.get("evidence"):
                    normalized["evidence"] = issue["evidence"]
                findings.append(normalized)
        logger.info(f"📥 [Burp] 层级1(扩展桥audit) = {len(bridge_issues)} 条")

        # --- 层级 2：REST issue_events 回退 ---
        if True:  # 始终尝试，避免 endpoint_broken 判断把分支切死
            fallback_evs = []
            for sid in ok_ids:
                st = await self.get_scan_status(sid)
                if not isinstance(st, dict):
                    continue
                events = st.get("issue_events")
                if isinstance(events, list):
                    fallback_evs.extend(ev for ev in events if isinstance(ev, dict))
                # 另外也看看 Burp 2026 另一个字段名
                alt = st.get("issueEvents") or st.get("new_issues")
                if isinstance(alt, list):
                    fallback_evs.extend(ev for ev in alt if isinstance(ev, dict))
            if fallback_evs:
                logger.info(
                    f"📥 [Burp] 层级2(REST issue_events) = {len(fallback_evs)} 条 raw"
                )
            # 去重键：name+host+path
            seen = set()
            for ev in fallback_evs:
                data = ev if (isinstance(ev, dict) and "name" in ev) else (ev.get("data") if isinstance(ev, dict) else None)
                if not isinstance(data, dict):
                    continue
                name = (data.get("name") or data.get("issueName")
                        or data.get("issue_name") or data.get("type_name") or "")
                if not name:
                    continue
                host = (data.get("host") or data.get("origin")
                        or data.get("base_url") or "")
                path_part = data.get("path") or data.get("location") or ""
                url = data.get("url") or ""
                if not url and host:
                    if str(path_part).startswith(("http://", "https://")):
                        url = str(path_part)
                    else:
                        pp = path_part if str(path_part).startswith("/") else f"/{path_part}"
                        url = str(host).rstrip("/") + pp
                sev = str(data.get("severity") or data.get("issueSeverity")
                          or data.get("issue_severity") or "Medium").title()
                if sev == "Information":
                    sev = "Info"
                conf = str(data.get("confidence") or data.get("issueConfidence")
                           or data.get("issue_confidence") or "Certain").title()
                key = (name, host, path_part, sev)
                if key in seen:
                    continue
                seen.add(key)
                item = {
                    "name": name,
                    "severity": sev,
                    "confidence": conf,
                    "url": url,
                    "issue_detail": (data.get("detail") or data.get("issueDetail")
                                     or data.get("issue_detail") or ""),
                    "issue_background": data.get("issue_background")
                                        or data.get("issueBackground") or "",
                    "issue_remediation": data.get("remediation")
                                         or data.get("issueRemediation") or "",
                    "issue_type_index": data.get("issue_type_index")
                                        or data.get("issueTypeIndex") or "",
                    "evidence": data.get("evidence") or [],
                }
                nrm = self.normalize_issue(item, fallback_url=url or "")
                if nrm:
                    nrm["bridge_confirmed"] = False
                    nrm["source"] = "burp_scanner_fallback"
                    if conf and conf.lower() not in ("unknown", ""):
                        nrm["confidence"] = conf
                    if item["issue_remediation"]:
                        nrm["remediation"] = item["issue_remediation"]
                    if item["evidence"]:
                        nrm["evidence"] = item["evidence"]
                    findings.append(nrm)

        # --- 层级 3：GET /scan/{id}/issues 官方端点最后兜底 ---
        rest_issues: List[Dict] = []
        for sid in ok_ids:
            try:
                raw = await self.get_scan_issues(sid)
                if isinstance(raw, list) and raw:
                    rest_issues.extend(raw)
            except Exception as e:
                logger.debug(f"get_scan_issues({sid}) fail: {e}")
        logger.info(f"📥 [Burp] 层级3(GET /scan/id/issues) = {len(rest_issues)} 条")
        for issue in rest_issues:
            nrm = self.normalize_issue(issue)
            if nrm:
                findings.append(nrm)

        # 去重（按 finding 的 type + url）
        dedup: List[Dict] = []
        seen_f = set()
        for f in findings:
            if not isinstance(f, dict): continue
            k = (str(f.get("type") or f.get("name")),
                 str(f.get("url"))[:200])
            if k in seen_f: continue
            seen_f.add(k)
            dedup.append(f)
        logger.info(
            f"📥 [Burp] 扫描完成。合计 {len(findings)} 条 → 去重后 "
            f"{len(dedup)} 条（桥={len(bridge_issues)} REST回退="
            f"{max(0, len(findings) - len(bridge_issues) - len(rest_issues))}"
            f" 官方端点={len(rest_issues)}）"
        )
        return dedup

    async def get_cookies_from_history(
        self,
        limit: int = 100,
        filter_self: bool = True,
        target_domain: Optional[str] = None
    ) -> Dict[str, Dict[str, str]]:
        """提取 Cookie（步骤1）。

        优先从 Burp Proxy History 响应头的 Set-Cookie 解析；
        Burp 不可用时回退到手工导出的 ~/burp_cookies.json。
        """
        cookies = await self._extract_cookies_from_history(limit)
        if not cookies:
            cookies = self._load_cookie_file()

        if not target_domain:
            if cookies:
                logger.warning("⚠️ get_cookies_from_history 未传入 target_domain，将返回所有 Cookie")
            return cookies

        if target_domain.startswith('www.'):
            target_domain = target_domain[4:]

        filtered = {}
        for domain, cookie_dict in cookies.items():
            clean_domain = str(domain).lstrip('.')
            if clean_domain == target_domain or clean_domain.endswith('.' + target_domain):
                filtered[domain] = cookie_dict

        logger.info(f"🔒 已过滤，返回 {len(filtered)} 个匹配域名的凭证")
        return filtered

    def _load_cookie_file(self) -> Dict[str, Dict[str, str]]:
        cookie_file = os.path.expanduser("~/burp_cookies.json")
        if not os.path.exists(cookie_file):
            return {}
        try:
            with open(cookie_file, 'r', encoding='utf-8') as f:
                all_cookies = json.load(f)
            logger.debug(f"从 burp_cookies.json 加载了 {len(all_cookies)} 个域名的凭证")
            return all_cookies or {}
        except Exception as e:
            logger.warning(f"读取 burp_cookies.json 失败: {e}")
            return {}

    async def _extract_cookies_from_history(self, limit: int) -> Dict[str, Dict[str, str]]:
        """从 Proxy History 的响应头解析 Set-Cookie（后见覆盖先见）。"""
        try:
            if not await self.get_status():
                return {}
            history = await self.get_history_since(0, limit=limit)
            cookies: Dict[str, Dict[str, str]] = {}
            for entry in history:
                host = (entry.get("host") or "").split(":")[0]
                if not host:
                    continue
                for sc in entry.get("response_set_cookies") or []:
                    pair = sc.split(";", 1)[0].strip()
                    if not pair or "=" not in pair:
                        continue
                    name, _, value = pair.partition("=")
                    name, value = name.strip(), value.strip()
                    if not name or name.lower() in _COOKIE_ATTRS:
                        continue
                    if not value or value.lower() == "deleted":
                        continue
                    cookies.setdefault(host, {})[name] = value
            if cookies:
                logger.info(f"🍪 从 Burp Proxy history 提取到 {len(cookies)} 个域名的 Cookie")
            return cookies
        except Exception as e:
            logger.debug(f"从 Burp history 提取 Cookie 失败: {e}")
            return {}

    async def get_tokens_from_history(
        self,
        limit: int = 100,
        filter_self: bool = True,
        target_domain: Optional[str] = None
    ) -> Dict[str, Dict[str, str]]:
        """从 Proxy History 的请求头提取 Token 类凭证（步骤1）。"""
        tokens: Dict[str, Dict[str, str]] = {}
        try:
            if not await self.get_status():
                return {}
            history = await self.get_history_since(0, limit=limit)
            for entry in history:
                host = (entry.get("host") or "").split(":")[0]
                if not host:
                    continue
                for name, value in (entry.get("request_headers") or {}).items():
                    if str(name).lower() in _TOKEN_HEADERS and value:
                        tokens.setdefault(host, {})[name] = str(value)
        except Exception as e:
            logger.debug(f"从 Burp history 提取 Token 失败: {e}")
        if tokens:
            logger.info(f"🔑 从 Burp Proxy history 提取到 {len(tokens)} 个域名的 Token")
        if target_domain:
            if target_domain.startswith('www.'):
                target_domain = target_domain[4:]
            tokens = {
                d: v for d, v in tokens.items()
                if str(d).lstrip('.') == target_domain
                or str(d).lstrip('.').endswith('.' + target_domain)
            }
        return tokens

    async def get_traffic_by_browser(self) -> Dict[str, List[Dict]]:
        return {"edge": [], "chrome": [], "other": []}

    async def get_history_since(self, timestamp: float, limit: int = 50) -> List[Dict]:
        """从 Burp Proxy 历史拉取流量（GET /v0.1/proxy/history，步骤1）。

        timestamp <= 0 表示不限时间，取最新 limit 条（先查 count 再用 offset 定位）。
        返回扁平化条目（url/method/host/status/timestamp/请求响应头），
        供 _fetch_from_burp 等直接消费。
        服务端 after 过滤若不被当前版本支持，自动降级为全量拉取 + 本地时间过滤。
        """
        if not await self.get_status():
            return []
        num = int(limit) if limit and limit > 0 else 50
        try:
            if timestamp and timestamp > 0:
                iso = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                )
                result = await self._request(
                    "GET", f"/proxy/history?after={quote(iso)}&num={num}"
                )
                if not (isinstance(result, dict) and result.get("events")):
                    # 降级：某些版本不支持 after 参数
                    result = await self._request("GET", f"/proxy/history?num={num}")
                entries = self._parse_history_response(result, timestamp)
            else:
                probe = await self._request("GET", "/proxy/history?num=1")
                total = probe.get("count", 0) if isinstance(probe, dict) else 0
                offset = max(0, int(total or 0) - num)
                result = await self._request(
                    "GET", f"/proxy/history?offset={offset}&num={num}"
                )
                entries = self._parse_history_response(result, 0)
            if entries:
                _out = entries[:num] if num else entries
                self._feed_live_from_history(_out)
                return _out
        except Exception as e:
            logger.debug(f"Burp proxy history 获取失败: {e}")

        # ---- 扩展桥回退：精简 REST API（如 Burp 2026.x）无 /proxy/history 端点 ----
        if not self._bridge_checked:
            self._bridge_checked = True
            if self.get_bridge_status():
                logger.info("🌉 检测到 Burp 扩展桥，被动采集走 JSONL 通道")
        _bridge_entries = self.get_history_from_bridge(limit=num)
        self._feed_live_from_history(_bridge_entries)  # R2-A S1: Burp 流回注
        return _bridge_entries

    def _feed_live_from_history(self, entries: List[Dict]) -> int:
        """R2-A S1: Burp 流量流 → LiveIntake 回注（开关关时零成本短路）。

        每条历史条目的 URL 与其 query 参数构成注入面；重复/低分由 LiveIntake
        内部双层防重与评分阈值滤除。异常全吞，绝不影响被动采集主流程。
        """
        try:
            from urllib.parse import parse_qs, urlparse
            from vulnclaw.modules.live_intake import feed_live
        except Exception:  # noqa: BLE001
            return 0
        fed = 0
        for e in entries or []:
            try:
                url = str((e or {}).get("url") or "").strip()
                if not url.lower().startswith(("http://", "https://")):
                    continue
                q = parse_qs(urlparse(url).query, keep_blank_values=True)
                params = {k: (v[0] if v else "") for k, v in q.items()}
                if feed_live(url, method=str((e or {}).get("method") or "GET"),
                             params=params, source="burp"):
                    fed += 1
            except Exception:  # noqa: BLE001
                logger.debug("suppressed exception (live intake burp)")
                continue
        return fed

    def _parse_history_response(self, result: Any, min_timestamp: float) -> List[Dict]:
        if not isinstance(result, dict):
            return []
        entries: List[Dict] = []
        for event in result.get("events") or []:
            try:
                entry = self._normalize_history_event(event)
            except Exception:
                continue
            if entry is None:
                continue
            if min_timestamp > 0:
                ts = entry.get("timestamp") or 0
                if ts and ts < min_timestamp * 1000:
                    continue
            entries.append(entry)
        if entries:
            logger.info(f"📥 Burp proxy history 解析出 {len(entries)} 条流量")
        return entries

    @classmethod
    def _normalize_history_event(cls, event: Any) -> Optional[Dict]:
        """把 /proxy/history 的 event 扁平化为稳定结构。

        兼容 requestResponse.request/response 嵌套与顶层 request/response 两种形态，
        兼容 headers 为 [{name,value}] 列表或 dict 两种形态。
        """
        if not isinstance(event, dict):
            return None
        rr = event.get("requestResponse")
        if not isinstance(rr, dict):
            rr = {}
        req = rr.get("request") if isinstance(rr.get("request"), dict) else event.get("request")
        resp = rr.get("response") if isinstance(rr.get("response"), dict) else event.get("response")
        req = req if isinstance(req, dict) else {}
        resp = resp if isinstance(resp, dict) else {}
        url = req.get("url") or ""
        if not url:
            return None
        parsed = urlparse(url)
        resp_headers = resp.get("headers")
        return {
            "url": url,
            "method": req.get("method") or "",
            "host": parsed.netloc,
            "path": parsed.path,
            "status": resp.get("statusCode"),
            "timestamp": cls._parse_event_time(event, rr),
            "request_headers": cls._headers_to_dict(req.get("headers")),
            "response_headers": cls._headers_to_dict(resp_headers),
            "response_set_cookies": cls._header_values(resp_headers, "set-cookie"),
            "request_body": req.get("body"),
            "response_body": resp.get("body"),
        }

    @staticmethod
    def _headers_to_dict(headers: Any) -> Dict[str, str]:
        result: Dict[str, str] = {}
        if isinstance(headers, dict):
            return {str(k): (v if isinstance(v, str) else str(v)) for k, v in headers.items()}
        if isinstance(headers, list):
            for h in headers:
                if isinstance(h, dict) and h.get("name"):
                    result[str(h["name"])] = str(h.get("value", ""))
        return result

    @staticmethod
    def _header_values(headers: Any, name_lower: str) -> List[str]:
        """取出指定头名的全部值（含重复头，如多个 Set-Cookie）。"""
        values: List[str] = []
        if isinstance(headers, list):
            for h in headers:
                if isinstance(h, dict) and str(h.get("name", "")).lower() == name_lower:
                    values.append(str(h.get("value", "")))
        elif isinstance(headers, dict):
            for k, v in headers.items():
                if str(k).lower() == name_lower:
                    if isinstance(v, list):
                        values.extend(str(x) for x in v)
                    elif v is not None:
                        values.append(str(v))
        return values

    @staticmethod
    def _parse_event_time(event: Dict, rr: Dict) -> Optional[int]:
        """解析事件时间为 epoch 毫秒。兼容秒/毫秒时间戳与 ISO-8601 字符串。"""
        candidates = []
        proxy = event.get("proxy")
        if isinstance(proxy, dict):
            candidates.append(proxy.get("time"))
        if isinstance(rr, dict):
            candidates.append(rr.get("time"))
        candidates.append(event.get("time"))
        for t in candidates:
            if isinstance(t, (int, float)):
                ts = int(t)
                if ts < 10 ** 12:  # 秒级时间戳
                    ts *= 1000
                return ts
            if isinstance(t, str) and t:
                try:
                    dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
                    return int(dt.timestamp() * 1000)
                except ValueError:
                    continue
        return None

    async def get_extension_data(self, extension_name: str) -> List[Dict]:
        return []

    async def collaborator_generate(self) -> Dict:
        """获取 OOB 域名（步骤0 重写）。

        Burp REST API（v0.1）没有 /collaborator/* 端点，旧代码该调用永远 404；
        旧降级实现还会伪造未注册的 oast.fun 假域名，导致 OOB 检测静默漏报。

        现在统一委托 core.oob_channel.OOBChannel（auto 模式：interactsh 为主，
        dnslog.cn 为备），interactsh-client 不可用时自动回退 dnslog，不再让
        主扫描路径在 interactsh 挂掉时直接跳过 OOB——此前与 verify 阶段的
        OOBVerifier（有 interactsh→dnslog→local 回退）行为不一致，构成能力缺口。
        两者均不可用才返回 {"domain": None}，由调用方跳过 OOB 检测，不再伪造域名。
        """
        if self._collaborator_domain:
            logger.debug(f"使用缓存的 Collaborator 域名: {self._collaborator_domain}")
            return {"domain": self._collaborator_domain}

        try:
            from vulnclaw.core.oob_channel import OOBChannel
            self._oob_channel = OOBChannel(provider="auto")
            domain = await asyncio.wait_for(self._oob_channel.request_domain(), timeout=settings.oob_domain_timeout)
        except asyncio.TimeoutError:
            logger.warning("⚠️ OOB 通道申请超时（interactsh + dnslog 均未在 20s 内就绪）")
            domain = None
        except Exception as e:  # noqa: BLE001
            logger.debug(f"OOB 通道申请异常: {e}")
            domain = None

        if domain and "." in domain:
            self._collaborator_domain = domain
            provider = getattr(self._oob_channel, "_resolved_provider", "unknown")
            logger.info(f"✅ OOB 通道就绪 ({provider}): {domain}")
            return {"domain": domain, "provider": provider}

        logger.warning("⚠️ 无可用 OOB 通道（interactsh 与 dnslog 均不可用），本轮跳过 OOB 检测")
        return {"domain": None, "error": "no_oob_channel"}

    async def collaborator_poll(self, domain: str) -> Dict:
        """轮询 OOB 回调（步骤0 重写）。

        优先复用 collaborator_generate 时创建的 OOBChannel 实例（它知道本次
        域名来自 interactsh 还是 dnslog，自动路由到对应轮询实现）；若该实例
        不存在（旧调用路径直接 check），回退到 legacy interactsh 轮询。
        """
        if not domain or "." not in domain:
            return {"results": [], "count": 0}
        ch = getattr(self, "_oob_channel", None)
        if ch is not None and getattr(ch, "_domain", None):
            try:
                interactions = await ch.poll(timeout=settings.oob_poll_timeout)
                results = [i.to_dict() for i in (interactions or [])]
                return {"results": results, "count": len(results)}
            except Exception as e:  # noqa: BLE001
                logger.debug(f"OOBChannel 回调轮询失败: {e}")
                return {"results": [], "count": 0}
        # legacy 回退：仅 interactsh 域名有效
        try:
            from vulnclaw.modules.vuln_scanner.oob_interactsh import get_interactsh_poll
            interactions = await get_interactsh_poll(domain, timeout=settings.oob_poll_timeout)
            interactions = interactions or []
            return {"results": interactions, "count": len(interactions)}
        except Exception as e:
            logger.debug(f"OOB 回调轮询失败: {e}")
            return {"results": [], "count": 0}


class BurpController:
    def __init__(self):
        self.burp = None
        self.session = None
        self._interactsh_domain = None

    def set_session(self, session):
        self.session = session

    def _get_burp(self):
        if self.burp is None:
            self.burp = get_burp_client()
        return self.burp

    async def _ensure_session(self):
        if self.session is None:
            logger.warning("⚠️ BurpController.session 未设置，使用共享会话")
            self.session = await get_shared_session()

    async def collaborator(
        self,
        action: str = "get_domain",
        payloads: List[str] = None,
        timeout: int = 30
    ) -> Dict:
        logger.info(f"📡 [Burp] AI 启动协作器: {action}")
        burp = self._get_burp()

        if action == "get_domain":
            if burp:
                result = await burp.collaborator_generate()
                if result and result.get('domain'):
                    self._interactsh_domain = result['domain']
                    logger.info(f"✅ Collaborator 就绪: {self._interactsh_domain}")
                    return {
                        "domain": self._interactsh_domain,
                        "url": f"http://{self._interactsh_domain}"
                    }
                logger.warning("⚠️ 无可用 OOB 通道，本轮跳过 OOB 检测（步骤0：不再伪造域名）")
                return {"domain": None, "error": "no_oob_channel"}
            return {"domain": None, "error": "burp_client_unavailable"}

        elif action == "check":
            if not self._interactsh_domain:
                return {"error": "没有 Collaborator 域名", "results": [], "count": 0}
            if burp:
                result = await burp.collaborator_poll(self._interactsh_domain)
                if result:
                    results = result.get('results', []) or result.get('interactions', [])
                    return {"results": results, "count": len(results)}
            return {"results": [], "count": 0}

        elif action == "generate_payload":
            if not self._interactsh_domain:
                await self.collaborator("get_domain")
            if not self._interactsh_domain:
                return {"payloads": [], "domain": None, "error": "no_oob_channel"}
            if not payloads:
                payloads = []
            generated = []
            for p in payloads:
                if self._interactsh_domain:
                    generated.append(p.replace("{{collaborator-domain}}", self._interactsh_domain))
            if not generated:
                generated = [
                    f"http://{self._interactsh_domain}",
                    f"ping {self._interactsh_domain}",
                ]
            logger.info(f"✅ 生成 {len(generated)} 个带外 Payload")
            return {"payloads": generated, "domain": self._interactsh_domain}

        return {"error": "未知操作"}


_burp_client: Optional[BurpClient] = None
_burp_controller: Optional[BurpController] = None


def get_burp_client() -> Optional[BurpClient]:
    global _burp_client
    if _burp_client is None:
        try:
            from vulnclaw.config.settings import settings as _st
            base_url = _st.burp_api_url or "http://127.0.0.1:1337"
            api_key = _st.burp_api_key or ""
            _burp_client = BurpClient(
                base_url=base_url,
                api_key=api_key,
                max_retries=3,
                connect_timeout=settings.request_timeout,
                read_timeout=30  # 保留原值：Burp 大响应读取需宽松超时（勿收紧）
            )
        except Exception as e:
            logger.error(f"❌ 创建 BurpClient 失败: {e}")
            return None
    return _burp_client


def get_burp_controller() -> BurpController:
    global _burp_controller
    if _burp_controller is None:
        _burp_controller = BurpController()
    return _burp_controller


async def close_burp_client():
    global _burp_client
    if _burp_client:
        await _burp_client.close()
        _burp_client = None