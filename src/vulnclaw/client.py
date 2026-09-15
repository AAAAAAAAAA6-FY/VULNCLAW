# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""workflow7 生态/API：dashboard REST 客户端的薄封装（httpx.AsyncClient）。

设计目标
--------
- **薄**：只负责拼 URL / header / JSON body，具体请求语义由 dashboard 服务端决定。
- **离线可单测**：``base_url`` 仅作参数，模块内没有真实联网逻辑；测试用
  ``build_request``（httpx build-only，不发送）即可断言方法 / URL / 头 / body，
  不会触发任何网络。
- **可选鉴权**：构造时 ``token`` 非空自动带 ``X-Dashboard-Token`` header。
- **互导复用**：``build_payload`` 包装 ``core.interop.export_any``，把 finding
  列表序列化为所选格式的 webhook payload。
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional, Union

import httpx

from vulnclaw.core.interop import export_any, resolve_format, to_unified_dicts

#: 导入侧接受的 webhook 功能格式（与 interop.IMPORTERS 对齐，文档/校验用）
INGEST_FORMATS = (
    "nuclei_jsonl", "jsonl", "vulnclaw_json", "burp_xml",
    "zap_json", "sarif", "csv", "raw_http",
)


def _serialize(payload: Any) -> str:
    """把非字符串 payload 序列化为 JSON 文本（确定性 ensure_ascii=False）。"""
    if isinstance(payload, str):
        return payload
    return json.dumps(payload, ensure_ascii=False, default=str)


class DashboardClient:
    """VULNCLAW dashboard REST 客户端（薄封装，离线可测）。

    Args:
        base_url: dashboard 根地址，如 ``http://127.0.0.1:8080``（仅参数，不触发联网）。
        token: 可选的 ``DASHBOARD_TOKEN``；非空时所有请求自动带 ``X-Dashboard-Token``。
        timeout: httpx 超时秒数。
    """

    def __init__(self, base_url: str, token: str = "", timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token or ""
        headers = {"Accept": "application/json"}
        if self.token:
            headers["X-Dashboard-Token"] = self.token
        self._headers = headers
        self._timeout = timeout
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=self._timeout)

    async def aclose(self) -> None:
        """关闭底层 httpx.AsyncClient。"""
        await self._client.aclose()

    # ---------- 请求构造（build-only，可离线断言） ----------
    def build_request(self, method: str, path: str, **kwargs: Any) -> httpx.Request:
        """构造但不发送一个 httpx.Request（便于离线单测 URL/头/body）。

        每次构造都会应用 ``self._headers``；除非调用方显式覆盖同名头。
        """
        merged = dict(self._headers)
        merged.update(kwargs.pop("headers", {}))
        return self._client.build_request(method, path, headers=merged, **kwargs)

    # ---------- API ----------
    async def get_status(self) -> httpx.Response:
        return await self._send(self.build_request("GET", "/api/status"))

    async def list_scans(self) -> httpx.Response:
        return await self._send(self.build_request("GET", "/api/scans"))

    async def get_scan(self, scan_id: str) -> httpx.Response:
        return await self._send(self.build_request("GET", "/api/scans/{0}".format(scan_id)))

    async def get_findings(self, scan_id: Optional[str] = None) -> httpx.Response:
        params: Dict[str, Any] = {} if scan_id is None else {"scan_id": scan_id}
        return await self._send(self.build_request("GET", "/api/findings", params=params))

    async def start_scan(self, target: str, **kw: Any) -> httpx.Response:
        body: Dict[str, Any] = {"target": target}
        body.update(kw)
        return await self._send(self.build_request("POST", "/api/scans", json=body))

    async def push_findings(self, fmt: str, payload: Union[str, list, dict]) -> httpx.Response:
        body = {"format": fmt, "payload": _serialize(payload)}
        return await self._send(
            self.build_request("POST", "/api/webhook/ingest", json=body))

    # ---------- 底层发送 ----------
    async def _send(self, request: httpx.Request) -> httpx.Response:
        return await self._client.send(request)

    # ---------- 静态辅助 ----------
    @staticmethod
    def build_payload(fmt: str, findings: Any) -> Dict[str, str]:
        """把 finding 列表序列化为 webhook ingest 可消费的 payload dict（见模块级同名函数）。"""
        return build_payload(fmt, findings)


def build_payload(fmt: str, findings: Any) -> Dict[str, str]:
    """把 finding 列表序列化为 webhook ingest 可消费的 payload dict。

    经 ``core.interop`` 的 ``to_unified_dicts + export_any`` 生成确定性文本，
    返回 ``{"format": <规范化格式>, "payload": <导出文本>}``，可直接喂
    ``push_findings``。
    """
    fkey = resolve_format(fmt)
    text = export_any(to_unified_dicts(findings), fkey)
    return {"format": fkey, "payload": text}


__all__ = ["DashboardClient", "INGEST_FORMATS", "build_payload"]