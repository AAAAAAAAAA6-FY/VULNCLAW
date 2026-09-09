# -*- coding: utf-8 -*-
"""目标反检测基线（2026-09-07）。

问题：SPA 大站（如 Audible）正常页面天生携带大量动态 UUID + 大体积响应，
按出厂固定阈值（uuid>15 / text>8000）会被误判为蜜罐/假404 → 指数退避 → 扫描停摆。

方案：扫描起步时对目标做少量采样，统计"正常页面"动态特征峰值，
推导判定阈值 = max(出厂默认, 峰值 x 余量系数)。零手动、量体定制。

优先级：用户显式配置 > 目标基线 > 出厂默认。
结果经模块级注册表全局可读 get_anti_scan_baseline()。
"""
import asyncio
import math
import re
import uuid
from dataclasses import dataclass
from typing import List, Optional

import aiohttp

from vulnclaw.core.logger import logger

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)
_PLACEHOLDER_RE = re.compile(
    r"\{\{[a-zA-Z_][a-zA-Z0-9_]*\}\}|__[a-zA-Z0-9]{16,}__|id=\"[a-zA-Z0-9]{20,}\""
)

# 出厂默认（与 AntiScanDetector 保持一致）
DEF_UUID_TH = 15
DEF_MIN_TEXT = 8000
DEF_PLACEHOLDER_TH = 10


@dataclass
class AntiScanBaseline:
    """目标反检测基线快照。"""

    probed: bool = False                       # 是否成功学到基线
    uuid_threshold: int = DEF_UUID_TH          # 推导的 UUID 判定阈值
    min_text: int = DEF_MIN_TEXT               # 推导的正文长度阈值
    placeholder_threshold: int = DEF_PLACEHOLDER_TH
    sample_max_uuid: int = 0                   # 采样峰值
    sample_max_len: int = 0
    sample_max_placeholder: int = 0
    samples: int = 0
    fingerprint: str = ""                      # 摘要：uuid/len/status


# 进程级注册表（仅供最近一次扫描；无并发写）
_baseline: Optional[AntiScanBaseline] = None


def get_anti_scan_baseline() -> Optional[AntiScanBaseline]:
    """返回最近一次目标基线；未探测过返回 None。"""
    return _baseline


def _reset_baseline() -> None:
    global _baseline
    _baseline = None


def _count_features(text: str) -> tuple:
    return (
        len(_UUID_RE.findall(text or "")),
        len(text or ""),
        len(_PLACEHOLDER_RE.findall(text or "")),
    )


async def detect_anti_scan_baseline(
    target: str,
    *,
    session=None,
    headers: Optional[dict] = None,
    concurrency: int = 2,
    samples: Optional[int] = None,
) -> AntiScanBaseline:
    """对目标做少量采样，统计动态特征峰值并推导判定阈值。

    采样点：目标根路径 + 少量随机不存在路径（覆盖"软404"响应特征）。
    阈值 = max(出厂默认, ceil(峰值 x 余量系数))；余量系数取 settings
    anti_scan_baseline_factor（默认 1.5），宁钝勿误（低误报政策）。

    2026-09-08 修复（SPA 带登录态基线失配）：必须复用运行时会话（带 auth
    cookie / Burp 出口）采样。此前用独立直连会话 → Audible 未登录拿到轻量页
    (uuid=2)，运行时登录页 426 UUID 直接击穿阈值 -> 全站误判蜜罐。现在调用方
    传入 self.session，采样与运行时同通道同内容，阈值量体定制。
    """
    global _baseline
    from vulnclaw.config.settings import settings

    factor = float(getattr(settings, "anti_scan_baseline_factor", 1.5) or 1.5)
    n = int(getattr(settings, "anti_scan_baseline_samples", 6) or 6)
    n = max(1, n)

    close_session = False
    import aiohttp  # noqa: F401  统一在此导入，_probe 内部直接可用

    _sem = asyncio.Semaphore(max(1, min(concurrency, n)))
    try:
        if session is None:
            # 独立 aiohttp 直连会话：绕过全局限流器，不影响探测结论
            session = aiohttp.ClientSession()
            close_session = True
        pts = [target.rstrip("/")]
        for i in range(max(0, n - 1)):
            pts.append(target.rstrip("/") + "/" + uuid.uuid4().hex[:7])

        async def _probe(url: str):
            async with _sem:
                _kwargs = {"timeout": aiohttp.ClientTimeout(total=15)}
                if concurrency > 1:
                    _kwargs["allow_redirects"] = False
                resp = await asyncio.wait_for(
                    session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)),
                    timeout=15,
                )
                return resp

        max_u = max_l = max_p = 0
        ok = 0
        for p in pts[: n if n > 0 else 6]:
            try:
                resp = await asyncio.wait_for(
                    _probe(p), timeout=18,
                )
                txt = await resp.text()
                status = resp.status
                u, l_, pp = _count_features(txt)
                max_u = max(max_u, u)
                max_l = max(max_l, l_)
                max_p = max(max_p, pp)
                ok += 1
            except Exception:
                continue
        if ok == 0:
            logger.warning("反检测基线：采样全失败，沿用出厂默认阈值")
            return AntiScanBaseline()
        bl = AntiScanBaseline(
            probed=True,
            uuid_threshold=max(DEF_UUID_TH, _ceil_mul(max_u, factor)),
            min_text=max(DEF_MIN_TEXT, _ceil_mul(max_l, factor)),
            placeholder_threshold=max(DEF_PLACEHOLDER_TH, _ceil_mul(max_p, factor)),
            sample_max_uuid=max_u,
            sample_max_len=max_l,
            sample_max_placeholder=max_p,
            samples=ok,
            fingerprint=f"uuid={max_u}/len={max_l}",
        )
        _baseline = bl
        logger.debug(
            "反检测基线: %s → uuid>%s len>%s ph>%s (%s)",
            bl.fingerprint, bl.uuid_threshold, bl.min_text,
            bl.placeholder_threshold, bl.samples,
        )
        return bl
    finally:
        if close_session:
            asyncio.ensure_future(session.close())


async def _fetch(session, url):
    return await asyncio.wait_for(
        session.get(url, timeout=aiohttp.ClientTimeout(total=15)), timeout=15
    )


def _ceil_mul(v: int, factor: float) -> int:
    return int(math.ceil(v * factor))


__all__ = [
    "AntiScanBaseline", "get_anti_scan_baseline", "detect_anti_scan_baseline",
]
