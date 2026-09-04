# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""A3.2: 目标画像持久化 + 增量扫描只测变化面。

验收判据：二次扫描跳过未变资产（日志可证）。

设计：
- recon 完成后从 brief 构建目标画像（surface_fp = 目标表面整体指纹，
  assets = 端点级指纹表），收尾经 IncrementalSaver.save_target_profile 落库
  （该 API 此前零调用，此处闭合其数据链）。
- 下次扫描 taskgen 阶段：surface_fp 一致 → 参数级任务全部跳过；
  端点级指纹一致 → 该端点的任务跳过；画像超 TTL → 视为过期全量重扫。
- 纯函数（build/surface_fp/diff）与 IO（save/load）分离，便于单测。

本模块不发起任何网络请求；指纹只消费 recon brief 里已有的确定性字段。
"""
import hashlib
import json
import time
from typing import Any, Dict, Optional, Tuple

from vulnclaw.core.logger import logger

__all__ = [
    "build_asset_profile",
    "surface_fp",
    "profile_expired",
    "target_unchanged",
    "crawl_asset_unchanged",
    "generic_asset_unchanged",
    "save_profile",
    "load_prev_profile",
]

_SAVER = None  # 进程级单例（惰性创建）


def _get_saver():
    global _SAVER
    if _SAVER is None:
        from vulnclaw.core_modules.persistence import IncrementalSaver

        _SAVER = IncrementalSaver()
    return _SAVER


def _canon(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)


def _fp(obj: Any) -> str:
    return hashlib.sha1(_canon(obj).encode("utf-8")).hexdigest()[:16]


def _ep_url(item: Any) -> str:
    url = item.get("url") if isinstance(item, dict) else item
    return url.split("?", 1)[0] if isinstance(url, str) else ""


def _ep_params(item: Any) -> list:
    params = item.get("params") if isinstance(item, dict) else None
    if isinstance(params, list):
        return sorted(str(p) for p in params if p)
    return []


def surface_fp(brief: Optional[Dict]) -> str:
    """目标表面整体指纹：只取影响攻击面的确定性字段。"""
    brief = brief or {}
    _view = {
        "status": brief.get("status"),
        "tech_stack": sorted(str(t) for t in (brief.get("tech_stack") or [])),
        "url_params": sorted(str(p) for p in (brief.get("url_params") or [])),
        "forms": sorted(str(f) for f in (brief.get("forms") or [])),
        "apis": sorted(_ep_url(a) for a in (brief.get("apis") or [])),
        "js_endpoints": sorted(_ep_url(j) for j in (brief.get("js_endpoints") or [])),
        "crawled_endpoints": sorted(_ep_url(c) for c in (brief.get("crawled_endpoints") or [])),
        "open_ports": sorted(brief.get("open_ports") or []),
        "subdomains": sorted(str(s) for s in (brief.get("subdomains") or [])),
    }
    return _fp(_view)


def build_asset_profile(target: str, brief: Optional[Dict]) -> Dict:
    """从 recon brief 构建目标画像（含端点级指纹表）。"""
    brief = brief or {}
    assets: Dict[str, str] = {}
    for item in brief.get("crawled_endpoints") or []:
        url = _ep_url(item)
        if url:
            assets[f"ep::{url}"] = _fp({"u": url, "p": _ep_params(item)})
    for item in brief.get("apis") or []:
        url = _ep_url(item)
        if url:
            assets[f"api::{url}"] = _fp({"a": url})
    for item in brief.get("js_endpoints") or []:
        url = _ep_url(item)
        if url:
            assets[f"js::{url}"] = _fp({"j": url})
    return {
        "target": target,
        "surface_fp": surface_fp(brief),
        "assets": assets,
        "updated_at": time.time(),
    }


def profile_expired(profile: Optional[Dict], ttl_hours: float) -> bool:
    """画像超龄视为过期（过期 → 全量重扫，避免陈旧指纹掩盖真实变化）。"""
    if not profile:
        return True
    try:
        ts = float(profile.get("updated_at") or 0)
    except (TypeError, ValueError):
        return True
    if ts <= 0:
        return True
    return (time.time() - ts) > max(0.0, float(ttl_hours)) * 3600.0


def target_unchanged(
    prev_profile: Optional[Dict], brief: Optional[Dict], ttl_hours: float
) -> bool:
    """目标表面与上次画像完全一致（且画像未过期）→ 参数级任务可整体跳过。"""
    if not prev_profile or profile_expired(prev_profile, ttl_hours):
        return False
    prev_fp = prev_profile.get("surface_fp")
    return bool(prev_fp) and prev_fp == surface_fp(brief)


def crawl_asset_unchanged(prev_assets: Dict, url: str, params: Any) -> bool:
    """端点级判定：同 URL（去 query）且同参数集 → 该端点任务可跳过。"""
    if not isinstance(prev_assets, dict) or not prev_assets:
        return False
    key_url = url.split("?", 1)[0] if isinstance(url, str) else ""
    if not key_url:
        return False
    fp = _fp({"u": key_url, "p": sorted(str(p) for p in (params or []) if p)})
    return prev_assets.get(f"ep::{key_url}") == fp


def generic_asset_unchanged(prev_assets: Dict, prefix: str, raw: Any) -> bool:
    """api/js 端点级判定（key 前缀区分来源）。"""
    if not isinstance(prev_assets, dict) or not prev_assets:
        return False
    url = _ep_url(raw)
    if not url:
        return False
    return prev_assets.get(f"{prefix}::{url}") == _fp({prefix[0] if prefix else "x": url})


async def save_profile(target: str, profile: Dict, saver=None) -> None:
    """画像落库（复用 IncrementalSaver 攒批 KV，强制 flush 保证可证）。"""
    sv = saver or _get_saver()
    await sv.save_target_profile(target, profile)
    await sv.flush()


def load_prev_profile(target: str, saver=None) -> Optional[Dict]:
    return (saver or _get_saver()).load_target_profile(target)
