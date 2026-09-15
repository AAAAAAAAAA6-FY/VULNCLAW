# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ============================================================
# modules/asset_surface.py —— B4 资产面枚举端（道3）
# ============================================================
"""B4 资产面枚举：在既有侦察之下补齐"资产覆盖面"。

目标面（7 类，全部 fail-open + 预算硬超时，异常绝不影响主流程）：
  1. 子域        —— 复用 recon 既有结果（subdomains），不做重复劳动
  2. API         —— 复用既有 apis/js_endpoints + 补充 swagger/openapi/graphql 显式探测
  3. 移动端      —— 移动前缀子域（m/app/…）+ 页面 .apk 下载链接识别
  4. 供应链前端   —— 页面/JS 引用的第三方 CDN 域名与 JS 库版本线索（信息收集，不派任务）
  5. 云资产(桶)  —— 由主域派生候选桶名，探测 S3/OSS/COS/GCS/Azure 是否被误公开
  6. 开发者设施   —— .git/.svn 泄露 + CI 配置文件 + 调试口，返回可入池的探测 URL
  7. 公开仓库线索 —— GitHub 仓库/代码搜索（受 OSINT 开关约束，无 token 静默降级）

授权红线（与 phases_executor/_scope_guard 同口径）：
  * 新增可扫描资产（URL）一律经 url_in_scope 校验，越界只进"线索"不进任务池；
  * 外部探测（bucket/GitHub）全部直连公网数据源（requests），不经过目标会话、
    不受 allowed_scope 拦截，但仅在 osint_disable=False 且目标非内网时才启用；
  * 预算默认 90s 总硬超时，子枚举器各自带独立超时，超时即降级该面。
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings

__all__ = ["enumerate_asset_surface"]

# ------------------------------------------------------------
# 常量
# ------------------------------------------------------------
# 移动端常见前缀子域（与既有 recon 的 API_SUBDOMAINS 互补，偏"移动资产"语义）
MOBILE_SUBDOMAIN_PREFIXES = (
    "m", "mobile", "app", "apps", "wap", "3g", "mapi", "mobile-api",
    "api-mobile", "apk", "dl", "download", "store", "h5", "mini", "i",
)

# 常见二级后缀（用于从子域反推主域；与 net_engines.MULTI_LEVEL_SUFFIXES 一致预防漂移）
MULTI_LEVEL_SUFFIXES = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk",
    "co.uk", "org.uk", "com.tw", "co.jp", "com.au", "co.kr", "com.br",
}

# CI / 开发者设施探测路径（命中任一即记录，并入 crawled_endpoints 提示）
DEV_FACILITY_PATHS = (
    ".git/config", ".git/HEAD", ".svn/entries", ".hg/store",
    ".gitlab-ci.yml", ".travis.yml", ".circleci/config.yml",
    "Jenkinsfile", "Jenkinsfile.groovy", "buildspec.yml",
    "cloudbuild.yaml", "bitbucket-pipelines.yml", "azure-pipelines.yml",
    ".env", ".npmrc", ".pypirc", "docker-compose.yml",
)

# 调试口探测路径（命中即记录为 dev_facilities.debug，提示信息泄露）
DEBUG_PATHS = (
    "actuator", "actuator/env", "swagger-ui.html", "swagger/index.html",
    "api-docs", "v2/api-docs", "v3/api-docs", "openapi.json",
    "graphiql", "debug", "druid/index.html", "nacos",
)

# 供应链前端：常见第三方 CDN 域名（命中即只记录，不扫描该外域）
SCM_CDN_MARKERS = (
    "unpkg.com", "jsdelivr.net", "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
    "cloudflare.com", "aliyuncs.com", "alicdn.com",
    "gstatic.com", "googleapis.com", "fastly.net", "cloudfront.net",
    "amazonaws.com", "azureedge.net", "akamaihd.net", "azurefd.net",
)

# 供应链前端：感兴趣的 JS 库（命中即记录库名+版本线索）
SCM_LIB_MARKERS = {
    "react": "React", "vue": "Vue", "angular": "Angular", "jquery": "jQuery",
    "axios": "axios", "lodash": "Lodash", "underscore": "Underscore",
    "element-ui": "Element-UI", "antd": "Ant Design", "echarts": "ECharts",
    "d3": "D3.js", "bootstrap": "Bootstrap", "moment": "Moment.js",
    "dayjs": "Day.js", "webpack": "Webpack", "vite": "Vite", "next": "Next.js",
    "nuxt": "Nuxt.js", "gatsby": "Gatsby", "svelte": "Svelte",
}

# 云存储桶候选名派生规则：由主域 brand 生成
BUCKET_NAME_PATTERNS = (
    "{brand}", "{brand}-assets", "{brand}-static", "{brand}-backup",
    "{brand}-backups", "{brand}-uploads", "{brand}-media", "{brand}-files",
    "{brand}-data", "{brand}-bucket", "{brand}-public", "{brand}-test",
    "{brand}-dev", "{brand}-logs", "{brand}-images", "{brand}s",
)
# 云存储厂商探测端点（provider 名 -> (URL 模板, 不存在指纹)）
BUCKET_PROVIDERS = {
    "aws-s3": (
        "https://{bucket}.s3.amazonaws.com/",
        ("NoSuchBucket", "specified bucket does not exist"),
    ),
    "aliyun-oss-cn-hangzhou": (
        "https://{bucket}.oss-cn-hangzhou.aliyuncs.com/",
        ("NoSuchBucket", "InvalidBucketName"),
    ),
    "aliyun-oss-cn-shanghai": (
        "https://{bucket}.oss-cn-shanghai.aliyuncs.com/",
        ("NoSuchBucket", "InvalidBucketName"),
    ),
    "tencent-cos-ap-shanghai": (
        "https://{bucket}.cos.ap-shanghai.myqcloud.com/",
        ("NoSuchBucket", "The specified bucket does not exist"),
    ),
    "gcs": (
        "https://storage.googleapis.com/{bucket}/",
        ("NoSuchBucket", "The specified bucket does not exist"),
    ),
    "azure-blob": (
        "https://{bucket}.blob.core.windows.net/",
        ("404 BlobNotFound", "The specified resource does not exist"),
    ),
}

# 内网 TLD（与 recon._is_internal_domain 同步判级）
_INTERNAL_TLDS = (".local", ".localhost", ".internal", ".corp", ".lan", ".intranet")


# ------------------------------------------------------------
# 工具函数
# ------------------------------------------------------------
def _is_internal_host(host: str) -> bool:
    """主机为内网/IP/伪 TLD -> True（外部数据源短路用）。"""
    if not host:
        return True
    h = host.strip().lower()
    if "." not in h:
        return True
    for tld in _INTERNAL_TLDS:
        if h.endswith(tld):
            return True
    try:
        import ipaddress as _ia
        ip = _ia.ip_address(h.rstrip("."))
        return bool(ip.is_loopback or ip.is_private or ip.is_link_local
                    or ip.is_multicast or ip.is_unspecified)
    except (ValueError, TypeError):
        return False


def _base_domain(domain: str) -> str:
    """从完整域名（可含端口/路径/scheme）取主域（eTLD+1，处理二级后缀）。"""
    d = (domain or "").strip().lower()
    if "://" in d:
        d = urlparse(d).netloc or d.split("://")[1]
    host = d.split("@")[-1].split(":")[0].split("/")[0].strip(".")
    if not host or _is_internal_host(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    tail = ".".join(parts[-2:])
    # 二级后缀（com.cn / co.uk 等）下的主域应取三段（example.com.cn）
    if tail in MULTI_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return tail


def _brand_from(domain: str) -> str:
    """主域 -> 桶名派生的品牌词（eTLD+1 的首个主标签）。"""
    base = _base_domain(domain or "")
    parts = base.split(".")
    if not parts or not parts[0]:
        return ""
    return re.sub(r"[^a-z0-9_-]", "", parts[0].lower())[:32]


def _strip_www(domain: str) -> str:
    """域名归一：必须用 startswith('www.') 剥前缀（禁 lstrip，防字符集误剥）。"""
    d = (domain or "").strip().lower()
    if d.startswith("www."):
        return d[4:]
    return d


def _norm_url_candidate(host: str) -> str:
    """子域/主机候选 -> https URL（探测用）。"""
    host = (host or "").strip().strip("/")
    if not host:
        return ""
    return "https://" + host if "://" not in host else host


# ------------------------------------------------------------
# 各子枚举器（全部独立 try/except，绝不冒泡）
# ------------------------------------------------------------
async def _enum_mobile_hosts(target: str, domain: str, budget_left: float) -> dict:
    """面3-移动端：常见移动前缀子域存活探测 + 页面 .apk 下载链接识别。"""
    out = {"hosts": [], "apk_urls": [], "alive_urls": []}
    try:
        base = _strip_www(domain or "")
        if not base or _is_internal_host(base):
            return out
        from vulnclaw.core.utils import async_get
        # 1) 前缀子域存活探测（限并发，单个 6s 超时）
        candidates = [f"{p}.{base}" for p in MOBILE_SUBDOMAIN_PREFIXES]
        sem = asyncio.Semaphore(6)
        started = asyncio.get_running_loop().time()

        async def _probe_one(host: str):
            if asyncio.get_running_loop().time() - started > budget_left:
                return
            u = _norm_url_candidate(host)
            if not u:
                return
            async with sem:
                try:
                    resp = await asyncio.wait_for(
                        async_get(u, timeout=6), timeout=4)
                    status = resp[0] if isinstance(resp, (tuple, list)) else 0
                    if 200 <= status < 500:
                        out["hosts"].append(host)
                        out["alive_urls"].append(u)
                except asyncio.TimeoutError:
                    pass  # 单主机超时：降级跳过
                except Exception:  # noqa: BLE001
                    pass

        await asyncio.gather(*(_probe_one(h) for h in candidates))
        if out["hosts"]:
            logger.info(f"      [B4-移动端] 存活移动子域: {len(out['hosts'])}")

        # 2) 目标页面的 .apk / 应用商店链接（仅信息收集，不抓包下载）
        from vulnclaw.core.utils import async_get as _ag
        try:
            resp = await asyncio.wait_for(_ag(target, timeout=8), timeout=6)
            text = resp[1] if isinstance(resp, (tuple, list)) else ""
            if text:
                for m in re.findall(r'["\']([^"\']*\.apk)["\']', text, re.I):
                    if m.startswith(("http", "/")):
                        out["apk_urls"].append(urljoin(target, m))
                store_pat = re.findall(
                    r'["\'](https?://(?:play\.google\.com|apps\.apple\.com)[^"\']+)["\']',
                    text, re.I)
                out["apk_urls"].extend(list(dict.fromkeys(store_pat)))
                if out["apk_urls"]:
                    logger.info(f"      [B4-移动端] 发现移动应用链接: {len(out['apk_urls'])}")
        except Exception:  # noqa: BLE001
            pass
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[B4-移动端] 枚举异常（忽略）: {exc}")
    return out


async def _enum_api_docs(target: str, base: str, budget_left: float) -> dict:
    """面2-API 补充：swagger/openapi/graphql 显式探测（不重复既有 js/apis）。

    注意：这是对目标自身路径的探测（非外部数据源），IP/内网靶机同样有效，
    因此不以内网判定短路——授权由目标域内请求天然满足。
    """
    out = {"endpoints": []}
    paths = (
        "swagger-ui.html", "swagger/index.html", "swagger/v1/swagger.json",
        "api-docs", "v2/api-docs", "v3/api-docs", "openapi.json",
        "graphql", "graphiql", "api/swagger", "swagger",
    )
    try:
        from vulnclaw.core.utils import async_get
        root = target.rstrip("/") + "/"
        sem = asyncio.Semaphore(5)
        started = asyncio.get_running_loop().time()

        async def _probe_one(path: str):
            if asyncio.get_running_loop().time() - started > budget_left:
                return
            u = urljoin(root, path)
            async with sem:
                try:
                    resp = await asyncio.wait_for(async_get(u, timeout=6), timeout=4)
                    status = resp[0] if isinstance(resp, (tuple, list)) else 0
                    body = resp[1] if isinstance(resp, (tuple, list)) else ""
                    if status != 200:
                        return
                    # 区分真命中（swagger JSON / 内省关键词）与软404
                    hit = False
                    for kw in ("swagger", "openapi", "__schema", "graphql"):
                        if kw in body[:4000].lower():
                            hit = True
                            break
                    if hit:
                        out["endpoints"].append(u)
                except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                    pass

        await asyncio.gather(*(_probe_one(p) for p in paths))
        if out["endpoints"]:
            logger.info(f"      [B4-API文档] 显式命中: {len(out['endpoints'])} 个")
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[B4-API文档] 枚举异常（忽略）: {exc}")
    return out


def _bucket_probe_sync(bucket: str, provider: str, url_tpl: str, absent_markers: tuple) -> dict:
    """单桶单厂商探测（线程池内执行）：存在性判定，不做列表拉取。"""
    u = url_tpl.format(bucket=bucket)
    try:
        import requests as _rq
        resp = _rq.get(u, timeout=5, allow_redirects=False,
                       headers={"User-Agent": settings.user_agent})
        status = resp.status_code
        head = (resp.headers.get("Content-Type") or "") + (resp.text or "")[:600]
        if resp.status_code in (301, 302, 307, 308):
            return {"provider": provider, "url": u, "status": status,
                    "public": False, "exists": True, "redirect": resp.headers.get("Location", "")}
        absent = any(m.lower() in head.lower() for m in absent_markers)
        if absent:
            return {"provider": provider, "url": u, "status": status,
                    "exists": False, "public": False}
        if status in (200, 203):
            public = ("ListBucketResult" in resp.text
                      or "<Key>" in resp.text
                      or resp.headers.get("x-amz-request-id") is not None
                      or "AccessDenied" not in resp.text)
        elif status in (403,):
            public = False
        else:
            public = False
        return {"provider": provider, "url": u, "status": status,
                "exists": status in (200, 203, 403), "public": public}
    except Exception as exc:  # noqa: BLE001
        return {"provider": provider, "url": u, "status": 0,
                "exists": False, "public": False, "error": str(exc)[:120]}


async def _enum_cloud_buckets(domain: str, budget_left: float) -> dict:
    """面5-云资产：派生候选桶名 x 多厂商存在性探测（仅信息收集）。"""
    out = {"buckets": [], "public_buckets": []}
    if getattr(settings, "osint_disable", False) or _is_internal_host(domain or ""):
        return out
    brand = _brand_from(domain)
    if not brand:
        return out
    candidates = [p.format(brand=brand) for p in BUCKET_NAME_PATTERNS]
    loop = asyncio.get_running_loop()
    started = loop.time()
    tasks = []
    sem_bucket = asyncio.Semaphore(8)

    async def _probe(bucket: str):
        if loop.time() - started > budget_left:
            return None
        async with sem_bucket:
            results = await loop.run_in_executor(
                None,
                lambda b=bucket: [
                    _bucket_probe_sync(b, prov, tpl, marks)
                    for prov, (tpl, marks) in BUCKET_PROVIDERS.items()
                ],
            )
        return bucket, results

    for cand in candidates:
        if loop.time() - started > budget_left:
            break
        tasks.append(asyncio.create_task(_probe(cand)))
    if tasks:
        done = await asyncio.gather(*tasks, return_exceptions=True)
    else:
        done = []
    for item in done:
        if isinstance(item, Exception) or not item:
            continue
        bucket, results = item
        for r in results:
            if r and r.get("exists"):
                out["buckets"].append(r)
                if r.get("public"):
                    out["public_buckets"].append(r)
    if out["buckets"]:
        logger.info(
            f"      [B4-云资产] 命中 {len(out['buckets'])} 个存储桶"
            f"（{len(out['public_buckets'])} 个疑似公开）"
        )
    return out


async def _enum_dev_facilities(target: str, domain: str, budget_left: float) -> dict:
    """面6-开发者设施：.git/.svn 泄露 + CI 配置 + 调试口（指定路径探测）。

    对目标自身路径的探测，IP/内网靶机同样有效（不短路）。
    """
    out = {"git": [], "ci": [], "debug": [], "env": []}
    try:
        from vulnclaw.core.utils import async_get
        root = target.rstrip("/") + "/"
        sem = asyncio.Semaphore(8)
        started = asyncio.get_running_loop().time()

        async def _probe(path: str):
            if asyncio.get_running_loop().time() - started > budget_left:
                return
            u = urljoin(root, path)
            async with sem:
                try:
                    resp = await asyncio.wait_for(async_get(u, timeout=6), timeout=4)
                    status = resp[0] if isinstance(resp, (tuple, list)) else 0
                    body = resp[1] if isinstance(resp, (tuple, list)) else ""
                    if status != 200:
                        return
                    low = body[:4000].lower()
                    if ".git/" in path or path == ".git/HEAD":
                        ok = ("[core]" in low or "ref: " in low
                              or "repository" in low or "dirmode" in low)
                        if ok:
                            out["git"].append(u)
                    elif path == ".svn/entries":
                        if "Pristine" in body or "dir" in low:
                            out["git"].append(u)
                    elif path.endswith((".yml", ".yaml")) or "Jenkinsfile" in path:
                        if any(k in low for k in ("deploy", "build", "script", "stage", "image:")):
                            out["ci"].append(u)
                    elif path in DEBUG_PATHS or path.startswith("actuator"):
                        if not _looks_like_soft404(body):
                            out["debug"].append(u)
                    elif path in (".env", ".npmrc", ".pypirc"):
                        if "=" in body and len(body) < 8000:
                            out["env"].append(u)
                    elif path == "docker-compose.yml":
                        if "services:" in low or "image:" in low:
                            out["ci"].append(u)
                except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                    pass

        await asyncio.gather(*(_probe(p) for p in DEV_FACILITY_PATHS))
        total = sum(len(v) for v in out.values())
        if total:
            logger.info(f"      [B4-开发者设施] 命中 {total} 项"
                        f"（git={len(out['git'])}, ci={len(out['ci'])}, debug={len(out['debug'])}, env={len(out['env'])}）")
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[B4-开发者设施] 枚举异常（忽略）: {exc}")
    return out


def _looks_like_soft404(body: str) -> bool:
    """启发式软 404 判定：正文极短或含典型 404 文案。"""
    b = (body or "").strip()
    if not b:
        return True
    if len(b) < 120:
        return True
    low = b.lower()
    for kw in ("404 not found", "page not found", "not found", "error 404"):
        if kw in low[:500]:
            return True
    return False


async def _enum_supply_chain(target: str, brief: dict, budget_left: float) -> dict:
    """面4-供应链前端：第三方 CDN 域名 + JS 库版本线索（仅信息收集）。"""
    out = {"cdn_domains": [], "libraries": []}
    try:
        from vulnclaw.core.utils import async_get
        got = None
        try:
            resp = await asyncio.wait_for(async_get(target, timeout=8), timeout=6)
            got = resp[1] if isinstance(resp, (tuple, list)) else ""
        except Exception:  # noqa: BLE001
            pass
        body = got or ""
        # 补充来自 JS 端点清单的脚本 URL（不重复抓取，仅解析域名）
        for u in (brief.get("js_endpoints") or [])[:200]:
            if isinstance(u, str) and "://" in u:
                body += "\n" + u
        # 1) 第三方 CDN 域名引用
        for m in re.findall(r'https?://([a-z0-9.\-]+\.(?:com|net|io|dev|org))[^"\'\s]*',
                            body, re.I):
            d = m.lower()
            if d.endswith(".js") or d.endswith(".css"):
                d = d.rsplit("/", 1)[0]
            if any(marker in d for marker in SCM_CDN_MARKERS):
                host = urlparse("https://" + d).netloc or d
                if host not in out["cdn_domains"]:
                    out["cdn_domains"].append(host)
        # 2) JS 库名 + 版本线索
        for m in re.finditer(
            r'(["\']?)(react|vue|angular|jquery|axios|lodash|echarts|bootstrap|'
            r'moment|dayjs|element-ui|antd|d3|webpack|vite|next|nuxt|svelte)'
            r'([/@.][0-9][0-9a-z.\-]*)',
            body, re.I,
        ):
            lib = m.group(2).lower()
            ver = m.group(3).lstrip("/@.").split("-")[0]
            label = SCM_LIB_MARKERS.get(lib, lib)
            item = f"{label}@{ver}" if ver else label
            if item not in out["libraries"]:
                out["libraries"].append(item)
        # 去重保持稳定
        out["cdn_domains"] = list(dict.fromkeys(out["cdn_domains"]))
        out["libraries"] = list(dict.fromkeys(out["libraries"]))
        if out["cdn_domains"] or out["libraries"]:
            logger.info(
                f"      [B4-供应链] CDN 域名 {len(out['cdn_domains'])} 个，"
                f"JS 库线索 {len(out['libraries'])} 条"
            )
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[B4-供应链] 枚举异常（忽略）: {exc}")
    return out


async def _enum_public_repos(domain: str, budget_left: float) -> dict:
    """面7-公开仓库线索：GitHub 搜索（org/repo/用户），无 token 静默降级。"""
    out = {"repos": []}
    if getattr(settings, "osint_disable", False) or _is_internal_host(domain or ""):
        return out
    base = _strip_www(domain or "")
    if not base:
        return out
    try:
        loop = asyncio.get_running_loop()
        brand = _brand_from(base)
        queries = []
        if brand:
            queries.append(f'org:"{brand}"')
        queries.append(f'"{base}"')
        if not queries:
            return out
        results = await loop.run_in_executor(
            None, lambda qs=queries[:3]: _github_search(qs))
        for repo in results[:10]:
            out["repos"].append(repo)
        out["repos"] = list(dict.fromkeys(out["repos"]))
        if out["repos"]:
            logger.info(f"      [B4-公开仓库] GitHub 命中 {len(out['repos'])} 个仓库（线索）")
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[B4-公开仓库] 枚举异常（忽略）: {exc}")
    return out


def _github_search(queries: list) -> list:
    """线程内执行 GitHub 公共搜索（无 token：限流失败静默降级）。"""
    out = []
    try:
        import requests as _rq
        token = getattr(settings, "github_token", "") or ""
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "vulnclaw-b4"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        for q in queries:
            if not q or len(out) >= 5:
                continue
            try:
                resp = _rq.get(
                    "https://api.github.com/search/repositories",
                    params={"q": q, "per_page": 3},
                    headers=headers, timeout=8,
                )
                if resp.status_code == 200:
                    for it in (resp.json().get("items") or []):
                        full = it.get("full_name") or ""
                        if full and full not in out:
                            out.append(full)
                elif resp.status_code in (403, 429):
                    logger.warning("  [B4-公开仓库] GitHub 限流（403/429），静默降级")
                    break
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass
    return out


# ------------------------------------------------------------
# 主入口
# ------------------------------------------------------------
async def enumerate_asset_surface(
    target: str,
    domain: str = "",
    brief: dict | None = None,
    budget_s: int = 0,
    session=None,  # noqa: ARG001 —— 保留签名兼容，内部使用独立连接
) -> dict:
    """B4 资产面枚举主入口（6 面并发，总预算硬超时，fail-open）。

    返回结构（不抛异常）：
      {
        "target", "base_domain", "budget_s", "elapsed_s",
        "subdomains_candidates": [...],   # 移动端前缀子域
        "api_docs": [...],
        "mobile": {...},
        "supply_chain": {...},
        "cloud": {...},
        "dev_facilities": {...},
        "public_repos": {...},
        "extra_scan_urls": [...],          # 授权校验后可并入 crawled_endpoints 的 URL
        "lines": {...},                    # 合并建议（key -> 新列表）
      }
    """
    budget = int(budget_s or getattr(settings, "asset_surface_budget_s", 0) or 90)
    base = _base_domain(domain or urlparse(target).netloc)
    brief = brief or {}
    started = asyncio.get_running_loop().time()

    async def _budget_wrap(coro):
        """剩余预算计时器：超时截断单个子枚举器。"""
        left = max(2.0, budget - (asyncio.get_running_loop().time() - started))
        try:
            return await asyncio.wait_for(coro, timeout=left)
        except (asyncio.TimeoutError, Exception):  # noqa: BLE001 —— 超时即降级该面
            return {}

    # 6 面并发（各自内部又用 semaphore 控制请求并发）
    results = await asyncio.gather(
        _budget_wrap(_enum_mobile_hosts(target, base, budget)),
        _budget_wrap(_enum_api_docs(target, base, budget)),
        _budget_wrap(_enum_cloud_buckets(base, budget)),
        _budget_wrap(_enum_dev_facilities(target, base, budget)),
        _budget_wrap(_enum_supply_chain(target, brief, budget)),
        _budget_wrap(_enum_public_repos(base, budget)),
        return_exceptions=True,
    )
    mobile, api_docs, cloud, dev, scm, repos = (
        r if isinstance(r, dict) else {} for r in results
    )
    # 子枚举器超时/异常降级时可能返回 {}，统一补齐默认键，避免下游 None 相加
    dev = {k: (dev.get(k) or []) for k in ("git", "ci", "debug", "env")}

    # 计算授权范围内可并入目标池的新 URL（越界仅线索）
    extra_scan_urls: list = []
    try:
        from vulnclaw.core.http_client import url_in_scope
    except Exception:  # noqa: BLE001
        url_in_scope = lambda u, *a, **k: True  # noqa: E731 —— 缺库放行
    _seen = set()
    for u in mobile.get("alive_urls") or []:
        if u and u not in _seen and url_in_scope(u):
            extra_scan_urls.append(u)
            _seen.add(u)
    for u in api_docs.get("endpoints") or []:
        if u and u not in _seen and url_in_scope(u):
            extra_scan_urls.append(u)
            _seen.add(u)
    for u in dev.get("git") + dev.get("ci") + dev.get("debug") + dev.get("env"):
        if u and u not in _seen and url_in_scope(u):
            extra_scan_urls.append(u)
            _seen.add(u)

    surface = {
        "target": target,
        "base_domain": base,
        "budget_s": budget,
        "elapsed_s": round(asyncio.get_running_loop().time() - started, 2),
        "subdomains_candidates": sorted(set(mobile.get("hosts") or [])),
        "api_docs": sorted(api_docs.get("endpoints") or []),
        "mobile": {
            "hosts": sorted(set(mobile.get("hosts") or [])),
            "alive_urls": sorted(set(mobile.get("alive_urls") or [])),
            "apk_urls": sorted(set(mobile.get("apk_urls") or [])),
        },
        "supply_chain": {
            "cdn_domains": sorted(set(scm.get("cdn_domains") or [])),
            "libraries": sorted(set(scm.get("libraries") or [])),
        },
        "cloud": cloud or {"buckets": [], "public_buckets": []},
        "dev_facilities": dev or {"git": [], "ci": [], "debug": [], "env": []},
        "public_repos": repos or {"repos": []},
        # 授权范围内、可并入扫描目标池的新 URL
        "extra_scan_urls": extra_scan_urls,
        "lines": {
            "crawled_endpoints": [
                {"url": u, "params": []} for u in extra_scan_urls
            ],
            "subdomains": sorted(set(mobile.get("hosts") or [])),
        },
    }
    logger.info(
        f"[B4] 资产面枚举完成: 子域候选 {len(surface['subdomains_candidates'])} | "
        f"API文档 {len(surface['api_docs'])} | 云桶 {len(surface['cloud'].get('buckets', []))} | "
        f"开发者设施 {sum(len(v) for v in surface['dev_facilities'].values())} | "
        f"供应链 {len(surface['supply_chain']['cdn_domains'])} CDN | "
        f"仓库 {len(surface['public_repos'].get('repos', []))} | "
        f"可入池 {len(extra_scan_urls)} | 耗时 {surface['elapsed_s']}s"
    )
    return surface
