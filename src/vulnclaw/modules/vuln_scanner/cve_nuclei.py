# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

from vulnclaw.core.tool_registry import run_tool, load_tool_config, tool_available
from vulnclaw.core.settings import settings
from typing import Dict, List, Optional

# ============================================================

# 合并自: modules/tools.py
# ============================================================


# modules/tools.py
"""工具调用封装：Arjun、Nuclei、FFUF、Interactsh 等"""

import asyncio
import tempfile
import os
import json
import time

from vulnclaw.core.logger import logger


# ============================================================
# Arjun - 隐藏参数发现
# ============================================================
def _extract_arjun_params(data) -> List[str]:
    """从 arjun 的 JSON 输出提取参数名（兼容单目标/多目标/裸键多种结构）。

    arjun JSON 实测形态（thirdparty/arjun/arjun.exe）：
      {"<url>": {"params": ["debug"], "method": "GET", "headers": {...}, ...}}
    注意键名是 **params**（不是 "parameters"）——早期实现只认 "parameters"，
    会导致 arjun 明明扫出结果却被解析成空列表。两种键名一并兼容。
    """
    _PARAM_KEYS = ("params", "parameters")

    def _pick(d) -> List[str]:
        if not isinstance(d, dict):
            return []
        out: List[str] = []
        for key in _PARAM_KEYS:
            val = d.get(key)
            if isinstance(val, list):
                out.extend(str(p) for p in val if p)
        return out

    if isinstance(data, list):
        return [str(p) for p in data if p]
    if not isinstance(data, dict):
        return []

    found = _pick(data)
    if not found:
        for value in data.values():
            found.extend(_pick(value))
    return list(dict.fromkeys(found))


def _extract_arjun_params_from_text(text: str) -> List[str]:
    """stdout 兜底解析：抓 "Parameters found: a, b" 一行。"""
    for line in (text or "").splitlines():
        if "parameters found" in line.lower():
            _, _, tail = line.partition(":")
            return [p.strip() for p in tail.split(",") if p.strip()]
    return []


async def run_arjun(url: str, timeout: int = 30) -> List[str]:
    """
    调用 Arjun 发现隐藏参数，返回参数名列表。

    实测 three-party/arjun/arjun.exe -h 的参数约定（早期实现三处都写错，导致
    即使门禁通过也必然失败）：
      · HTTP 超时是 `-T`（不存在 `--timeout` 长选项，传了会被 argparse 直接拒绝）
      · 静默是 `-q`（不存在 `--silent`）
      · 结果 JSON 用 `-o <file>` 落盘最稳（stdout 以进度条/表格为主，不是 JSON）
    """
    # 门禁必须与 run_tool 同口径：arjun 在 thirdparty/arjun/ 下，不在系统 PATH，
    # 早期用 shutil.which("arjun") 判定会让本函数每次都提前返回空，
    # 使治理目录声明的 param_discovery 能力（candidates: [arjun]）形同虚设。
    if not tool_available("arjun"):
        logger.warning("⚠️ arjun 未安装，跳过参数发现")
        return []

    out_fd, out_path = tempfile.mkstemp(suffix=".json", prefix="arjun_")
    os.close(out_fd)
    try:
        result = await run_tool(
            "arjun",
            args=["-u", url, "-T", str(timeout), "-q", "-o", out_path],
            timeout=timeout + 30,
        )

        params: List[str] = []
        # 优先读 JSON 落盘文件（最可靠）
        try:
            if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
                with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                    params = _extract_arjun_params(json.load(f))
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.debug(f"Arjun JSON 解析失败，回退 stdout: {exc}")

        if not params:
            params = _extract_arjun_params_from_text(result.get("stdout", ""))

        if not params and not result.get("success"):
            err = str(result.get("stderr") or result.get("error") or "")
            logger.debug(f"Arjun 执行失败: {err[:200]}")
        return params
    except Exception as e:
        logger.debug(f"Arjun 运行异常: {e}")
        return []
    finally:
        try:
            if os.path.exists(out_path):
                os.unlink(out_path)
        except OSError:
            logger.debug("arjun 临时输出清理失败（忽略）")


# ============================================================
# Nuclei - 漏洞扫描
# ============================================================
# P4-3: 技术栈 → Nuclei tags 映射（按指纹只加载相关模板，避免全量扫描）
_TECH_TAG_MAP: Dict[str, List[str]] = {
    "spring": ["spring", "springboot"],
    "tomcat": ["tomcat", "apache"],
    "nginx": ["nginx"],
    "apache": ["apache"],
    "php": ["php"],
    "java": ["java"],
    "python": ["python"],
    "node": ["node", "javascript"],
    "wordpress": ["wordpress", "wp"],
    "joomla": ["joomla"],
    "drupal": ["drupal"],
    "iis": ["iis", "microsoft"],
    "asp.net": ["microsoft", "asp"],
    "jenkins": ["jenkins"],
    "jboss": ["jboss"],
    "weblogic": ["weblogic", "oracle"],
    "websphere": ["websphere"],
    "grafana": ["grafana"],
    "kibana": ["kibana", "elastic"],
    "elasticsearch": ["elastic"],
    "redis": ["redis"],
    "mongodb": ["mongodb"],
    "mysql": ["mysql"],
    "postgres": ["postgres"],
    "kubernetes": ["k8s", "kubernetes"],
    "docker": ["docker"],
    "git": ["git", "exposure"],
    "graphql": ["graphql"],
    "laravel": ["laravel"],
    "django": ["django"],
    "flask": ["flask"],
    "swagger": ["swagger", "api"],
}


def nuclei_template_health(min_count: int = 300) -> tuple:
    """统计 ~/nuclei-templates 下 yaml 模板数。返回 (count, 是否健康)。

    模板库缺失/0 模板/计数低于阈值 → (count, False)：调用方必须 fail-closed
    并打醒目 WARNING（不产出、绝不向报告写无模板支撑的扫描结论）。
    """
    try:
        base = os.path.expanduser(settings.nuclei_template_dir or "~/nuclei-templates")
        if not os.path.isdir(base):
            return 0, False
        count = 0
        for _root, _dirs, files in os.walk(base):
            count += sum(1 for f in files if f.endswith(('.yaml', '.yml')))
        ok = count >= int(min_count or 0)
        return count, ok
    except Exception:  # noqa: BLE001 - 健康检查失败按不健康 fail-closed
        return 0, False


async def collect_line_targets(brief: dict, budget: int = 0) -> list:
    """从 recon brief 收集社区线目标：存活资产优先，其次 js/apis/found_dirs。

    返回归一化 http(s) URL 列表（去重、按预算截断）。budget<=0 → []（仅主域根）。
    """
    if int(budget or 0) <= 0:
        return []
    from urllib.parse import urlparse as _up
    seen: set = set()
    out: list = []
    brief = brief or {}
    sources = [
        brief.get("alive_assets", []) or [],
        brief.get("js_endpoints", []) or [],
        brief.get("apis", []) or [],
        brief.get("found_dirs", []) or [],
        brief.get("crawled_endpoints", []) or [],
    ]
    for lst in sources:
        for u in lst:
            if isinstance(u, dict):
                # alive_assets 可能是 dict 列表（{url,status,...}），必须取 url 字段
                u = u.get("url", "")
            if not isinstance(u, str) or not u:
                continue
            u = u.strip()
            # 相对路径/非 http(s) scheme 交由调用方/上游处理（此处不拼接，避免双归一）
            if not u.startswith(("http://", "https://")):
                continue
            try:
                p = _up(u)
                # 端点级扫描目标：剥离 query/fragment，同一路径不同 query 视为同一端点
                nu = p._replace(fragment="", query="").geturl().rstrip("/")
            except Exception:  # noqa: BLE001 - 畸形 URL 直接丢弃
                continue
            key = nu.encode("utf-8", "replace")
            if key in seen:
                continue
            seen.add(key)
            out.append(nu)
            if len(out) >= int(budget or 0):
                return out
    return out


async def run_nuclei_community_line(
    target: str,
    brief: dict,
    severity: str = "critical,high",
    timeout: int = 300,
    budget: int = 0,
    min_templates: int = 300,
) -> list:
    """C 方案社区线核心：模板健康检查 + 主域根 + 端点预算扫描。

    健康失败/扫描异常 → []（fail-closed，绝不产出）。结果带 line_target 字段
    供证据链定位。复用 run_nuclei_async 的 -o json 解析，零 TLS/代理改造。
    """
    try:
        count, ok = nuclei_template_health(min_templates)
        if not ok:
            logger.warning(
                f"🚨 [Nuclei社区线] 模板健康检查未通过（{count} 个 < 阈值 {min_templates}），"
                f"整线 fail-closed 跳过（不产出、不误报）"
            )
            return []
    except Exception as e:  # noqa: BLE001 - 健康检查异常按 fail-closed
        logger.warning(f"🚨 [Nuclei社区线] 模板健康检查异常: {e}（fail-closed）")
        return []
    targets = [str(target or "").rstrip("/")]
    try:
        extra = await collect_line_targets(brief or {}, budget)
        targets += [t for t in extra if t and t.rstrip("/") != (target or "").rstrip("/")]
    except Exception:  # noqa: BLE001 - 目标收集失败不影响主域根
        logger.debug("suppressed exception (core audit)")
    logger.info(f"🧬 [Nuclei社区线] 模板健康 OK({count}), 准备扫描 {len(targets)} 个目标(severity={severity}, timeout={timeout}s)")
    # 审计M：nuclei 在本机/小站点常整体超时（真扫实证：每端点 300s、exit=-1、
    # 输出 0B、0 结果），逐端点重试会把整轮预算烧光（extras 曾自适应给到 1704s，
    # 而 nuclei 一条结果都没产出）。对策：
    #   ① 单端点超时封顶（默认 120s）；
    #   ② 连续"疑似超时"达阈值即熔断本轮剩余目标，不再逐个白等。
    _cap = int(getattr(settings, "nuclei_community_timeout_cap", 120) or 120)
    if timeout > _cap:
        logger.info(f"🧬 [Nuclei社区线] 单端点超时封顶: {timeout}s → {_cap}s")
        timeout = _cap
    _fail = {"n": 0, "aborted": False}
    _max_fail = max(1, int(getattr(settings, "nuclei_community_max_fail", 3) or 3))

    out: list = []
    seen_key: set = set()
    sem = asyncio.Semaphore(4)

    async def _scan_one(url: str) -> None:
        if _fail["aborted"]:
            return
        async with sem:
            if _fail["aborted"]:
                return
            _t0 = time.monotonic()
            try:
                rs = await run_nuclei_async(url, severity=severity, timeout=timeout)
            except Exception:  # noqa: BLE001 - 单端点失败单独跳过，不阻断整线
                logger.debug(f"[Nuclei社区线] 目标异常跳过: {url}")
                _fail["n"] += 1
                if _fail["n"] >= _max_fail:
                    _fail["aborted"] = True
                    logger.warning(
                        f"🧬 [Nuclei社区线] 连续失败 {_fail['n']} 次，熔断本轮剩余目标"
                    )
                return
            _elapsed = time.monotonic() - _t0
            # 无结果且耗时逼近超时上限 → 判为"疑似超时"，而非"目标确实干净"
            if not rs and _elapsed >= timeout * 0.9:
                _fail["n"] += 1
                if _fail["n"] >= _max_fail:
                    _fail["aborted"] = True
                    logger.warning(
                        f"🧬 [Nuclei社区线] 连续疑似超时 {_fail['n']} 次"
                        f"({_elapsed:.0f}s/个)，熔断本轮剩余目标"
                        f"（nuclei 对该目标大概率不可用）"
                    )
                return
            if rs:
                _fail["n"] = 0
            for r in rs or []:
                k = (r.get("template") or "", r.get("matched") or "", r.get("url") or "")
                kk = (k[0].encode("utf-8", "replace"), k[1].encode("utf-8", "replace"), k[2].encode("utf-8", "replace"))
                if kk in seen_key:
                    continue
                seen_key.add(kk)
                r = dict(r)
                r["line_target"] = url
                out.append(r)

    await asyncio.gather(*(_scan_one(u) for u in targets), return_exceptions=True)

    # D 方案补充：Nikto Web 漏洞扫描（声明未接线的 web_probe 能力）。
    # 仅在主域根跑一次（不摊到端点预算，避免耗时爆炸）；结果与 nuclei 同源去重 +
    # 走同一 verify_nuclei_with_ai_async 验证（FP 安全）。缺失/超时/崩溃均 fail-closed。
    if tool_available("nikto"):
        try:
            nikto_rs = await run_nikto(
                str(target or "").rstrip("/"),
                timeout=max(60, int(min(int(timeout or 120), 300))),
            )
            root = str(target or "").rstrip("/")
            for r in nikto_rs or []:
                k = (r.get("template") or "", r.get("matched") or "", r.get("url") or "")
                kk = (k[0].encode("utf-8", "replace"),
                      k[1].encode("utf-8", "replace"),
                      k[2].encode("utf-8", "replace"))
                if kk in seen_key:
                    continue
                seen_key.add(kk)
                r = dict(r)
                r["line_target"] = root
                out.append(r)
            if nikto_rs:
                logger.info(f"🧬 [Nikto补充] 主域根 → {len(nikto_rs)} 条候选并入社区线")
        except Exception:  # noqa: BLE001 - 补充扫描异常不影响社区线
            logger.debug("[Nikto] 补充扫描异常跳过")

    logger.info(f"🧬 [Nuclei社区线] 完成：{len(targets)} 目标 → {len(out)} 条候选")
    return out


# ============================================================


def build_tags_from_tech(tech_stack: Optional[List[str]], limit: int = 6) -> List[str]:
    """P4-3: 从 reconnaissance 技术栈构建 Nuclei -tags 列表。"""
    if not tech_stack:
        return []
    blob = " ".join(str(t).lower() for t in tech_stack)
    tags: List[str] = []
    for key, vals in _TECH_TAG_MAP.items():
        if key in blob:
            for v in vals:
                if v not in tags:
                    tags.append(v)
    return tags[:limit]


async def update_nuclei_templates(timeout: int = 300) -> bool:
    """P4-3: 后台执行 nuclei -update-templates -silent。

    扫描启动时作为后台协程调用，失败仅告警，不阻塞主流程。
    """
    if not settings.nuclei_auto_update:
        logger.info("🧬 [Nuclei] 模板自动更新已关闭（NUCLEI_AUTO_UPDATE=false）")
        return False
    if not load_tool_config("nuclei"):
        logger.info("🧬 [Nuclei] 未安装，跳过模板更新")
        return False
    try:
        tool_result = await run_tool(
            "nuclei", args=["-update-templates", "-silent"], timeout=timeout
        )
        ok = bool(tool_result.get("success"))
        if ok:
            logger.info("🧬 [Nuclei] 已更新模板")
        else:
            logger.warning(
                f"🧬 [Nuclei] 模板更新失败: "
                f"{(tool_result.get('stderr') or tool_result.get('error') or '')[:200]}"
            )
        return ok
    except asyncio.TimeoutError:
        logger.warning(f"🧬 [Nuclei] 模板更新超时 ({timeout}s)")
        return False
    except Exception as e:
        logger.warning(f"🧬 [Nuclei] 模板更新异常: {e}")
        return False


# ============================================================
# P1-5：原生 YAML 模板解释器一致性审计（开关 native_templates_compare，默认关）
# ============================================================
async def _native_template_audit(
    target: str,
    nuclei_hit_ids: set,
    timeout: int = 120,
    max_templates: int = 50,
) -> None:
    """原生解释器 vs nuclei 二进制双跑对比（只审计不改变主结果）。

    对模板目录递归取前 max_templates 个可解释模板，用 core.native_templates
    的纯 Python 解释器跑同一目标，按 template-id 与 nuclei 实际命中对比，
    输出 一致/仅原生命中/仅nuclei命中 计数。仅原生命中属预期内差异来源：
    nuclei 侧受 severity/tags 档位过滤——本函数只给数据，不下结论。
    """
    try:
        from vulnclaw.core.native_templates import load_template, run_template
    except Exception:  # noqa: BLE001
        return
    base = os.path.expanduser(getattr(settings, "nuclei_template_dir", "") or "~/nuclei-templates")
    if not os.path.isdir(base):
        logger.debug("🧬 [原生模板审计] 模板目录不存在，跳过")
        return
    # 递归收集体积内的 .yaml/.yml
    files: List[str] = []
    for root, _dirs, names in os.walk(base):
        for n in sorted(names):
            if n.lower().endswith((".yaml", ".yml")):
                files.append(os.path.join(root, n))
                if len(files) >= max_templates * 4:  # 预放大：部分会被 MVP 边界跳过
                    break
        if len(files) >= max_templates * 4:
            break
    if not files:
        return
    native_hits: Dict[str, Dict] = {}
    try:
        import aiohttp
        to = aiohttp.ClientTimeout(total=max(5, min(timeout, 30)))
        async with aiohttp.ClientSession(timeout=to) as session:
            attempted = 0
            for path in files:
                if attempted >= max_templates:
                    break
                tmpl = load_template(path)
                if not isinstance(tmpl, dict):
                    continue
                attempted += 1
                res = await run_template(tmpl, target.rstrip("/"), session, timeout=20)
                if res:
                    native_hits[str(res.get("template_id") or res.get("type") or "?")] = res
    except Exception as e:  # noqa: BLE001 - 审计绝不影响主链路
        logger.debug(f"🧬 [原生模板审计] 执行异常（忽略）: {e}")
        return
    if not native_hits:
        logger.info("🧬 [原生模板审计] 原生解释器 0 命中（无一致性差异可报告）")
        return
    both = [tid for tid in native_hits if tid in nuclei_hit_ids]
    native_only = [tid for tid in native_hits if tid not in nuclei_hit_ids]
    logger.info(
        f"🧬 [原生模板审计] 原生命中 {len(native_hits)} 条 | "
        f"与 nuclei 一致 {len(both)} | 仅原生命中 {len(native_only)}"
        f"（预期内：nuclei 受 severity/tags 过滤）"
    )
    for tid in both[:5]:
        logger.info(f"🧬 [原生模板审计] 一致样例: {tid}")


async def run_nuclei_async(
    target: str,
    severity: str = "critical,high,medium,low",
    timeout: int = 120,
    tags: Optional[List[str]] = None,
    tech_stack: Optional[List[str]] = None,
    exclude_severity: str = "info",
    template_ids: Optional[List[str]] = None,
) -> List[Dict]:
    """
    异步运行 Nuclei 扫描，返回结果列表。
    本修复：
      - 输出完整命令、返回码、stdout/stderr、输出文件大小，便于定位 0 结果根因
      - 所有异常升级为 warning 级日志（原来 debug 级在默认日志级别下不可见）
      - 即使 returncode != 0 也尝试解析输出（nuclei 发现漏洞时非 0 退出）
    Z1.2：新增 template_ids 参数——指定 CVE 模板 ID（-id），用于情报驱动的专项扫描。
    """
    if not load_tool_config("nuclei"):
        logger.warning(f"⚠️ [Nuclei] 未找到 nuclei 可执行文件 (PATH={os.environ.get('PATH','')[:200]}...)，跳过 CVE 扫描")
        return []

    # P4-3: 按技术栈构建 tags（显式传入 tags 优先级最高）
    tag_list = [str(t).strip() for t in (tags or []) if str(t).strip()]
    if not tag_list and settings.nuclei_tags_from_stack and tech_stack:
        tag_list = build_tags_from_tech(tech_stack)

    # E2: nuclei 模板分档 —— 按 nuclei_template_tier 收窄默认 severity，控制扫描耗时。
    # 仅当调用方沿用默认全量 severity 时才应用档位；显式指定窄 severity 的调用
    # （如定向 CVE 复扫 severity="critical,high"）保持原样，不受影响。
    if severity == "critical,high,medium,low":
        _tier_sev = {
            "fast": "critical,high",
            "balanced": "critical,high,medium",
            "full": "critical,high,medium,low",
        }.get(str(getattr(settings, "nuclei_template_tier", "balanced") or "balanced").lower(),
              "critical,high,medium")
        if _tier_sev and _tier_sev != severity:
            severity = _tier_sev
            logger.info(f"🧬 [Nuclei] 按模板档位 {settings.nuclei_template_tier} 收窄 severity -> {severity}")

    # 创建临时输出文件
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
        output_file = f.name

    code = -999
    out = err = ""
    try:
        args = [
            "-u", target,
            "-severity", severity,
            "-o", output_file,
            "-timeout", str(settings.nuclei_per_host_timeout),
            "-retries", str(settings.nuclei_retries),
            "-rl", str(settings.nuclei_rate_limit),
        ]
        # Z1.2：指定模板 ID 时用 -id 精确命中（覆盖 tags 无法匹配的 CVE 模板）
        id_list = [str(i).strip() for i in (template_ids or []) if str(i).strip()]
        if id_list:
            args.extend(["-id", ",".join(id_list[:50])])
        if tag_list and not id_list:
            args.extend(["-tags", ",".join(tag_list)])
        if exclude_severity:
            # P4-3: Info 级模板默认跳过，减少无效噪声
            args.extend(["-exclude-severity", exclude_severity])
        logger.info(
            f"🧬 [Nuclei] 启动: target={target} severity={severity} "
            f"ids={','.join(id_list[:8]) if id_list else '全部'} "
            f"tags={','.join(tag_list) or '全部'} timeout={timeout}s"
        )
        if tag_list:
            logger.info(
                f"🧬 [Nuclei] 本次启用 tags: {', '.join(tag_list)}"
                + (f"（跳过 {exclude_severity} 级模板）" if exclude_severity else "")
            )
        tool_result = await run_tool("nuclei", args=args, timeout=timeout)
        code = tool_result.get("returncode", -1)
        out = tool_result.get("stdout", "")
        err = tool_result.get("stderr", "")
        cmd = tool_result.get("cmd", "nuclei " + " ".join(args))
        results = []
        file_size = os.path.getsize(output_file) if os.path.exists(output_file) else 0
        if code == 0:
            logger.info(f"🧬 [Nuclei] 执行成功 exit=0，输出文件 {output_file} size={file_size}B")
        else:
            logger.warning(
                f"🧬 [Nuclei] exit={code}；stdout_len={len(out or '')}；"
                f"stderr[:300]={(err or '')[:300]}；output_file_exists={os.path.exists(output_file)}，size={file_size}B"
            )
        if os.path.exists(output_file):
            if file_size == 0:
                logger.warning("🧬 [Nuclei] 输出文件为空，跳过解析（未发现漏洞或工具未写入结果）")
            else:
                with open(output_file, 'r', encoding='utf-8') as f:
                    line_no = 0
                    for line in f:
                        line_no += 1
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            info = data.get('info', {})
                            results.append({
                                'template': data.get('template-id', ''),
                                'severity': data.get('severity', ''),
                                'info': info.get('description', '') or info.get('name', ''),
                                'matched': data.get('matched-at', ''),
                                'url': data.get('host', ''),
                                'raw': data
                            })
                        except json.JSONDecodeError as e:
                            logger.warning(f"🧬 [Nuclei] JSON 解析失败（L{line_no}）: {e} line[:120]={line[:120]}")
        logger.info(f"🧬 [Nuclei] 解析完成，共 {len(results)} 条结果")
        # P1-5：原生模板一致性审计（开关默认关；只读对比，不影响主结果）
        if getattr(settings, "native_templates_compare", False):
            try:
                await _native_template_audit(
                    target, {str(r.get("template") or "") for r in results}, timeout=timeout
                )
            except Exception as e:  # noqa: BLE001
                logger.debug(f"🧬 [原生模板审计] 未执行: {e}")
        return results
    except asyncio.TimeoutError:
        logger.warning(f"🧬 [Nuclei] 进程通信超时 (> {timeout + 30}s)；cmd={' '.join(cmd)}")
        return []
    except Exception as e:
        logger.warning(
            f"🧬 [Nuclei] 运行异常: {e} (exit={code})；stderr[:300]={(err or '')[:300]}"
        )
        return []
    finally:
        if os.path.exists(output_file):
            try:
                os.unlink(output_file)
            except BaseException:
                logger.debug("suppressed exception (core audit)")


# ============================================================
# Nikto - Web 漏洞扫描补充引擎（web_probe 能力，声明未接线 → 本函数接线）
# ============================================================
# 中文 Windows 下 perl 会因 locale(936) 在数值比较处崩（nikto.pl:155 `numeric ne`），
# 必须给子进程注入 LC_ALL=C 等环境变量（经 run_tool 的 env 参数，仅作用于本次进程、
# 且与 os.environ 合并不覆盖 PATH，perl 才能被解析到）。
_NIKTO_ENV = {
    "LC_ALL": "C",
    "LANG": "C",
    "LC_NUMERIC": "C",
    "LC_CTYPE": "C",
    "PERL_BADLANG": "0",
}


async def run_nikto(target: str, timeout: int = 180) -> List[Dict]:
    """Nikto Web 漏洞扫描（补充引擎）。

    tool_directory.yaml 把 nikto 列在 web_probe 能力（candidates: [curl, nikto]），
    但此前**没有任何代码调用 nikto**——与 arjun/gitleaks 同类「声明未接线」。
    Nikto 本质是 Web 漏洞扫描器（curl 才是探针），故接在 web 漏洞扫描阶段，
    产出并入社区线同一 results 流，经 verify_nuclei_with_ai_async 走同一套 AI 验证
    （FP 安全：非真实漏洞不会入报告）。

    实测旗标（nikto v2.6.1 -H）：`-h <host>` / `-o <file>` / `-Format json` /
    `-ask no`（避免更新回传交互卡死）/ `-maxtime <s>` / `-timeout <s>` / `-Display V`。
    JSON 结构：`[{"host","port","vulnerabilities":[{"id","method","url","msg",...}]}]`；
    连接失败等扫描器自身错误表现为 `id=="FAIL"`，**不是漏洞**，必须过滤。
    """
    if not tool_available("nikto"):
        logger.debug("⚠️ nikto 未安装，跳过 Web 漏洞补充扫描")
        return []

    out_fd, out_path = tempfile.mkstemp(suffix=".json", prefix="nikto_")
    os.close(out_fd)
    try:
        args = [
            "-h", str(target).rstrip("/"),
            "-o", out_path,
            "-Format", "json",
            "-ask", "no",
            "-maxtime", str(timeout),
            "-timeout", "10",
            "-Display", "V",
        ]
        result = await run_tool(
            "nikto", args=args, timeout=timeout + 30, env=_NIKTO_ENV)

        findings: List[Dict] = []
        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            try:
                with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError, ValueError):
                data = []
            for host in (data if isinstance(data, list) else []):
                if not isinstance(host, dict):
                    continue
                host_url = host.get("host") or str(target)
                for v in host.get("vulnerabilities", []) or []:
                    if not isinstance(v, dict):
                        continue
                    msg = (v.get("msg") or "").strip()
                    # 连接失败/扫描器自身错误不是漏洞，过滤
                    if not msg or v.get("id") == "FAIL" \
                            or "unable to connect" in msg.lower():
                        continue
                    vid = v.get("id") or "generic"
                    findings.append({
                        "template": f"nikto:{vid}",
                        "severity": (v.get("severity") or "low"),
                        "info": msg,
                        "matched": v.get("url") or host_url,
                        "url": host_url,
                        "raw": v,
                    })
        elif not result.get("success"):
            logger.debug(
                f"[Nikto] 执行失败: {str(result.get('stderr') or result.get('error'))[:200]}")
        return findings
    except Exception as e:  # noqa: BLE001 - 补充扫描异常 fail-closed，不影响主流程
        logger.debug(f"[Nikto] 运行异常（fail-closed）: {e}")
        return []
    finally:
        try:
            if os.path.exists(out_path):
                os.unlink(out_path)
        except OSError:
            logger.debug("suppressed exception (core audit)")


# ============================================================


__all__ = [
    'run_arjun',
    'run_nuclei_async',
    'run_nikto',
    'update_nuclei_templates',
    'build_tags_from_tech',
    'nuclei_template_health',
    'collect_line_targets',
    'run_nuclei_community_line',
]
