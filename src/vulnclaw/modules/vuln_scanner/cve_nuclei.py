# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

from vulnclaw.core.tool_registry import run_tool, load_tool_config
from vulnclaw.core.settings import settings
from typing import Dict, List, Optional

# ============================================================

# 合并自: modules/tools.py
# ============================================================


# modules/tools.py
"""工具调用封装：Arjun、Nuclei、FFUF、Interactsh 等"""

import asyncio
import shutil
import tempfile
import os
import json

from vulnclaw.core.logger import logger


# ============================================================
# Arjun - 隐藏参数发现
# ============================================================
async def run_arjun(url: str, timeout: int = 30) -> List[str]:
    """
    调用 Arjun 发现隐藏参数
    返回参数名列表
    """
    if not shutil.which("arjun"):
        logger.warning("⚠️ arjun 未安装，跳过参数发现")
        return []

    try:
        result = await run_tool(
            "arjun",
            args=["-u", url, "--timeout", str(timeout)],
            timeout=timeout + 10,
        )
        if not result.get("success"):
            err = result.get("stderr", result.get("error", ""))
            logger.debug(f"Arjun 执行失败: {err[:200]}")
            return []

        # 解析输出（arjun 默认输出 JSON）
        out = result.get("stdout", "")
        try:
            data = json.loads(out)
            params = data.get("parameters", [])
            if isinstance(params, list):
                return [p for p in params if p]
        except json.JSONDecodeError:
            # 尝试按行解析
            lines = out.splitlines()
            params = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith("[") and not line.startswith("{"):
                    params.append(line)
            return params
    except Exception as e:
        logger.debug(f"Arjun 运行异常: {e}")
    return []


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


async def run_nuclei_async(
    target: str,
    severity: str = "critical,high,medium",
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
            "-timeout", str(timeout),
            "-retries", "1",
            "-rl", "5",
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
                pass


# ============================================================


__all__ = [
    'run_arjun',
    'run_nuclei_async',
    'update_nuclei_templates',
    'build_tags_from_tech',
]
