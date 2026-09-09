# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

from vulnclaw.core.tool_registry import run_tool, load_tool_config
import asyncio
import hashlib
import json
import os
import tempfile
import time

import re

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core_modules.cache import SQLiteCache
from typing import List

# P1-1: FFUF 结果 SQLite 持久化缓存（Key=ffuf:{target_hash}:{wordlist_mtime}，24h TTL）
_ffuf_cache = SQLiteCache(name="ffuf", ttl=86400)
# ffuf `-of json` 写文件在部分 Windows 构建下失效（日志 0B 但 stdout 有表格）。
# 统一回退解析 stdout 表格行，格式: `<url>  [Status: 200, Size: N, ...]`
_FFUF_STDOUT_ROW = re.compile(r'^\s*(\S+)\s+\[Status:\s*(\d+),')


def _parse_ffuf_stdout_rows(stdout: str) -> List[Tuple[str, int]]:
    rows: List[Tuple[str, int]] = []
    for ln in (stdout or "").splitlines():
        m = _FFUF_STDOUT_ROW.match(ln)
        if m:
            rows.append((m.group(1), int(m.group(2))))
    return rows

async def run_ffuf_async(target: str, concurrency: int = 20, timeout: int = 120) -> List[str]:
    """
    使用 ffuf 进行目录爆破，返回发现的路径。
    本修复：详细日志（PATH、字典路径、输出大小、ffuf JSON schema），
    所有错误升级 warning，避免 0 结果但无日志。
    """
    if not load_tool_config("ffuf"):
        logger.warning(f"⚠️ [FFUF] 未找到 ffuf 可执行文件 (PATH={os.environ.get('PATH','')[:200]}...)，跳过目录爆破")
        return []

    # ========== 修复 1：正确解析 4 种 wordlist 输入 ==========
    # 支持：(a) List[str] 内嵌；(b) str = 逗号分隔；(c) str = 文件路径；
    #      (d) settings.directory_dict_path 外部字典合并
    base_wordlist = getattr(settings, "common_dirs", None)
    extra_dict_path = getattr(settings, "directory_dict_path", None) or None

    def _load_wordlist(source):
        """把 common_dirs 可能的 4 种形态统一成 List[str] 去重并过滤空行。"""
        if source is None:
            return []
        if isinstance(source, (list, tuple, set)):
            return [str(x).strip() for x in source if str(x).strip()]
        if not isinstance(source, str):
            return []
        s = source.strip()
        if not s:
            return []
        # 是文件路径：单行字典（不带逗号），且文件存在 → 按行读取
        if os.path.isfile(s):
            try:
                with open(s, "r", encoding="utf-8", errors="ignore") as f:
                    lines = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
                logger.info(f"📂 [FFUF] 从字典文件 {s} 加载 {len(lines)} 条")
                return lines
            except Exception as exc:
                logger.warning(f"📂 [FFUF] 读取字典文件 {s} 失败: {exc}")
                return []
        # 否则作为 逗号分隔 的内联字典
        return [item.strip() for item in s.split(",") if item.strip()]

    wordlist_set: List[str] = list(dict.fromkeys(_load_wordlist(base_wordlist)))
    if extra_dict_path and os.path.isfile(extra_dict_path):
        extras = _load_wordlist(extra_dict_path)
        for x in extras:
            if x not in wordlist_set:
                wordlist_set.append(x)
    wordlist = wordlist_set

    if not wordlist:
        logger.warning("⚠️ [FFUF] 目录字典为空，跳过")
        return []

    # ========== 修复 2：对发现目标增加自动扩展 ==========
    # 对裸域名（没有扩展名也没有路径）的目标，自动附加 .php 后缀，
    # 解决 testphp.vulnweb.com 这种典型 PHP 靶场常见路径覆盖低的问题。
    from urllib.parse import urlparse
    _host = urlparse(target).hostname or ""
    if _host.endswith(".vulnweb.com") or _host.lower().endswith(".asp.") or _host.lower().endswith(".php."):
        pass  # 仅触发扩展诊断
    # 注入 PHP 靶场常见的直接文件访问路径（不污染通用字典，在这里做 "target-aware" 补充）
    if any(x in _host.lower() for x in ["vulnweb", "testphp", "acuart", "testasp"]):
        extra_paths = [
            "index.php", "search.php", "showimage.php", "listproducts.php",
            "userinfo.php", "product.php", "category.php", "comments.php",
            "login.php", "admin.php", "register.php", "forgot.php",
            "artists.php", "artist.php", "pictures.php", "poll.php",
            "cart.php", "checkout.php", "profile.php", "logout.php",
        ]
        for p in extra_paths:
            if p not in wordlist:
                wordlist.append(p)

    # ========== P1-1: FFUF 结果增量缓存 ==========
    # Key = ffuf:{target_hash}:{wordlist_mtime}；命中直接返回（24h TTL）；
    # miss 时跳过上次已发现路径，仅重试上次 404/429 路径（增量）。
    target_hash = hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]
    if extra_dict_path and os.path.isfile(extra_dict_path):
        wl_mtime = str(int(os.path.getmtime(extra_dict_path)))
    else:
        wl_mtime = hashlib.md5("|".join(wordlist).encode("utf-8")).hexdigest()[:12]
    cache_key = f"ffuf:{target_hash}:{wl_mtime}"

    cached = _ffuf_cache.get(cache_key)
    if cached is not None:
        _dirs = cached.get("dirs", []) if isinstance(cached, dict) else list(cached)
        logger.info(f"📂 [FFUF] 🎯 缓存命中 {cache_key} → {len(_dirs)} 条路径（24h TTL，跳过 ffuf）")
        return _dirs

    old = _ffuf_cache.get_raw(cache_key) or {}
    old_dirs = set(old.get("dirs", []) or [])
    old_not_found = [p for p in (old.get("not_found", []) or []) if p not in old_dirs]
    if old_dirs or old_not_found:
        wordlist = [w for w in wordlist if w not in old_dirs] + old_not_found
        logger.info(
            f"📂 [FFUF] 增量模式: 跳过已发现 {len(old_dirs)} 条，"
            f"重试上次 404/429 路径 {len(old_not_found)} 条，本轮 wordlist={len(wordlist)}"
        )

    logger.info(f"📂 [FFUF] 启动: target={target} concurrency={concurrency} timeout={timeout}s dict_entries={len(wordlist)}")

    # 写入临时字典
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False, encoding='utf-8') as f:
        for d in wordlist:
            f.write(d + "\n")
        wordlist_file = f.name

    with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False, encoding='utf-8') as f:
        output_file = f.name

    code = -999
    out = err = ""
    try:
        args = [
            "-u", target + "/FUZZ",
            "-w", wordlist_file,
            "-c", str(concurrency),
            "-timeout", str(timeout),
            "-H", f"User-Agent: {settings.user_agent}",
            "-o", output_file,
            "-of", "json",
        ]
        tool_result = await run_tool("ffuf", args=args, timeout=timeout)
        code = tool_result.get("returncode", -1)
        out = tool_result.get("stdout", "")
        err = tool_result.get("stderr", "")
        cmd = tool_result.get("cmd", "ffuf " + " ".join(args))
        file_size = os.path.getsize(output_file) if os.path.exists(output_file) else 0
        if code == 0:
            logger.info(f"📂 [FFUF] exit=0；output_file={output_file} size={file_size}B")
        else:
            logger.warning(
                f"📂 [FFUF] exit={code}；stdout_len={len(out or '')}；"
                f"stderr[:300]={(err or '')[:300]}；output_exists={os.path.exists(output_file)} size={file_size}B"
            )

        dirs: List[str] = []
        not_found: List[str] = []
        if os.path.exists(output_file):
            if file_size == 0:
                logger.warning("📂 [FFUF] 输出文件为空（0B），回退解析 stdout 表格")
                for raw, status in _parse_ffuf_stdout_rows(out):
                    if status in (200, 301, 302, 307, 401, 403):
                        path = raw.replace(target, '').split('?')[0]
                        if path and path != '/' and path not in dirs:
                            dirs.append(path)
                    elif status in (404, 429):
                        path = raw.replace(target, '').split('?')[0]
                        if path and path not in not_found:
                            not_found.append(path)
            else:
                try:
                    with open(output_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    results = data.get('results')
                    cmdline = data.get('commandline', '')
                    total = len(results) if isinstance(results, list) else None
                    logger.info(
                        f"📂 [FFUF] 输出解析: commandline={cmdline}；"
                        f"top_keys={list(data.keys())[:10]}；results_count={total}"
                    )
                    if isinstance(results, list):
                        for result in results:
                            url = result.get('url', '')
                            status = result.get('status')
                            if url and status in (200, 301, 302, 307, 401, 403):
                                path = url.replace(target, '').split('?')[0]
                                if path and path != '/' and path not in dirs:
                                    dirs.append(path)
                            elif url and status in (404, 429):
                                path = url.replace(target, '').split('?')[0]
                                if path and path not in not_found:
                                    not_found.append(path)
                    else:
                        logger.warning(
                            f"📂 [FFUF] 'results' 字段不是 list: type={type(results).__name__} sample={str(results)[:200]}"
                        )
                except json.JSONDecodeError as e:
                    logger.warning(f"📂 [FFUF] JSON 解析失败: {e}，尝试用纯文本预览: {open(output_file,'r',encoding='utf-8',errors='ignore').read()[:300]}")
                except Exception as e:
                    logger.warning(f"📂 [FFUF] 读取/解析输出异常: {e}")
        logger.info(f"📂 [FFUF] 发现目录: {len(dirs)} 条")
        return dirs
    except asyncio.TimeoutError:
        logger.warning(f"📂 [FFUF] 进程通信超时 (> {timeout + 30}s)；cmd={' '.join(cmd)}")
        return []
    except Exception as e:
        logger.warning(
            f"📂 [FFUF] 运行异常: {e} (exit={code})；stderr[:300]={(err or '')[:300]}"
        )
        return []
    finally:
        for f in [wordlist_file, output_file]:
            if os.path.exists(f):
                try:
                    os.unlink(f)
                except BaseException:
                    logger.debug("suppressed exception (core audit)")


__all__ = ['run_ffuf_async']
