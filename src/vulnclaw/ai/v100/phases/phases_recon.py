# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

import asyncio, json, os, re, time
from urllib.parse import urlparse
from vulnclaw.core.logger import logger
from vulnclaw.core.utils import async_get, limit_response_size
from vulnclaw.core.session_manager import get_session_manager
from vulnclaw.modules.vuln_scanner import run_arjun
from typing import Dict, List, Optional
async def _recon(self):
    logger.info("🔍 [侦察] 收集目标信息...")
    brief = {
        "target": self.target, "domain": urlparse(self.target).netloc,
        "status": 0, "tech_stack": [], "url_params": [], "forms": [],
        "has_auth": False, "apis": [], "burp_params": [],
        "burp_cookies": {}, "burp_tokens": {}, "subdomains": [],
        "alive_assets": [], "nuclei_results": [], "js_endpoints": [],
        "open_ports": [], "found_dirs": [],
    }
    try:
        resp = await async_get(self.target, session=self.session, timeout=15)
        status, text, headers = resp
        brief["status"] = status
        brief["tech_stack"] = self._detect_tech(headers, text)
        if '?' in self.target:
            for part in self.target.split('?')[1].split('&'):
                if '=' in part:
                    brief["url_params"].append(part.split('=')[0])
        inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', text, re.I)
        brief["forms"] = list(set(inputs))[:30]
        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v[0-9]+/[^"\']+)["\']',
            r'["\'](/graphql[^"\']*)["\']'
        ]
        for pattern in api_patterns:
            matches = re.findall(pattern, text)
            brief["apis"].extend([m for m in matches if len(m) > 2])
        self._normal_responses[self.target] = {"status": status, "text": text, "headers": headers}
        logger.info(f"   🔎 状态码: {status}, 技术栈: {brief['tech_stack']}")
        logger.info(f"   📋 参数: {len(brief['url_params'])} URL, {len(brief['forms'])} 表单")
        logger.info(f"   API endpoints: {len(brief['apis'])}")
    except Exception as e:
        logger.warning(f"侦察失败: {e}")
    if self._enable_deep_recon:
        await self._deep_recon(brief)
    if self.burp_available and self.burp_client:
        await self._fetch_from_burp(brief)
    try:
        arjun_params = await run_arjun(self.target, timeout=30)
        if arjun_params:
            brief["burp_params"] = list(set(brief.get("burp_params", []) + arjun_params))
            logger.info(f"   Arjun found hidden parameters: {len(arjun_params)}")
    except Exception as e:
        logger.debug(f"Arjun 执行失败: {e}")
    session_mgr = get_session_manager()
    if session_mgr:
        cookies = session_mgr.get_cookies_for_url(self.target)
        brief["has_auth"] = bool(cookies)
    if brief.get("burp_cookies"):
        brief["has_auth"] = True
    # P4-1: Shodan / Censys 情报补全（未配置 API Key 时自动跳过）
    try:
        from vulnclaw.modules.intelligence import enrich_brief_with_intel
        await enrich_brief_with_intel(brief, domain=brief.get("domain", ""))
    except Exception as e:
        logger.debug(f"情报补全跳过: {e}")
    self._recon_brief = brief
    if self.burp_available:
        self._collaborator_domain = await self._get_collaborator_domain()
    logger.info("=" * 60)
    logger.info("📊 侦察汇总")
    logger.info(f"   Subdomains: {len(brief.get('subdomains', []))}")
    logger.info(f"   Alive assets: {len(brief.get('alive_assets', []))}")
    logger.info(f"   Nuclei findings: {len(brief.get('nuclei_results', []))}")
    logger.info(f"   JS endpoints: {len(brief.get('js_endpoints', []))}")
    logger.info(f"   Open ports: {len(brief.get('open_ports', []))}")
    if brief.get("intel", {}).get("ports"):
        logger.info(
            f"   🌐 Intel: 端口 {len(brief['intel']['ports'])} 个, "
            f"CVE {len(brief['intel'].get('vulns', []))} 个, "
            f"服务提示 {', '.join(brief['intel'].get('service_hints', [])[:8])}"
        )
    logger.info(f"   Found directories: {len(brief.get('found_dirs', []))}")
    logger.info(f"   Parameters: {len(brief.get('url_params', [])) + len(brief.get('forms', [])) + len(brief.get('burp_params', []))}")
    if self._collaborator_domain:
        logger.info(f"   📡 Collaborator: {self._collaborator_domain}")
    model_stats = await self._get_model_stats()
    logger.info(f"   AI calls: {model_stats.get('total_calls', 0)}")
    for m, count in model_stats.get('per_model', {}).items():
        logger.info(f"      {m}: {count}")
    logger.info("=" * 60)
async def _deep_recon(self, brief: Dict):
    logger.info("   🚀 [深度侦察] 启动...")
    domain = brief["domain"]
    try:
        await asyncio.wait_for(self._deep_recon_internal(brief, domain), timeout=600)
        logger.info("   ✅ [深度侦察] 完成")
    except asyncio.TimeoutError:
        logger.warning("   ⚠️ [深度侦察] 超时 (600s)，跳过剩余阶段，继续扫描")
    except Exception as e:
        logger.warning(f"   ⚠️ [深度侦察] 异常: {e}")
async def _deep_recon_internal(self, brief: Dict, domain: str):
    subs = []
    alive = []
    async def recon_subdomains():
        try:
            from vulnclaw.modules.recon import get_subdomains_async
            logger.info(f"      📥 [1/10] 收集子域名... start_ts={time.time():.3f}")
            return await asyncio.wait_for(
                get_subdomains_async(domain, compliant=False),
                timeout=120
            )
        except asyncio.TimeoutError:
            logger.warning("      Subdomain collection timeout (120s), skipping")
        except Exception as e:
            logger.warning(f"      ⚠️ 子域名收集失败: {e}")
        return []
    async def recon_alive():
        try:
            from vulnclaw.modules.recon import alive_scan
            if not subs:
                logger.info("      📡 [2/10] 跳过存活探测（无子域名）")
                return []
            logger.info(f"      💚 [2/10] 存活探测 (全部 {len(subs)} 个子域名)...")
            loop = asyncio.get_running_loop()
            return await asyncio.wait_for(
                loop.run_in_executor(None, lambda: alive_scan(subs, False)),
                timeout=180
            )
        except asyncio.TimeoutError:
            logger.warning("      Alive scan timeout (180s), skipping")
        except Exception as e:
            logger.warning(f"      ⚠️ 存活探测失败: {e}")
        return []
    async def run_group1():
        nonlocal subs, alive
        group1_start = time.time()
        logger.info(f"      🚀 [并发组1] 启动 1-7 步骤 start_ts={group1_start:.3f}")
        group1_results = await asyncio.gather(
            recon_subdomains(), recon_nuclei(), recon_js(),
            recon_ports(), recon_ffuf(), recon_collaborator(),
            return_exceptions=True,
        )
        group1_elapsed = time.time() - group1_start
        logger.info(f"      ✅ [并发组1] 完成，耗时 {group1_elapsed:.2f}s")
        subs_result = group1_results[0]
        subs = subs_result if isinstance(subs_result, list) else []
        brief["subdomains"] = subs
        logger.info(f"         ✅发现 {len(subs)} 个子域名")
        alive_start = time.time()
        alive_result = await recon_alive()
        alive = alive_result if isinstance(alive_result, list) else []
        brief["alive_assets"] = alive
        logger.info(f"         ✅发现 {len(alive)} 个存活资产，耗时 {time.time() - alive_start:.2f}s")
        for index, result in enumerate(group1_results[1:], start=3):
            if isinstance(result, Exception):
                logger.warning(f"      ⚠️ 步骤 {index} 异常（不影响主流程）: {result}")
    async def recon_nuclei():
        try:
            from vulnclaw.modules.vuln_scanner import run_nuclei_async, verify_nuclei_with_ai_async
            logger.info(f"      🔬 [3/10] Nuclei CVE 扫描... start_ts={time.time():.3f}")
            results = await asyncio.wait_for(run_nuclei_async(
                self.target, severity="critical,high,medium", timeout=120,
                tech_stack=brief.get("tech_stack", [])), timeout=150)
            brief["nuclei_results"] = results[:20]
            if results:
                logger.info(f"      🔬 AI正在过滤 {len(results)} 条nuclei结果...")
                for item in await verify_nuclei_with_ai_async(results, self.target):
                    if item.get("ai_verdict") == "真实漏洞":
                        self._add_finding({
                            "type": f"Nuclei: {item.get('info', '未知')}",
                            "severity": item.get("severity", "Medium"),
                            "evidence": item.get("matched", "")[:200],
                            "url": item.get("url", self.target), "source": "nuclei",
                            "confidence": "高", "ai_reason": item.get("ai_reason", ""),
                        })
                        self._nuclei_findings += 1
            else:
                logger.info("      Nuclei found no high-severity issues")
        except asyncio.TimeoutError:
            logger.warning("      Nuclei scan timeout (150s), skipping")
        except Exception as e:
            logger.warning(f"      ⚠️ Nuclei 扫描失败: {e}")
    async def recon_js():
        try:
            from vulnclaw.modules.collectors import analyze_js_deep
            logger.info(f"      📜 [4/10] JS 深度分析... start_ts={time.time():.3f}")
            resp = await async_get(self.target, session=self.session, timeout=10)
            text = resp[1] if isinstance(resp, tuple) else await resp.text()
            text = limit_response_size(text, 50000) if len(text) > 50000 else text
            js_urls = [u for u in re.findall(r'<script[^>]+src=["\']([^"\']+)', text)
                       if u and not u.startswith("data:")][:5]
            semaphore = asyncio.Semaphore(4)
            async def analyze_one(js_url):
                async with semaphore:
                    try:
                        full_url = js_url if js_url.startswith("http") else urlparse(self.target)._replace(path=js_url).geturl()
                        js_resp = await async_get(full_url, session=self.session, timeout=10)
                        content = js_resp[1] if isinstance(js_resp, tuple) else await js_resp.text()
                        content = limit_response_size(content, 50000) if len(content) > 50000 else content
                        result = await asyncio.wait_for(
                            analyze_js_deep(content, base_url=self.target, source_url=full_url), timeout=25)
                        return list(result.get("api_endpoints", []))
                    except asyncio.TimeoutError:
                        logger.debug(f"         ⚠️ JS 分析超时（单JS）: {js_url[:100]}")
                        return []
                    except Exception as e:
                        logger.debug(f"         ⚠️ JS 分析失败 {js_url[:100]}: {e}")
                        return []
            results = await asyncio.gather(*(analyze_one(u) for u in js_urls))
            brief["js_endpoints"] = list({ep for result in results for ep in result})[:30]
            logger.info(f"         ✅发现 {len(brief['js_endpoints'])} 个 API 端点")
        except Exception as e:
            logger.warning(f"      ⚠️ JS 分析失败: {e}")
    async def recon_ports():
        try:
            from vulnclaw.modules.recon import port_scan
            logger.info(f"      🔌 [5/10] 端口扫描... start_ts={time.time():.3f}")
            loop = asyncio.get_running_loop()
            ports = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: port_scan(domain, False)), timeout=90)
            brief["open_ports"] = [p for p in ports if p in [80, 443, 8080, 8443, 3000, 5000, 7000, 8000, 9000]]
            logger.info(f"         Open ports found: {len(brief['open_ports'])}")
        except asyncio.TimeoutError:
            logger.warning("      Port scan timeout (90s), skipping")
        except Exception as e:
            logger.warning(f"      ⚠️ 端口扫描失败: {e}")
    async def recon_ffuf():
        if not self._enable_ffuf:
            return
        try:
            from vulnclaw.modules.vuln_scanner import run_ffuf_async
            logger.info(f"      📂 [6/10] 目录爆破... start_ts={time.time():.3f}")
            dirs = await asyncio.wait_for(run_ffuf_async(self.target, concurrency=20), timeout=120)
            brief["found_dirs"] = dirs[:50]
            for item in dirs[:20]:
                path = item.get("path") or item.get("url") or item.get("endpoint") if isinstance(item, dict) else item
                if path and len(path) > 2:
                    self._add_finding({
                        "type": f"发现目录: {path}", "severity": "Info",
                        "evidence": f"Directory {path} is accessible",
                        "url": self.target.rstrip("/") + (path if path.startswith("/") else "/" + path),
                        "source": "ffuf", "confidence": "high",
                    })
            logger.info(f"         Directories found: {len(dirs)}")
        except asyncio.TimeoutError:
            logger.warning("      Directory brute-force timeout (120s), skipping")
        except Exception as e:
            logger.warning(f"      ⚠️ 目录爆破失败: {e}")
    async def recon_collaborator():
        if self.burp_available:
            logger.info(f"      📡 [7/10] 获取Collaborator... start_ts={time.time():.3f}")
            self._collaborator_domain = await self._get_collaborator_domain()
            if self._collaborator_domain:
                logger.info(f"         ✅{self._collaborator_domain}")
    await run_group1()
    async def recon_static_endpoints():
        logger.info("      🛰️[8/10] 静态端点收割...")
        try:
            from vulnclaw.modules.recon import EndpointCollector
            collector = EndpointCollector(
                session=self.session,
                burp_client=self.burp_client if self.burp_available else None
            )
            endpoints = await collector.collect(
                target_domain=domain,
                subdomains=brief.get("subdomains", []),
                js_endpoints=brief.get("js_endpoints", []),
                max_subdomains=30
            )
            unique_endpoints = list(endpoints)
            logger.info(f"      📊 静态收割完成: {len(unique_endpoints)} 个唯一端点")
            if unique_endpoints:
                existing = brief.get("js_endpoints", [])
                brief["js_endpoints"] = list(set(existing + unique_endpoints[:1000]))
                logger.info(f"      📤 导入 {len(unique_endpoints[:1000])} 个静态端点注入迭代子池")
            auto_import = os.getenv("ENABLE_BURP_IMPORT", "false").lower() == "true"
            if self.burp_available and self.burp_client and auto_import:
                try:
                    await collector.import_to_burp(endpoints, limit=200)
                    logger.info(f"      📥 导入 {min(200, len(unique_endpoints))} 个端点到Burp")
                except Exception as e:
                    logger.warning(f"      ⚠️ Burp导入失败: {e}")
            else:
                logger.info(f"      Burp import skipped: {len(unique_endpoints)} endpoints")
        except ImportError as e:
            logger.warning(f"      ⚠️ EndpointCollector 导入失败: {e}")
        except Exception as e:
            logger.warning(f"      ⚠️ 静态收割失败: {e}")
    async def recon_iterative():
        logger.info("      📦 [9/10] 启动盲点击多轮迭代（3轮，纯HTTP）...")
        try:
            seed_urls = [self.target]
            if brief.get("js_endpoints"):
                seed_urls.extend([ep for ep in brief["js_endpoints"] if ep.startswith('/') or ep.startswith('http')][:10])
            if brief.get("apis"):
                seed_urls.extend([ep for ep in brief["apis"] if ep.startswith('/') or ep.startswith('http')][:10])
            if brief.get("found_dirs"):
                def _dp(d):
                    if isinstance(d, dict): return d.get('path') or d.get('url') or d.get('endpoint') or ''
                    return d if isinstance(d, str) else str(d)
                seed_urls.extend([
                    self.target.rstrip('/') + ('/' + p if not p.startswith('/') else p)
                    for d in brief["found_dirs"][:5]
                    for p in [_dp(d)] if p
                ])
            seed_urls = list(set(seed_urls))[:15]
            iterative_urls = await self._iterative_api_explorer(seed_urls, max_rounds=3)
            if iterative_urls:
                brief["js_endpoints"] = list(set(brief.get("js_endpoints", []) + iterative_urls))[:100]
                logger.info(f"         ✅迭代发现 {len(iterative_urls)} 个新端点")
            else:
                logger.info("         ⛔ 迭代未发现新端点")
        except Exception as e:
            logger.warning(f"      ⚠️ 多轮迭代异常（不影响主流程）: {e}")
    group2_start = time.time()
    logger.info(f"      🚀 [并发组2] 启动 8-9 步骤 start_ts={group2_start:.3f}")
    group2_results = await asyncio.gather(
        recon_static_endpoints(), recon_iterative(), return_exceptions=True
    )
    for index, result in enumerate(group2_results, start=8):
        if isinstance(result, Exception):
            logger.warning(f"      ⚠️ 步骤 {index} 异常（不影响主流程）: {result}")
    logger.info(f"      ✅ [并发组2] 完成，耗时 {time.time() - group2_start:.2f}s")
async def _iterative_api_explorer(self, seed_urls: List[str], max_rounds: int = 3) -> List[str]:
    discovered = set()
    queue = list(seed_urls)
    round_num = 0; visited = set()
    logger.info(f"   Iterative API explorer started: {len(seed_urls)} seed URLs, max {max_rounds} rounds")
    while queue and round_num < max_rounds:
        round_num += 1
        next_queue = []
        batch = queue[:30]
        logger.info(f"      💚 第{round_num} 轮：处理 {len(batch)} 个URL")
        for url in batch:
            if url in visited:
                continue
            visited.add(url)
            if url.startswith('/'):
                url = urlparse(self.target)._replace(path=url).geturl()
            try:
                resp = await async_get(url, session=self.session, timeout=10)
                status, text = resp[0], resp[1]
                if status != 200:
                    continue
                discovered.add(url)
                if '<html' in text.lower() or '<a ' in text.lower():
                    hrefs = re.findall(r'href=["\']([^"\']+)["\']', text, re.I)
                    for h in hrefs:
                        if h.startswith('/') and not h.endswith(('.css', '.js', '.png', '.jpg', '.svg', '.ico', '.woff', '.woff2', '.ttf')):
                            full = urlparse(self.target)._replace(path=h).geturl()
                            if full not in visited:
                                next_queue.append(full)
                try:
                    data = json.loads(text)
                    strings = self._extract_strings_from_json(data)
                    for s in strings:
                        if isinstance(s, str) and s.startswith('/') and len(s) > 3:
                            if not s.endswith(('.css', '.js', '.png', '.jpg', '.svg', '.ico')):
                                full = urlparse(self.target)._replace(path=s).geturl()
                                if full not in visited:
                                    next_queue.append(full)
                        if isinstance(s, str) and self._is_likely_id(s):
                            base_path = urlparse(url).path.rstrip('/')
                            if base_path and not base_path.endswith(('.css', '.js')):
                                if not any(part in base_path for part in ['detail', 'view', 'get']):
                                    detail_url = urlparse(self.target)._replace(path=f"{base_path}/{s}").geturl()
                                    if detail_url not in visited:
                                        next_queue.append(detail_url)
                except BaseException:
                    pass
                if isinstance(resp, tuple) and len(resp) > 2:
                    location = resp[2].get('Location', '')
                    if location and location.startswith('/'):
                        full = urlparse(self.target)._replace(path=location).geturl()
                        if full not in visited:
                            next_queue.append(full)
            except Exception as e:
                logger.debug(f"         ⚠️ 探索 {url} 失败: {e}")
        queue = list(set(next_queue))[:30]
        logger.info(f"      ✅第{round_num} 轮完成！发现 {len(queue)} 个新URL")
    logger.info(f"   ✅ [多轮迭代] 完成，共发现 {len(discovered)} 个唯一URL")
    return list(discovered)
def _extract_strings_from_json(self, obj, depth=0) -> List[str]:
    if depth > 5:
        return []
    results = []
    if isinstance(obj, dict):
        for v in obj.values():
            results.extend(self._extract_strings_from_json(v, depth + 1))
    elif isinstance(obj, list):
        for item in obj:
            results.extend(self._extract_strings_from_json(item, depth + 1))
    elif isinstance(obj, str):
        results.append(obj)
    return results
def _is_likely_id(self, value: str) -> bool:
    if re.match(r'^\d+$', value) and len(value) > 1:
        return True
    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
        return True
    if re.match(r'^[0-9a-f]{32,64}$', value, re.I):
        return True
    return False
async def _fetch_from_burp(self, brief: Dict):
    logger.info("   🔌 [Burp] 获取历史数据...")
    try:
        history = await self.burp_client.get_history_since(0, limit=100)
        if history:
            logger.info(f"      Burp history entries: {len(history)}")
            params_found = set()
            for item in history[:50]:
                url = item.get('url', '')
                if '?' in url:
                    for part in url.split('?')[1].split('&'):
                        if '=' in part:
                            pname = part.split('=')[0]
                            if pname and pname not in self._safe_params:
                                params_found.add(pname)
            brief["burp_params"] = list(params_found)
            logger.info(f"      Burp hidden parameters: {len(params_found)}")
    except Exception as e:
        logger.debug(f"Burp历史获取失败: {e}")
    try:
        cookies = await self.burp_client.get_cookies_from_history(limit=100)
        if cookies:
            target_domain = urlparse(self.target).netloc
            for domain, cookie_dict in cookies.items():
                if target_domain in domain or domain in target_domain:
                    brief["burp_cookies"] = cookie_dict
                    logger.info(f"      🍪 Burp获取 {len(cookie_dict)} 个Cookie")
                    break
    except Exception:
        pass
    try:
        tokens = await self.burp_client.get_tokens_from_history(limit=100)
        if tokens:
            target_domain = urlparse(self.target).netloc
            for domain, token_dict in tokens.items():
                if target_domain in domain or domain in target_domain:
                    brief["burp_tokens"] = token_dict
                    logger.info(f"      🔑 Burp获取 {len(token_dict)} 个Token")
                    break
    except Exception:
        pass
    # 步骤2 修复：原逻辑把 Burp 知识库的 issue 类型定义（静态目录）
    # 当作目标漏洞加入 findings，属于严重误报，已移除。
    # 真实的 Burp 扫描结果应通过 send_to_scanner 提交后用
    # get_scan_issues(scan_id) 拉取（见 orchestrator 集成，步骤3）。
async def _get_collaborator_domain(self) -> Optional[str]:
    if not self.burp_available:
        return None
    try:
        result = await self.burp.collaborator("get_domain")
        if result and result.get("domain"):
            self.burp._interactsh_domain = result["domain"]
            return result["domain"]
    except Exception:
        pass
    return None
async def _check_collaborator_callback(self):
    if not self._collaborator_domain:
        return
    try:
        logger.info(f"💚 [Collaborator] 检查回调: {self._collaborator_domain}")
        results = await self.burp.collaborator("check")
        if results and results.get("results"):
            logger.info(f"   Collaborator callbacks: {len(results['results'])}")
            for item in results["results"]:
                self._add_finding({
                    "type": "带外交互 (OOB)",
                    "severity": "High",
                    "evidence": f"收到 {item.get('type', 'unknown')} 回调: {item.get('data', '')[:100]}",
                    "url": self.target,
                    "source": "burp_collaborator",
                    "confidence": "high",
                })
    except Exception as e:
        logger.debug(f"Collaborator 回调检查失败: {e}")
def _detect_tech(self, headers: Dict, text: str) -> List[str]:
    techs = []
    server = headers.get("Server", "")
    if server:
        techs.append(server)
    x_powered = headers.get("X-Powered-By", "")
    if x_powered:
        techs.append(x_powered)
    patterns = {
        "wordpress": "WordPress", "laravel": "Laravel", "django": "Django",
        "react": "React", "vue": "Vue", "angular": "Angular",
        "spring": "Spring", "php": "PHP", "java": "Java", "python": "Python",
        "ruby": "Ruby", "node.js": "Node.js", "go": "Go",
        "asp.net": "ASP.NET", "nginx": "Nginx", "apache": "Apache"
    }
    text_lower = text.lower()
    for kw, name in patterns.items():
        if kw in text_lower:
            techs.append(name)
    return list(set(techs))[:10]
__all__ = ['_recon', '_deep_recon', '_deep_recon_internal', '_iterative_api_explorer', '_extract_strings_from_json', '_is_likely_id', '_fetch_from_burp', '_get_collaborator_domain', '_check_collaborator_callback', '_detect_tech']
