# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""内置漏洞声明集——**新增漏洞类型就是在这里加一条数据**。

这些声明覆盖了以往需要多个独立引擎才能实现的能力（报错型注入、反射型 XSS、
时间盲注、命令注入、LFI、SSRF），全部由同一套执行器（SpecRunner）驱动，
无需为每个类型编写引擎代码。
"""
import json
import os
from typing import Dict, List, Optional, Tuple

from .model import from_dict


# 声明即数据：后续可整体迁移到 YAML/JSON 外部文件，代码零改动。
_BUILTIN: List[Dict] = [
    {
        "id": "sql_error",
        "name": "SQL 注入（报错型）",
        "category": "injection",
        "payloads": ["'", "\\", "1'", '1"', "')", "1')"],
        "detect": {
            "type": "regex",
            "patterns": [
                r"you have an error in your sql",
                r"sql syntax",
                r"mysql_fetch|mysqli?_",
                r"unclosed quotation mark",
                r"ora-\d{4,5}",
                r"pg_query|postgresql",
                r"sqlite|sqlite3",
                r"microsoft odbc|odbc driver",
            ],
        },
        "severity": "high",
        "cvss": 8.6,
        "confidence": "medium",
        "remediation": "使用参数化查询（预编译语句）或经过严格白名单校验的 ORM，禁止字符串拼接 SQL。",
        "recommendation": "统一数据访问层强制参数化；对错误信息脱敏，避免泄露数据库细节。",
    },
    {
        "id": "xss_reflect",
        "name": "跨站脚本（反射型）",
        "category": "xss",
        "payloads": [
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert(1)>",
            "'><svg/onload=alert(1)>",
        ],
        # require_content_type：JSON 响应里回显 <script> 不会执行，
        # 不加此约束会对"原样回显输入"的接口大量误报。
        "detect": {"type": "reflect", "extra": {"core": "alert(1)"},
                   "require_content_type": "html"},
        "severity": "medium",
        "cvss": 6.1,
        "confidence": "medium",
        "remediation": "输出到 HTML 前按上下文做转义（HTML/属性/JS/URL 各自编码），并设置 CSP。",
        "recommendation": "使用模板引擎自动转义；对富文本使用白名单净化；启用 CSP 与 HttpOnly Cookie。",
    },
    {
        "id": "sqli_time_blind",
        "name": "SQL 注入（时间盲注）",
        "category": "injection",
        "payloads": ["1' AND SLEEP(3)-- ", "1 AND SLEEP(3)", "1'; WAITFOR DELAY '0:0:3'-- "],
        "detect": {"type": "time", "threshold": 2.5},
        "severity": "high",
        "cvss": 8.6,
        "confidence": "medium",
        "remediation": "使用参数化查询；限制数据库账户权限与慢查询，避免延时原语被利用。",
        "recommendation": "统一参数化；对异常耗时请求做监控告警。",
    },
    {
        "id": "sqli_boolean_blind",
        "name": "SQL 注入（布尔盲注）",
        "category": "injection",
        "payloads": ["1 AND 1=1", "1' AND '1'='1", "1 AND 2=2"],
        # 可观察破绽：真条件使**结果集变大**，全程无报错（区别于 sql_error 的报错型）。
        # 局限：当前用正则抓"结果行数增多"这一信号；理想是双 payload 布尔差分
        # （A/B 响应差异互证），框架暂无双 payload 对比 oracle——需另开判据类型。
        "detect": {"type": "regex", "patterns": [
            r"\b([2-9]|[1-9]\d+)\s+rows?\s+returned\b",
            r"\b([2-9]|[1-9]\d+)\s+(records?|results?|entries)\b",
        ]},
        "severity": "high",
        "cvss": 8.6,
        "confidence": "medium",
        "param_hints": ["id", "uid", "pid", "num", "no", "key", "cat", "item", "page"],
        "remediation": "使用参数化查询（预编译语句）；不要用字符串拼接构造 SQL 条件。",
        "recommendation": "统一参数化；对同一参数的响应差异做基线对比监控。",
    },
    {
        "id": "cmd_injection",
        "name": "命令注入",
        "category": "rce",
        "payloads": [";id", "|id", "$(id)", "`id`", "&& id"],
        "detect": {"type": "regex", "patterns": [r"uid=\d+", r"gid=\d+", r"root:x:0:0:"]},
        "severity": "critical",
        "cvss": 9.8,
        "confidence": "high",
        "remediation": "禁止将外部输入拼接到 shell 命令；使用参数化的进程调用接口并做白名单校验。",
        "recommendation": "移除命令拼接，改用受控 API；最小权限运行服务进程。",
    },
    {
        "id": "lfi",
        "name": "本地文件包含 / 路径穿越",
        "category": "file",
        "payloads": [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
        ],
        "detect": {"type": "regex", "patterns": [r"root:x:0:0:", r"/bin/(?:ba)?sh"]},
        "severity": "high",
        "cvss": 7.5,
        "confidence": "medium",
        "param_hints": ["file", "path", "page", "template", "include", "dir", "doc", "name"],
        "remediation": "禁止以用户输入拼接文件路径；使用白名单映射或规范化后校验根前缀。",
        "recommendation": "文件路径一律服务端映射；开启 open_basedir/沙箱；拒绝包含 .. 与绝对路径。",
    },
    {
        "id": "ssrf_internal",
        "name": "服务端请求伪造（SSRF / 内网探测）",
        "category": "ssrf",
        "payloads": [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8080/",
            "http://[::1]/",
        ],
        "detect": {
            "type": "regex",
            "patterns": [r"ami-id", r"instance-id", r"169\.254\.169\.254", r"meta-data"],
        },
        "severity": "high",
        "cvss": 7.5,
        "confidence": "medium",
        "param_hints": ["url", "uri", "fetch", "target", "dest", "redirect", "proxy", "host", "site"],
        "remediation": "服务端对出站请求做白名单校验，禁止访问内网/链路本地地址与云元数据端点。",
        "recommendation": "统一出网代理并校验目标；禁用非必要协议；屏蔽 169.254.169.254 等元数据地址。",
    },
    {
        "id": "xxe",
        "name": "XML 外部实体注入（XXE）",
        "category": "xxe",
        "payloads": [
            '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>',
        ],
        "detect": {"type": "regex", "patterns": [r"root:x:0:0:", r"daemon:x:\d+", r"/bin/(?:ba)?sh"]},
        "severity": "high",
        "cvss": 7.5,
        "confidence": "medium",
        "param_hints": ["xml", "data", "body", "payload", "soap", "content", "doc"],
        "remediation": "禁用 XML 外部实体与 DTD 解析，使用安全配置的解析器。",
        "recommendation": "关闭 DTD/外部实体；优先改用 JSON；对 XML 输入做白名单校验。",
    },
    {
        "id": "ssti",
        "name": "服务端模板注入（SSTI）",
        "category": "ssti",
        "payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
        "detect": {"type": "regex", "patterns": [r"\b49\b"]},
        "severity": "high",
        "cvss": 8.6,
        "confidence": "medium",
        "param_hints": ["tpl", "template", "name", "q", "view", "render", "content", "page"],
        "remediation": "禁止将用户输入拼接进模板；使用沙箱化模板引擎并转义动态内容。",
        "recommendation": "模板与数据分离；对模板变量做严格类型与白名单校验。",
    },
    {
        "id": "crlf",
        "name": "CRLF / 响应头注入",
        "category": "header_injection",
        "payloads": ["%0d%0aX-Injected:1", "\r\nX-Injected:1", "%0aSet-Cookie:%20inj=1"],
        # 判据落在**响应头**：body 里出现该字符串只是普通回显，不代表头注入
        "detect": {"type": "header", "header_name": "X-Injected", "patterns": [r".+"]},
        "severity": "medium",
        "cvss": 6.1,
        "confidence": "medium",
        "remediation": "对写入响应头的输入剥离 CR/LF；禁止用户输入直接进入头字段。",
        "recommendation": "统一头写入封装并过滤 \\r\\n；对重定向地址做白名单。",
    },
    {
        "id": "open_redirect",
        "name": "开放重定向",
        "category": "redirect",
        "payloads": ["//evil.test", "https://evil.test", "/\\\\/evil.test"],
        "detect": {"type": "reflect", "extra": {"core": "evil.test"}},
        "severity": "medium",
        "cvss": 6.1,
        "confidence": "medium",
        "param_hints": ["url", "uri", "redirect", "next", "return", "to", "goto", "target", "dest"],
        "remediation": "重定向目标做白名单校验，禁止完全由外部输入决定跳转地址。",
        "recommendation": "使用相对路径或映射 ID；对外部域名做白名单校验。",
    },
    {
        "id": "nosql_injection",
        "name": "NoSQL 注入",
        "category": "injection",
        "payloads": ['{"$gt": ""}', "' || '1'=='1", "[$ne]=1"],
        "detect": {
            "type": "regex",
            "patterns": [r"unknown operator", r"\$where", r"bson", r"Cast to ObjectId failed", r"mongo"],
        },
        "severity": "high",
        "cvss": 8.6,
        "confidence": "medium",
        "param_hints": ["q", "query", "filter", "where", "search", "id", "user", "name"],
        "remediation": "对查询参数做类型与结构校验，禁止把请求对象直接当作查询条件。",
        "recommendation": "用 schema 校验过滤 $ 开头操作符；禁用 $where 等危险操作。",
    },
    {
        "id": "ldap_injection",
        "name": "LDAP 注入",
        "category": "injection",
        "payloads": ["*", "*)(uid=*", "admin*)((|userPassword=*)"],
        "detect": {
            "type": "regex",
            "patterns": [r"invalid dn", r"javax\.naming", r"80090308", r"ldap_search", r"Bad search filter", r"search filter syntax"],
        },
        "severity": "high",
        "cvss": 7.5,
        "confidence": "low",
        "param_hints": ["user", "uid", "name", "dn", "filter", "search", "login", "account"],
        "remediation": "对 LDAP 查询参数做转义与白名单，禁止拼接过滤器。",
        "recommendation": "使用参数化 LDAP API；对 * ( ) \\ NUL 等特殊字符转义。",
    },
    {
        "id": "java_deserialization",
        "name": "Java 反序列化",
        "category": "deserialization",
        "payloads": ["rO0ABXQACkhlbGxvV29ybGQ=", "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==", "aced000573720011"],
        "detect": {
            "type": "regex",
            "patterns": [r"ClassNotFoundException", r"java\.io\.", r"ObjectInputStream",
                         r"InvokerTransformer", r"org\.apache\.commons"],
        },
        "severity": "critical",
        "cvss": 9.8,
        "confidence": "medium",
        "param_hints": ["data", "obj", "object", "payload", "token", "rO0", "ser", "session"],
        "remediation": "禁止反序列化不可信数据；使用白名单类校验（ObjectInputFilter）或改用 JSON。",
        "recommendation": "升级依赖移除可利用 gadget；开启 JEP 290 过滤；对反序列化入口做鉴权。",
    },
    {
        "id": "dotnet_deserialization",
        "name": ".NET 反序列化",
        "category": "deserialization",
        "payloads": ["AAEAAAD/////AQAAAAAAAAAEAQAAABJTeXN0ZW0u", "AAEAAAD/////AQAAAAAAAAAMAgAAAF9uZXQ="],
        "detect": {
            "type": "regex",
            "patterns": [r"TypeLoadException", r"System\.Runtime\.Serialization",
                         r"BinaryFormatter", r"ObjectStateFormatter", r"System\.Web\.UI"],
        },
        "severity": "critical",
        "cvss": 9.8,
        "confidence": "medium",
        "param_hints": ["data", "obj", "viewstate", "__VIEWSTATE", "payload", "state"],
        "remediation": "禁用 BinaryFormatter/不安全的反序列化；使用安全序列化器并校验类型白名单。",
        "recommendation": "替换 BinaryFormatter；对 ViewState 启用 MAC 校验与加密。",
    },
    {
        "id": "php_object_injection",
        "name": "PHP 对象注入（反序列化）",
        "category": "deserialization",
        "payloads": ['O:8:"stdClass":0:{}', 'O:4:"Test":1:{s:4:"test";s:3:"aaa";}',
                     'a:1:{i:0;O:8:"stdClass":0:{}}'],
        "detect": {
            "type": "regex",
            "patterns": [r"unserialize\(\)", r"__PHP_Incomplete_Class",
                         r"Notice: unserialize", r"Error at offset"],
        },
        "severity": "high",
        "cvss": 8.1,
        "confidence": "medium",
        "param_hints": ["data", "obj", "payload", "ser", "cookie", "session", "value"],
        "remediation": "不要对用户可控数据调用 unserialize()；改用 json_decode 并校验结构。",
        "recommendation": "移除危险反序列化入口；对必须的场景使用 allowed_classes 限制。",
    },
    {
        "id": "python_pickle_injection",
        "name": "Python pickle 反序列化",
        "category": "deserialization",
        "payloads": ["gASV", "gASVKQAAAAAAAACMCGJ1aWx0aW5zlIwDZXZhbJSTlIwAc2VsZi5fX2NsYXNzX18=",
                     "cos\nsystem\n(S'id'\ntR."],
        "detect": {
            "type": "regex",
            "patterns": [r"UnpicklingError", r"pickle", r"__reduce__", r"invalid load key"],
        },
        "severity": "critical",
        "cvss": 9.8,
        "confidence": "medium",
        "param_hints": ["data", "obj", "payload", "pickle", "ser", "state", "session"],
        "remediation": "禁止对不可信数据使用 pickle.loads；改用 JSON 等安全格式。",
        "recommendation": "移除 pickle 反序列化入口；必须使用时校验签名与来源。",
    },
    {
        "id": "graphql_introspection",
        "name": "GraphQL 内省开放（信息泄露）",
        "category": "info_disclosure",
        "payloads": ["{__schema{types{name}}}", "{__typename}",
                     "query{__schema{queryType{name}}}"],
        # ⚠️ 只认**内省响应的 JSON 键形态**（"__schema": / "__typename": / "queryType":），
        # 不能只搜 __schema 字样：真实误报（2026-09-12 外部测试集实测）——
        # 回显型服务（如 httpbin /get）会把我们发出去的 payload `{__schema{types{name}}}`
        # 原样回显，于是"我方载荷的回显"被误判成"内省开放"。
        "detect": {"type": "regex",
                   "patterns": [r'"__schema"\s*:', r'"__typename"\s*:', r'"queryType"\s*:'],
                   "require_content_type": "json"},
        "severity": "low",
        "cvss": 5.3,
        "confidence": "medium",
        "param_hints": ["query", "q", "graphql", "data"],
        "remediation": "生产环境关闭 GraphQL 内省；对 API 增加鉴权与限流。",
        "recommendation": "按环境禁用 introspection；暴露面最小化并加访问控制。",
    },
    {
        "id": "xpath_injection",
        "name": "XPath 注入",
        "category": "injection",
        "payloads": ["' or '1'='1", "' or 1=1 or ''='", "x' | //* | 'y"],
        "detect": {
            "type": "regex",
            "patterns": [r"Invalid XPath", r"XPathException", r"xmlXPathEval",
                         r"SimpleXMLElement", r"XQuery"],
        },
        "severity": "high",
        "cvss": 7.5,
        "confidence": "medium",
        "param_hints": ["q", "query", "xpath", "search", "filter", "expr", "name"],
        "remediation": "XPath 查询参数化或对特殊字符转义，禁止拼接查询表达式。",
        "recommendation": "使用预编译 XPath 或白名单查询；对 ' \" | // 等字符转义。",
    },
    {
        "id": "log4shell",
        "name": "Log4Shell（JNDI 注入，需 OOB 复核）",
        "category": "rce",
        "payloads": ["${jndi:ldap://127.0.0.1:1389/a}", "${jndi:rmi://127.0.0.1:1099/a}",
                     "${${::-j}ndi:ldap://127.0.0.1/a}"],
        # 无 OOB 时以"JNDI 外连造成的显著延时"作为弱信号；真实确认需 OOB 回连。
        "detect": {"type": "time", "threshold": 2.0},
        "severity": "critical",
        "cvss": 10.0,
        "confidence": "low",
        "remediation": "升级 Log4j 至 2.17+；移除 JndiLookup 类；禁止日志输出执行 JNDI 查找。",
        "recommendation": "升级并移除 JndiLookup；WAF 拦截 ${jndi:；**本结论需 OOB 回连复核确认**。",
    },
    {
        "id": "cors_misconfig",
        "name": "CORS 配置不当（任意源可读取响应）",
        "category": "cors",
        "payloads": ["probe"],
        "request_headers": {"Origin": "https://evil.test"},
        "detect": {"type": "header", "header_name": "Access-Control-Allow-Origin",
                   "patterns": [r"^\*$", r"^null$", r"evil\.test"]},
        "severity": "medium",
        "cvss": 6.5,
        "confidence": "medium",
        "remediation": "Access-Control-Allow-Origin 只返回可信来源白名单，禁止通配 * 或回显任意 Origin。",
        "recommendation": "按白名单返回 ACAO；带凭证时绝不使用 *；同时限制 Allow-Methods/Headers。",
    },
    {
        "id": "missing_security_headers",
        "name": "缺失安全响应头",
        "category": "hardening",
        "payloads": ["probe"],
        "detect": {"type": "header", "header_name": "X-Content-Type-Options",
                   "header_absent": True},
        "severity": "low",
        "cvss": 3.7,
        "confidence": "high",
        "remediation": "补充 X-Content-Type-Options: nosniff（并建议 X-Frame-Options / CSP / HSTS）。",
        "recommendation": "在网关统一注入安全头；用本声明做回归校验。",
    },
    {
        "id": "host_header_injection",
        "name": "Host 头注入（X-Forwarded-Host 被拼进响应）",
        "category": "header_injection",
        "payloads": ["evil.test"],
        "request_headers": {"X-Forwarded-Host": "evil.test"},
        # 只认"被拼成 URL 主机部分"的回显；普通文本里出现 evil.test 不算
        "detect": {"type": "regex", "patterns": [r"https?://evil\.test"]},
        "severity": "medium",
        "cvss": 6.1,
        "confidence": "medium",
        "param_hints": ["url", "host", "redirect", "next", "to", "target", "q", "x"],
        "remediation": "禁止用 Host / X-Forwarded-Host 拼绝对 URL；对主机头做白名单校验。",
        "recommendation": "配置可信主机白名单；生成链接时使用站点配置域名而非请求头。",
    },
    {
        "id": "ssi_injection",
        "name": "SSI 服务端包含注入",
        "category": "injection",
        "payloads": [
            "<!--#exec cmd=\"id\"-->",
            "<!--#include virtual=\"/etc/passwd\"-->",
            "<!--#echo var=\"DATE_LOCAL\"-->",
            "<!--#config errmsg=\"x\"-->",
        ],
        "detect": {
            "type": "regex",
            "patterns": [
                r"\[an error occurred while processing this directive\]",
                r"root:x:0:0:",
                r"DATE_LOCAL",
            ],
        },
        "severity": "high",
        "cvss": 7.5,
        "confidence": "medium",
        "param_hints": ["page", "file", "template", "tpl", "include", "name", "path", "view", "section", "load"],
        "remediation": "禁用/剥离用户输入中的 SSI 指令，或关闭 SSI 解析。",
        "recommendation": "禁止将用户输入拼接进 SSI 模板；对 SSI 指令语法严格过滤。",
    },
    {
        "id": "el_injection",
        "name": "EL 表达式注入",
        "category": "injection",
        "payloads": ["${7*7}", "#{7*7}", "${''.getClass()}", "${pageContext.request.requestURI}"],
        "detect": {
            "type": "regex",
            "patterns": [
                r"javax\.el",
                r"ELException",
                r"ExpressionFactory",
                r"ELProcessor",
                r"StandardELContext",
            ],
        },
        "severity": "high",
        "cvss": 8.6,
        "confidence": "medium",
        "param_hints": ["el", "expr", "expression", "eval", "value", "data", "param", "config", "setting", "query", "search", "filter"],
        "remediation": "禁止将用户输入拼接进 EL 表达式；使用白名单校验的 EL 解析上下文。",
        "recommendation": "对 EL 解析上下文做沙箱与类白名单；避免暴露表达式入口。",
    },
    {
        "id": "rfi",
        "name": "远程文件包含（RFI）",
        "category": "file",
        "payloads": [
            "http://rfi-probe-nonexistent.invalid/x.php",
            "//rfi-probe-nonexistent.invalid/x.php",
        ],
        "detect": {
            "type": "regex",
            "patterns": [
                r"failed to open stream",
                r"getaddrinfo failed",
                r"php_network_getaddresses",
                r"include\(\): failed opening",
                r"require\(\): failed opening",
            ],
        },
        "severity": "high",
        "cvss": 8.1,
        "confidence": "medium",
        "param_hints": ["page", "file", "path", "url", "include", "require", "module", "template", "view", "doc", "load", "lang", "src"],
        "remediation": "禁止以用户输入拼接远程包含路径；关闭 allow_url_include 类特性。",
        "recommendation": "只允许包含本地白名单资源；校验协议与主机；禁用远程包装器。",
    },
    {
        "id": "dotenv_exposure",
        "name": "环境配置文件泄露（.env 可公开访问）",
        "category": "info_disclosure",
        "payloads": ["probe"],
        # 直接 GET 暴露的 .env/.env.* 文件：内容是 KEY=VALUE 且含敏感键
        "detect": {"type": "regex", "patterns": [
            r"(?i)^\s*(DB_PASSWORD|DB_PASS|API_KEY|SECRET_KEY|ACCESS_TOKEN|PRIVATE_KEY|AWS_|STRIPE_)\s*=",
            r"(?i)(DB_PASSWORD|API_KEY|SECRET)\s*[=:]\s*\S+",
        ]},
        "severity": "high",
        "cvss": 7.5,
        "confidence": "high",
        "remediation": "将 .env 移出 web 根目录；在网关/服务器层禁止访问 .env* 与配置文件。",
        "recommendation": "Web 服务器 deny .env*；密钥注入改为运行时环境变量而非文件落盘。",
    },
    {
        "id": "actuator_exposure",
        "name": "Actuator / 未授权敏感端点暴露（配置泄露）",
        "category": "info_disclosure",
        "payloads": ["probe"],
        # Spring Boot Actuator /env 类端点：响应含 propertySources + 敏感键
        "detect": {"type": "regex", "patterns": [
            r'(?i)"(DB_PASSWORD|JWT_SECRET|SPRING_DATASOURCE|PASSWORD)"\s*"\s*:\s*\{?\s*"value"',
            r'(?i)"activeProfiles"',
            r'(?i)"propertySources"',
        ]},
        "severity": "high",
        "cvss": 7.5,
        "confidence": "medium",
        "remediation": "禁用/限制 Actuator 端点暴露，对 /env /configprops 等做鉴权与网络隔离。",
        "recommendation": "endpoints.web.exposure.include 白名单；敏感端点仅内网 + 鉴权。",
    },
    {
        "id": "component_version_disclosure",
        "name": "前端组件版本泄露（已知脆弱版本）",
        "category": "component",
        "payloads": ["probe"],
        # 升级：版本号 → 脆弱阈值 → CVE 知识库对照（component 型 oracle）。
        # 不再"命中版本字符串即报"，而是提取版本并与 vulnerable_below 比较，
        # 仅版本落在脆弱区间才判定，并标注对应 CVE。
        "detect": {"type": "component", "signatures": [
            {"lib": "jQuery",    "pattern": r"(?i)jquery[ /.\-_]*v?(\d+\.\d+(?:\.\d+)?)",
             "vulnerable_below": "3.5.0", "cve": "CVE-2020-11022"},
            {"lib": "AngularJS", "pattern": r"(?i)angular[.\-]?js[ /.\-_]*v?(\d+\.\d+(?:\.\d+)?)",
             "vulnerable_below": "1.8.0", "cve": "CVE-2019-10712"},
            # 同一库多分支阈值必须把**主版本写进正则**：否则 Bootstrap 3.3.7 会同时满足
            # "3.3.7<3.4.0" 与 "3.3.7<4.3.1" 两条 → 报出实际不适用 3.x 的 CVE-2018-14041（4.x 专属）。
            {"lib": "Bootstrap", "pattern": r"(?i)bootstrap[ /.\-_]*v?(3\.\d+(?:\.\d+)?)",
             "vulnerable_below": "3.4.0", "cve": "CVE-2019-8331"},
            {"lib": "Bootstrap", "pattern": r"(?i)bootstrap[ /.\-_]*v?(4\.\d+(?:\.\d+)?)",
             "vulnerable_below": "4.3.1", "cve": "CVE-2018-14041"},
            {"lib": "lodash", "pattern": r"(?i)lodash[ /.\-_]*v?(\d+\.\d+(?:\.\d+)?)", "vulnerable_below": "4.17.21", "cve": "CVE-2020-8203"},
            {"lib": "moment", "pattern": r"(?i)moment[.\-]?js[ /.\-_]*v?(\d+\.\d+(?:\.\d+)?)", "vulnerable_below": "2.29.4", "cve": "CVE-2022-24785"},
            {"lib": "jQuery UI", "pattern": r"(?i)jquery[ .\-]?ui[ /.\-_]*v?(\d+\.\d+(?:\.\d+)?)", "vulnerable_below": "1.13.2", "cve": "CVE-2022-31160"},
            {"lib": "axios", "pattern": r"(?i)axios[ /.\-_]*v?(\d+\.\d+(?:\.\d+)?)", "vulnerable_below": "0.21.2", "cve": "CVE-2021-3749"},
            {"lib": "Handlebars", "pattern": r"(?i)handlebars[ /.\-_]*v?(\d+\.\d+(?:\.\d+)?)", "vulnerable_below": "4.7.7", "cve": "CVE-2021-23369"},
            {"lib": "DOMPurify", "pattern": r"(?i)dompurify[ /.\-_]*v?(\d+\.\d+(?:\.\d+)?)", "vulnerable_below": "2.0.17", "cve": "CVE-2020-26870"},
            {"lib": "marked", "pattern": r"(?i)marked[ /.\-_]*v?(\d+\.\d+(?:\.\d+)?)", "vulnerable_below": "4.0.10", "cve": "CVE-2022-21680"},
            {"lib": "React", "pattern": r"(?i)react[ /.\-_]*v?(\d+\.\d+(?:\.\d+)?)", "vulnerable_below": "16.4.1", "cve": "CVE-2018-6341"},
            {"lib": "underscore", "pattern": r"(?i)underscore[ /.\-_]*v?(\d+\.\d+(?:\.\d+)?)", "vulnerable_below": "1.13.1", "cve": "CVE-2021-23358"},
            {"lib": "serialize-javascript", "pattern": r"(?i)serialize-javascript[ /.\-_]*v?(\d+\.\d+(?:\.\d+)?)", "vulnerable_below": "3.1.0", "cve": "CVE-2020-7660"},
            {"lib": "Vue", "pattern": r"(?i)vue(?:\.js)?[ /.\-_]*v?(\d+\.\d+(?:\.\d+)?)", "vulnerable_below": "2.7.16", "cve": "CVE-2024-6783"},
            # 加厚第三批（CVE 版本阈值均经外部漏洞库核实，非臆测）
            {"lib": "pdf.js", "pattern": r"(?i)pdf\.?js(?:-dist)?[ /.\-_@]*v?(\d+\.\d+(?:\.\d+)?)",
             "vulnerable_below": "4.2.67", "cve": "CVE-2024-4367"},
            {"lib": "Chart.js", "pattern": r"(?i)chart\.?js[ /.\-_]*v?(\d+\.\d+(?:\.\d+)?)",
             "vulnerable_below": "2.9.4", "cve": "CVE-2020-7746"},
        ]},
        "severity": "medium",
        "cvss": 6.1,
        "confidence": "medium",
        "remediation": "升级前端依赖到修复版本；对静态资源做版本指纹管理并定期审计 CVE。",
        "recommendation": "引入 SCA（软件成分分析）对接 CVE 库；构建期锁定安全版本。",
    },
    {
        "id": "file_upload_point",
        "name": "文件上传点暴露（可上传文件功能）",
        "category": "upload",
        "payloads": ["probe"],
        # 响应含 multipart/form-data 表单 + file 输入 → 存在文件上传功能点
        # （侦察级发现；"是否可执行/可绕过"需引擎线进一步验证）。
        "detect": {"type": "regex", "patterns": [
            r'(?i)<form[^>]+enctype\s*=\s*["\']?multipart/form-data',
            r'(?i)<input[^>]+type\s*=\s*["\']?file',
        ]},
        "severity": "medium",
        "cvss": 5.3,
        "confidence": "low",
        "remediation": "上传点做类型/大小白名单、服务端重命名、存储隔离与执行权限收口；上传目录禁止脚本执行。",
        "recommendation": "落地到非执行目录；图片二次渲染；限制 Content-Type 与扩展名。",
    },
    {
        "id": "idor_unauthorized_access",
        "name": "越权/未授权资源访问（多会话 IDOR 证实）",
        "category": "access_control",
        "payloads": ["probe"],
        # 升级：从"单请求弱线索（响应里出现 role=owner 字样）"改为**多身份对比证实**——
        # 同一资源用属主/非属主两种身份各请求一次，两者都读到属主数据 → 越权成立。
        # 该口径天然排除"公开数据"与"属主都读不到"的假象，结论从"线索"升级为"证实"。
        "detect": {"type": "idor_multisession", "extra": {
            "owner_headers": {"Cookie": "session=owner"},
            "attacker_headers": {"Cookie": "session=attacker"},
            "owner_marker": r"(?i)admin@corp\.local",
        }},
        "severity": "medium",
        "cvss": 6.5,
        "confidence": "medium",
        "remediation": "资源访问须做对象级属主校验；禁止仅凭 id 返回他人数据。",
        "recommendation": "引入鉴权中间件 + 资源归属校验；对敏感接口做横向越权自测。",
    },
    {
        "id": "git_exposure",
        "name": "Git 源码仓库泄露（.git 可公开访问）",
        "category": "info_disclosure",
        "payloads": ["probe"],
        # 直接 GET 暴露的 .git/config 等元数据：内容是仓库配置段。
        # 泄露后可结合 .git/objects 拉取源码（源码级信息泄露，非仅线索）。
        "detect": {"type": "regex", "patterns": [
            r"(?i)\[core\]\s*\n\s*repositoryformatversion",
            r"(?i)\[remote\s*\"origin\"\]",
            r"(?i)^ref:\s*refs/heads/",
        ]},
        "severity": "high",
        "cvss": 7.5,
        "confidence": "high",
        "remediation": "禁止 Web 直接访问 .git 目录；网关/服务器层 deny `.git`；部署时排除版本控制目录。",
        "recommendation": "Web 服务器 deny `/.git/*`；发布产物剥离 .git；定期扫描源码泄露路径。",
    },
    {
        "id": "stored_xss",
        "name": "存储型 XSS（写入后回读未转义）",
        "category": "xss",
        "payloads": ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>',
                     "'><svg/onload=alert(1)>"],
        # 流程型 oracle：先把 payload 写入留言，再回读列表；读回时未被转义 → 存储型 XSS 证实。
        "detect": {"type": "flow", "extra": {"flow": {
            "write": {"path": "/guestbook", "param": "msg"},
            "read": {"path": "/guestbook/list"},
            "assert": {"mode": "unescaped_reflect"},
        }}},
        "severity": "high",
        "cvss": 7.2,
        "confidence": "medium",
        "remediation": "存储前对富文本做白名单净化，输出时按上下文转义；对用户内容启用 CSP。",
        "recommendation": "入库净化 + 出库编码双层防护；富文本用成熟 sanitizer；开启 HttpOnly/CSP。",
    },
    {
        "id": "second_order_sqli",
        "name": "二次注入（存储型 SQL 注入）",
        "category": "injection",
        "payloads": ["'", "1'", "1\"", "')", "1')"],
        # 流程型 oracle：payload 先被安全存入，随后被**拼接**进查询 → 读回时触发 SQL 报错。
        "detect": {"type": "flow", "extra": {"flow": {
            "write": {"path": "/notes", "param": "note"},
            "read": {"path": "/notes/search"},
            "assert": {"mode": "regex", "patterns": [
                r"sql syntax", r"unterminated", r"sqlite error", r"quotation mark",
            ]},
        }}},
        "severity": "high",
        "cvss": 8.1,
        "confidence": "medium",
        "remediation": "二次查询同样使用参数化；不要把已存储的字符串再拼进 SQL。",
        "recommendation": "统一数据访问层强制参数化；对存储值二次使用时也走绑定变量。",
    },
    {
        "id": "dependency_manifest",
        "name": "依赖清单暴露（已知脆弱依赖 / SCA）",
        "category": "component",
        "payloads": ["probe"],
        # SCA 的 HTTP 落地（复用 component oracle，不新增类型）：
        # 目标暴露依赖清单（package.json / requirements.txt）时，从清单里按"包名+版本"提取，
        # 与已知脆弱阈值/CVE 对照。数据源不同于 component 的"静态 JS 库文件指纹"，两族互补。
        "detect": {"type": "component", "signatures": [
            {"lib": "npm:lodash", "pattern": r'"?lodash"?\s*[:=]\s*"?[\^~]?(\d+\.\d+\.\d+)',
             "vulnerable_below": "4.17.21", "cve": "CVE-2020-8203"},
            {"lib": "npm:axios", "pattern": r'"?axios"?\s*[:=]\s*"?[\^~]?(\d+\.\d+\.\d+)',
             "vulnerable_below": "0.21.2", "cve": "CVE-2021-3749"},
            {"lib": "pip:django", "pattern": r"(?i)django==(\d+\.\d+(?:\.\d+)?)",
             "vulnerable_below": "3.2.15", "cve": "CVE-2022-28346"},
            {"lib": "pip:requests", "pattern": r"(?i)requests==(\d+\.\d+(?:\.\d+)?)",
             "vulnerable_below": "2.31.0", "cve": "CVE-2023-32681"},
            {"lib": "npm:node-fetch", "pattern": r'"?node-fetch"?\s*[:=]\s*"?[\^~]?(\d+\.\d+(?:\.\d+)?)',
             "vulnerable_below": "2.6.7", "cve": "CVE-2022-0235"},
            {"lib": "composer:guzzle", "pattern": r'(?i)"guzzlehttp/guzzle"\s*:\s*"[\^~]?(\d+\.\d+\.\d+)',
             "vulnerable_below": "7.4.5", "cve": "CVE-2022-31042"},
            {"lib": "maven:log4j-core",
             "pattern": r"(?i)log4j-core\s*</artifactId>[\s\S]{0,80}?<version>(\d+\.\d+(?:\.\d+)?)",
             "vulnerable_below": "2.17.0", "cve": "CVE-2021-44228"},
            {"lib": "npm:debug", "pattern": r'"?debug"?\s*[:=]\s*"?[\^~]?(\d+\.\d+(?:\.\d+)?)',
             "vulnerable_below": "2.6.9", "cve": "CVE-2017-16137"},
            {"lib": "npm:minimist", "pattern": r'"?minimist"?\s*[:=]\s*"?[\^~]?(\d+\.\d+(?:\.\d+)?)',
             "vulnerable_below": "1.2.6", "cve": "CVE-2021-44906"},
            {"lib": "gem:nokogiri", "pattern": r"(?i)nokogiri\s*\((\d+\.\d+(?:\.\d+)?)\)",
             "vulnerable_below": "1.13.6", "cve": "CVE-2022-24836"},
            {"lib": "go:x/text", "pattern": r"golang\.org/x/text\s+v?(\d+\.\d+(?:\.\d+)?)",
             "vulnerable_below": "0.3.7", "cve": "CVE-2021-38561"},
            {"lib": "maven:spring-core",
             "pattern": r"(?i)spring-core\s*</artifactId>[\s\S]{0,80}?<version>(\d+\.\d+(?:\.\d+)?)",
             "vulnerable_below": "5.3.18", "cve": "CVE-2022-22965"},
            {"lib": "pip:pyyaml", "pattern": r"(?i)pyyaml==(\d+\.\d+(?:\.\d+)?)",
             "vulnerable_below": "5.4", "cve": "CVE-2020-14343"},
            {"lib": "npm:jsonwebtoken",
             "pattern": r'"?jsonwebtoken"?\s*[:=]\s*"?[\^~]?(\d+\.\d+(?:\.\d+)?)',
             "vulnerable_below": "9.0.0", "cve": "CVE-2022-23529"},
            # 加厚第三批（CVE 版本阈值均经外部漏洞库核实）
            # npm 短包名统一加 (?<![\w-]) 左边界，避免 "ws" 误配 "aws" 这类子串。
            {"lib": "npm:express", "pattern": r'(?<![\w-])"?express"?\s*[:=]\s*"?[\^~]?(\d+\.\d+\.\d+)',
             "vulnerable_below": "4.17.3", "cve": "CVE-2022-24999"},
            {"lib": "npm:ws", "pattern": r'(?<![\w-])"?ws"?\s*[:=]\s*"?[\^~]?(\d+\.\d+(?:\.\d+)?)',
             "vulnerable_below": "8.17.1", "cve": "CVE-2024-37890"},
            {"lib": "npm:ejs", "pattern": r'(?<![\w-])"?ejs"?\s*[:=]\s*"?[\^~]?(\d+\.\d+(?:\.\d+)?)',
             "vulnerable_below": "3.1.7", "cve": "CVE-2022-29078"},
            {"lib": "pip:jinja2", "pattern": r"(?i)jinja2==(\d+\.\d+(?:\.\d+)?)",
             "vulnerable_below": "3.1.3", "cve": "CVE-2024-22195"},
            {"lib": "pip:setuptools", "pattern": r"(?i)setuptools==(\d+\.\d+(?:\.\d+)?)",
             "vulnerable_below": "65.5.1", "cve": "CVE-2022-40897"},
            {"lib": "maven:fastjson",
             "pattern": r"(?i)fastjson\s*</artifactId>[\s\S]{0,80}?<version>(\d+\.\d+(?:\.\d+)?)",
             "vulnerable_below": "1.2.83", "cve": "CVE-2022-25845"},
            # 加厚第四批：**锁文件**（真实项目更常暴露的是 lock 而非 manifest）。
            # 数据源与上面"清单文件"互补：同一 component oracle，零代码改动。
            {"lib": "npm:lodash(package-lock)",
             "pattern": r'"node_modules/lodash"\s*:\s*\{[^}]{0,200}?"version"\s*:\s*"(\d+\.\d+\.\d+)"',
             "vulnerable_below": "4.17.21", "cve": "CVE-2020-8203"},
            {"lib": "npm:lodash(yarn.lock)",
             "pattern": r'(?m)^lodash@[^\n]*\n\s+version\s+"(\d+\.\d+(?:\.\d+)?)"',
             "vulnerable_below": "4.17.21", "cve": "CVE-2020-8203"},
            {"lib": "pip:django(poetry.lock)",
             "pattern": r'(?s)name\s*=\s*"django"\s*\n\s*version\s*=\s*"(\d+\.\d+(?:\.\d+)?)"',
             "vulnerable_below": "3.2.15", "cve": "CVE-2022-28346"},
            {"lib": "pip:django(Pipfile.lock)",
             "pattern": r'"django"\s*:\s*\{[^}]{0,120}?"version"\s*:\s*"==(\d+\.\d+(?:\.\d+)?)"',
             "vulnerable_below": "3.2.15", "cve": "CVE-2022-28346"},
            {"lib": "composer:guzzle(composer.lock)",
             "pattern": r'"name"\s*:\s*"guzzlehttp/guzzle"[\s\S]{0,160}?"version"\s*:\s*"v?(\d+\.\d+\.\d+)"',
             "vulnerable_below": "7.4.5", "cve": "CVE-2022-31042"},
            {"lib": "maven:log4j-core(gradle.lockfile)",
             "pattern": r"(?m)^org\.apache\.logging\.log4j:log4j-core:(\d+\.\d+(?:\.\d+)?)=",
             "vulnerable_below": "2.17.0", "cve": "CVE-2021-44228"},
            # ★ KB（OSV）型：一条签名覆盖**整个 Maven 生态**——宽度 = KB 里的包数
            # （当前 3363 个包 / 13171 条影响区间），且随数据重生成而保鲜。
            # 与上面手写阈值的区别：不再逐包手写，改由"包名+版本 → 查影响区间"。
            # groupId + artifactId + version：Maven 包名是 groupId:artifactId，两者都要取
            {"lib": "maven(KB)", "kb": "Maven", "kb_pkg_group": 2, "kb_ver_group": 3,
             "kb_groupid_group": 1,
             "pattern": r"<groupId>([\w\.\-]+)</groupId>\s*<artifactId>([\w\.\-]+)</artifactId>"
                        r"\s*<version>(\d[\w\.\-]*)</version>"},
            # pip（requirements.txt 风格）：name==version
            {"lib": "pip(KB)", "kb": "PyPI", "kb_pkg_group": 1, "kb_ver_group": 2,
             "pattern": r"(?m)^([A-Za-z0-9][\w\.\-]*)\s*==\s*(\d[\w\.\-]*)"},
            # npm（package.json 风格）："pkg": "1.2.3"
            {"lib": "npm(KB)", "kb": "npm", "kb_pkg_group": 1, "kb_ver_group": 2,
             "pattern": r'"([a-z0-9][\w\.\-@/]*)"\s*:\s*"[\^~]?(\d+\.\d+\.\d+)"'},
        ]},
        "severity": "medium",
        "cvss": 6.1,
        "confidence": "medium",
        "remediation": "定期对依赖清单做 SCA；升级/移除已知脆弱依赖；禁止将清单文件暴露到 Web。",
        "recommendation": "CI 集成 OSV/Dependabot 类扫描；锁定安全版本；生产环境 deny 清单文件路径。",
    },
    {
        "id": "dom_xss",
        "name": "DOM 型 XSS（浏览器执行证实）",
        "category": "xss",
        "payloads": ['<img src=x onerror=alert(1)>', '<svg/onload=alert(1)>',
                     '"><img src=x onerror=alert(1)>'],
        # 浏览器执行 oracle：渲染页面并监听 dialog；**只有真的弹出 alert 才算**
        # （执行级证实，而非"响应里出现 payload 字符串"的字符串匹配）。
        "detect": {"type": "dom_xss", "extra": {"path": "/dom-xss", "inject": "hash"}},
        "severity": "high",
        "cvss": 6.1,
        "confidence": "medium",
        "remediation": "禁止把 URL/不可信数据写入 innerHTML/document.write/eval；改用 textContent 或 sanitizer。",
        "recommendation": "引入受信 sanitizer（如 DOMPurify）；启用 CSP 限制内联脚本；规避危险 DOM sink。",
    },
    {
        "id": "biz_negative_amount",
        "name": "业务逻辑：非法金额被接受（负/零价下单）",
        "category": "business_logic",
        "payloads": ["-100", "-1", "0", "-0.01", "999999999"],
        # 业务不变量：订单金额必须为正。把负数/零/超限值发给下单点，
        # 若服务端接受并回显异常金额 → 业务校验缺失（不变量被破坏）。
        "detect": {"type": "biz_logic", "extra": {"logic": {
            "mode": "violation",
            "path": "/api/order",
            "param": "price",
            "violation": {"patterns": [r'"total"\s*:\s*-\d', r'"amount"\s*:\s*-\d']},
        }}},
        "severity": "high",
        "cvss": 7.1,
        "confidence": "medium",
        "remediation": "服务端对金额/数量做范围与类型校验；价格以服务端计价为准，禁止客户端决定。",
        "recommendation": "所有业务数值在服务端二次校验（>0、上限、类型）；价格后端计算，不信任入参。",
    },
    {
        "id": "biz_coupon_reuse",
        "name": "业务逻辑：一次性操作可重复（优惠券复用）",
        "category": "business_logic",
        "payloads": ["probe"],
        # 业务不变量：优惠券/一次性凭证只能用一次。同一请求连续发两次，
        # 若两次都返回"已应用" → 可重复使用 → 不变量破坏。
        "detect": {"type": "biz_logic", "extra": {"logic": {
            "mode": "repeatable",
            "path": "/api/coupon",
            "param": "code",
            "value": "SAVE10",
            "success_patterns": [r'"status"\s*:\s*"applied"', r'"success"\s*:\s*true'],
        }}},
        "severity": "medium",
        "cvss": 6.5,
        "confidence": "medium",
        "remediation": "一次性凭证服务端原子核销（用后置失效）；重复提交需幂等拒绝。",
        "recommendation": "优惠券/一次性 token 走服务端状态机 + 原子占用；重复请求返回已使用。",
    },
    # ===== 带外回连（OOB）：盲漏洞族的唯一可靠判据 =====
    # 盲 SSRF / 盲 RCE / 盲 XXE 的共同点：响应里**什么痕迹都没有**，
    # 单请求 oracle（regex/reflect/diff）到此为止；只能看目标是否回连我们。
    # 未配置 OOB_BASE_URL / OOB_HITS_FILE 时一律不探测（fail-closed）。
    {
        "id": "blind_ssrf",
        "name": "服务端请求伪造（盲，带外回连证实）",
        "category": "ssrf",
        "payloads": ["probe"],
        "detect": {"type": "oob", "extra": {"path": "/ssrf-blind"}},
        "severity": "high",
        "cvss": 8.6,
        "confidence": "high",
        "remediation": "对用户可控 URL 做协议/主机白名单，禁止访问内网与云元数据；出网走统一代理并审计。",
        "recommendation": "URL 白名单 + 禁 302 跳转 + 禁 DNS 重绑定 + 内网地址黑名单；出网流量集中审计。",
    },
    {
        "id": "cmd_blind",
        "name": "命令注入（盲，带外回连证实）",
        "category": "cmdi",
        "payloads": ["probe"],
        "detect": {"type": "oob", "extra": {"path": "/cmdi-blind"}},
        "severity": "critical",
        "cvss": 9.8,
        "confidence": "high",
        "remediation": "禁止拼接执行系统命令；必须执行时用白名单 + 参数数组传参，绝不经过 shell。",
        "recommendation": "移除 shell 调用，改语言内 API；无法避免时严格白名单 + 最小权限运行。",
    },
    {
        # 密钥/凭证泄露：以前只会找 .env/.git，认不出散落在 JS、配置里的真实密钥。
        # 规则来自 **gitleaks**（开源规则集），由 scripts/build_external_sigs.py 生成注入。
        # 未生成时 patterns 为空 → 声明自动失效（不报），绝不凭空猜测。
        "id": "secret_leak",
        "name": "密钥/凭证泄露（硬编码 AKIA、私钥、Token 等）",
        "category": "sensitive_data",
        "payloads": ["probe"],
        "detect": {"type": "regex", "patterns": []},
        "severity": "high",
        "cvss": 7.5,
        "confidence": "medium",
        "remediation": "立即吊销并轮换泄露的凭证；从代码与构建产物中移除。",
        "recommendation": "凭证只走环境变量/密钥管理服务；CI 增加密钥扫描门禁，禁止入库。",
    },
]


def _inject_external_sigs() -> None:
    """把外部现成知识源生成的签名并入声明（**缺失则静默跳过**）。

    为什么这样做：这些"知识"别人维护得比我们好（sqlmap 的 DBMS 报错库、
    gitleaks 的密钥规则、Retire.js 的前端库库表），自己手搓既窄又会过期。
    但外部数据一律**可选**：文件不在就退回手写部分，绝不因为外部数据缺失而报错。
    """
    try:
        from vulnclaw.core.settings import settings
        path = str(getattr(settings, "external_sigs_path", "") or "")
        if not path or not os.path.isfile(path):
            return
        with open(path, "r", encoding="utf-8") as fh:
            ext = json.load(fh)
    except Exception:  # noqa: BLE001 - 外部数据缺失/损坏一律降级，不影响主流程
        return

    for spec in _BUILTIN:
        sid = str(spec.get("id") or "")
        det = spec.get("detect")
        if not isinstance(det, dict):
            continue
        if sid == "sql_error" and ext.get("sql_errors"):
            det["patterns"] = list(dict.fromkeys(
                list(det.get("patterns") or []) + list(ext["sql_errors"])))
        elif sid == "secret_leak" and ext.get("secrets"):
            det["patterns"] = [s.get("pattern") for s in ext["secrets"]
                               if s.get("pattern")]
        elif sid == "component_version_disclosure" and ext.get("components"):
            det["signatures"] = list(det.get("signatures") or []) + list(ext["components"])


def _inject_promoted_component_sigs() -> int:
    """把 growth 晋升（人审后）的组件签名并入 component 声明（缺失静默跳过）。

    闭环（P1-6，2026-09-15）：OSV KB → 草稿 → validate → **人审 promote**
    （growth/component_osv_ingest.ComponentOsvIngest.promote →
    {cache}/growth/promoted_component_sigs.json）→ 本函数在声明构建时并入
    builtin —— 晋升即生效，无需改代码。返回注入条数（供测试断言）。
    """
    try:
        from vulnclaw.core.settings import PROJECT_CACHE_DIR
        path = os.path.join(str(PROJECT_CACHE_DIR), "growth",
                            "promoted_component_sigs.json")
        if not os.path.isfile(path):
            return 0
        with open(path, "r", encoding="utf-8") as fh:
            promoted = json.load(fh) or {}
    except Exception:  # noqa: BLE001 - 晋升数据缺失/损坏一律降级，不影响主流程
        return 0

    sigs = []
    for entry in promoted.values():
        for s in (entry.get("signatures") or []):
            if s.get("lib") and s.get("pattern") and s.get("cve"):
                sigs.append(s)
    if not sigs:
        return 0
    for spec in _BUILTIN:
        if str(spec.get("id") or "") == "component_version_disclosure":
            det = spec.get("detect")
            if isinstance(det, dict):
                det["signatures"] = list(det.get("signatures") or []) + sigs
                return len(sigs)
    return 0


_inject_external_sigs()
_inject_promoted_component_sigs()


BUILTIN_SPECS: Tuple = tuple(from_dict(d) for d in _BUILTIN)


def iter_specs(enabled_only: bool = True):
    for s in BUILTIN_SPECS:
        if enabled_only and not s.enabled:
            continue
        yield s


def get_spec(spec_id: str) -> Optional[object]:
    for s in BUILTIN_SPECS:
        if s.id == spec_id:
            return s
    return None


__all__ = ["BUILTIN_SPECS", "get_spec", "iter_specs"]
