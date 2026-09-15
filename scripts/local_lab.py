#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地轻量漏洞靶场（方案 C, 无 Docker）：XSS / SQLi(报错+布尔) / 文件上传 / SSTI / NoSQL / LDAP / 开放重定向 / CORS / 反序列化 / .env 泄露 端点。"""
import re
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

_SSTI_RE = re.compile(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}")

# 自建基准（G1）：每个端点的预期检出结论，供基准回归校验。
# 扫描结束后拿报告 vulnerabilities 按 expected/negatives 比对，得到 TP/FP/FN。
# 必须同时统计 FP（误报）与 FN（漏报），只看 FP 会造出“零误报的零发现”。
EXPECTED_FINDINGS = {
    "target": "http://127.0.0.1:8090",
    "endpoints": {
        "/xss?q=":             {"expect": ["XSS"],                          "min_severity": "High"},
        "/sqli?id=1":          {"expect": ["SQL注入", "SQLi"],              "min_severity": "High"},
        "/ssti?name=":         {"expect": ["SSTI", "模板注入"],             "min_severity": "High"},
        "/.env?q=":            {"expect": ["环境变量泄露", ".env"],         "min_severity": "Critical"},
        "/upload?q=":          {"expect": ["文件上传"],                      "min_severity": "High"},
        "/nosql?q=1":          {"expect": ["NoSQL"],                        "min_severity": "High"},
        "/ldap?user=admin":    {"expect": ["LDAP"],                         "min_severity": "High"},
        "/redirect?next=home": {"expect": ["开放重定向", "Open Redirect"],   "min_severity": "Medium"},
        "/cors":               {"expect": ["CORS"],                         "min_severity": "Medium"},
        "/deser?data=x":       {"expect": ["反序列化", "deserialization"],   "min_severity": "Medium"},
        # ===== tier=hard：难样本（2026-09-12 新增）=====
        # 目的：基础 10 端点已 100% 全中，标尺没有区分度；这些样本故意做成
        # "有可观察破绽但需要更强判据/更多上下文" 或 "当前无覆盖能力"，
        # 让分数先掉下来，再作为优化目标。
        # 判据难点：上下文（属性内）、布尔差分（无报错）、OOB/内网回显、XML 实体展开
        "/xss-attr?q=":        {"expect": ["XSS"],                          "min_severity": "High",   "tier": "hard"},
        "/sqli-blind?id=1":    {"expect": ["SQL注入", "SQLi"],              "min_severity": "High",   "tier": "hard"},
        "/ssrf?url=":          {"expect": ["SSRF"],                          "min_severity": "High",   "tier": "hard"},
        "/xxe?xml=":           {"expect": ["XXE", "实体注入"],               "min_severity": "High",   "tier": "hard"},
        # 覆盖缺口（预期 NA：声明线目前无对应能力，暴露功能空白而非漏报）
        "/idor?id=1&q=":       {"expect": ["越权", "IDOR"],                  "min_severity": "Medium", "tier": "hard"},
        "/actuator/env?q=":    {"expect": ["未授权", "信息泄露", "Actuator"], "min_severity": "Medium", "tier": "hard"},
        "/static/jquery-1.7.1.js?q=": {"expect": ["组件", "CVE", "jQuery"],  "min_severity": "Low",    "tier": "hard"},
        "/static/lodash-3.10.1.min.js?q=": {"expect": ["组件", "CVE"],        "min_severity": "Low",    "tier": "hard"},
        "/static/moment-2.18.1.min.js?q=": {"expect": ["组件", "CVE"],        "min_severity": "Low",    "tier": "hard"},
        "/static/jquery-ui-1.12.1.min.js?q=": {"expect": ["组件", "CVE"],     "min_severity": "Low",    "tier": "hard"},
        "/static/axios-0.21.1.min.js?q=":     {"expect": ["组件", "CVE"],     "min_severity": "Low",    "tier": "hard"},
        # ===== 缺口补齐（2026-09-12）：命令注入 / 反序列化多语言 / 源码泄露 =====
        "/cmdi?cmd=echo":      {"expect": ["命令注入"],               "min_severity": "Critical", "tier": "hard"},
        "/deser-dotnet?data=": {"expect": ["反序列化", ".NET"],       "min_severity": "Critical", "tier": "hard"},
        "/deser-php?data=":    {"expect": ["反序列化", "PHP对象注入"], "min_severity": "High",     "tier": "hard"},
        "/deser-pickle?data=": {"expect": ["反序列化", "Pickle"],     "min_severity": "Critical", "tier": "hard"},
        "/.git/config?q=":     {"expect": ["源码泄露", "Git"],        "min_severity": "High",     "tier": "hard"},
        # 流程型（有状态）样本：写入→回读，单请求 oracle 覆盖不了
        "/guestbook?msg=hello": {"expect": ["存储XSS"],  "min_severity": "High", "tier": "hard"},
        "/notes?note=1":        {"expect": ["二次注入"],  "min_severity": "High", "tier": "hard"},
        # 供应链 SCA：依赖清单暴露 → 已知脆弱依赖
        "/package.json?q=":    {"expect": ["依赖审计"], "min_severity": "Medium", "tier": "hard"},
        "/requirements.txt?q=": {"expect": ["依赖审计"], "min_severity": "Medium", "tier": "hard"},
        # DOM 型 XSS：需浏览器执行 oracle（渲染后捕获 alert）
        "/dom-xss":             {"expect": ["DOMXSS"], "min_severity": "High", "tier": "hard"},
        # 业务逻辑：非法金额被接受 / 一次性操作可重复
        "/api/order?price=100":    {"expect": ["业务逻辑"], "min_severity": "High",   "tier": "hard"},
        "/api/coupon?code=SAVE10": {"expect": ["业务逻辑"], "min_severity": "Medium", "tier": "hard"},
        # ===== 加厚（2026-09-12）：更多真实库 + 更多依赖生态 =====
        "/static/handlebars-4.7.6.min.js?q=": {"expect": ["组件", "CVE"], "min_severity": "Low",    "tier": "hard"},
        "/static/dompurify-2.0.16.min.js?q=": {"expect": ["组件", "CVE"], "min_severity": "Low",    "tier": "hard"},
        "/static/marked-4.0.9.min.js?q=":     {"expect": ["组件", "CVE"], "min_severity": "Low",    "tier": "hard"},
        "/composer.json?q=":                  {"expect": ["依赖审计"],   "min_severity": "Medium", "tier": "hard"},
        "/pom.xml?q=":                        {"expect": ["依赖审计"],   "min_severity": "Critical", "tier": "hard"},
        "/Gemfile.lock?q=":                   {"expect": ["依赖审计"],   "min_severity": "High",   "tier": "hard"},
        "/go.mod?q=":                         {"expect": ["依赖审计"],   "min_severity": "High",   "tier": "hard"},
        # ===== 加厚第二批（2026-09-12）：更多真实前端库 + 更多依赖生态 =====
        "/static/react-16.4.0.min.js?q=":          {"expect": ["组件", "CVE"], "min_severity": "Low",      "tier": "hard"},
        "/static/underscore-1.13.0.min.js?q=":     {"expect": ["组件", "CVE"], "min_severity": "Low",      "tier": "hard"},
        "/static/serialize-javascript-3.0.0.js?q=": {"expect": ["组件", "CVE"], "min_severity": "Low",     "tier": "hard"},
        "/static/vue-2.7.15.min.js?q=":            {"expect": ["组件", "CVE"], "min_severity": "Low",      "tier": "hard"},
        "/spring-pom.xml?q=":                      {"expect": ["依赖审计"],   "min_severity": "Critical", "tier": "hard"},
        "/requirements-extra.txt?q=":              {"expect": ["依赖审计"],   "min_severity": "High",     "tier": "hard"},
        "/deps.json?q=":                           {"expect": ["依赖审计"],   "min_severity": "High",     "tier": "hard"},
        # ===== 加厚收尾（2026-09-12）：补齐 2 条"有签名无样本"的历史虚胖项 =====
        # 加厚纪律：签名库里每条签名都必须有靶机样本 + 真值，否则只是"看着大但不命中"。
        # AngularJS / Bootstrap 是早期就写进签名库但一直没有验证样本的两条，本轮补上。
        "/static/angular-1.7.9.min.js?q=":    {"expect": ["组件", "CVE"], "min_severity": "Low", "tier": "hard"},
        "/static/bootstrap-3.3.7.min.js?q=":  {"expect": ["组件", "CVE"], "min_severity": "Low", "tier": "hard"},
        # ===== 加厚第三批（2026-09-12）：新库 + 多阈值边界样本 =====
        # CVE-2024-4367（pdf.js 任意 JS 执行）/ CVE-2020-7746（Chart.js 原型污染）
        "/static/pdf-2.16.105.min.js?q=":     {"expect": ["组件", "CVE"], "min_severity": "Low", "tier": "hard"},
        "/static/chart-2.9.3.min.js?q=":      {"expect": ["组件", "CVE"], "min_severity": "Low", "tier": "hard"},
        # 复用已有签名的"第二条阈值"边界样本：jQuery 3.4.1(<3.5.0)、Bootstrap 4.3.0(<4.3.1)
        "/static/jquery-3.4.1.min.js?q=":     {"expect": ["组件", "CVE"], "min_severity": "Low", "tier": "hard"},
        "/static/bootstrap-4.3.0.min.js?q=":  {"expect": ["组件", "CVE"], "min_severity": "Low", "tier": "hard"},
        # 依赖清单新生态：express/ws/ejs（npm）、jinja2/setuptools（pip）、fastjson（maven）
        "/deps-npm-extra.json?q=":            {"expect": ["依赖审计"],   "min_severity": "Medium",   "tier": "hard"},
        "/requirements-more.txt?q=":          {"expect": ["依赖审计"],   "min_severity": "High",     "tier": "hard"},
        "/fastjson-pom.xml?q=":               {"expect": ["依赖审计"],   "min_severity": "Critical", "tier": "hard"},
        # ===== 加厚第四批（2026-09-12）：锁文件生态 + 过滤绕过 =====
        "/package-lock.json?q=":              {"expect": ["依赖审计"], "min_severity": "Medium",   "tier": "hard"},
        "/yarn.lock?q=":                      {"expect": ["依赖审计"], "min_severity": "Medium",   "tier": "hard"},
        "/poetry.lock?q=":                    {"expect": ["依赖审计"], "min_severity": "High",     "tier": "hard"},
        "/Pipfile.lock?q=":                   {"expect": ["依赖审计"], "min_severity": "High",     "tier": "hard"},
        "/composer.lock?q=":                  {"expect": ["依赖审计"], "min_severity": "Medium",   "tier": "hard"},
        "/gradle.lockfile?q=":                {"expect": ["依赖审计"], "min_severity": "Critical", "tier": "hard"},
        # 朴素黑名单绕过：只删 <script> 关键字，多 payload 里 <img onerror> 仍能穿过
        "/xss-filter?q=":                     {"expect": ["XSS"],      "min_severity": "High",     "tier": "hard"},
        # 带外回连（OOB）：响应里零痕迹，只有"目标主动回连"能证实（盲 SSRF / 盲命令注入）
        "/ssrf-blind?url=":                   {"expect": ["SSRF"],     "min_severity": "High",     "tier": "hard"},
        "/cmdi-blind?cmd=":                   {"expect": ["命令注入"], "min_severity": "Critical", "tier": "hard"},
        # 组件 KB（OSV）宽度样本：这两个包**从未写过手写签名**，只能靠 KB 查表命中
        "/jackson-pom.xml?q=":                {"expect": ["依赖审计"], "min_severity": "High",     "tier": "hard"},
        "/struts-pom.xml?q=":                 {"expect": ["依赖审计"], "min_severity": "Critical", "tier": "hard"},
        # ===== 外部现成知识源样本（sqlmap 报错 / gitleaks 密钥 / Retire.js 组件）=====
        "/sqli-db2?id=":                      {"expect": ["SQL注入"], "min_severity": "High",     "tier": "hard"},
        "/secrets.js?q=":                     {"expect": ["密钥泄露"], "min_severity": "High",    "tier": "hard"},
        "/static/knockout-3.4.0.js?q=":       {"expect": ["组件", "CVE"], "min_severity": "Medium", "tier": "hard"},
    },
    "negatives": {
        "/safe": "正常端点，不应出现在漏洞报告中（出现即误报）",
        # 误报陷阱（2026-09-12 新增）：回显 ≠ 可执行，专门测"转义检查"是否真的生效
        "/safe-escaped?q=": "HTML 实体正确转义后回显，绝不应判为 XSS（误报陷阱）",
        "/safe-param?id=1": "参数化查询/无注入，不应判为 SQLi",
    },
    "notes": "本清单由 scripts/local_lab.py 内置；GET /__baseline__ 返回此 JSON，供基准回归校验。",
}

# 存储型漏洞靶面：内存存储（供流程型 oracle「写入→回读」）
_STORE = {"guestbook": [], "notes": []}


def _ssti_eval(text):
    m = _SSTI_RE.search(text)
    return text.replace(m.group(0), str(int(m.group(1)) * int(m.group(2)))) if m else text

class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def _send(self, code, body, ctype='text/html'):
        b = body.encode('utf-8', 'replace')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(b)))
        self.send_header('Connection', 'close')
        self.end_headers()
        try: self.wfile.write(b)
        except BrokenPipeError: pass

    def do_GET(self):
        u = urlparse(self.path); p = u.path; q = parse_qs(u.query)
        if p == '/':
            self._send(200, '<html><h1>Local Lab</h1>'
                '<p><a href="/xss?s=hello">xss</a></p>'
                '<p><a href="/sqli?id=1">sqli</a></p>'
                '<p><a href="/upload">upload</a></p>'
                '<p><a href="/ssti?name=hello">ssti</a></p>'
                '<p><a href="/lfi?file=../../windows/win.ini">lfi</a></p>'
                '<p><a href="/cmdi?cmd=echo hi">cmdi</a></p>'
                '<p><a href="/nosql?q=1">nosql</a></p>'
                '<p><a href="/ldap?user=admin">ldap</a></p>'
                '<p><a href="/redirect?next=home">redirect</a></p>'
                '<p><a href="/cors">cors</a></p>'
                '<p><a href="/deser?data=x">deser</a></p>'
                '<p><a href="/.env">env</a></p>'
                '<p><a href="/safe">safe(neg)</a></p>'
                '<p><a href="/__baseline__">baseline</a></p>'
                '</html>')
            return
        if p == '/xss':
            val = q.get('q', q.get('s', q.get('param', [''])))[0]
            self._send(200, '<!doctype html><html><body><h1>Search results</h1><div id="out">' + val + '</div><p>none</p></body></html>')
            return
        if p == '/xss-filter':
            # 朴素黑名单（真实站点最常见的"防护"）：只删 <script> 关键字，其余原样反射。
            # 用于验证"多 payload 能绕过黑名单"——单 payload 的 scanner 会在这里漏报。
            val = q.get('q', [''])[0]
            for _kw in ('<script>', '</script>', '<SCRIPT>', '</SCRIPT>'):
                val = val.replace(_kw, '')
            self._send(200, '<html><body><h1>Search</h1><div id="out">' + val + '</div></body></html>')
            return
        if p == '/ssrf-blind':
            # 盲 SSRF：服务端去取该 URL，但**完全不回显结果**（响应永远是一句 ok）。
            # 单请求 oracle 在这里必然无解——只有"目标是否回连我们"能证实。
            val = q.get('url', [''])[0]
            if val.startswith('http'):
                try:
                    import urllib.request as _ur
                    _ur.urlopen(val, timeout=3).read(100)
                except Exception:  # noqa: BLE001 - 回连失败与漏洞无关
                    pass
            self._send(200, '<html><body>ok</body></html>')
            return
        if p == '/cmdi-blind':
            # 盲命令注入（无回显）：模拟"命令里的 curl 把结果外带到攻击者"。
            # 真机上这是 `ping/curl/nslookup $INPUT` 类拼接；靶机以服务端外连等价复现。
            val = q.get('cmd', q.get('q', ['']))[0]
            _m = re.search(r'https?://[^\s;|&]+', val)
            if _m:
                try:
                    import urllib.request as _ur
                    _ur.urlopen(_m.group(0), timeout=3).read(100)
                except Exception:  # noqa: BLE001
                    pass
            self._send(200, '<html><body>done</body></html>')
            return
        if p == '/sqli':
            val = q.get('id', q.get('uid', q.get('q', [''])))[0]
            if "'1'='1" in val or "' OR '1'='1" in val or '1=1' in val:
                self._send(200, '<pre>2 rows returned</pre>'); return
            if "'1'='2" in val or '1=2' in val:
                self._send(200, '<pre>0 rows returned</pre>'); return
            if "'" in val or '"' in val:
                self._send(500, "<pre>SQLite error: SELECT * FROM users WHERE id='" + val + "' <br>near \"&quot;\": syntax error</pre>")
                return
            self._send(200, '<pre>1 row: id=' + val + '</pre>')
            return
        if p == '/ssti':
            val = q.get('name', [''])[0]
            rendered = _ssti_eval(val)
            # 同时回显原始 payload 与渲染结果，使 A4 计算证明能确认模板被执行计算
            self._send(200, '<html><body><h1>SSTI</h1><div>input=' + val + '; result=' + rendered + '</div></body></html>')
            return
        if p == '/nosql':
            val = q.get('q', [''])[0]
            if any(tok in val for tok in ('$', '{', '}', '[', ']', '(', ')', "'", '"', '||', '==')):
                self._send(200, '<pre>MongoError: Cannot apply $gt operator to field (SyntaxError)</pre>')
            else:
                self._send(200, '<pre>ok</pre>')
            return
        if p == '/ldap':
            val = q.get('user', [''])[0]
            if any(c in val for c in '*()|&\\'):
                self._send(200, '<pre>LDAPException: invalid search filter syntax</pre>')
            else:
                self._send(200, '<pre>welcome</pre>')
            return
        if p == '/redirect':
            val = q.get('next', [''])[0]
            if val:
                self.send_response(302)
                self.send_header('Location', val)
                self.send_header('Content-Length', '0')
                self.send_header('Connection', 'close')
                self.end_headers()
                return
            self._send(200, '<html><body><h1>Home</h1></body></html>')
            return
        if p == '/cors':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Length', '20')
            self.send_header('Connection', 'close')
            self.end_headers()
            try:
                self.wfile.write(b'<html><body>cors</body></html>')
            except BrokenPipeError:
                pass
            return
        if p == '/deser':
            self._send(200, '<pre>java.io.NotSerializableException: com.example.User</pre>')
            return
        if p == '/deser-dotnet':
            self._send(200, '<pre>System.Runtime.Serialization.SerializationException: '
                            'TypeLoadException: could not load type</pre>')
            return
        if p == '/deser-php':
            self._send(200, '<pre>Notice: unserialize(): Error at offset 0 of 24 bytes</pre>')
            return
        if p == '/deser-pickle':
            self._send(200, '<pre>UnpicklingError: invalid load key, \'\\x00\'.</pre>')
            return
        if p == '/.env':
            self._send(200, 'DB_PASSWORD=secret123\nAPI_KEY=ak-xxxx\n', ctype='text/plain')
            return
        if p.startswith('/.git/'):
            # 源码仓库泄露：直接 GET .git/config 等元数据（可进一步拉源码）
            self._send(200, '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n'
                            '[remote "origin"]\n\turl = https://git.corp.local/app.git\n',
                       ctype='text/plain')
            return
        if p == '/package.json':
            # 依赖清单暴露：可直接审计已知脆弱依赖（SCA）
            self._send(200, json.dumps({"name": "demo-app", "dependencies": {
                "lodash": "4.17.20", "axios": "0.21.1", "node-fetch": "2.6.6",
                "debug": "2.6.8", "minimist": "1.2.5"}}),
                       ctype='application/json')
            return
        if p == '/requirements.txt':
            self._send(200, 'Django==3.2.10\nrequests==2.25.0\n', ctype='text/plain')
            return
        if p == '/composer.json':
            self._send(200, json.dumps({"require": {"guzzlehttp/guzzle": "6.5.0"}}),
                       ctype='application/json')
            return
        if p == '/pom.xml':
            self._send(200, '<dependency><groupId>org.apache.logging.log4j</groupId>'
                            '<artifactId>log4j-core</artifactId><version>2.14.1</version>'
                            '</dependency>', ctype='application/xml')
            return
        if p == '/Gemfile.lock':
            self._send(200, 'GEM\n  specs:\n    nokogiri (1.13.5)\n', ctype='text/plain')
            return
        if p == '/go.mod':
            self._send(200, 'module demo\n\ngo 1.20\n\nrequire (\n'
                            '\tgolang.org/x/text v0.3.6\n)\n', ctype='text/plain')
            return
        if p.startswith('/static/handlebars'):
            self._send(200, '/*! Handlebars v4.7.6 (c) Yehuda Katz */\n',
                       ctype='application/javascript')
            return
        if p.startswith('/static/dompurify'):
            self._send(200, '/*! DOMPurify v2.0.16 */\n', ctype='application/javascript')
            return
        if p.startswith('/static/marked'):
            self._send(200, '/*! marked v4.0.9 */\n', ctype='application/javascript')
            return
        if p.startswith('/static/react'):
            self._send(200, '/*! React v16.4.0 */\n', ctype='application/javascript')
            return
        if p.startswith('/static/underscore'):
            self._send(200, '/*! underscore v1.13.0 */\n', ctype='application/javascript')
            return
        if p.startswith('/static/serialize-javascript'):
            self._send(200, '/*! serialize-javascript v3.0.0 */\n', ctype='application/javascript')
            return
        if p.startswith('/static/vue'):
            self._send(200, '/*! Vue.js v2.7.15 */\n', ctype='application/javascript')
            return
        if p == '/spring-pom.xml':
            self._send(200, '<dependency><groupId>org.springframework</groupId>'
                            '<artifactId>spring-core</artifactId><version>5.3.10</version>'
                            '</dependency>', ctype='application/xml')
            return
        if p == '/requirements-extra.txt':
            self._send(200, 'PyYAML==5.3.1\n', ctype='text/plain')
            return
        if p == '/deps.json':
            self._send(200, json.dumps({"minimist": "1.2.5", "jsonwebtoken": "8.5.1",
                                        "debug": "2.6.8"}),
                       ctype='application/json')
            return
        if p == '/deps-npm-extra.json':
            # express<4.17.3 / ws<8.17.1 / ejs<3.1.7 → 三条 npm 生态脆弱依赖
            self._send(200, json.dumps({"dependencies": {
                "express": "4.16.0", "ws": "8.16.0", "ejs": "3.1.6"}}),
                       ctype='application/json')
            return
        if p == '/package-lock.json':
            self._send(200, json.dumps({"name": "demo", "lockfileVersion": 3, "packages": {
                "node_modules/lodash": {"version": "4.17.20"}}}),
                       ctype='application/json')
            return
        if p == '/yarn.lock':
            self._send(200, 'lodash@^4.17.0:\n  version "4.17.20"\n'
                            '  resolved "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"\n',
                       ctype='text/plain')
            return
        if p == '/poetry.lock':
            self._send(200, '[[package]]\nname = "django"\nversion = "3.2.10"\n'
                            'description = "A high-level Python Web framework"\n',
                       ctype='text/plain')
            return
        if p == '/Pipfile.lock':
            self._send(200, json.dumps({"default": {"django": {"version": "==3.2.10"}},
                                        "_meta": {"hash": {"sha256": "x"}}}),
                       ctype='application/json')
            return
        if p == '/composer.lock':
            self._send(200, json.dumps({"packages": [
                {"name": "guzzlehttp/guzzle", "version": "7.4.4"}]}),
                       ctype='application/json')
            return
        if p == '/sqli-db2':
            # DB2 报错：我们手写正则里**没有** DB2（只有 MySQL/SQLite/Oracle/PG/MSSQL），
            # 靠 sqlmap 的 errors.xml 才能命中 → 证明外部数据真的补了宽度。
            val = q.get('id', [''])[0]
            if "'" in val or '"' in val:
                self._send(500, '<pre>DB2 SQL error: SQLCODE: -204, SQLSTATE: 42704, '
                                'SQLERRMC: USERS</pre>')
                return
            self._send(200, '<pre>1 row</pre>')
            return
        if p == '/secrets.js':
            # 硬编码密钥（AWS 官方示例 key）：gitleaks 规则命中，手写规则认不出
            self._send(200, '// config\nvar AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";\n'
                            'var region = "us-east-1";\n', ctype='application/javascript')
            return
        if p.startswith('/static/knockout'):
            # knockout 3.4.0 < 3.5.0（CVE-2019-14862）：来自 Retire.js，我们从未手写过
            self._send(200, '/*! Knockout */\n'
                            '<script src="knockout-3.4.0.js"></script>\n',
                       ctype='application/javascript')
            return
        if p == '/jackson-pom.xml':
            # jackson-databind 2.9.5：KB 中命中 GHSA-27xj-rqx5-2255（区间 2.9.0–2.9.10.4）
            self._send(200, '<dependency><groupId>com.fasterxml.jackson.core</groupId>'
                            '<artifactId>jackson-databind</artifactId><version>2.9.5</version>'
                            '</dependency>', ctype='application/xml')
            return
        if p == '/struts-pom.xml':
            # struts2-core 2.5.12：KB 中命中 GHSA-2j39-qcjm-428w（区间 2.0.0–2.5.33）
            self._send(200, '<dependency><groupId>org.apache.struts</groupId>'
                            '<artifactId>struts2-core</artifactId><version>2.5.12</version>'
                            '</dependency>', ctype='application/xml')
            return
        if p == '/gradle.lockfile':
            self._send(200, 'org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath\n'
                            'org.apache.logging.log4j:log4j-api:2.14.1=compileClasspath\n',
                       ctype='text/plain')
            return
        if p == '/requirements-more.txt':
            # jinja2<3.1.3 / setuptools<65.5.1
            self._send(200, 'jinja2==3.1.2\nsetuptools==65.5.0\n', ctype='text/plain')
            return
        if p == '/fastjson-pom.xml':
            # fastjson<1.2.83 → CVE-2022-25845（autoType 反序列化）
            self._send(200, '<dependency><groupId>com.alibaba</groupId>'
                            '<artifactId>fastjson</artifactId><version>1.2.80</version>'
                            '</dependency>', ctype='application/xml')
            return
        if p.startswith('/upload') or '/file' in p or '/import' in p:
            self._send(200, '<html><body><h1>Upload Point</h1><form method="post" enctype="multipart/form-data"><input type="file" name="file"><button>Upload</button></form></body></html>')
            return
        if p == '/__baseline__':
            self._send(200, json.dumps(EXPECTED_FINDINGS, ensure_ascii=False, indent=2),
                       ctype='application/json')
            return
        if p == '/cmdi':
            import time as _t
            cmd = q.get('cmd', q.get('q', ['']))[0]
            _m = re.search(r'sleep\s+(\d+)', cmd)
            if _m:
                _n = min(int(_m.group(1)), 10)
                _t.sleep(_n)
                self._send(200, '<pre>done in ' + str(_n) + 's</pre>')
                return
            # 命令注入可观察破绽：`;id` / `|id` / `$(id)` / 反引号 / `&& id` 拼接后执行 → 回显 uid=
            if re.search(r'(;|\||&&|\$\(|`)\s*id\b', cmd):
                self._send(200, '<pre>uid=0(root) gid=0(root) groups=0(root)</pre>')
                return
            self._send(200, '<pre>cmd=' + cmd + '</pre>')
            return
        if p == '/lfi':
            fname = q.get('file', [''])[0]
            _low = fname.lower()
            _target = None
            if 'win.ini' in _low:
                _target = r'C:\Windows\win.ini'
            elif 'hosts' in _low:
                _target = r'C:\Windows\System32\drivers\etc\hosts'
            elif 'passwd' in _low or 'etc' in _low:
                _target = r'C:\Windows\win.ini'
            if _target:
                try:
                    with open(_target, 'r', encoding='utf-8', errors='replace') as _f:
                        _content = _f.read()
                    self._send(200, '<pre>' + _content + '</pre>')
                except Exception:
                    self._send(500, 'read error')
                return
            self._send(404, 'file not found')
            return
        if p == '/safe':
            self._send(200, '<html><body><h1>Safe Page</h1><p>no vulnerability here</p></body></html>')
            return
        # ===== tier=hard 难样本端点（2026-09-12）=====
        if p == '/xss-attr':
            val = q.get('q', q.get('s', ['']))[0]
            # 反射进 HTML 属性内且未转义 → 真 XSS（难在上下文判断，不是简单 <script> 回显）
            self._send(200, '<!doctype html><html><body>'
                            '<input type="text" value="' + val + '"><p>ok</p></body></html>')
            return
        if p == '/sqli-blind':
            val = q.get('id', [''])[0]
            # 布尔盲注：无报错，只有行数差异 → 必须靠差分判据
            if "'1'='1" in val or '1=1' in val or '1 = 1' in val:
                self._send(200, '<pre>2 rows returned</pre>'); return
            if "'1'='2" in val or '1=2' in val or '1 = 2' in val:
                self._send(200, '<pre>0 rows returned</pre>'); return
            self._send(200, '<pre>1 row: id=' + val + '</pre>')
            return
        if p == '/ssrf':
            val = q.get('url', q.get('u', q.get('target', [''])))[0]
            # 内网/元数据地址 → 回显内网特征（可观察破绽）
            if any(t in val.lower() for t in
                   ('127.0.0.1', 'localhost', '169.254', '10.', '192.168.', 'file://')):
                self._send(200, '<pre>metadata: instance-id=i-0a1b2c3d; host=internal-svc.local</pre>')
            else:
                self._send(200, '<pre>fetched: ' + val + '</pre>')
            return
        if p == '/xxe':
            val = q.get('xml', [''])[0]
            # 实体展开回显 → 真 XXE
            if '<!ENTITY' in val.upper() or 'SYSTEM' in val.upper() or 'file://' in val:
                self._send(200, '<pre>root:x:0:0:root:/root:/bin/bash</pre>')
            else:
                self._send(200, '<pre>xml ok</pre>')
            return
        if p == '/idor':
            uid = q.get('id', q.get('uid', ['1']))[0]
            # 无鉴权即可读他人资料 → 真越权（需两身份对比才能证实，声明线大概率无覆盖）
            _db = {'1': 'admin: admin@corp.local / role=owner',
                   '2': 'alice: alice@corp.local / role=user'}
            self._send(200, '<pre>' + _db.get(uid, 'user ' + uid + ': no record') + '</pre>')
            return
        if p == '/actuator/env':
            self._send(200, json.dumps({
                "activeProfiles": ["prod"],
                "propertySources": [{"name": "systemEnvironment", "properties": {
                    "DB_PASSWORD": {"value": "s3cr3t-prod"},
                    "JWT_SECRET": {"value": "hs256-signing-key"},
                }}],
            }), ctype='application/json')
            return
        if p.startswith('/static/jquery-1.7.1.js'):
            # 组件漏洞线索：老版本库（当前无匹配器 → 预期 NA，暴露覆盖缺口）
            self._send(200, '/*! jQuery v1.7.1 jquery.com | jquery.org/license */\n'
                            '!function(a,b){/* legacy jquery... */}(window,document);\n',
                       ctype='application/javascript')
            return
        if p.startswith('/static/lodash'):
            self._send(200, '/*! lodash v3.10.1 (c) Jeremy Ashkenas */\n'
                            'function _(o){return o;}\n', ctype='application/javascript')
            return
        if p.startswith('/static/moment'):
            self._send(200, '//! moment.js v2.18.1 (c) JS Foundation\n'
                            'function moment(){return 0;}\n', ctype='application/javascript')
            return
        if p.startswith('/static/jquery-ui'):
            self._send(200, '/*! jQuery UI - v1.12.1 - 2016-09-14 */\n'
                            '(function(factory){})(function($){});\n', ctype='application/javascript')
            return
        if p.startswith('/static/axios'):
            self._send(200, '/*! axios v0.21.1 (c) 2020 Matt Zabriskie */\n'
                            'function axios(){};\n', ctype='application/javascript')
            return
        if p.startswith('/static/angular'):
            # AngularJS 1.7.9 < 1.8.0 → CVE-2019-10712（补齐"有签名无样本"）
            self._send(200, '/*! AngularJS v1.7.9 (c) 2010-2020 Google, Inc. */\n'
                            'function angular(){};\n', ctype='application/javascript')
            return
        if p.startswith('/static/bootstrap'):
            # 同一签名库两条阈值各配一个样本：
            #   3.3.7 < 3.4.0 → CVE-2019-8331；4.3.0 < 4.3.1 → CVE-2018-14041
            _bv = '4.3.0' if '-4.' in p else '3.3.7'
            self._send(200, f'/*! Bootstrap v{_bv} (c) 2011-2019 Twitter, Inc. */\n'
                            'function bootstrap(){};\n', ctype='application/javascript')
            return
        if p.startswith('/static/jquery-3'):
            # jQuery 3.4.1 < 3.5.0 → CVE-2020-11022（复用 jQuery 签名，验证第二版本区间）
            self._send(200, '/*! jQuery v3.4.1 jquery.com | jquery.org/license */\n'
                            'function jQuery(){};\n', ctype='application/javascript')
            return
        if p.startswith('/static/pdf'):
            # pdf.js 2.16.105 < 4.2.67 → CVE-2024-4367（任意 JS 执行）
            self._send(200, '/*! pdf.js v2.16.105 (c) 2012 Mozilla Foundation */\n'
                            'function pdfjsLib(){};\n', ctype='application/javascript')
            return
        if p.startswith('/static/chart'):
            # Chart.js 2.9.3 < 2.9.4 → CVE-2020-7746（原型污染）
            self._send(200, '/*! Chart.js v2.9.3 (c) 2018 Nick Downie */\n'
                            'function Chart(){};\n', ctype='application/javascript')
            return
        if p == '/safe-escaped':
            val = q.get('q', q.get('s', ['']))[0]
            esc = (val.replace('&', '&amp;').replace('<', '&lt;')
                      .replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;'))
            self._send(200, '<!doctype html><html><body><div id="out">' + esc + '</div></body></html>')
            return
        if p == '/safe-param':
            val = q.get('id', [''])[0]
            # 参数化查询模拟：任何输入都只当字符串字面量，不进语法
            self._send(200, '<pre>1 row: id=' + re.sub(r'[^0-9A-Za-z_.-]', '', val) + '</pre>')
            return
        # ===== 流程型（存储）靶面（2026-09-12）=====
        if p == '/guestbook':
            val = q.get('msg', [''])[0]
            if val:
                _STORE['guestbook'].append(val)
            self._send(200, '<html><body>stored</body></html>')
            return
        if p == '/guestbook/list':
            # 存储内容原样拼接回显（未转义）→ 存储型 XSS
            body = ''.join(_STORE['guestbook'])
            self._send(200, '<html><body><div id="gbook">' + body + '</div></body></html>')
            return
        if p == '/notes':
            val = q.get('note', [''])[0]
            if val:
                _STORE['notes'].append(val)
            self._send(200, '<pre>note saved</pre>')
            return
        if p == '/notes/search':
            key = ''.join(_STORE['notes'])
            # 模拟把"已存储的值"二次拼接进 SQL → 含引号即报错（二次注入）
            if "'" in key or '"' in key:
                self._send(500, '<pre>SQLite error: SELECT * FROM notes WHERE body=\''
                                + key + '\' near syntax error</pre>')
            else:
                self._send(200, '<pre>search ok</pre>')
            return
        if p == '/dom-xss':
            # DOM 型 XSS：把 URL hash 直接写进 innerHTML（危险 DOM sink）→ 浏览器执行
            self._send(200, '<!doctype html><html><body><h1>DOM XSS</h1><div id="out"></div>'
                            '<script>document.getElementById("out").innerHTML='
                            'decodeURIComponent(location.hash.slice(1));</script></body></html>')
            return
        # ===== 业务逻辑靶面（2026-09-12）=====
        if p == '/api/order':
            # 漏洞版：不校验金额范围，负数/零/超限直接接受并回显
            price = q.get('price', q.get('amount', ['100']))[0]
            try:
                total = int(float(price))
            except Exception:
                total = 0
            self._send(200, json.dumps({"status": "created", "total": total}),
                       ctype='application/json')
            return
        if p == '/api/coupon':
            # 漏洞版：不核销，重复申请依然 applied（一次性操作可重复）
            self._send(200, json.dumps({"status": "applied", "discount": 10}),
                       ctype='application/json')
            return
        self._send(404, '<html>not found</html>')

    def do_POST(self):
        p = urlparse(self.path).path
        length = int(self.headers.get('Content-Length', 0))
        if length: self.rfile.read(length)
        if p.startswith('/upload') or '/file' in p or '/import' in p:
            self._send(200, '<body>upload success: /uploads/test.txt saved</body>')
            return
        self._send(200, 'ok')

if __name__ == '__main__':
    print('LOCAL_LAB on 127.0.0.1:8090', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 8090), H).serve_forever()