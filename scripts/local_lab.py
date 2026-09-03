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
        "/.env":               {"expect": ["环境变量泄露", ".env"],         "min_severity": "Critical"},
        "/upload":             {"expect": ["文件上传"],                      "min_severity": "High"},
        "/nosql?q=1":          {"expect": ["NoSQL"],                        "min_severity": "High"},
        "/ldap?user=admin":    {"expect": ["LDAP"],                         "min_severity": "High"},
        "/redirect?next=home": {"expect": ["开放重定向", "Open Redirect"],   "min_severity": "Medium"},
        "/cors":               {"expect": ["CORS"],                         "min_severity": "Medium"},
        "/deser?data=x":       {"expect": ["反序列化", "deserialization"],   "min_severity": "Medium"},
    },
    "negatives": {
        "/safe": "正常端点，不应出现在漏洞报告中（出现即误报）",
    },
    "notes": "本清单由 scripts/local_lab.py 内置；GET /__baseline__ 返回此 JSON，供基准回归校验。",
}


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
        if p == '/.env':
            self._send(200, 'DB_PASSWORD=secret123\nAPI_KEY=ak-xxxx\n', ctype='text/plain')
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