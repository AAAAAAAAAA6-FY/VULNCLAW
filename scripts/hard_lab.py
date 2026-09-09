#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高难度本地漏洞靶场（方案 C, 无 Docker）。端口 8091。
涵盖 WAF 过滤 SQLi / 时间盲注 / 属性注入 XSS / 双重编码 / SSRF 绕过 /
JWT alg:none / IDOR / 开放重定向 / LFI 绕过 / 默认弱口令。
"""
import re
import json
import time
import base64
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

EXPECTED_FINDINGS = {
    "target": "http://127.0.0.1:8091",
    "endpoints": {
        "/waf_sqli?id=1":         {"expect": ["SQL注入", "SQLi"],       "min_severity": "High"},
        "/time_blind?id=1":       {"expect": ["时间盲注", "SQLi"],      "min_severity": "High"},
        "/input_xss?q=test":      {"expect": ["XSS", "反射型XSS"],     "min_severity": "High"},
        "/double_encode?q=x":     {"expect": ["XSS", "编码绕过"],       "min_severity": "High"},
        "/ssrf?url=http://x":     {"expect": ["SSRF"],                 "min_severity": "High"},
        "/jwt":                   {"expect": ["JWT"],                  "min_severity": "Medium"},
        "/idor/profile/1":        {"expect": ["IDOR", "越权"],         "min_severity": "High"},
        "/open_redirect?next=/":  {"expect": ["开放重定向"],           "min_severity": "Medium"},
        "/lfi_bypass?file=x":     {"expect": ["LFI", "路径遍历"],      "min_severity": "High"},
        "/admin/default":         {"expect": ["弱口令", "默认凭据"],   "min_severity": "High"},
    },
    "negatives": {
        "/static": "静态资源端点，不应出现在漏洞报告中"
    },
    "notes": "高难度：WAF 绕过的布尔 SQLi / 纯时间盲注 / 属性注入 XSS / SSRF 地址变形 / JWT 算法绕过等，对引擎启发式与 AI 复验要求高。",
}


def _dec(m: str) -> str:
    """模拟后端重复解码两次的漏洞。"""
    try:
        return urllib.parse.unquote(urllib.parse.unquote(m))
    except Exception:
        return m


class HA(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _send(self, code, body, ctype='text/html'):
        b = body.encode('utf-8', 'replace')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(b)))
        self.send_header('Connection', 'close')
        self.end_headers()
        try:
            self.wfile.write(b)
        except BrokenPipeError:
            pass

    def do_GET(self):
        u = urlparse(self.path)
        p, q = u.path, parse_qs(u.query)

        if p == '/':
            self._send(200, '<html><body><h1>Hard Lab (8091)</h1><ul>'
                       '<li><a href="/waf_sqli?id=1">waf_sqli</a></li>'
                       '<li><a href="/time_blind?id=1">time_blind</a></li>'
                       '<li><a href="/input_xss?q=test">input_xss</a></li>'
                       '<li><a href="/double_encode?q=x">double_encode</a></li>'
                       '<li><a href="/ssrf?url=http://example.com">ssrf</a></li>'
                       '<li><a href="/jwt">jwt</a></li>'
                       '<li><a href="/idor/profile/1">idor</a></li>'
                       '<li><a href="/open_redirect?next=home">redirect</a></li>'
                       '<li><a href="/lfi_bypass?file=etc">lfi_bypass</a></li>'
                       '<li><a href="/admin/default">admin</a></li>'
                       '<li><a href="/__baseline__">baseline</a></li>'
                       '</ul></body></html>')
            return

        if p == '/__baseline__':
            self._send(200, json.dumps(EXPECTED_FINDINGS, ensure_ascii=False, indent=2), 'application/json')
            return

        # ---- WAF 过滤的布尔 SQLi ----
        if p.startswith('/waf_sqli'):
            v = q.get('id', q.get('u', ['']))[0]
            lv = v.lower()
            if any(k in lv for k in ('union', '--', '/*', '#', ' or ')):
                self._send(403, '<pre>WAF: 关键词被拒</pre>')
                return
            # 大小写/注释绕过 WAF 后在数据库侧生效
            if '1\'1' in v or '1=1' in v.replace('%20', '') or ("'or" in lv):
                self._send(200, '<pre>2 rows returned</pre>')
            elif '1\'2' in v or '1=2' in v:
                self._send(200, '<pre>0 rows returned</pre>')
            elif 'error' in lv:
                self._send(500, '<pre>near "": syntax error</pre>')
            else:
                self._send(200, f'<pre>row: id={v[0] if v else "?"}</pre>')
            return

        # ---- 时间盲注 ----
        if p.startswith('/time_blind'):
            v = q.get('id', [''])[0]
            if 'sleep' in v.lower() or 'benchmark' in v.lower():
                time.sleep(2.0)
                self._send(200, '<pre>query done in 2.0s</pre>')
            elif "1'='1" in v or "1=1" in v:
                time.sleep(0.05)
                self._send(200, '<pre>ok</pre>')
            else:
                self._send(200, '<pre>ok</pre>')
            return

        # ---- 属性注入 XSS（双引号被转义、单引号可闭合） ----
        if p.startswith('/input_xss'):
            v = q.get('q', [''])[0].replace('"', '&quot;')
            self._send(200, '<html><body><input type="text" name="q" value="'
                            + v + '"><button>go</button></body></html>')
            return

        # ---- 双重编码 ----
        if p.startswith('/double_encode'):
            v = _dec(q.get('q', [''])[0])
            self._send(200, '<html><body><p>echo: ' + v + '</p></body></html>')
            return

        # ---- SSRF ----
        if p.startswith('/ssrf'):
            v = q.get('url', [''])[0]
            lv = v.lower()
            if not v:
                self._send(200, '<p>usage: ?url=http://host[:port]</p>')
                return
            if '127.0.0.1' in lv or 'localhost' in lv:
                self._send(200, '<pre>[blocked] 内网地址被过滤</pre>')
                return
            if any(pat in lv for pat in ('2130706433', '0x7f', '127.1', 'adr', '[::1]')):
                self._send(200, '<pre>[fetch] <b>INTERNAL_SECRET_7f000001</b> len=18</pre>')
            else:
                self._send(200, f'<pre>[fetch] ok ({len(v)}ch)</pre>')
            return

        # ---- JWT alg=none ----
        if p == '/jwt':
            au = self.headers.get('Authorization', '')
            if not au.startswith('Bearer '):
                self._send(200, '<p>Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.</p>', 'text/plain')
                return
            tok = au.split(' ', 1)[1]
            try:
                hdr_b = tok.split('.')[0]
                hdr_b += '=' * ((4 - len(hdr_b) % 4) % 4)
                hdr = json.loads(base64.urlsafe_b64decode(hdr_b))
                alg = str(hdr.get('alg', '')).lower()
                if alg in ('none', 'null', ''):
                    self._send(200, '<pre>JWT alg=none accepted, userId=1</pre>')
                else:
                    self._send(200, f'<pre>JWT verified ({alg})</pre>')
            except Exception as e:
                self._send(400, f'<pre>bad jwt: {e}</pre>')
            return

        # ---- IDOR ----
        m = re.match(r'/idor/profile/(\d+)', p)
        if m:
            uid = m.group(1)
            if uid == '1001':
                self._send(200, json.dumps({"name": "Alice"}))
            else:
                self._send(200, json.dumps({"name": "other-user", "email": "secret@x"}))
            return

        # ---- 开放重定向 ----
        if p.startswith('/open_redirect'):
            v = q.get('next', q.get('url', q.get('goto', ['']))) [0]
            nv = v.lower()
            if nv.startswith(('http:', 'https:')):
                self._send(400, '<pre>外部跳转被拒</pre>')
                return
            self.send_response(302)
            _loc = '//evil.net/' if v == '' else ('/' + v.lstrip('/'))
            self.send_header('Location', _loc.encode('latin-1', 'replace').decode('latin-1'))
            self.send_header('Connection', 'close')
            self.end_headers()
            return

        # ---- LFI 绕过 ----
        if p.startswith('/lfi_bypass'):
            v = q.get('file', [''])[0]
            if '....//' in v or '...\\' in v:
                v = v.replace('....//', '../').replace('...\\', '..\\')
            if 'passwd' in v or 'win.ini' in v or 'etc' in v:
                self._send(200, '<pre>root:x:0:0:root:/root:/bin/bash (truncated)</pre>')
            else:
                self._send(200, f'<pre>file: {v}</pre>')
            return

        # ---- 默认弱口令 ----
        if p == '/admin/default':
            au = self.headers.get('Authorization', '')
            if au.startswith('Basic '):
                try:
                    c = base64.b64decode(au.split(' ', 1)[1]).decode('utf-8')
                    if c == 'admin:admin':
                        self._send(200, '<pre>default creds accepted: admin:admin</pre>')
                        return
                except Exception:
                    pass
                self._send(403, '<pre>auth failed</pre>')
                return
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="admin"')
            self.send_header('Connection', 'close')
            self.end_headers()
            return

        if p == '/static':
            self._send(200, '<p>safe</p>')
            return

        self._send(404, '<pre>404</pre>')

    def log_message(self, *a):
        pass


if __name__ == '__main__':
    print('Hard Lab on http://127.0.0.1:8091  (expect %d vulns)' % len(EXPECTED_FINDINGS['endpoints']))
    ThreadingHTTPServer(('127.0.0.1', 8091), HA).serve_forever()