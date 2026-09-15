#!/usr/bin/env python3
"""MEGA LAB (127.0.0.1:8092)：local_lab + hard_lab + logic 合并「全明星」靶场。

一端口聚合全量漏洞端点，按 path 前缀委托给对应 handler 逻辑：
  local_lab(8090)  -> xss/sqli/upload/ssti/lfi/cmdi/nosql/ldap/redirect/cors/deser/.env/safe
  hard_lab(8091)   -> waf_sqli/time_blind/input_xss/double_encode/ssrf/jwt/idor/open_redirect/lfi_bypass/admin
  logic(8092)      -> 逻辑漏洞线(重置口令越权/金额守恒/一次性 coupon/状态机跳跃)，正确线+漏洞线成对差分
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import json
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import local_lab  # noqa: E402
import hard_lab   # noqa: E402

HARD_PREFIXES = (
    "/waf_sqli", "/time_blind", "/input_xss", "/double_encode", "/ssrf",
    "/jwt", "/idor", "/open_redirect", "/lfi_bypass", "/admin",
)
LOGIC_PREFIXES = ("/logic",)

# ---- 逻辑漏洞线 baseline（仿 hard_lab EXPECTED_FINDINGS 风格） ----
LOGIC_BASELINE = {
    "target": "http://127.0.0.1:8092",
    "endpoints": {
        "/logic/vuln/reset":  {"expect": ["越权", "重置口令", "IDOR"], "min_severity": "High"},
        "/logic/vuln/charge": {"expect": ["金额不守恒", "负数金额", "逻辑漏洞"], "min_severity": "Medium"},
        "/logic/vuln/coupon": {"expect": ["重复领取", "一次性不变量", "逻辑漏洞"], "min_severity": "Medium"},
        "/logic/vuln/pay":    {"expect": ["状态跳跃", "未授权支付", "逻辑漏洞"], "min_severity": "High"},
    },
    "negatives": {
        "/logic/reset":  "绑定校验正确端点，不应误报",
        "/logic/charge": "负数被拒正确端点，不应误报",
        "/logic/coupon": "重复被拒正确端点，不应误报",
        "/logic/pay":    "状态机正确端点，不应误报",
    },
    "notes": "逻辑漏洞线：绑定不变量(重置口令越权)/金额守恒与一次性(负数抵扣、coupon重复领取)/状态机跳跃(未支付订单改发货)。每组都做正确线+漏洞线双端点，供差分不变量引擎成对差分。",
}

# ---- 模块级状态（线程安全无需严谨，够用即可） ----
_TOKEN_BIND = {}        # reset_token -> user
_WALLET = {"balance": 0}
_COUPONS_USED = set()
_ORDERS = {}            # oid -> {"status": ...}
_ORDER_SEQ = [0]


class LogicHandler(BaseHTTPRequestHandler):
    """逻辑漏洞线：/logic/*。正确线校验不变量，漏洞线跳过校验（供差分引擎成对差分）。"""
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

    # ---- 组1 重置口令越权（绑定不变量） ----
    def _forgot(self, q):
        user = q.get('user', [''])[0]
        if not user:
            return self._send(400, '<pre>user required</pre>')
        tok = f"{user}@{secrets.token_hex(4)}"
        _TOKEN_BIND[tok] = user          # 仅保留最新，同 user 的新 token 覆盖旧 token
        return self._send(200, f'<pre>reset_token={tok}</pre>', 'text/plain')

    def _reset(self, q, vuln=False):
        tok = q.get('token', [''])[0]
        user = q.get('user', [''])[0]
        if vuln:
            # 漏洞线：不校验 token 与 user 的绑定，任何 token+任何 user 都成功（越权重置）
            return self._send(200, f'<pre>reset ok (impersonated {user})</pre>')
        if _TOKEN_BIND.get(tok) == user:
            return self._send(200, f'<pre>reset ok for {user}</pre>')
        return self._send(403, '<pre>token not bound to this user</pre>')

    # ---- 组2 金额守恒 + 一次性 ----
    def _charge(self, q, vuln=False):
        try:
            amt = int(q.get('amt', ['0'])[0])
        except ValueError:
            amt = 0
        if not vuln and amt < 0:
            return self._send(403, '<pre>negative amount rejected</pre>')
        _WALLET['balance'] += amt
        return self._send(200, f'<pre>balance={_WALLET["balance"]}</pre>')

    def _coupon(self, q, vuln=False):
        code = q.get('code', [''])[0]
        if vuln:
            # 漏洞线：不查已用，永远成功（可重复领取）
            return self._send(200, f'<pre>coupon {code or ""} ok</pre>')
        if code in _COUPONS_USED:
            return self._send(403, '<pre>already redeemed</pre>')
        _COUPONS_USED.add(code)
        return self._send(200, f'<pre>coupon {code or ""} ok</pre>')

    # ---- 组3 状态机跳跃 ----
    def _order(self):
        _ORDER_SEQ[0] += 1
        oid = str(_ORDER_SEQ[0])
        _ORDERS[oid] = {"status": "pending"}
        return self._send(200, f'<pre>order created oid={oid}</pre>')

    def _pay(self, q, vuln=False):
        oid = q.get('oid', [''])[0]
        if vuln:
            # 漏洞线：不校验状态，任意 oid 直接改发货/已支付
            if oid:
                _ORDERS[oid] = {"status": "shipped"}
            return self._send(200, f'<pre>order {oid} paid/shipped (state bypass)</pre>')
        if oid not in _ORDERS:
            return self._send(404, '<pre>order not found</pre>')
        if _ORDERS[oid]["status"] != "pending":
            return self._send(403, '<pre>wrong state (not pending)</pre>')
        if q.get('ok', [''])[0] != '1':
            return self._send(403, '<pre>payment not confirmed</pre>')
        _ORDERS[oid]["status"] = "paid"
        return self._send(200, f'<pre>order {oid} paid</pre>')

    def _route(self, q):
        p = self.path.split('?')[0].replace('//', '/')
        if p == '/logic/forgot':
            return self._forgot(q)
        if p == '/logic/reset':
            return self._reset(q)
        if p == '/logic/vuln/reset':
            return self._reset(q, vuln=True)
        if p == '/logic/charge':
            return self._charge(q)
        if p == '/logic/vuln/charge':
            return self._charge(q, vuln=True)
        if p == '/logic/coupon':
            return self._coupon(q)
        if p == '/logic/vuln/coupon':
            return self._coupon(q, vuln=True)
        if p in ('/logic/order', '/logic/vuln/order'):
            return self._order()
        if p == '/logic/pay':
            return self._pay(q)
        if p == '/logic/vuln/pay':
            return self._pay(q, vuln=True)
        return self._send(404, '<pre>404</pre>')

    def do_GET(self):
        self._route(parse_qs(urlparse(self.path).query))

    def do_POST(self):
        self._route(parse_qs(urlparse(self.path).query))

    def log_message(self, *a):
        pass


MEGA_INDEX = (
    "<html><body><h1>MEGA LAB (8092)</h1>"
    "<h2>local_lab 线</h2>"
    "<p><a href=\"/xss?s=hello\">xss</a> <a href=\"/sqli?id=1\">sqli</a> "
    "<a href=\"/upload\">upload</a> <a href=\"/ssti?name=hello\">ssti</a> "
    "<a href=\"/lfi?file=../../windows/win.ini\">lfi</a> <a href=\"/cmdi?cmd=echo%20hi\">cmdi</a> "
    "<a href=\"/nosql?q=1\">nosql</a> <a href=\"/ldap?user=admin\">ldap</a> "
    "<a href=\"/redirect?next=home\">redirect</a> <a href=\"/cors\">cors</a> "
    "<a href=\"/deser?data=x\">deser</a> <a href=\"/.env\">env</a> <a href=\"/safe\">safe(neg)</a></p>"
    "<h2>hard_lab 线</h2>"
    "<p><a href=\"/waf_sqli?id=1\">waf_sqli</a> <a href=\"/time_blind?id=1\">time_blind</a> "
    "<a href=\"/input_xss?q=test\">input_xss</a> <a href=\"/double_encode?q=x\">double_encode</a> "
    "<a href=\"/ssrf?url=http://example.com\">ssrf</a> <a href=\"/jwt\">jwt</a> "
    "<a href=\"/idor/profile/1\">idor</a> <a href=\"/open_redirect?next=home\">redirect</a> "
    "<a href=\"/lfi_bypass?file=etc\">lfi_bypass</a> <a href=\"/admin/default\">admin</a></p>"
    "<h2>logic 线</h2>"
    "<p><a href=\"/logic/forgot?user=alice\">forgot</a> "
    "<a href=\"/logic/reset?token=T&user=bob\">reset</a> "
    "<a href=\"/logic/vuln/reset?token=T&user=bob\">vuln/reset</a> "
    "<a href=\"/logic/charge?amt=1\">charge</a> <a href=\"/logic/vuln/charge?amt=-5\">vuln/charge</a> "
    "<a href=\"/logic/coupon?code=C\">coupon</a> <a href=\"/logic/vuln/coupon?code=C\">vuln/coupon</a> "
    "<a href=\"/logic/order\">order</a> <a href=\"/logic/pay?oid=1&ok=1\">pay</a> "
    "<a href=\"/logic/vuln/pay?oid=1\">vuln/pay</a></p>"
    "<p><a href=\"/__baseline__\">baseline(merged)</a></p>"
    "</body></html>"
)


class MegaHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _delegate(self, cls):
        inst = cls.__new__(cls)
        inst.__dict__.update(self.__dict__)
        return inst

    def _delegate_do(self, cls, method):
        try:
            getattr(self._delegate(cls), method)()
        except Exception as e:  # noqa: BLE001
            self.send_error(500, f"delegate {cls.__name__}.{method} failed: {e}")

    def _send_baseline(self):
        merged = {
            "target": "http://127.0.0.1:8092",
            "endpoints": dict(hard_lab.EXPECTED_FINDINGS.get("endpoints", {})),
            "negatives": dict(hard_lab.EXPECTED_FINDINGS.get("negatives", {})),
            "notes": LOGIC_BASELINE.get("notes", ""),
        }
        merged["endpoints"].update(LOGIC_BASELINE.get("endpoints", {}))
        merged["negatives"].update(LOGIC_BASELINE.get("negatives", {}))
        b = json.dumps(merged, ensure_ascii=False, indent=2).encode("utf-8", "replace")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(b)
        except BrokenPipeError:
            pass

    def do_GET(self):
        path = self.path.split("?")[0].replace("//", "/")
        if path.startswith(LOGIC_PREFIXES):
            self._delegate_do(LogicHandler, "do_GET")
        elif path == "/":
            self._send_mega_index()
        elif path == "/__baseline__":
            self._send_baseline()
        elif path.startswith(HARD_PREFIXES):
            self._delegate_do(hard_lab.HA, "do_GET")
        else:
            self._delegate_do(local_lab.H, "do_GET")

    def do_POST(self):
        path = self.path.split("?")[0].replace("//", "/")
        if path.startswith(LOGIC_PREFIXES):
            self._delegate_do(LogicHandler, "do_POST")
        else:
            self._delegate_do(local_lab.H, "do_POST")

    def _send_mega_index(self):
        b = MEGA_INDEX.encode("utf-8", "replace")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(b)
        except BrokenPipeError:
            pass


if __name__ == "__main__":
    port = 8092
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            port = 8092
    print(f"MEGA_LAB on 127.0.0.1:{port} (local_lab+hard_lab+logic merged)", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), MegaHandler).serve_forever()