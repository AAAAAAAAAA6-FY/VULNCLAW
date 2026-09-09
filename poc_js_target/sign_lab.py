#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""poc_js_target / sign_lab —— K.3 验收靶场：受 sign 签名保护的端点。

零第三方依赖（http.server + base64 常量表），直接运行：
    python poc_js_target/sign_lab.py --port 8765

路由：
  GET /sign/            前端页面（script 内含用 CryptoJS 生成 sign 的还原样本）
  GET /sign/get_info    user/ts/sign 校验：sign 合法且 ts 新鲜 → 200 回显 user
                          （构成"签名正确后才发现"的业务参数注入点）
                          sign 缺失/错误/过期 → 403
sign 协议：base64("SALT|<ts>") （前端用 btoa 生成；K.1/K.2 可静态读懂）
"""
import argparse
import base64
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

SALT = "SALT|"


def valid_sign(raw_sign: str, ts: str) -> bool:
    ts_i = int(ts) if ts.isdigit() else 0
    now = int(time.time())
    if abs(now - ts_i) > 600:  # 防重放窗口 10 分钟
        return False
    expect = base64.b64encode((SALT + ts).encode()).decode()
    from hmac import compare_digest

    return compare_digest(raw_sign or "", expect)


PAGE = r"""<!DOCTYPE html>
<html><head><title>sign lab</title></head><body>
<script src="https://cdn.example.com/javascript.js"></script>
<script>
// K.1 可静态还原样本：sign = btoa("SALT|" + ts)  （Base64-chain 模式）
function genSign(ts) {
  var raw = "SALT|" + ts;
  return btoa(raw);
}
</script>
<form id="f">
  <input id="user" value="admin">
</form>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/sign/":
            body = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/sign/get_info":
            qs = parse_qs(parsed.query)
            user = (qs.get("user") or [""])[0]
            ts = (qs.get("ts") or [""])[0]
            sign = (qs.get("sign") or [""])[0]
            if not valid_sign(sign, ts):
                self._send(403, {"err": "bad signature"})
                return
            # 签名有效后才处理业务参数 —— K.3 的"签名正确后才发现"注入点
            self._send(200, {
                "ok": True, "user": user,
                "sql": "SELECT * FROM users WHERE name='" + user + "'",
                "echo": user,
            })
            return
        self._send(404, {"err": "not found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[sign_lab] listening on http://{args.host}:{args.port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
