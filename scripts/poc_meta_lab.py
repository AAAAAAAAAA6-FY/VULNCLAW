#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""poc_meta_lab —— 元orphic 不变量探针验收靶场（零第三方依赖）。

提供三个**故意留漏洞**的端点，用于端到端验证 MetamorphicEngine 能否在
"不注入任何业务知识"的前提下抓到逻辑漏洞：

  POST /order/create?price=100&qty=1  -> 服务端采信客户端 price 并回显（价格篡改）
  POST /coupon/claim?coupon_id=C1     -> 重复请求返回不同 coupon_code（重放非幂等）
  GET  /profile?user_id=1001          -> 改 user_id 返回他人数据且无鉴权（越权）

另有一个**安全**端点作对照（不应被报）：
  GET  /profile_safe?user_id=1001     -> 改 user_id 返回 403（有鉴权）

运行：python scripts/poc_meta_lab.py --port 8791
"""
import argparse
import json
import secrets
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


USERS = {
    "1001": {"user": "alice", "orders": []},
    "1002": {"user": "bob", "orders": [{"id": 9001, "item": "laptop"}], "address": "Shanghai"},
}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # 静音访问日志
        return

    # ---------------------------------------------------------------- 工具
    def _params(self) -> dict:
        q = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
        length = int(self.headers.get("Content-Length") or 0)
        self._raw = ""
        if length:
            self._raw = self.rfile.read(length).decode("utf-8", "replace")
            q.update({k: v[0] for k, v in parse_qs(self._raw).items()})
        return q

    def _json(self, obj, status: int = 200) -> None:
        raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    # ---------------------------------------------------------------- 路由
    def do_GET(self):
        self._route()

    def do_POST(self):
        self._route()

    def _route(self):
        path = urlparse(self.path).path
        p = self._params()

        if path == "/order/create":
            # ⚠️ 漏洞：直接采信客户端提交的 price，不按商品单价重算
            price = p.get("price", "100")
            self._json({
                "success": True,
                "order_id": "ORD" + secrets.token_hex(3).upper(),
                "price": price,
                "qty": p.get("qty", "1"),
            })
            return

        if path == "/coupon/claim":
            # ⚠️ 漏洞：无幂等/去重，每次请求都发一张新券
            self._json({
                "success": True,
                "coupon_id": p.get("coupon_id", "C1"),
                "coupon_code": "CP" + secrets.token_hex(3).upper(),
            })
            return

        if path == "/profile":
            # ⚠️ 漏洞：不校验属主，改 user_id 即可看他人数据
            uid = p.get("user_id", "1001")
            self._json({"success": True, "data": USERS.get(uid, {"user": "unknown"})})
            return

        if path == "/profile_safe":
            # ✅ 安全对照：非属主直接 403
            uid = p.get("user_id", "1001")
            if uid != "1001":
                self._json({"error": "unauthorized", "success": False}, 403)
                return
            self._json({"success": True, "data": USERS["1001"]})
            return

        if path.startswith("/api/order"):
            # ⚠️ 漏洞：JSON body 里的 total / items[0].price 被直接采信并回显
            try:
                obj = json.loads(self._raw or "{}")
            except Exception:
                obj = {}
            items = obj.get("items") or []
            self._json({
                "success": True,
                "order_id": "ORD" + secrets.token_hex(3).upper(),
                "total": obj.get("total"),
                "price": (items[0].get("price") if items and isinstance(items[0], dict) else None),
            })
            return

        if path.startswith("/api/profile/"):
            # ⚠️ 漏洞：路径段里的 uid 不做属主校验
            uid = path.rsplit("/", 1)[-1]
            self._json({"success": True, "data": USERS.get(uid, {"user": "unknown"})})
            return

        if path == "/api/me":
            # ⚠️ 漏洞：身份取自 header / cookie，不做属主校验
            uid = self.headers.get("X-User-Id") or ""
            if not uid:
                for part in (self.headers.get("Cookie") or "").split(";"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        if k.strip() == "uid":
                            uid = v.strip()
            self._json({"success": True, "data": USERS.get(uid or "1001", {"user": "unknown"})})
            return

        if path == "/search":
            q = p.get("q", "")
            # ⚠️ 漏洞1：单/双引号直接进入 SQL -> 报数据库错误
            # ⚠️ 漏洞2：输入原样回显且未转义 -> 反射型 XSS
            if ("'" in q or '"' in q or "\\" in q) and "<" not in q:
                self._json({
                    "success": False,
                    "error": "You have an error in your SQL syntax; check the manual",
                    "q": q,
                }, 500)
                return
            # 真实形态：原样回显到 HTML 页面（Content-Type: text/html）
            raw = f"<html><body><div>result for {q}</div></body></html>".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if path == "/api/cmd":
            # ⚠️ 漏洞：输入拼进 shell 命令
            c = p.get("c", "")
            self._json({"success": True, "output":
                        "uid=0(root) gid=0(root) groups=0(root)" if "id" in c else "ok"})
            return

        if path == "/api/file":
            # ⚠️ 漏洞：路径穿越读取任意文件
            f = p.get("file", "")
            if "etc/passwd" in f or ".." in f:
                self._json({"success": True,
                            "content": "root:x:0:0:root:/root:/bin/bash"})
                return
            self._json({"success": True, "content": "not found"})
            return

        if path == "/api/fetch":
            # ⚠️ 漏洞：服务端代访未校验目标 -> 可打云元数据
            u = p.get("url", "")
            if "169.254.169.254" in u:
                self._json({"success": True, "data": "ami-id\ninstance-id\nlocal-hostname"})
                return
            self._json({"success": True, "data": "fetched"})
            return

        if path == "/api/sleep":
            # ⚠️ 漏洞：延时原语可执行 -> 时间盲注
            q = p.get("q", "")
            if "SLEEP" in q.upper() or "WAITFOR" in q.upper():
                time.sleep(3)
            self._json({"success": True, "q": q})
            return

        if path == "/api/xml":
            # ⚠️ 漏洞：解析外部实体
            if "ENTITY" in (p.get("xml") or "").upper():
                self._json({"success": True, "parsed": "root:x:0:0:root:/root:/bin/bash"})
                return
            self._json({"success": True, "parsed": "ok"})
            return

        if path == "/api/tpl":
            # ⚠️ 漏洞：模板表达式被执行（7*7 -> 49）
            tpl = p.get("tpl") or ""
            if "7*7" in tpl:
                self._json({"success": True, "rendered": "49"})
                return
            self._json({"success": True, "rendered": tpl})
            return

        if path == "/api/header":
            # ⚠️ 漏洞：CRLF 未过滤，可控内容真的写入**响应头**
            v = p.get("v") or ""
            if "X-Injected" in v:
                raw = b'{"success": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-Injected", "1")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            self._json({"success": True, "note": "clean"})
            return

        if path == "/api/redirect":
            # ⚠️ 漏洞：跳转地址完全由外部输入决定
            self._json({"success": True, "location": p.get("url", "/")})
            return

        if path == "/api/nosql":
            # ⚠️ 漏洞：请求对象直接作为查询条件
            if "$" in (p.get("q") or ""):
                self._json({"success": False, "error": "unknown operator: $gt"}, 500)
                return
            self._json({"success": True, "data": []})
            return

        if path == "/api/ldap":
            # ⚠️ 漏洞：LDAP 过滤器拼接
            if "*" in (p.get("user") or ""):
                self._json({"success": False, "error": "Invalid DN syntax"}, 500)
                return
            self._json({"success": True, "data": "not found"})
            return

        if path == "/api/deser":
            # ⚠️ 漏洞：直接反序列化不可信数据
            d = p.get("data") or ""
            if "rO0AB" in d or "aced" in d:
                self._json({"success": False,
                            "error": "java.io.InvalidClassException: ClassNotFoundException"}, 500)
                return
            self._json({"success": True, "obj": "ok"})
            return

        if path == "/api/ssi":
            # ⚠️ 漏洞：SSI 指令被解析（模拟服务器解析了 SSI 指令）
            self._json({"success": False,
                        "error": "[an error occurred while processing this directive] (simulated SSI parse)"}, 500)
            return

        if path == "/api/el":
            # ⚠️ 漏洞：EL 表达式被解析（模拟 javax.el 解析异常）
            self._json({"success": False,
                        "error": "javax.el.ELException: Failed to parse expression (simulated EL error)"}, 500)
            return

        if path == "/api/rfi":
            # ⚠️ 漏洞：后端尝试包含远程资源（模拟 PHP allow_url_include 生效）
            v = p.get("url") or p.get("file") or p.get("path") or p.get("src") or ""
            if "http://" in v or "//" in v:
                self._json({"success": False,
                            "error": "failed to open stream: http request failed (simulated RFI include error)"}, 500)
                return
            self._json({"success": True, "data": "ok"})
            return

        if path == "/api/dotnet":
            # ⚠️ 漏洞：.NET BinaryFormatter 反序列化
            if "AAEAAAD" in (p.get("data") or ""):
                self._json({"success": False,
                            "error": "System.Runtime.Serialization: TypeLoadException"}, 500)
                return
            self._json({"success": True, "obj": "ok"})
            return

        if path == "/api/php":
            # ⚠️ 漏洞：PHP unserialize 处理用户输入
            if (p.get("data") or "").startswith("O:"):
                self._json({"success": False,
                            "error": "Notice: unserialize(): Error at offset"}, 500)
                return
            self._json({"success": True, "obj": "ok"})
            return

        if path == "/api/pickle":
            # ⚠️ 漏洞：Python pickle.loads 处理用户输入
            if "gASV" in (p.get("data") or "") or "cos" in (p.get("data") or ""):
                self._json({"success": False, "error": "UnpicklingError: invalid load key"}, 500)
                return
            self._json({"success": True, "obj": "ok"})
            return

        if path == "/api/graphql":
            # ⚠️ 漏洞：内省未关闭
            q = p.get("query") or ""
            if "__schema" in q or "__typename" in q:
                self._json({"data": {"__schema": {"queryType": {"name": "Query"}}}})
                return
            self._json({"data": {}})
            return

        if path == "/api/xpath":
            # ⚠️ 漏洞：XPath 表达式拼接
            if "'" in (p.get("q") or ""):
                self._json({"success": False, "error": "Invalid XPath expression"}, 500)
                return
            self._json({"success": True, "data": []})
            return

        if path == "/api/log":
            # ⚠️ 漏洞：日志触发 JNDI 外连（此处以延时模拟外连耗时）
            if "jndi" in (p.get("msg") or "").lower():
                time.sleep(2.5)
            self._json({"success": True, "logged": True})
            return

        if path == "/api/cors":
            # ⚠️ 漏洞：ACAO 原样回显任意 Origin（等同允许任意源）
            origin = self.headers.get("Origin") or "*"
            raw = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if path == "/api/headers":
            # ⚠️ 漏洞：响应不含任何安全头（无 nosniff / XFO / HSTS）
            self._json({"success": True})
            return

        if path == "/api/host":
            # ⚠️ 漏洞：用 X-Forwarded-Host 拼接并回显绝对地址
            xfh = self.headers.get("X-Forwarded-Host") or "x.test"
            self._json({"success": True, "base": f"https://{xfh}/"})
            return

        if path == "/safe/html":
            # ✅ 安全对照：原样回显但**做了正确的 HTML 转义**（不可执行）
            q = (p.get("q") or "").replace("&", "&amp;").replace("<", "&lt;") \
                                  .replace(">", "&gt;").replace('"', "&quot;")
            raw = f"<html><body><div>result for {q}</div></body></html>".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if path == "/api/safe":
            # ✅ 安全对照：只原样回显，无任何漏洞特征
            self._json({"success": True, "echo": p.get("c", "")})
            return

        self._json({"error": "not found", "success": False}, 404)


def main() -> int:
    ap = argparse.ArgumentParser(description="元orphic 探针验收靶场")
    ap.add_argument("--port", type=int, default=8791)
    args = ap.parse_args()
    srv = HTTPServer(("127.0.0.1", args.port), _Handler)
    print(f"[meta-lab] listening on http://127.0.0.1:{args.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
