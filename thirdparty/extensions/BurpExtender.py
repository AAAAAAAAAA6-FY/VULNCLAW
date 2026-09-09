# -*- coding: utf-8 -*-
# BurpExtender.py - Cookie/Token 自动导出插件
import json
import os
import time
import traceback
from threading import Lock
from burp import IBurpExtender, IHttpListener

OUTPUT_FILE = os.path.expanduser("~/burp_cookies.json")
LOCK = Lock()

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Cookie Exporter")
        callbacks.registerHttpListener(self)
        self._data = {}
        self._save_interval = 2
        print("[+] Cookie Exporter 已加载")
        print("[+] 输出文件: " + OUTPUT_FILE)
        try:
            if os.path.exists(OUTPUT_FILE):
                with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                    _old = json.load(f)
                _domains = [k for k in _old if k != "_meta"]
                print("[+] 已继承历史 Cookie 域 " + str(len(_domains)) + " 个")
        except Exception as e:
            print("[!] 读取历史 Cookie 失败（将从头累积）: " + repr(e))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return
        try:
            request = messageInfo.getRequest()
            if request is None: return
            analyzed = self._helpers.analyzeRequest(request)
            headers = analyzed.getHeaders()
            url = messageInfo.getUrl()
            if url is None: return
            host = url.getHost()
            if not host: return
            cookies = {}
            tokens = {}
            for header in headers:
                h = header.lower()
                if h.startswith("cookie:"):
                    for part in header[7:].strip().split(";"):
                        part = part.strip()
                        if "=" in part:
                            k, v = part.split("=", 1)
                            cookies[k] = v
                elif h.startswith("authorization:"):
                    tokens["Authorization"] = header[14:].strip()
                elif h.startswith("x-api-key:"):
                    tokens["X-API-Key"] = header[10:].strip()
            if cookies or tokens:
                with LOCK:
                    if host not in self._data:
                        self._data[host] = {}
                    self._data[host].update(cookies)
                    self._data[host].update(tokens)
                self._save_data()
        except Exception:
            print("[!] Cookie Exporter 处理请求异常（插件仍运行）:")
            traceback.print_exc()

    def _save_data(self):
        if not self._data:
            return
        with LOCK:
            existing = {}
            if os.path.exists(OUTPUT_FILE):
                try:
                    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                        existing = json.load(f)
                except Exception:
                    print("[!] 读取历史 Cookie 文件失败，将重建该文件:")
                    traceback.print_exc()
            for domain, items in self._data.items():
                if domain not in existing:
                    existing[domain] = {}
                existing[domain].update(items)
            existing["_meta"] = {
                "last_update": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "domains": len([k for k in existing if k != "_meta"]),
            }
            try:
                with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                    json.dump(existing, f, indent=2, ensure_ascii=False)
                print("[+] Cookie 已写盘: " + time.strftime("%H:%M:%S") + " 域数=" + str(existing["_meta"]["domains"]))
            except Exception:
                print("[!] 写 cookie 文件失败:")
                traceback.print_exc()
