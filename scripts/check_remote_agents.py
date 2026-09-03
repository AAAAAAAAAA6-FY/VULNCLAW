#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""远端 Agent 池连通性自检：读 .env 的 REMOTE_AGENTS，向每个 type=http 端点发极简请求，
报告状态。独立运行，只依赖标准库，避免 vulnclaw 的 numpy 崩溃。"""
import json, re, ssl, sys, urllib.error, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV = ROOT / ".env"

def load_agents():
    if not ENV.is_file():
        print(f"[x] 找不到 .env: {ENV}"); return None
    line = ""
    for raw in ENV.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if s.startswith("REMOTE_AGENTS="):
            line = s
    if not line:
        print("[!] .env 中未找到 REMOTE_AGENTS"); return None
    val = line.split("=", 1)[1]
    val = re.sub(r",\s*([}\]])", r"\1", val)
    try:
        parsed = json.loads(val)
        return parsed if isinstance(parsed, list) else None
    except Exception as e:
        print(f"[x] REMOTE_AGENTS 解析失败: {e}"); return None

def check(agent):
    name = agent.get("name", "?"); atype = agent.get("type", "?")
    url = (agent.get("url") or "").rstrip("/"); token = agent.get("token") or ""; model = agent.get("model", "")
    if atype != "http":
        return {"name": name, "ok": None, "note": "非 http 类型，跳过"}
    if not url:
        return {"name": name, "ok": False, "note": "缺少 url"}
    api = url + ("/chat/completions" if not url.endswith("/chat/completions") else "")
    payload = {"model": model or "?", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 5}
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = json.dumps(payload).encode()
    try:
        req = urllib.request.Request(api, data=body, headers=headers); ctx = ssl.create_default_context()
        try:
            resp = urllib.request.urlopen(req, context=ctx, timeout=25); code = resp.status
            data = json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            code = e.code; data = {}
            try: data = json.loads(e.read() or b"{}")
            except Exception: pass
        if code == 200:
            choices = data.get("choices"); ok = isinstance(choices, list) and bool(choices)
            if ok:
                content = str(choices[0].get("message", {}).get("content", ""))[:30]
                return {"name": name, "ok": True, "note": f"HTTP 200 OK -> {content}"}
            return {"name": name, "ok": False, "note": "HTTP 200 但空/异常响应"}
        if code in (401, 403): return {"name": name, "ok": False, "note": f"HTTP {code} 鉴权失败（key 无效）"}
        if code == 404: return {"name": name, "ok": False, "note": f"HTTP {code} 端点/模型不存在（检查 url 或 model）"}
        if code == 429: return {"name": name, "ok": False, "note": f"HTTP {code} 被限流（可能暂时）"}
        msg = str(data.get("error") or data.get("message") or "")[:120]
        return {"name": name, "ok": False, "note": f"HTTP {code} {msg}"}
    except Exception as e:
        return {"name": name, "ok": False, "note": f"网络/超时: {type(e).__name__}: {str(e)[:100]}"}

def main():
    agents = load_agents()
    if not agents: return 1
    print(f"远端 Agent 池自检：共 {len(agents)} 个\n")
    passed = 0
    for a in agents:
        r = check(a)
        if r["ok"] is True: icon = "OK "; passed += 1
        elif r["ok"] is False: icon = "FAIL"
        else: icon = "SKIP"
        print(f"[{icon}] {r['name']:<24} type={a.get('type','-'):<5} model={a.get('model','-'):<46} {r['note']}")
    print(f"\n可用 {passed}/{len(agents)}")
    return 0 if passed else 1

if __name__ == "__main__":
    sys.exit(main())