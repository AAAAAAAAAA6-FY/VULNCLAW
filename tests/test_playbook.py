#!/usr/bin/env python3
"""B3：L3 剧本生成器单测（微型靶场，零真实 LLM 调用）。"""
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qsl, urlparse

from vulnclaw.engines.playbook_engine import (
    Playbook,
    PlaybookAction,
    PlaybookEngine,
    _annotate_features_local,
    _collect_seed_endpoints,
    _map_llm_to_real,
    _with_params,
)

# 微型靶场：正确线（拒）+ 漏洞线（放行）成对
_TOKENS = {}


class MiniHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body):
        b = str(body).encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(b)
        except BrokenPipeError:
            pass

    def do_GET(self):
        u = urlparse(self.path)
        p, q = u.path, dict(parse_qsl(u.query))
        if p == "/reset":
            tok, user = q.get("token", ""), q.get("user", "")
            ok = _TOKENS.get(tok) == user
            self._send(200 if ok else 403, "reset ok" if ok else "token not bound")
        elif p == "/vuln_reset":
            self._send(200, "reset ok (impersonated)")
        elif p == "/forgot":
            user = q.get("user", "")
            tok = f"{user}@tok"
            _TOKENS[tok] = user
            self._send(200, tok)
        elif p == "/charge":
            amt = int(q.get("amt", "0") or 0)
            self._send(403 if amt < 0 else 200, f"balance={amt}")
        elif p == "/vuln_charge":
            self._send(200, "balance ok")
        elif p == "/vuln_coupon":
            self._send(200, "coupon ok")
        elif p == "/vuln_pay":
            self._send(200, "paid/shipped done")
        else:
            self._send(404, "no")

    def log_message(self, *a):
        pass


class _Srv:
    url = None

    def __enter__(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), MiniHandler)
        self.url = f"http://127.0.0.1:{srv.server_address[1]}"
        self.thread = Thread(target=srv.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *a):
        pass


def _brief(url):
    return {
        "crawled_endpoints": [
            f"{url}/vuln_reset?token=t&user=a",
            f"{url}/vuln_charge?amt=1",
        ],
        "js_endpoints": [f"{url}/vuln_coupon"],
        "apis": [f"{url}/vuln_pay"],
    }


def _gen_no_llm(eng, brief, target):
    """强制本地标注路径执行 generate_playbooks。"""

    async def _inner():
        with patch("vulnclaw.engines.playbook_engine._annotate_features_llm",
                   new=AsyncMock(return_value=[])):
            return await eng.generate_playbooks(brief, target)

    return asyncio.run(_inner())


# ---------------------------------------------------------------- 单元
def test_collect_seed_endpoints_dedup_and_skip_bad():
    eps = _collect_seed_endpoints(
        {"crawled_endpoints": ["/a", "http://127.0.0.1:1/a", "data:x", "htttps://bad", "/b"],
         "js_endpoints": ["/a", "javascript:void(0)", "/c"]},
        "http://127.0.0.1:1",
    )
    paths = {u.split("?")[0] for u in eps}
    assert paths == {f"http://127.0.0.1:1{a}" for a in ("", "/a", "/b", "/c")}, paths


def test_collect_requires_absolute_target():
    assert _collect_seed_endpoints({"crawled_endpoints": ["/a"]}, "not-a-url") == []


def test_map_llm_to_real_suffix():
    real = ["http://h/logic/vuln/reset?a=1", "http://h/logic/reset", "http://h/other"]
    got = _map_llm_to_real(["/vuln/reset", "/reset"], real)
    assert got == ["http://h/logic/vuln/reset?a=1", "http://h/logic/reset"]
    assert _map_llm_to_real(["/nonexistent"], real) == []


def test_with_params_no_overwrite():
    u = _with_params("http://h/a?token=t1", {"token": "t2", "user": "u1"})
    assert "token=t1" in u and "user=u1" in u and "token=t2" not in u


def test_local_annotate_buckets():
    feats = _annotate_features_local([
        "http://h/reset", "http://h/vuln_reset", "http://h/charge",
        "http://h/static/app.js",
    ])
    kinds = {f["feature"] for f in feats}
    assert any("绑定" in k for k in kinds)
    assert any("金额" in k for k in kinds)


# ---------------------------------------------------------------- 集成
def test_generate_playbooks_local_real_urls_and_empty_fail_closed():
    with _Srv() as s:
        eng = PlaybookEngine(timeout=5)
        books = _gen_no_llm(eng, _brief(s.url), s.url)
        assert books, "local 标注应生成剧本"
        for b in books:
            for a in b.actions:
                assert a.url.startswith(s.url), a.url
        assert _gen_no_llm(eng, {}, s.url) == []


def test_execute_produces_findings_with_shape():
    with _Srv() as s:
        eng = PlaybookEngine(timeout=5)
        books = _gen_no_llm(eng, _brief(s.url), s.url)
        assert books

        async def _run():
            findings = []
            for b in books:
                f = await eng.execute(b, budget_s=20)
                if f:
                    findings.append(f)
            return findings

        findings = asyncio.run(_run())
        assert findings, f"漏洞线剧本应产出 finding（books={[b.invariant for b in books]}）"
        kinds = set()
        for f in findings:
            for k in ("url", "type", "severity", "title", "description", "evidence",
                      "ai_verdict", "confidence", "method", "cvss", "remediation",
                      "recommendation"):
                assert k in f
            assert f["ai_verdict"] == "待验证"
            assert any(t["family"] == "playbook" for t in f["evidence_trace"])
            assert f["playbook"]["source"] == "local"
            kinds.update(t["kind"] for t in f["evidence_trace"])
        assert {"binding", "amount", "once", "state"} <= kinds, f"kinds={kinds}"


def test_execute_fail_closed_bad_action():
    eng = PlaybookEngine(timeout=3)
    book = Playbook(
        id="pb-x", title="x", domain="通用", feature="x", invariant="binding",
        expected_state="e",
        actions=[PlaybookAction(seq=1, verb="reset", url="http://127.0.0.1:1/reset")],
    )
    assert asyncio.run(eng.execute(book)) is None  # 端口关闭 → 差分失败 → fail-closed


def test_manual_book_describe():
    b = Playbook(id="pb-1", title="t", domain="电商", feature="口令重置",
                 invariant="binding", expected_state="仅属主",
                 actions=[PlaybookAction(1, "reset", "http://h/reset?a=1")])
    assert "pb-1" in b.describe()
    assert b.evidence_tag