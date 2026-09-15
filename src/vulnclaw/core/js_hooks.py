#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""浏览器运行时 JS 监控 hook（P3-10，2026-09-15）。

补齐"静默 DOM XSS"盲区：现有浏览器验证只监听 dialog 事件（alert/confirm/
prompt）——无弹窗的数据外带型 DOM XSS（innerHTML 注入、eval 执行、cookie
读取）完全漏检。

本模块提供注入脚本（render_session 对每个新 page 执行 add_init_script）：
① 危险 sink：document.write/eval/Function/insertAdjacentHTML/innerHTML setter
② 敏感读取：document.cookie getter
命中写入 `window.__vulnclaw_hits`（去重由 Python 侧按 sink+detail 处理，
上限 50 条防页面侧无限增长），Python 侧 evaluate 读回。

纪律：
- hook 自身**绝不改变页面行为**（全部 try/catch；包装函数原样透传返回值）；
- 读回失败/无 hits → 一律空列表，**不得当作命中**（沿用 render_session
  "渲染故障不得伪装成漏洞"的既有纪律）；
- 与 dialog 监听并存互不干扰（事件 vs 变量）。
"""

JS_HOOK = r"""
(function(){
  if (window.__vulnclaw_hooked) return;
  window.__vulnclaw_hooked = true;
  window.__vulnclaw_hits = [];
  function push(sink, detail){
    try {
      if (window.__vulnclaw_hits.length >= 50) return;
      window.__vulnclaw_hits.push({
        sink: String(sink),
        detail: String(detail).slice(0, 200),
        ts: Date.now()
      });
    } catch(e){}
  }
  function wrap(obj, name, sink){
    try {
      var orig = obj[name];
      if (typeof orig !== 'function') return;
      obj[name] = function(){
        try { push(sink, Array.prototype.slice.call(arguments, 0).join(' ')); } catch(e){}
        return orig.apply(this, arguments);
      };
    } catch(e){}
  }
  wrap(document, 'write', 'document.write');
  wrap(document, 'writeln', 'document.writeln');
  wrap(window, 'eval', 'eval');
  try {
    var origFn = window.Function;
    window.Function = function(){
      try { push('Function', Array.prototype.slice.call(arguments, 0).join(' ')); } catch(e){}
      return origFn.apply(this, arguments);
    };
    window.Function.prototype = origFn.prototype;
  } catch(e){}
  wrap(Element.prototype, 'insertAdjacentHTML', 'insertAdjacentHTML');
  try {
    var d = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (d && d.set) {
      Object.defineProperty(Element.prototype, 'innerHTML', {
        set: function(v){ try { push('innerHTML', v); } catch(e){}; return d.set.call(this, v); },
        get: d.get,
        configurable: true
      });
    }
  } catch(e){}
  try {
    var cd = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (cd && cd.get) {
      Object.defineProperty(Document.prototype, 'cookie', {
        get: function(){ try { push('cookie.read', 'document.cookie'); } catch(e){}; return cd.get.call(this); },
        set: function(v){ try { push('cookie.write', v); } catch(e){}; return cd.set.call(this, v); },
        configurable: true
      });
    }
  } catch(e){}
  // XHR / fetch 外带监控（数据流出/SSRF 前置；detail=目标 URL）
  try {
    var _xopen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(m, u){
      try { push('xhr.open', (typeof u === 'string') ? u : ''); } catch(e){}
      return _xopen.apply(this, arguments);
    };
  } catch(e){}
  try {
    var _ofetch = window.fetch;
    if (typeof _ofetch === 'function') {
      window.fetch = function(input){
        try {
          push('fetch', (typeof input === 'string') ? input : ((input && input.url) || ''));
        } catch(e){}
        return _ofetch.apply(this, arguments);
      };
    }
  } catch(e){}
  // DOM 注入观察（MutationObserver：script/iframe 节点动态插入）
  try {
    if (window.MutationObserver) {
      var _mo = new MutationObserver(function(muts){
        try {
          for (var i = 0; i < muts.length && i < 20; i++) {
            var added = muts[i].addedNodes || [];
            for (var j = 0; j < added.length && j < 10; j++) {
              var n = added[j];
              if (n && n.nodeType === 1) {
                var tag = (n.tagName || '').toLowerCase();
                if (tag === 'script' || tag === 'iframe') {
                  push('dom.' + tag + '_inject', (n.src || n.textContent || ''));
                }
              }
            }
          }
        } catch(e){}
      });
      _mo.observe(document.documentElement || document, { childList: true, subtree: true });
    }
  } catch(e){}
})();
"""

SENSITIVE_SINKS = ("eval", "Function", "document.write", "document.writeln")
DOM_SINKS = ("innerHTML", "insertAdjacentHTML")
DATA_SINKS = ("cookie.read", "cookie.write")
NET_SINKS = ("xhr.open", "fetch")
OBSERVER_SINKS = ("dom.script_inject", "dom.iframe_inject")


def summarize_hits(hits) -> str:
    """hits 列表 → 一行可读摘要（供 evidence 使用）。"""
    try:
        items = [h for h in (hits or []) if isinstance(h, dict)]
        if not items:
            return ""
        seen = []
        for h in items:
            s = str(h.get("sink") or "")
            if s and s not in seen:
                seen.append(s)
        return ", ".join(seen[:6])
    except Exception:  # noqa: BLE001
        return ""


__all__ = [
    "JS_HOOK", "summarize_hits",
    "SENSITIVE_SINKS", "DOM_SINKS", "DATA_SINKS", "NET_SINKS", "OBSERVER_SINKS",
]
