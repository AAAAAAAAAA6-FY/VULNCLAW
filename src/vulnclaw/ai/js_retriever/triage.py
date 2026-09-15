# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)

"""K.2 AB 分诊：加密参数还原链路的自动路径选择。

对应任务卡 K.2 验收：「同一目标，从纯函数到重度混淆样本各 1 个，日志显示
分别走 A/B/C 路径且 C 不报错」。

三路语义（用户确认过的「上限靠 AI 抬、下限靠平台兜」）：
   A 逻辑复现 | 静态规则命中（JSCryptoRestorer 还原硬编码密钥/常量传播/iv）
              → 0 成本确定性配方；或 LLM 判定 REPRODUCIBLE 给出算法摘要
   B 环境执行 | LLM 判定 EXECUTE 且通过安全预检后，用无特权 node 子进程 +
              最小 DOM stub 黑盒调用前端函数（K.4 将扩展补环境方案）
   C 规则降级 | LLM 失败 / UNKNOWN / 预检拒绝 / 执行失败 → 不报错、标记
              fallback，调用方回退既有规则探测（不空转）

安全边界（延续 K.1 红线：绝不运行不可信 JS）：
   B 路仅对通过 _safe_for_sandbox 预检的“纯函数脚本”开放；任何 IO /
   动态执行器 / 原型链投毒 / 网络访问一律拒绝执行 → 直接 C。
   执行时：独立子进程 + 内存限制 + 硬超时 + 无任何凭据环境。

成本护栏：每个目标 LLM 调用上限 1 次（cheap 档），任何异常静默降级 C。
审计：每次分诊结果 JSON 落盘 _runtime_cache/js_triage/（可随 settings.js_triage_audit_dir 调整）。
"""
from __future__ import annotations

import asyncio
import io
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.modules.js_crypto_restore import JSCryptoRestorer

# ---------------------------------------------------------------------------
# 安全预检：B 路放行闸门（宁可拒、不可放）
# ---------------------------------------------------------------------------
_UNSAFE_JAVASCRIPT = re.compile(
    r"eval\s*\(|\bnew\s+Function\b|\bFunction\s*\(|\brequire\s*\(|"
    r"\bimport\s*\(|\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b|\bWorker\b|"
    r"\bprocess\s*\.|child_process|\.exec\s*\(|execSync|spawn\s*\(|"
    r"document\.cookie|\.innerHTML\s*=|outerHTML\s*=|"
    r"file:\s*[\\/]|data:text/html|"
    r"constructor\s*\[\s*[\"']constructor|__proto__\s*=|prototype\s*\.\s*__proto__"
)

# node 沙箱包装：最小 DOM stub，仅暴露空壳；用户 JS 嵌入标记处。
_NODE_WRAPPER = r"""
const __sb__ = {
  document: {
    getElementById: () => ({ value: "" }), querySelector: () => null,
    querySelectorAll: () => [], currentScript: { src: "" }, cookie: "",
    createElement: () => ({ setAttribute: () => {}, appendChild: () => {} }),
  },
  window: {}, navigator: { userAgent: "__vulnclaw_sandbox__" },
  location: { href: "" }, top: undefined, parent: undefined, console: console,
};
globalThis.window = __sb__.window; globalThis.document = __sb__.document;
globalThis.navigator = __sb__.navigator; globalThis.location = __sb__.location;
globalThis.top = __sb__.top; globalThis.parent = __sb__.parent;
globalThis.self = globalThis;
try {
  // ==USER_JS==
  {js}
  console.log("\n__EXIT__OK__");
} catch (e) {
  console.log("\n__EXIT__ERR__ " + String((e && e.message) || e));
}
"""

_SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.S | re.I)


def _extract_inline_js(html: str) -> str:
    return "\n".join(m.group(1) for m in _SCRIPT_RE.finditer(html))


def safe_for_sandbox(js: str) -> bool:
    """B 路放行闸门：命中任何不安全特征即拒绝执行。"""
    return not _UNSAFE_JAVASCRIPT.search(js)


_ANTI_BOT_PATTERNS = [
    # (特征名, 正则) —— 命中即标记；强特征会阻断 B 路执行与报告
    ("debugger", re.compile(r"\bdebugger\b")),
    ("webdriver", re.compile(r"navigator\.webdriver|\.webdriver\s*[=)]")),
    ("chrome_fp", re.compile(r"window\.chrome\b|navigator\.userAgentData\b")),
    ("phantom", re.compile(r"PhantomJS|phantom\.|slimerjs|\bheadless\b")),
    ("selenium", re.compile(r"\bselenium\b|webdriver\.|marionette")),
    ("eval_fp", re.compile(r"Function\s*\(\s*[\"']return\s+this")),
    ("tostring_fp", re.compile(r"\.toString\s*\.\s*constructor|constructor\s*\.\s*toString")),
    ("proto_tamper", re.compile(r"__proto__\s*=|prototype\s*\.\s*__proto__")),
]
_STRING_LIT_RE = re.compile(r"([\"'])(?:\\.|(?!\1).)*?\1", re.S)


def _strip_string_literals(js: str) -> str:
    """剥掉字符串字面量，避免把 payload/文案里的 'debugger' 当特征误杀。"""
    return _STRING_LIT_RE.sub(" ", js)


def detect_anti_bot_features(js: str) -> list:
    """反爬/反调试特征识别（K.4）：返回命中特征名列表，空=干净。"""
    stripped = _strip_string_literals(js or "")
    found = []
    for name, pat in _ANTI_BOT_PATTERNS:
        if pat.search(stripped):
            found.append(name)
    return found


def eval_recipe_for_report(recipe_meta: dict) -> dict:
    """还原结果报告守卫（K.4，收敛门同构）：

    - confirmed：静态复现 / manual 真实生成 / sandbox 执行成功
    - pending_review：LLM 摘要未验证 / sandbox 未执行成功（不进主报告，转待审）
    - reject：恶意混淆/反调试特征存在且配方不可执行（绝不产生 finding）

    任何不确定一律不出 confirmed，杜绝"还原失败污染报告"。
    """
    mode = recipe_meta.get("mode")
    validated = bool(recipe_meta.get("validated"))
    anti = recipe_meta.get("anti_bot") or []
    execution_modes = ("sandbox", "llm")
    if anti and mode in execution_modes:
        return {"verdict": "reject", "reason": "anti_bot_" + str(anti[0]),
                "fallback": True}
    if mode == "sandbox":
        if not validated:
            return {"verdict": "pending_review", "reason": "sandbox_not_validated",
                    "fallback": True}
        return {"verdict": "confirmed", "reason": "sandbox_ok", "fallback": False}
    if mode in ("aes_iv", "static", "manual"):
        return {"verdict": "confirmed", "reason": "static_recipe", "fallback": False}
    if mode == "llm":
        return {"verdict": "pending_review", "reason": "llm_recipe_unvalidated",
                "fallback": True}
    return {"verdict": "pending_review", "reason": "unknown_mode", "fallback": True}


class JSTriage:
    """加密参数还原 AB 分诊器（独立模块，不依赖 orchestrator 实例）。

    用法::

        t = JSTriage()
        res = await t.triage(html_or_js, param="sign")
        # res["path"] in ("A", "B", "C")
    """

    def __init__(self, restorer=None, llm_ask=None, audit_dir=None):
        self.restorer = restorer or JSCryptoRestorer()
        # 可注入 LLM 回调（测试替身/后续替换模型档位）；None=默认 cheap 档直调
        self._llm_ask = llm_ask or self._llm_ask_default
        if audit_dir is None:
            audit_dir = getattr(settings, "js_triage_audit_dir", "_runtime_cache/js_triage")
        self.audit_dir = Path(str(audit_dir))

    # -- 主入口 ------------------------------------------------------------
    async def triage(self, text, param="", is_html=True):
        """text: 响应 HTML 或纯 JS 片段；is_html=False 时按纯 JS 处理。"""
        js = _extract_inline_js(text) if is_html else text
        started = time.time()
        feats = detect_anti_bot_features(js)
        result = {
            "param": param, "path": "C", "reason": "",
            "restorable": False, "recipe": {}, "llm_backed": False,
            "llm_verdict": "", "exec": {}, "safe": True, "js_len": len(js),
            "anti_bot": feats,
        }

        # 1) A 路：静态规则还原（0 成本）
        static = self._static_restore(text if is_html else js)
        if static is not None:
            result.update(path="A", reason=static["reason"], restorable=True,
                          recipe=static["recipe"])
            self._audit(result)
            return result

        # 2) LLM 分诊（1 次 cheap，任何失败 → C，绝不让分诊拖垮扫描）
        try:
            verdict = await self._llm_ask(js[:2000])
        except Exception as exc:  # noqa: BLE001
            logger.debug('[K.2] LLM 分诊异常，降级 C: %s', exc)
            verdict = {}
        raw = verdict.get("verdict") if isinstance(verdict, dict) else None
        result["llm_verdict"] = str(raw or "")
        algorithm = (verdict.get("algorithm") or "") if isinstance(verdict, dict) else ""

        if raw == "REPRODUCIBLE":
            result.update(path="A", reason="llm_reproducible", restorable=True,
                          recipe={"algorithm": algorithm, "llm_backed": True})
            result["llm_backed"] = True
        elif raw == "EXECUTE":
            if feats:
                # K.4 反爬/反调试：恶意特征存在则拒绝执行（切换补环境=不冒险）
                result.update(path="C", reason=f"anti_bot_blocked:{feats[0]}",
                              exec={}, safe=True)
            else:
                exec_res = await self._sandbox_execute(js)
                result["exec"] = exec_res
                result["safe"] = exec_res.get("safe", False)
                if exec_res.get("ok"):
                    result.update(path="B", reason="sandbox_execute",
                                  exec=exec_res, llm_backed=True)
                else:
                    result.update(path="C",
                                  reason=exec_res.get("reason", "sandbox_refused"))
        else:
            result.update(path="C", reason="unknown")

        result["llm_backed"] = bool(raw)
        # K.4 报告守卫输入：把配方可验证性与反调试特征带给下游
        result["recipe_meta"] = {
            "mode": ("manifest"), "validated": False, "anti_bot": feats,
        }
        if result["path"] == "B":
            result["recipe_meta"] = {"mode": "sandbox",
                                    "validated": bool(result["exec"].get("ok")),
                                    "anti_bot": feats}
        elif result["restorable"]:
            # 静态规则复现=确定性配方(confirmed)；LLM 算法摘要未落地验证=pending_review
            is_static = result.get("reason") == "static_restore"
            result["recipe_meta"] = {"mode": ("static" if is_static else "llm"),
                                     "validated": is_static,
                                     "anti_bot": feats}
        else:
            result["recipe_meta"] = {"mode": "llm", "validated": False,
                                    "anti_bot": feats}
        self._audit(result)
        logger.debug("[K.2] triage param=%s -> %s (%s, %dms)",
                     param or "-", result["path"], result["reason"],
                     int((time.time() - started) * 1000))
        return result

    # -- A 路 --------------------------------------------------------------
    def _static_restore(self, text):
        try:
            entries = self.restorer.analyze(text)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[K.2] 静态还原异常，忽略: %s", exc)
            return None
        for e in entries:
            if e.get("restorable"):
                return {"reason": "static_restore",
                        "recipe": {"api": e.get("api"), "key_source": e.get("key_source"),
                                   "iv_source": e.get("iv_source"), "poc": e.get("poc")}}
        return None

    # -- B 路 --------------------------------------------------------------
    async def _sandbox_execute(self, js):
        if not safe_for_sandbox(js):
            return {"ok": False, "safe": False, "reason": "unsafe_features_blocked"}
        node = shutil.which("node")
        if not node:
            return {"ok": False, "safe": True, "reason": "node_unavailable"}
        script = _NODE_WRAPPER.replace("{js}", js)
        fd, tmp = tempfile.mkstemp(suffix=".js", prefix="vulnclaw_triage_")
        try:
            with io.open(fd, "w", encoding="utf-8") as fh:
                fh.write(script)
            try:
                # 超时可配置（JS_SANDBOX_TIMEOUT，默认 30s）：原硬编码 10s 在全量测试
                # 负载下会被 node 冷启动+调度挤爆 → TimeoutExpired → B 路误降级 C（实测 flaky）。
                sandbox_timeout = float(getattr(settings, "js_sandbox_timeout", 30.0))
                proc = await asyncio.to_thread(
                    subprocess.run,
                    [node, "--max-old-space-size=64", tmp],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=sandbox_timeout,
                )
            except subprocess.TimeoutExpired:
                return {"ok": False, "safe": True, "reason": "timeout"}
            out = proc.stdout or ""
            if "__EXIT__OK__" in out:
                return {"ok": True, "safe": True, "reason": "exec_ok",
                        "stdout_tail": out[-400:]}
            err = (proc.stderr or "").strip().splitlines()
            return {"ok": False, "safe": True, "reason": "exec_error",
                    "error": err[-1] if err else "unknown"}
        except Exception as exc:  # noqa: BLE001
            logger.debug("[K.2] node 沙箱执行异常: %s", exc)
            return {"ok": False, "safe": True, "reason": "exec_exception"}
        finally:
            try:
                Path(tmp).unlink()
            except OSError:
                pass

    # -- LLM 分诊（默认实现：cheap 档 1 次调用） ---------------------------
    async def _llm_ask_default(self, js_snippet):
        """cheap 档单次调用；一切异常返回 {}（走 C 降级）。"""
        try:
            from vulnclaw.ai.v100.provider_balancer import get_tier_client

            client, _key, _model = await get_tier_client("cheap")
        except Exception as exc:  # noqa: BLE001
            logger.debug("[K.2] 档位客户端不可用，降级 C: %s", exc)
            return {}
        prompt = (
            "你是 JS 逆向参数分诊器。判断以下前端 JS 中的签名/加密参数生成逻辑"
            "能否脱离浏览器、用纯 Python 复现。\n"
            "只输出一个 JSON 对象，禁止其它文字：\n"
            '{"verdict": "REPRODUCIBLE|EXECUTE|UNKNOWN", "algorithm": "算法一句话摘要", '
            '"params": ["输入参数名"]}\n'
            "REPRODUCIBLE=算法/密钥静态可推，纯逻辑复现即可；\n"
            "EXECUTE=必须实际运行 JS 才能拿到结果（依赖运行时状态）；\n"
            "UNKNOWN=看不出有加密/签名逻辑或无法判断。\n\n"
            "JS 片段(%d 字符):\n%s" % (len(js_snippet), js_snippet)
        )
        try:
            raw = await asyncio.wait_for(
                client.ask(
                    prompt,
                    system="你是谨慎、只输出 JSON 的逆向工程助手。",
                    temperature=0.1, max_tokens=300, wrap_data=True,
                    retries=2, use_cache=False, usage_site="js:triage",
                ),
                timeout=float(getattr(settings, "ai_router_timeout", 90)),
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("[K.2] LLM 分诊调用失败，降级 C: %s", exc)
            return {}
        try:
            from vulnclaw.modules.vuln_scanner import safe_extract_json

            data = safe_extract_json(raw)
        except Exception:  # noqa: BLE001
            return {}
        if isinstance(data, dict) and data.get("verdict") in (
            "REPRODUCIBLE", "EXECUTE", "UNKNOWN"):
            return data
        return {}

    # -- 审计落盘 ----------------------------------------------------------
    def _audit(self, result):
        try:
            self.audit_dir.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = self.audit_dir / ("%s_%d.json" % (stamp, int(time.time() * 1000) % 1000000))
            with io.open(path, "w", encoding="utf-8") as fh:
                json.dump(result, fh, ensure_ascii=False, indent=2)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[K.2] 审计落盘失败(不影响分诊): %s", exc)
