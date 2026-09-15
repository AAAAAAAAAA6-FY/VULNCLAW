# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""B6 端到端验收：MEGA(8092) 全量验收。

四条验收线（全部直连本地靶机，绕过 AI 编排，零 LLM 调用）：
  1. 输入洞声明线（SpecRunner 直跑 10 端点；硬判 8 原口径 + lfi/cmdi 附加）
  2. 负样本零误报（/safe /__baseline__ 上全声明 0 命中）
  3. 逻辑洞 B3 剧本线（PlaybookEngine 本地标注 4 个 /logic/vuln/* 端点，覆盖 >=3）
  4. 收敛门（剧本 finding 未 verify 背书 -> 全部降 Info 进 pending_review 桶可追溯）

达标度量表输出：输入洞命中率 / 逻辑洞覆盖 / 负样本误报 / 收敛门降级 / 不变量通过率。
用法: venv\Scripts\python scripts\verify_b6_acceptance.py   （前提：mega_lab.py 已在 8092 运行）
"""
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from unittest.mock import AsyncMock, patch  # noqa: E402

BASE = "http://127.0.0.1:8092"

# 输入洞声明线（url -> 评估声明）。8 原口径（HANDOFF 8/8）为硬判，lfi/cmdi 附加。
INPUT_LINE = {
    "/xss?s=hello": ["xss_reflect"],
    "/sqli?id=1": ["sql_error"],
    "/ssti?name=hello": ["ssti"],
    "/lfi?file=../../etc/passwd": ["lfi"],
    "/cmdi?cmd=whoami": ["cmd_injection"],
    "/nosql?q=1": ["nosql_injection"],
    "/ldap?user=admin": ["ldap_injection"],
    "/redirect?next=home": ["open_redirect"],
    "/cors": ["cors_misconfig"],
    "/deser?data=x": ["java_deserialization"],
}
# HANDOFF 8/8 原口径：过收敛硬判的最小必需命中集合
# lfi/cmdi：builtin 声明匹配 Linux 特征（root:x//uid=），Windows 靶场模板回显无法命中，标平台差异 NA（非回归）
NA_PLATFORM = {"/lfi?file=../../etc/passwd", "/cmdi?cmd=whoami"}
HARD_REQUIRE = {"/xss?s=hello", "/sqli?id=1", "/ssti?name=hello", "/nosql?q=1",
                "/ldap?user=admin", "/redirect?next=home", "/cors", "/deser?data=x"}
NEGATIVE = ["/safe", "/__baseline__"]

# 逻辑洞 B3 剧本线（MEGA 逻辑洞端点）
LOGIC_LINE = [
    "/logic/vuln/reset?token=T&user=bob",
    "/logic/vuln/charge?amt=-5",
    "/logic/vuln/coupon?code=C",
    "/logic/vuln/pay?oid=1",
]
MIN_LOGIC_COVER = 3  # TASKLIST：逻辑洞 3/3


def log(msg):
    print(f"[B6] {msg}", flush=True)


async def alive() -> bool:
    from vulnclaw.core.utils import async_get
    try:
        resp = await async_get(BASE, timeout=5)
        return bool(resp and resp[0] in (200, 403))
    except Exception:  # noqa: BLE001
        return False


async def run_input_line() -> dict:
    """声明线：逐端点直跑，返回 命中集合 / 全部集合 / finding 列表。"""
    from vulnclaw.core.attack_surface import spec_from_url
    from vulnclaw.core.vulnspec import SpecRunner, get_spec
    hits, findings = {}, []
    for path, spec_ids in INPUT_LINE.items():
        specs = [get_spec(s) for s in spec_ids if get_spec(s)]
        if not specs:
            hits[path] = ("no-spec", [])
            continue
        runner = SpecRunner(specs=specs, timeout=8)
        try:
            out = await runner.run(spec_from_url(BASE + path), budget=12)
        except Exception as exc:  # noqa: BLE001
            log(f"  输入洞 {path} 执行异常: {exc}")
            out = []
        hits[path] = ("hit" if out else "miss", [f.get("id") or f.get("type") for f in out])
        findings.extend(out)
    return hits, findings


async def run_negative() -> tuple:
    from vulnclaw.core.attack_surface import spec_from_url
    from vulnclaw.core.vulnspec import SpecRunner, get_spec
    all_specs = [get_spec(s) for s in (
        "xss_reflect", "sql_error", "ssti", "lfi", "cmd_injection",
        "nosql_injection", "ldap_injection", "open_redirect",
        "cors_misconfig", "java_deserialization")]
    all_specs = [s for s in all_specs if s]
    total = 0
    for path in NEGATIVE:
        runner = SpecRunner(specs=all_specs, timeout=8)
        out = await runner.run(spec_from_url(BASE + path), budget=30)
        total += len(out)
    return total, NEGATIVE


async def run_logic_line() -> tuple:
    """B3 剧本线：本地标注 -> 剧本 -> 执行差分。返回 (findings, books, 覆盖端点)。"""
    from vulnclaw.engines.playbook_engine import PlaybookEngine
    brief = {
        "crawled_endpoints": [BASE + p for p in LOGIC_LINE],
        "js_endpoints": [], "apis": [], "forms": [], "url_params": [],
    }
    eng = PlaybookEngine(timeout=8)
    with patch("vulnclaw.engines.playbook_engine._annotate_features_llm",
               new=AsyncMock(return_value=[])):
        books = await eng.generate_playbooks(brief, BASE)
    if not books:
        return [], [], set()
    findings = []
    for b in books:
        try:
            f = await eng.execute(b, budget_s=25)
            if f:
                findings.append(f)
        except Exception as exc:  # noqa: BLE001
            log(f"  剧本 {b.id if hasattr(b, 'id') else '?'} 执行异常: {exc}")
    covered = {f["url"].split("?")[0].replace(BASE, "") for f in findings}
    return findings, books, covered


def run_convergence_gate(findings: list) -> dict:
    """收敛门空壳：verify 未背书（ai_verdict=待验证）-> 全落 pending_review / Info。"""
    from vulnclaw.ai.v100.orchestrator import V100Orchestrator
    if not findings:
        return {"n_endorsed": 0, "n_downgraded": 0, "n_pending": 0}
    fcards = [dict(f) for f in findings]
    for f in fcards:
        f["verdict"] = V100Orchestrator._classify_finding_verdict(f)
    o = V100Orchestrator.__new__(V100Orchestrator)
    o.findings = fcards
    o._pending_review = []
    V100Orchestrator._apply_final_review_gate(o)
    pending = [f for f in o.findings if f.get("verdict") == "pending_review"]
    return {
        "n_endorsed": sum(1 for f in o.findings if f.get("verdict") not in ("pending_review",)),
        "n_downgraded": len(pending),
        "n_pending": len(o._pending_review),
        "sample": [{"url": f.get("url"), "original_severity": f.get("original_severity"),
                    "ai_verdict": f.get("ai_verdict")} for f in pending[:3]],
    }


async def main() -> int:
    t0 = time.time()
    log(f"MEGA 验收启动（{BASE}）")
    if not await alive():
        log("ERROR: MEGA(8092) 未存活。请先运行: python scripts/mega_lab.py")
        return 2

    # 1) 输入洞
    log("== 输入洞（声明线）==")
    hits, ifindings = await run_input_line()
    for path, (st, ids) in hits.items():
        log(f"  {st.upper():6s}  {path}  {ids}")
    hard_hit = {p for p, (st, _) in hits.items() if st == "hit"}
    hard_pass = HARD_REQUIRE <= hard_hit

    # 2) 负样本
    log("== 负样本零误报 ==")
    neg_total, _ = await run_negative()
    log(f"  /safe /__baseline__ 全声明命中合计: {neg_total}")

    # 3) 逻辑洞
    log("== 逻辑洞（B3 剧本线）==")
    lfinds, books, covered = await run_logic_line()
    for f in lfinds:
        pb = f.get("playbook") or {}
        log(f"  FIND  {f.get('url','')} | {f.get('title','')} | sev={f.get('severity')} "
            f"n_violations={pb.get('n_violations', '?')}")
    log(f"  剧本 {len(books)} 本，命中 finding {len(lfinds)} 条，覆盖端点: {sorted(covered)}")
    logic_pass = len(covered) >= MIN_LOGIC_COVER

    # 4) 收敛门
    log("== 收敛门（未背书 -> pending_review）==")
    gate = run_convergence_gate(lfinds)
    log(f"  剧本 finding {len(lfinds)} 条：背书 {gate['n_endorsed']} / 降级 {gate['n_downgraded']} / 入桶 {gate['n_pending']}")
    for s in gate.get("sample", []):
        log(f"    -> {s['url']} ({s['original_severity']} -> Info, ai_verdict={s['ai_verdict']!r})")
    gate_pass = len(lfinds) == 0 or (gate["n_downgraded"] == len(lfinds) and gate["n_pending"] == len(lfinds))

    # 5) 度量表
    total = len(hits)
    hit_n = len(hard_hit & HARD_REQUIRE)
    n_inv = sum((f.get("playbook") or {}).get("n_violations", 0) for f in lfinds)
    print()
    print("================ B6 达标度量表 ================")
    print(f"  输入洞 8 原口径      : {hit_n}/8  ({'PASS' if hard_pass else 'FAIL'})")
    print(f"  逻辑洞端点覆盖       : {len(covered)}/4  ({'PASS' if logic_pass else 'FAIL'})")
    print(f"  负样本误报           : {neg_total}  ({'PASS' if neg_total == 0 else 'FAIL'})")
    print(f"  收敛门未背书降级     : {gate['n_downgraded']}/{len(lfinds)}  ({'PASS' if gate_pass else 'FAIL'})")
    inv_total = sum(getattr(b, "n_violations", None) is not None and 1 or 0 for b in books) if books else 0
    print(f"  不变量违反候选/剧本  : {n_inv}/{len(books)} 差分证实（黑盒，符号证明 NA）")
    print(f"  总耗时               : {time.time() - t0:.1f}s")
    print("=" * 40)
    ok = hard_pass and logic_pass and neg_total == 0 and gate_pass
    print(f"B6 验收结论: {'PASS - MEGA 收敛' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))