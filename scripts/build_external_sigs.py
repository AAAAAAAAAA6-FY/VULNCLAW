#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""外部现成知识源 → 声明签名构建器（"别手搓别人已经维护好的东西"）。

三个来源
========
1. **sqlmap `data/xml/errors.xml`** —— 各 DBMS 的报错特征（几百条），
   替代我们手写的十来条 SQL 报错正则。
2. **gitleaks `gitleaks.toml`** —— 密钥/凭证规则（AKIA、私钥、token…），
   这是我们**当前的空白族**：只会找 .env/.git，认不出散落的真实密钥。
3. **Retire.js `jsrepository.json`** —— 上千个前端库的"取版本正则"+影响版本区间，
   与 OSV 互补：OSV 答"这个版本有没有洞"，Retire 答"怎么从 JS 里认出库名和版本"。

降噪设计（关键）
================
外部规则普遍偏宽松，直接全用会误报。本构建器做了三道收敛：
  · gitleaks：只收**带 keywords 的规则**，并把 keyword 做成**前瞻约束**
    （`(?:kw1|kw2)` 必须先出现）——等价于 gitleaks 自己的预过滤，能砍掉大量误报。
  · Retire.js：跳过带 `atOrAbove` 的条目（我们的模型只有单侧上界，用了会超报）。
  · 全部：正则必须能在 Python 里编译通过，编不过就跳过（Go RE2 与 Python re 有差异）。

用法
    python scripts/build_external_sigs.py            # 生成
    python scripts/build_external_sigs.py --stats    # 只看统计
产物
    thirdparty/rules/external_sigs.json（生成物，不入库；缺失时声明退化为手写部分）
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "src"))

from vulnclaw.paths import PROJECT_ROOT  # noqa: E402

RULES_DIR = os.path.join(PROJECT_ROOT, "thirdparty", "rules")
DEFAULT_OUT = os.path.join(RULES_DIR, "external_sigs.json")

SQLMAP_ERRORS = os.path.join(PROJECT_ROOT, "thirdparty", "sqlmap", "data", "xml", "errors.xml")
GITLEAKS_TOML = os.path.join(RULES_DIR, "gitleaks.toml")
RETIRE_JSON = os.path.join(RULES_DIR, "jsrepository.json")

MAX_COMPONENTS_PER_LIB = 3


def _ok_regex(p: str) -> bool:
    """正则必须在 Python 里能编译（跳过 Go/Python 不兼容的写法）。"""
    try:
        re.compile(p)
        return True
    except re.error:
        return False


def build_sql_errors(path: str) -> list:
    """sqlmap errors.xml → SQL 报错正则列表。"""
    if not os.path.isfile(path):
        print(f"[sig] 跳过 SQL 报错：缺少 {os.path.basename(path)}")
        return []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as e:
        print(f"[sig] SQL 报错解析失败：{e}")
        return []
    pats = []
    for dbms in root.findall("dbms"):
        for err in dbms.findall("error"):
            r = err.get("regexp")
            if r and _ok_regex(r):
                pats.append(r)
    # 去重保序
    return list(dict.fromkeys(pats))


def build_secrets(path: str) -> list:
    """gitleaks.toml → 带 keyword 前瞻约束的密钥正则。"""
    if not os.path.isfile(path):
        print(f"[sig] 跳过密钥规则：缺少 {os.path.basename(path)}")
        return []
    try:
        import tomllib
        with open(path, "rb") as fh:
            cfg = tomllib.load(fh)
    except Exception as e:  # noqa: BLE001
        print(f"[sig] gitleaks 解析失败：{type(e).__name__} {e}")
        return []
    out = []
    for rule in cfg.get("rules") or []:
        rx = rule.get("regex")
        kws = rule.get("keywords") or []
        if not rx or not kws or not _ok_regex(rx):
            continue
        kw_alt = "|".join(re.escape(str(k)) for k in kws if str(k).strip())
        if not kw_alt:
            continue
        # 关键词前瞻：等价于 gitleaks 的预过滤，显著降低裸正则的误报
        guarded = rf"(?=[\s\S]*?(?:{kw_alt}))" + rx
        if not _ok_regex(guarded):
            continue
        out.append({"id": str(rule.get("id") or ""), "pattern": guarded})
    return out


# Retire.js 用 §§version§§ 作占位符，必须替换成真正的版本匹配式
_VERSION_RE = r"[0-9][0-9a-zA-Z\-_\.\+]*"
_PLACEHOLDER = "§§version§§"


def _compile_retire_pattern(raw: str):
    """把 Retire 的占位符正则变成可用正则。

    只收**占位符已被括号包住**的写法（`(...§§version§§...)`）——这样我们依赖的
    "第 1 个捕获组 = 版本号"才成立；否则抓错组会把别的内容当版本号比较 → 误报。
    """
    if _PLACEHOLDER not in raw:
        return None
    i = raw.find(_PLACEHOLDER)
    before = raw[:i]
    if not before.endswith("("):
        return None
    pat = raw.replace(_PLACEHOLDER, _VERSION_RE)
    try:
        return re.compile(pat)
    except re.error:
        return None


def _literal_prefix(raw: str) -> str:
    """从正则里还原"字面前缀"，用来造贴近真实的自校验样本。

    例：`/\\*!? jQuery v(§§version§§)` → `/*! jQuery v`
    """
    i = raw.find(_PLACEHOLDER)
    pre = raw[:i]
    if pre.endswith("("):
        pre = pre[:-1]
    # 还原常见转义
    for a, b in ((r"\*", "*"), (r"\.", "."), (r"\$", "$"), (r"\-", "-"),
                 (r"\/", "/"), (r"\\", "\\"), (r"\s", " "), (r"\?", "?"),
                 (r"\(", "("), (r"\)", ")"), (r"\[", "["), (r"\]", "]")):
        pre = pre.replace(a, b)
    # 去掉尾部残留的正则量词（? * + 及其分组）
    while pre and pre[-1] in "?*+":
        pre = pre[:-1]
    return pre


def _selftest_extracts_version(rx, lib: str, raw: str = "", ver: str = "9.9.9") -> bool:
    """自校验：造"长得像"的样本，确认**第 1 捕获组真的能抽出版本号**。

    外部数据不能拿来就用——抽不到正确版本号的正则会直接产出误报，必须挡在构建期。
    样本来源：① 还原出的字面前缀（最贴近真实形态）② 几种常见命名兜底。
    """
    cands = []
    if raw:
        pre = _literal_prefix(raw)
        if pre:
            cands += [pre + ver, pre + ver + ".js", pre + " " + ver]
    cands += (f"{lib} v{ver}", f"{lib}-{ver}.js", f"{lib}-{ver}.min.js",
              f'"{lib}": "{ver}"', f"/{lib}/{ver}/{lib}.js", f"{lib} {ver}")
    for c in cands:
        m = rx.search(c)
        if m and len(m.groups()) >= 1 and m.group(1) == ver:
            return True
    return False


def build_components(path: str) -> list:
    """Retire.js jsrepository.json → 组件签名（库名 + 取版本正则 + 影响上界）。"""
    if not os.path.isfile(path):
        print(f"[sig] 跳过 Retire.js：缺少 {os.path.basename(path)}")
        return []
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        print(f"[sig] Retire.js 解析失败：{type(e).__name__}")
        return []
    sigs, skipped = [], 0
    for lib, meta in data.items():
        if not isinstance(meta, dict):
            continue
        # 跳过上游自带的示例/占位条目（CVE-XXXX-XXXX 之类）——报出来就是误报
        if lib in ("retire-example",) or str(lib).startswith("retire-"):
            continue
        vulns = meta.get("vulnerabilities") or []
        if not vulns:
            continue
        # 只取"最高修复版本"作为上界；带 atOrAbove 的条目跳过（单侧上界模型会超报）
        best, best_cve = None, ""
        for v in vulns:
            if not isinstance(v, dict) or v.get("atOrAbove"):
                continue
            below = str(v.get("below") or "")
            if not below:
                continue
            if best is None or _vtuple(below) > _vtuple(best):
                best = below
                idents = (v.get("identifiers") or {})
                cves = idents.get("CVE") or idents.get("cve") or []
                best_cve = ",".join(str(c) for c in (cves[:1] or []))
        if not best:
            continue
        exts = (meta.get("extractors") or {})
        # filecontent（响应体） + filename（HTML 里常出现 xxx-1.2.3.js）
        pool = list(exts.get("filecontent") or []) + list(exts.get("filename") or [])
        kept = 0
        for ex in pool:
            if kept >= MAX_COMPONENTS_PER_LIB:
                break
            if not isinstance(ex, str):
                continue
            rx = _compile_retire_pattern(ex)
            if rx is None:
                skipped += 1
                continue
            if not _selftest_extracts_version(rx, lib, ex):
                skipped += 1
                continue
            sigs.append({"lib": lib, "pattern": rx.pattern,
                         "vulnerable_below": best, "cve": best_cve})
            kept += 1
    if skipped:
        print(f"[sig] Retire.js 跳过 {skipped} 条（占位符不在捕获组内 / 自校验抽不出版本号）")
    return sigs


def _vtuple(s: str) -> tuple:
    out = []
    for p in str(s).split("."):
        if p.isdigit():
            out.append(int(p))
        else:
            break
    return tuple(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--stats", action="store_true")
    _a = ap.parse_args()

    os.makedirs(RULES_DIR, exist_ok=True)
    sql_errors = build_sql_errors(SQLMAP_ERRORS)
    secrets = build_secrets(GITLEAKS_TOML)
    components = build_components(RETIRE_JSON)

    stats = {"sql_errors": len(sql_errors), "secrets": len(secrets),
             "components": len(components)}
    print("[sig] 统计:", json.dumps(stats, ensure_ascii=False))
    if not any(stats.values()):
        print("[sig] 无可用外部数据 → 不生成（声明退化为手写部分，不会误报）")
        return 2
    if _a.stats:
        return 0

    payload = {"version": 1, "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
               "stats": stats, "sql_errors": sql_errors, "secrets": secrets,
               "components": components}
    with open(_a.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False)
    print(f"[sig] 已写入 {_a.out}（{os.path.getsize(_a.out)/1048576:.2f} MB）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
