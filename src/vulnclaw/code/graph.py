# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

# code/graph.py
"""
SP16.3 调用链上下文（轻量符号索引 + 可选 tree-sitter）

痛点对照：semgrep/codeql 报"第 N 行可能注入"，但该危险函数是否被外部
请求可达（request handler -> ... -> sink）语义缺失——这是"扫文件"与
"懂上下文"的分水岭。前沿（Greptile/SweepAI）用调用图（Call Graph）+
AST 做跨文件追踪。

本模块做渐进式落地（成本优先）：
1) symbol_index(paths) -> {rel_file: {symbol: {"line": n, "decorators": str}}}：
   tree-sitter 可用时用 AST 定义表（更准），缺失/失败自动降级纯 stdlib
   正则索引（def/async def 定义 + 紧邻装饰器行）；
2) entry_reachability(finding, index) -> "reachable"|"unreachable"|"unknown"：
   同文件调用链 BFS：从 finding 行的宿主函数出发回溯/前向，命中典型入口
   形态（@app.route/@bp.get/handler/view/main 等）即 reachable；
   解析不到一律 unknown（不参与判定，不新增误报——低误报铁律）。

开关：settings.scan_callgraph（默认 False，零行为回归）。
跨文件 import 展开留待下一期（本期只做同文件调用链，保守不误报）。
"""
import os
import re

from vulnclaw.core.logger import logger

TREE_SITTER_AVAILABLE = False
try:
    import tree_sitter  # noqa: F401
    TREE_SITTER_AVAILABLE = True
except Exception:  # noqa: BLE001 - 可选依赖缺失视为不可用
    TREE_SITTER_AVAILABLE = False

# 定义行正则（python）：def / async def
_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)
# 装饰器行（紧邻 def 上方）
_DECORATOR_RE = re.compile(r"^\s*(@\S+)", re.MULTILINE)
# 调用点正则：symbol( 出现在文本中
_CALL_RE = re.compile(r"([A-Za-z_]\w*)\s*\(")
# 入口形态启发：def 名或装饰器命中以下关键词即视为外部可达入口
_ENTRY_NAME = re.compile(r"(index|route|handler|handler_hook|view|main|controller|service|callback|api|login|logon|auth|register|send|create|update|delete|post|get|put)", re.IGNORECASE)
_ENTRY_DECORATOR = re.compile(r"(route|blueprint|router|\.(get|post|put|delete|patch|view|app)\b|Flask|FastAPI|aiohttp)", re.IGNORECASE)

_PY_SUFFIX = (".py",)


def is_source_file(path: str) -> bool:
    return isinstance(path, str) and path.endswith(_PY_SUFFIX)


def _walk_py(paths: list[str]) -> list[str] | None:
    """收集候选 python 文件（文件或目录递归）。非源码路径返回空。"""
    out: list[str] = []
    for p in paths or []:
        if not p or not isinstance(p, str):
            continue
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for f in files:
                    if f.endswith(_PY_SUFFIX):
                        out.append(os.path.join(root, f))
        elif os.path.isfile(p) and p.endswith(_PY_SUFFIX):
            out.append(p)
    return out


def _regex_index(paths: list[str]) -> dict[str, dict[str, dict]]:
    """纯 stdlib 降级：按正则提取 def 定义 + 紧邻装饰器（零三方依赖）。"""
    index: dict[str, dict[str, dict]] = {}
    for abs_path in _walk_py(paths):
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as _rf:
                lines = _rf.read().splitlines()
        except OSError:
            continue
        defs: dict[str, dict] = {}
        for i, line in enumerate(lines):
            m = _DEF_RE.match(line)
            if not m:
                continue
            name = m.group(1)
            decorators = ""
            if i > 0:
                dm = _DECORATOR_RE.match(lines[i - 1])
                if dm:
                    decorators = dm.group(1)
            defs[name] = {"line": i + 1, "decorators": decorators}
        if defs:
            index[abs_path] = defs
    return index


def _ts_index(paths: list[str]) -> dict[str, dict[str, dict]] | None:
    """tree-sitter AST 定义表（可选；任何失败返回 None 触发降级）。"""
    if not TREE_SITTER_AVAILABLE:
        return None
    try:
        from tree_sitter import Parser  # type: ignore
        from tree_sitter_languages import get_language  # type: ignore
        lang = get_language("python")
        parser = Parser()
        parser.set_language(lang)
    except Exception:  # noqa: BLE001 - 语法包缺失/失败一律降级
        return None
    index: dict[str, dict[str, dict]] = {}
    for abs_path in _walk_py(paths):
        try:
            with open(abs_path, "rb") as _rb:
                data = _rb.read()
        except OSError:
            continue
        try:
            tree = parser.parse(data)
        except Exception:  # noqa: BLE001
            logger.debug("[SP16.3] tree-sitter parse 失败，跳过: %s", abs_path)
            continue
        defs: dict[str, dict] = {}
        root = tree.root_node
        for node in root.children:
            nt = str(node.type)
            if nt not in ("function_definition", "decorated_definition"):
                continue
            # decorated_definition 的子节点含 decorator + function_definition
            fn_node = node
            decorators = ""
            if nt == "decorated_definition":
                for c in node.children:
                    if str(c.type) == "decorator":
                        snippet = data[c.start_byte:c.end_byte].decode("utf-8", "replace")
                        decorators = (decorators + " " + snippet).strip()
                    elif str(c.type) == "function_definition":
                        fn_node = c
            name_node = None
            for c in fn_node.children:
                if str(c.type) == "identifier":
                    name_node = c
                    break
            if name_node is None:
                continue
            name = data[name_node.start_byte:name_node.end_byte].decode("utf-8", "replace")
            defs[name] = {"line": fn_node.start_point[0] + 1, "decorators": decorators}
        if defs:
            index[abs_path] = defs
    return index


def symbol_index(paths: list[str], use_tree_sitter: bool = True) -> dict[str, dict[str, dict]]:
    """构建符号索引。tree-sitter 优先（use_tree_sitter=True 时），失败自动降级 regex。"""
    ts = None
    if use_tree_sitter:
        ts = _ts_index(paths)
    if ts is not None:
        return ts
    return _regex_index(paths)


def _calls_in_region(lines: list[str], start: int, end: int) -> set:
    """统计文本区间内被调用的函数名集合（宽松：名称后紧跟 '('）。"""
    calls: set = set()
    for line in lines[start:end]:
        for m in _CALL_RE.findall(line):
            calls.add(m)
    return calls


def _call_graph(index: dict[str, dict[str, dict]]) -> dict[str, dict[str, set]]:
    """file -> {def: called_defs}，基于源码区间粗粒度解析（只统计 0 缩进顶层函数体
    难；这里放宽为整个文件区间，命中即相连——宁可多报 reachable 少报 unknown，
    但 reachable 只是证据增强，不影响漏洞判定。"""
    graph: dict[str, dict[str, set]] = {}
    for abs_path, defs in index.items():
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as _rf:
                lines = _rf.read().splitlines()
        except OSError:
            continue
        ordered = sorted(defs.items(), key=lambda kv: kv[1]["line"])
        file_graph: dict[str, set] = {}
        for name, info in ordered:
            start = info["line"] - 1
            nxt = next((it[1]["line"] - 1 for it in ordered if it[1]["line"] > info["line"]), len(lines))
            body = lines[start + 1:min(nxt + 1, len(lines))] if start + 1 < len(lines) else []
            file_graph[name] = _calls_in_region(body, 0, len(body))
        graph[abs_path] = file_graph
    return graph


def _host_def(index: dict[str, dict[str, dict]], abs_path: str, line: int) -> str | None:
    """finding 行所在宿主函数（定义行 <= line 且最接近）。"""
    defs = index.get(abs_path) or {}
    cands = [(n, i["line"]) for n, i in defs.items() if i["line"] <= line]
    if not cands:
        return None
    return max(cands, key=lambda kv: kv[1])[0]


def _is_entry(name: str, info: dict) -> bool:
    d, dec = info.get("decorators", "") or "", str(info.get("decorators", "") or "")
    if _ENTRY_NAME.search(name) is not None:
        return True
    return _ENTRY_DECORATOR.search(d) is not None or _ENTRY_DECORATOR.search(dec) is not None


def entry_reachability(finding: dict, index: dict[str, dict[str, dict]], graph: dict[str, dict[str, set]] | None = None) -> str:
    """判定 finding 的 sink 宿主函数是否同文件可达入口。

    返回值：
      reachable   宿主函数本身是入口，或可经同文件调用链到达某入口
      unreachable 同文件调用链找不到任何入口（保守：明确排除外部可达）
      unknown     索引缺失/宿主函数无法定位（不参与判定）
    """
    if not isinstance(finding, dict):
        return "unknown"
    abs_path = str(finding.get("abs_path") or finding.get("file") or "")
    if not abs_path or not is_source_file(abs_path):
        return "unknown"
    line = int(finding.get("line", 0) or 0)
    if not line:
        return "unknown"
    defs = index.get(abs_path)
    if not defs:
        return "unknown"
    host = _host_def(index, abs_path, line)
    if host is None:
        return "unknown"
    if graph is None:
        graph = _call_graph({abs_path: defs})
    file_graph = graph.get(abs_path) or {}
    # BFS：sink 宿主 -> 反向（被谁调用）。粗粒度图已含全部 def，故直接沿
    # 调用反向可达即可：若存在 入口 def 直接/间接调用 host，即 reachable。
    reverse: dict[str, set] = {}
    for caller, callees in file_graph.items():
        for callee in callees:
            reverse.setdefault(callee, set()).add(caller)
    frontier = {host}
    seen = {host}
    while frontier:
        cur = frontier.pop()
        if _is_entry(cur, defs[cur]):
            return "reachable"
        for caller in reverse.get(cur, set()):
            if caller not in seen:
                seen.add(caller)
                frontier.add(caller)
    return "unreachable"


def enrich_findings(findings: list[dict], paths: list[str], use_tree_sitter: bool = True) -> list[dict]:
    """对 findings 批量附加 reachability 字段（副本语义，不修改入参；unknown 不写字段）。"""
    if not findings or not paths:
        return list(findings)
    try:
        index = symbol_index(paths, use_tree_sitter=use_tree_sitter)
        graph = _call_graph(index)
    except Exception:  # noqa: BLE001 - 索引失败降级为不写字段
        return list(findings)
    out = []
    for f in findings:
        f2 = dict(f)
        try:
            r = entry_reachability(f2, index, graph)
            if r != "unknown":
                f2["reachability"] = r
        except Exception:  # noqa: BLE001
            logger.debug("[SP16.3] reachability 判定异常，跳过: %s", str(f.get("file") or f.get("abs_path") or ""))
        out.append(f2)
    return out


__all__ = [
    "TREE_SITTER_AVAILABLE",
    "enrich_findings",
    "entry_reachability",
    "is_source_file",
    "symbol_index",
]