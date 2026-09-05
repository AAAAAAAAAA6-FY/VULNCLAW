# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

# code/graph.py
"""
SP16.3 / SP17.2 调用链上下文（轻量符号索引 + 跨文件 import 展开）

痛点对照：semgrep/codeql 报"第 N 行可能注入"，但该危险函数是否被外部
请求可达（request handler -> ... -> sink）语义缺失——这是"扫文件"与
"懂上下文"的分水岭。前沿（Greptile/SweepAI）用调用图（Call Graph）+
AST 做跨文件追踪。

本模块做渐进式落地（成本优先）：
1) symbol_index(paths) -> {rel_file: {symbol: {"line": n, "decorators": str}}}：
   tree-sitter 可用时用 AST 定义表（更准），缺失/失败自动降级纯 stdlib
   正则索引（def/async def 定义 + 紧邻装饰器行）；
2) entry_reachability(finding, index, graph=None, cross=None)：同文件调用链
   BFS（缺省，与旧版完全一致）；跨文件调用图 BFS（cross 传入时），从 finding
   行的宿主函数出发回溯/前向，命中典型入口形态（@app.route/@bp.get/handler/
   view/main 等）即 reachable；解析不到一律 unknown（低误报铁律）。
3) 跨文件（SP17.2）：import_index(paths) 解析 import/from 语句；
   build_cross_graph(paths) 构建跨文件调用图（module.func 形态）；BFS 支持
   把 "module.func" 调用点解析到具体文件的目标函数继续展开；enrich_findings
   提供 use_cross 开关。

开关：settings.scan_callgraph（默认 False，零行为回归）。
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

# ---- SP17.2 跨文件 import 解析（纯 stdlib 正则）----
# 不使用 AST 的原因：跨文件场景下 tree-sitter 定义表已足够支撑调用链展开，
# import 语句本身是简单、规律的语法（import/from ... import），正则即可稳定
# 解析，且避免对每个文件做 AST 解析的开销与失败分支——保持扫描大代码库的
# 轻量与零三方依赖原则。
# import X / import X as Y / import a, b as c
_IMPORT_RE = re.compile(r"^\s*import\s+(.+?)(?:\s*#.*)?$")
# from X import a   （X 为绝对点分模块，如 core.config）
_FROM_ABS_RE = re.compile(r"^\s*from\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s+import\s+(.+?)(?:\s*#.*)?$")
# from . import a / from .. import b / from .mod import name（相对）
_FROM_REL_RE = re.compile(r"^\s*from\s+(\.[A-Za-z_.]*)\s+import\s+(.+?)(?:\s*#.*)?$")
# 单条 import 目标中的 "mod as alias"
_AS_RE = re.compile(r"^([\w.]+)\s+as\s+(\w+)\s*$")
# 跨文件限定调用形态：module.func(
_QFUNC_RE = re.compile(r"([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*\(")


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


# ======================= SP17.2 跨文件 import 展开 =======================

def _file_module_name(abs_path: str) -> str:
    """从路径推导模块名（含包路径）：helper.py -> helper；pkg/core/config.py -> pkg.core.config。"""
    stem = os.path.splitext(os.path.basename(abs_path))[0]
    parts: list[str] = []
    d = os.path.dirname(abs_path)
    if not stem or stem == "__init__":
        parts.insert(0, os.path.basename(d))
        d = os.path.dirname(d)
    else:
        parts.insert(0, stem)
    while os.path.isfile(os.path.join(d, "__init__.py")):
        parts.insert(0, os.path.basename(d))
        d = os.path.dirname(d)
    return ".".join(parts)


def _module_file(base_dir: str, mod_tail: str) -> str | None:
    """在 base_dir 下定位模块 tail（点分）对应文件：tail.py 或 tail/__init__.py。"""
    if not mod_tail:
        return None
    p = os.path.join(base_dir, *mod_tail.split("."))
    if os.path.isfile(p + ".py"):
        return p + ".py"
    ini = os.path.join(p, "__init__.py")
    if os.path.isfile(ini):
        return ini
    return None


def _pkg_chain(importer_abs: str) -> tuple[list[str], list[str]]:
    """返回 importer 所在包的（模块名段列表, 对应目录列表），由内向外（含叶包）。"""
    parts: list[str] = []
    dirs: list[str] = []
    d = os.path.dirname(importer_abs)
    while os.path.isfile(os.path.join(d, "__init__.py")):
        parts.insert(0, os.path.basename(d))
        dirs.insert(0, d)
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return parts, dirs


def _relative_target(rel: str, parts: list[str], dirs: list[str]) -> tuple[str, str, str] | None:
    """拆分相对导入 'rel'（'.'/'..'/'.mod'/'..pkg.mod'）为 (包模块名前缀, 查找目录, 模块尾路径)。

    Python 语义：'.' 指当前包，'..' 指向上 N-1 层的包，模块尾路径再追加其后。
    超出包根（解析不到）返回 None。
    """
    dots = 0
    i = 0
    while i < len(rel) and rel[i] == ".":
        dots += 1
        i += 1
    tail = rel[i:]
    head_len = len(parts) - (dots - 1)
    if head_len < 1 or head_len > len(parts):
        return None  # 超出包根或向上越界
    return ".".join(parts[:head_len]), dirs[head_len - 1], tail


def _split_import_specs(seg: str) -> list[str]:
    """拆 'import a, b as c' 为 ['a', 'b as c']（宽松处理）。"""
    return [s.strip() for s in seg.split(",") if s.strip()]


def _split_import_names(seg: str) -> list[str]:
    """拆 'from X import a, b' / 'from X import (a, b)' 的目标名列表。"""
    seg = seg.strip()
    if seg.startswith("("):
        seg = seg.strip("()")
    return [s.strip().split(" as ")[0].strip() for s in seg.split(",") if s.strip()]


def _resolve_absolute(modpath: str, start_dir: str) -> str | None:
    """绝对点分模块 'X' / 'a.b.c' 向上锚定解析到文件（解析不到返回 None）。"""
    d = start_dir
    while True:
        f = _module_file(d, modpath)
        if f:
            return f
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


def import_index(paths: list[str]) -> dict[str, str]:
    """解析 python import 语句 -> {被导入模块名(module_key), 绝对路径}。

    支持：import X / import X as Y / from X import a / from . import a /
    from .mod import name。绝对导入按导入文件所在目录向上锚定解析；相对导入按
    同包路径解析；解析不到即跳过（不参与跨文件判定，保守）。module_key 如
    "requests"/"vulnclaw.core.logger"/"core.config"。
    """
    out: dict[str, str] = {}
    for abs_path in _walk_py(paths):
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as _rf:
                text = _rf.read()
        except OSError:
            continue
        fdir = os.path.dirname(abs_path)
        parts, dirs = _pkg_chain(abs_path)
        for line in text.splitlines():
            ls = line.split("#", 1)[0].strip()
            m = _IMPORT_RE.match(ls)
            if m:
                for spec in _split_import_specs(m.group(1)):
                    am = _AS_RE.match(spec)
                    if am:
                        modpath, alias = am.group(1), am.group(2)
                        f = _resolve_absolute(modpath, fdir)
                        if f:
                            out[modpath] = f
                            out[alias] = f
                            out.setdefault(modpath.split(".")[0], f)
                    else:
                        f = _resolve_absolute(spec, fdir)
                        if f:
                            out[spec] = f
                            out.setdefault(spec.split(".")[0], f)
                continue
            m = _FROM_ABS_RE.match(ls)
            if m:
                modpath = m.group(1)
                f = _resolve_absolute(modpath, fdir)
                if f:
                    out[modpath] = f
                continue
            m = _FROM_REL_RE.match(ls)
            if m:
                rel = m.group(1)
                rt = _relative_target(rel, parts, dirs)
                if rt is None:
                    continue
                base_mod, base_dir, tail = rt
                if tail:
                    # '.mod' 等：记录被导入模块自身
                    tf = _module_file(base_dir, tail)
                    if tf:
                        out.setdefault(f"{base_mod}.{tail}", tf)
                        out.setdefault(tail.split(".")[-1], tf)
                for nm in _split_import_names(m.group(2)):
                    f = _module_file(base_dir, nm)
                    if f:
                        out.setdefault(nm, f)
                        out.setdefault(f"{base_mod}.{nm}", f)
    return out


def build_cross_graph(paths: list[str], use_tree_sitter: bool = True) -> dict[str, dict[str, set]]:
    """在 symbol_index 基础上补 import 展开，构建跨文件调用图。

    file_abs -> {func: set[called]}。同文件调用记为裸函数名；跨文件调用（如
    logging.info、utils.helper）记录为 "module.func" 形式。用正则收集文本中
    "identifier.identifier(" 形态，用 import_index 判断 identifier 是否命中
    已解析模块且该模块被索引（目标函数真实存在才记录，避免误连）。

    记录的 module 取目标文件的规范模块名（_file_module_name），保证与
    entry_reachability 的 BFS 反解一致（import helper as h 后 h.func 记为
    helper.func）。
    """
    index = symbol_index(paths, use_tree_sitter=use_tree_sitter)
    mods = import_index(paths)
    indexed: set[str] = set(index.keys())
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
            calls = _calls_in_region(body, 0, len(body))
            for line in body:
                for modid, fid in _QFUNC_RE.findall(line):
                    target = mods.get(modid)
                    # 仅当命中已解析模块、模块被索引且目标函数真实存在（跨文件）才记录
                    if target and target in indexed and fid in (index[target] or {}):
                        calls.add(f"{_file_module_name(target)}.{fid}")
            file_graph[name] = calls
        graph[abs_path] = file_graph
    return graph


def _is_qualified_token(callee: str) -> bool:
    """判断调用 token 是否跨文件限定形态（module.func）。"""
    return "." in callee


def entry_reachability(finding: dict, index: dict[str, dict[str, dict]], graph: dict[str, dict[str, set]] | None = None, cross: dict | None = None) -> str:
    """判定 finding 的 sink 宿主函数是否可达入口（同文件或跨文件）。

    返回值：
      reachable   宿主函数本身是入口，或可经调用链到达某入口
      unreachable 调用链找不到任何入口（保守：明确排除外部可达）
      unknown     索引缺失/宿主函数无法定位/跨文件解析不到（不参与判定）

    参数：
      graph  同文件调用图（legacy）；cross=None 时行为与旧版完全一致。
      cross  build_cross_graph 产物；传入时 BFS 支持将 "module.func" 调用点
             解析到具体文件的目标函数继续展开；解析不到一律 unknown（低误报）。
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

    if cross is None:
        # ===== legacy 同文件路径（保持完全一致）=====
        if graph is None:
            graph = _call_graph({abs_path: defs})
        file_graph = graph.get(abs_path) or {}
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

    # ===== 跨文件路径：BFS 节点 (file, def)，支持 module.func 继续展开 =====
    # 宿主文件不在跨文件图中（跨文件解析不到）-> unknown，不新增误报
    if abs_path not in cross:
        return "unknown"
    # 规范模块名 -> 文件集：把 "module.func" 反解到具体文件的目标函数
    mod2files: dict[str, set] = {}
    for f2 in cross:
        mod2files.setdefault(_file_module_name(f2), set()).add(f2)
    reverse_in: dict[str, dict[str, set]] = {}
    reverse_x: dict[str, dict[str, set]] = {}
    for fpath, fg in cross.items():
        for caller, callees in fg.items():
            for callee in callees:
                if _is_qualified_token(callee):
                    modid, _, fid = callee.rpartition(".")
                    for target in mod2files.get(modid, set()):
                        tdefs = index.get(target)
                        if tdefs and fid in tdefs:
                            reverse_x.setdefault(target, {}).setdefault(fid, set()).add((fpath, caller))
                else:
                    reverse_in.setdefault(fpath, {}).setdefault(callee, set()).add(caller)

    frontier = {(abs_path, host)}
    seen = {(abs_path, host)}
    while frontier:
        fpath, cur = frontier.pop()
        fdefs = index.get(fpath)
        if not fdefs or cur not in fdefs:
            continue
        if _is_entry(cur, fdefs[cur]):
            return "reachable"
        for caller in (reverse_in.get(fpath) or {}).get(cur, set()):
            node = (fpath, caller)
            if node not in seen:
                seen.add(node)
                frontier.add(node)
        for node in (reverse_x.get(fpath) or {}).get(cur, set()):
            if node not in seen:
                seen.add(node)
                frontier.add(node)
    return "unreachable"


def enrich_findings(findings: list[dict], paths: list[str], use_tree_sitter: bool = True, use_cross: bool = False) -> list[dict]:
    """对 findings 批量附加 reachability 字段（副本语义，不修改入参；unknown 不写字段）。

    use_cross=True 时内部构建 import_index + build_cross_graph 做跨文件可达性
    （默认 False 保持旧版同文件行为）。
    """
    if not findings or not paths:
        return list(findings)
    try:
        index = symbol_index(paths, use_tree_sitter=use_tree_sitter)
        if use_cross:
            graph = build_cross_graph(paths, use_tree_sitter=use_tree_sitter)
            kw = {"cross": graph}
        else:
            graph = _call_graph(index)
            kw = {"graph": graph}
    except Exception:  # noqa: BLE001 - 索引失败降级为不写字段
        return list(findings)
    out = []
    for f in findings:
        f2 = dict(f)
        try:
            r = entry_reachability(f2, index, **kw)
            if r != "unknown":
                f2["reachability"] = r
        except Exception:  # noqa: BLE001
            logger.debug("[SP16.3] reachability 判定异常，跳过: %s", str(f.get("file") or f.get("abs_path") or ""))
        out.append(f2)
    return out


__all__ = [
    "TREE_SITTER_AVAILABLE",
    "build_cross_graph",
    "enrich_findings",
    "entry_reachability",
    "import_index",
    "is_source_file",
    "symbol_index",
]