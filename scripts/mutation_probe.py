#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""请求侧输入变异探针（纯离线 / 确定性 / 零随机）。

职责：把任意输入字符串按固定维度展开成"变异变体集合"，供
  - tests/test_mutation_fuzzing.py（解析器健壮性 / 规则不被简单绕过 / 资源边界）
  - 手工排查"某个编码形态为什么漏检"

设计铁律
--------
1. **零随机**：不使用 random，不依赖 set/dict 哈希顺序（Python 字符串哈希随
   PYTHONHASHSEED 变化 → 输出顺序会变）。去重统一走 dict 插入序，
   维度生成顺序固定为 FAMILIES 的声明顺序。
2. **零网络**：只做字符串变换，绝不发起请求。
3. **输出稳定**：同一 (input, family, long_len, json_depth) 多次运行必须得到
   逐字节相同的 JSON。
4. **变异必须不等价于原输入**：与输入逐字符相同的变体一律丢弃
   （避免"变异集合"里混入恒等项误导统计）。

变异维度（family → dimension）
-----------------------------
url       URL 编码 / 双重 / 三重、百分号大小写、空格 PLUS 与 %20、逐字节全编码
unicode   NFC/NFD/NFKC、全角、同形字、\\uXXXX 转义、零宽字符、BOM、UTF-8 overlong
boundary  JSON/XML 边界（引号、反斜杠、CDATA、实体嵌套、深层嵌套）、控制字符、空值/超长值
path      路径穿越变体（../、..%2f、....//、..;/、%2e%2e、双编码、overlong、尾点/尾空格）
case      大小写（全大写/全小写/交换/交替/标题）
query     参数顺序（轮转/逆序）、重复参数、空值、纯键、数组记法、分号分隔、参数名大小写、超长值
header    Header 顺序、名称大小写、重复头、obs-fold、非法名称字符、值内 CRLF/NUL、超长值

CLI
---
    python scripts/mutation_probe.py --input "<payload>" --family url
    python scripts/mutation_probe.py --input "a=1&b=2" --family query --pretty
    python scripts/mutation_probe.py --input "<payload>" --family all > variants.json
    python scripts/mutation_probe.py --list-families

退出码：0 正常；2 参数错误（argparse 约定）。
"""
from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from html import escape as _html_escape
from urllib.parse import quote as _quote, urlencode as _urlencode

__all__ = [
    "FAMILIES",
    "DIMENSIONS",
    "mutate",
    "mutate_all",
    "variant_values",
    "summarize",
    "main",
]

# ============================================================
# 常量
# ============================================================
#: family 声明顺序 = 输出顺序（改动会改变 JSON 逐字节结果）
FAMILIES: tuple[str, ...] = ("url", "unicode", "boundary", "path", "case", "query", "header")

#: 维度名清单（文档/自检用；与各 _*_dims 实际产出保持一致）
DIMENSIONS: dict[str, tuple[str, ...]] = {
    "url": (
        "url_encode", "url_encode_double", "url_encode_triple",
        "percent_case_lower", "percent_case_upper", "percent_case_mixed",
        "space_as_plus", "space_as_percent20", "url_encode_all_bytes",
    ),
    "unicode": (
        "unicode_nfd", "unicode_nfkc", "unicode_fullwidth", "unicode_homoglyph",
        "unicode_escape", "unicode_zero_width", "unicode_bom_prefix",
        "unicode_overlong_slash", "unicode_overlong_dot",
    ),
    "boundary": (
        "boundary_empty", "boundary_long", "boundary_nul_suffix", "boundary_nul_infix",
        "boundary_crlf_suffix", "boundary_crlf_infix", "boundary_ctrl_chars",
        "boundary_json_escape", "boundary_json_deep_nest",
        "boundary_xml_cdata", "boundary_xml_cdata_break",
        "boundary_xml_entity", "boundary_xml_entity_nested", "boundary_xml_numeric_entity",
    ),
    "path": (
        "path_traversal_dotdot", "path_traversal_dotdot_encoded_lower",
        "path_traversal_dotdot_encoded_upper", "path_traversal_double_write",
        "path_traversal_semicolon", "path_traversal_encoded_dots",
        "path_traversal_double_encoded", "path_traversal_overlong_utf8",
        "path_traversal_backslash", "path_absolute", "path_double_slash",
        "path_trailing_dot", "path_trailing_space", "path_trailing_nul_ext", "path_unc",
    ),
    "case": (
        "case_upper", "case_lower", "case_swap",
        "case_alternating", "case_alternating_reversed", "case_title",
    ),
    "query": (
        "query_order_rotate_1", "query_order_rotate_2", "query_order_rotate_3",
        "query_order_reversed", "query_duplicate_first", "query_duplicate_all",
        "query_empty_value", "query_key_only", "query_array_suffix",
        "query_index_suffix", "query_semicolon_sep", "query_param_name_upper",
        "query_param_name_fullwidth", "query_long_value",
    ),
    "header": (
        "header_name_lower", "header_name_upper", "header_name_title",
        "header_order_rotate_1", "header_order_reversed", "header_duplicate",
        "header_obs_fold", "header_name_trailing_space", "header_name_underscore",
        "header_value_nul", "header_value_crlf_inject", "header_value_long",
    ),
}

#: 默认"超长值"长度（CLI 可调；测试用更小的值保持快）
DEFAULT_LONG_LEN = 4096
#: 默认 JSON 嵌套深度（同一 key 深度）
DEFAULT_JSON_DEPTH = 64

#: 全角映射区间（ASCII 可见字符 → 全角）
_FULLWIDTH_OFFSET = 0xFEE0
#: 同形字表（拉丁 → 西里尔/希腊），只挑最常被 WAF 归一化差异利用的几个
_HOMOGLYPHS = {
    "a": "\u0430", "c": "\u0441", "e": "\u0435", "o": "\u043e",
    "p": "\u0440", "x": "\u0445", "y": "\u0443", "s": "\u0455",
    "i": "\u0456", "j": "\u0458", "A": "\u0410", "B": "\u0412",
    "C": "\u0421", "E": "\u0415", "H": "\u041d", "K": "\u041a",
    "M": "\u041c", "O": "\u041e", "P": "\u0420", "T": "\u0422",
    "X": "\u0425", "Y": "\u0423",
}
#: 控制字符（NUL/CR/LF 之外的"隐蔽"控制符）
_CTRL_CHARS = tuple(chr(c) for c in (0x01, 0x07, 0x0B, 0x0C, 0x1A, 0x1B, 0x7F))
#: 路径穿越前缀模板 → (dimension 后缀, 前缀串)
_PATH_PREFIXES = (
    ("dotdot", "../"),
    ("dotdot_encoded_lower", "..%2f"),
    ("dotdot_encoded_upper", "..%2F"),
    ("double_write", "....//"),
    ("semicolon", "..;/"),
    ("encoded_dots", "%2e%2e%2f"),
    ("double_encoded", "%252e%252e%252f"),
    ("overlong_utf8", "..%c0%af"),
    ("backslash", "..\\"),
)


# ============================================================
# 工具
# ============================================================
def _percent_case(text: str, upper: bool) -> str:
    """把文本里 `%xx` 的两位十六进制统一成大写/小写。"""
    out = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "%" and i + 2 < n:
            hexpair = text[i + 1:i + 3]
            if all(c in "0123456789abcdefABCDEF" for c in hexpair):
                out.append("%" + (hexpair.upper() if upper else hexpair.lower()))
                i += 3
                continue
        out.append(text[i])
        i += 1
    return "".join(out)


def _percent_case_mixed(text: str) -> str:
    """交替大小写百分号编码（%2F%2f 混排，绕简单小写/大写归一规则）。"""
    out = []
    i = 0
    n = len(text)
    idx = 0
    while i < n:
        if text[i] == "%" and i + 2 < n:
            hexpair = text[i + 1:i + 3]
            if all(c in "0123456789abcdefABCDEF" for c in hexpair):
                out.append("%" + (hexpair.upper() if idx % 2 == 0 else hexpair.lower()))
                idx += 1
                i += 3
                continue
        out.append(text[i])
        i += 1
    return "".join(out)


def _to_fullwidth(text: str) -> str:
    """ASCII 可见字符 → 全角（U+FF01..U+FF5E）。"""
    out = []
    for ch in text:
        code = ord(ch)
        if 0x21 <= code <= 0x7E:
            out.append(chr(code + _FULLWIDTH_OFFSET))
        elif ch == " ":
            out.append("\u3000")
        else:
            out.append(ch)
    return "".join(out)


def _to_homoglyph(text: str) -> str:
    """拉丁字母 → 西里尔/希腊同形字（NFKC 不折叠的那批）。"""
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def _xml_entity_nested(text: str, depth: int = 5) -> str:
    """XML 实体递归放大：&amp;amp;...&lt;payload&gt;（实体炸弹式嵌套）。"""
    body = _html_escape(text, quote=True)
    for _ in range(max(1, depth)):
        body = body.replace("&", "&amp;")
    return body


def _parse_pairs(text: str) -> list[tuple[str, str]]:
    """把文本解析成 [(k, v)] 键值对；无法解析时退化为 [("p", text)]。"""
    if "=" not in text:
        return []
    pairs: list[tuple[str, str]] = []
    for chunk in text.split("&"):
        if not chunk:
            continue
        key, sep, value = chunk.partition("=")
        if not sep:
            pairs.append((key, ""))
        else:
            pairs.append((key, value))
    return pairs


def _fmt_pairs(pairs: list[tuple[str, str]]) -> str:
    """键值对 → 查询串（值按查询串语法做一次转义，保证结果可直接当 URL query 用）。"""
    return _urlencode(pairs, doseq=False)


def _parse_header_lines(text: str) -> list[tuple[str, str]]:
    """把文本解析成 [(Name, Value)]；不含冒号时退化为 [("X-Probe", text)]。"""
    lines = [ln for ln in text.replace("\r\n", "\n").split("\n") if ln.strip()]
    headers: list[tuple[str, str]] = []
    for ln in lines:
        key, sep, value = ln.partition(":")
        if not sep:
            return []
        headers.append((key.strip(), value.strip()))
    return headers


def _fmt_headers(headers: list[tuple[str, str]]) -> str:
    return "\n".join(f"{k}: {v}" for k, v in headers)


# ============================================================
# 各 family 的维度生成器（返回 [(dimension, value)]，顺序固定）
# ============================================================
def _url_dims(text: str, long_len: int, json_depth: int) -> list[tuple[str, str]]:
    enc = _quote(text, safe="")
    double = _quote(enc, safe="")
    triple = _quote(double, safe="")
    all_bytes = "".join(f"%{b:02x}" for b in text.encode("utf-8"))
    return [
        ("url_encode", enc),
        ("url_encode_double", double),
        ("url_encode_triple", triple),
        ("percent_case_lower", _percent_case(text, upper=False)),
        ("percent_case_upper", _percent_case(text, upper=True)),
        ("percent_case_mixed", _percent_case_mixed(text)),
        ("space_as_plus", text.replace(" ", "+")),
        ("space_as_percent20", text.replace(" ", "%20")),
        ("url_encode_all_bytes", all_bytes),
    ]


def _unicode_dims(text: str, long_len: int, json_depth: int) -> list[tuple[str, str]]:
    return [
        ("unicode_nfd", unicodedata.normalize("NFD", text)),
        ("unicode_nfkc", unicodedata.normalize("NFKC", text)),
        ("unicode_fullwidth", _to_fullwidth(text)),
        ("unicode_homoglyph", _to_homoglyph(text)),
        ("unicode_escape", text.encode("unicode_escape").decode("ascii")),
        ("unicode_zero_width", "\u200b".join(text)),
        ("unicode_bom_prefix", "\ufeff" + text),
        ("unicode_overlong_slash", text.replace("/", "%c0%af")),
        ("unicode_overlong_dot", text.replace(".", "%c0%ae")),
    ]


def _boundary_dims(text: str, long_len: int, json_depth: int) -> list[tuple[str, str]]:
    depth = max(1, int(json_depth))
    return [
        ("boundary_empty", ""),
        ("boundary_long", "A" * max(1, int(long_len))),
        ("boundary_nul_suffix", text + "\x00"),
        ("boundary_nul_infix", text.replace(" ", "\x00") if " " in text else "\x00" + text),
        ("boundary_crlf_suffix", text + "\r\n"),
        ("boundary_crlf_infix", text + "\r\nX-Injected: 1"),
        ("boundary_ctrl_chars", text + "".join(_CTRL_CHARS)),
        ("boundary_json_escape", json.dumps(text)[1:-1]),
        ("boundary_json_deep_nest", "[" * depth + text + "]" * depth),
        ("boundary_xml_cdata", f"<![CDATA[{text}]]>"),
        ("boundary_xml_cdata_break", f"<![CDATA[{text}]]>]]>"),
        ("boundary_xml_entity", _html_escape(text, quote=True)),
        ("boundary_xml_entity_nested", _xml_entity_nested(text)),
        ("boundary_xml_numeric_entity", "".join(f"&#{ord(c)};" for c in text) or "&#0;"),
    ]


def _path_dims(text: str, long_len: int, json_depth: int) -> list[tuple[str, str]]:
    rel = (text or "etc/passwd").lstrip("/\\")
    dims: list[tuple[str, str]] = [
        (f"path_traversal_{suffix}", prefix * 4 + rel) for suffix, prefix in _PATH_PREFIXES
    ]
    dims.extend([
        ("path_absolute", "/" + rel),
        ("path_double_slash", "//" + rel),
        ("path_trailing_dot", text + "."),
        ("path_trailing_space", text + " "),
        ("path_trailing_nul_ext", text + "%00.jpg"),
        ("path_unc", "\\\\localhost\\" + rel.replace("/", "\\")),
    ])
    return dims


def _case_dims(text: str, long_len: int, json_depth: int) -> list[tuple[str, str]]:
    return [
        ("case_upper", text.upper()),
        ("case_lower", text.lower()),
        ("case_swap", text.swapcase()),
        ("case_alternating", "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text))),
        ("case_alternating_reversed", "".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(text))),
        ("case_title", text.title()),
    ]


def _query_dims(text: str, long_len: int, json_depth: int) -> list[tuple[str, str]]:
    pairs = _parse_pairs(text) or [("p", text)]
    dims: list[tuple[str, str]] = []
    for i in range(1, 4):
        if len(pairs) > i:
            dims.append((f"query_order_rotate_{i}", _fmt_pairs(pairs[i:] + pairs[:i])))
    if len(pairs) >= 2:
        dims.append(("query_order_reversed", _fmt_pairs(list(reversed(pairs)))))
    dims.extend([
        ("query_duplicate_first", _fmt_pairs(pairs + [pairs[0]])),
        ("query_duplicate_all", _fmt_pairs(pairs + pairs)),
        ("query_empty_value", _fmt_pairs([(k, "") for k, _ in pairs])),
        ("query_key_only", "&".join(k for k, _ in pairs)),
        ("query_array_suffix", _fmt_pairs([(k + "[]", v) for k, v in pairs])),
        ("query_index_suffix", _fmt_pairs([(f"{k}[0]", v) for k, v in pairs])),
        ("query_semicolon_sep", ";".join(f"{k}={v}" for k, v in pairs)),
        ("query_param_name_upper", _fmt_pairs([(k.upper(), v) for k, v in pairs])),
        ("query_param_name_fullwidth", "&".join(f"{_to_fullwidth(k)}={v}" for k, v in pairs)),
        ("query_long_value", _fmt_pairs([(pairs[0][0], "A" * max(1, int(long_len)))] + pairs[1:])),
    ])
    return dims


def _header_dims(text: str, long_len: int, json_depth: int) -> list[tuple[str, str]]:
    headers = _parse_header_lines(text) or [("X-Probe", text)]
    dims: list[tuple[str, str]] = [
        ("header_name_lower", _fmt_headers([(k.lower(), v) for k, v in headers])),
        ("header_name_upper", _fmt_headers([(k.upper(), v) for k, v in headers])),
        ("header_name_title", _fmt_headers([(k.title(), v) for k, v in headers])),
    ]
    if len(headers) > 1:
        dims.append(("header_order_rotate_1", _fmt_headers(headers[1:] + headers[:1])))
        dims.append(("header_order_reversed", _fmt_headers(list(reversed(headers)))))
    first_k, first_v = headers[0]
    dims.extend([
        ("header_duplicate", _fmt_headers(headers + [(first_k, first_v)])),
        ("header_obs_fold", _fmt_headers([(k, v.replace(" ", "\r\n ")) for k, v in headers])),
        ("header_name_trailing_space", _fmt_headers([(k + " ", v) for k, v in headers])),
        ("header_name_underscore", _fmt_headers([(k.replace("-", "_"), v) for k, v in headers])),
        ("header_value_nul", _fmt_headers([(k, v + "\x00") for k, v in headers])),
        ("header_value_crlf_inject", _fmt_headers([(k, v + "\r\nX-Injected: 1") for k, v in headers])),
        ("header_value_long", _fmt_headers([(first_k, "A" * max(1, int(long_len)))] + headers[1:])),
    ])
    return dims


_DIM_FUNCS = {
    "url": _url_dims,
    "unicode": _unicode_dims,
    "boundary": _boundary_dims,
    "path": _path_dims,
    "case": _case_dims,
    "query": _query_dims,
    "header": _header_dims,
}


# ============================================================
# 公共 API
# ============================================================
def _resolve_families(families) -> list[str]:
    """归一化 family 入参（支持 "all" / 单串 / 可迭代），返回按 FAMILIES 顺序去重的列表。"""
    if families is None:
        return list(FAMILIES)
    if isinstance(families, str):
        families = [families]
    wanted = {str(f).strip().lower() for f in families if str(f).strip()}
    if "all" in wanted or "*" in wanted:
        return list(FAMILIES)
    unknown = wanted - set(FAMILIES)
    if unknown:
        raise ValueError(
            f"未知 family: {sorted(unknown)}；可选: {', '.join(FAMILIES)} 或 all"
        )
    return [f for f in FAMILIES if f in wanted]


def mutate(
    text: str,
    families=("all",),
    *,
    long_len: int = DEFAULT_LONG_LEN,
    json_depth: int = DEFAULT_JSON_DEPTH,
) -> list[dict]:
    """生成变异变体。

    返回 ``[{"family": ..., "dimension": ..., "value": ...}, ...]``，
    顺序固定（family 声明序 + 维度声明序），并按 value 去重（保留首个）。
    与 ``text`` 逐字符相同的变体一律丢弃。
    """
    text = "" if text is None else str(text)
    fams = _resolve_families(families)
    seen: dict[str, dict] = {}
    for fam in fams:
        try:
            produced = _DIM_FUNCS[fam](text, long_len, json_depth)
        except Exception as exc:  # 单个 family 失败不影响其余（探针必须永不炸）
            seen.setdefault(
                f"__error__::{fam}",
                {"family": fam, "dimension": "__error__", "value": "", "error": str(exc)},
            )
            continue
        for dimension, value in produced:
            if value == text:
                continue
            seen.setdefault(
                str(value),
                {"family": fam, "dimension": dimension, "value": str(value)},
            )
    return [v for k, v in seen.items() if not k.startswith("__error__")] + [
        v for k, v in seen.items() if k.startswith("__error__")
    ]


def mutate_all(
    text: str,
    *,
    long_len: int = DEFAULT_LONG_LEN,
    json_depth: int = DEFAULT_JSON_DEPTH,
) -> list[dict]:
    """等价于 ``mutate(text, "all")`` 的便捷入口。"""
    return mutate(text, ("all",), long_len=long_len, json_depth=json_depth)


def variant_values(text: str, families=("all",), **kwargs) -> list[str]:
    """只取值字符串的便捷入口（测试主要用它构造语料）。"""
    return [v["value"] for v in mutate(text, families, **kwargs)]


def summarize(variants: list[dict]) -> dict:
    """按 family 统计维度/变体数量（供文档与自检使用）。"""
    per_family: dict[str, dict] = {}
    for fam in FAMILIES:
        per_family[fam] = {"count": 0, "dimensions": []}
    for v in variants:
        bucket = per_family.setdefault(v["family"], {"count": 0, "dimensions": []})
        bucket["count"] += 1
        if v["dimension"] not in bucket["dimensions"]:
            bucket["dimensions"].append(v["dimension"])
    return per_family


# ============================================================
# CLI
# ============================================================
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mutation_probe",
        description="请求侧输入变异探针（纯离线 / 确定性）：输出 JSON 变体列表。",
        epilog="示例：python scripts/mutation_probe.py --input \"' OR 1=1--\" --family url --pretty",
    )
    parser.add_argument("--input", "-i", default=None, help="待变异的原始输入（payload / 查询串 / header 串）")
    parser.add_argument(
        "--family", "-f", default="all",
        help=f"变异族：{'|'.join(FAMILIES)}|all（默认 all）",
    )
    parser.add_argument("--long-len", type=int, default=DEFAULT_LONG_LEN,
                        help=f"\"超长值\"维度的长度（默认 {DEFAULT_LONG_LEN}）")
    parser.add_argument("--json-depth", type=int, default=DEFAULT_JSON_DEPTH,
                        help=f"JSON 深层嵌套维度的深度（默认 {DEFAULT_JSON_DEPTH}）")
    parser.add_argument("--pretty", action="store_true", help="JSON 缩进输出")
    parser.add_argument("--summary", action="store_true", help="附加按 family 的维度统计")
    parser.add_argument("--list-families", action="store_true", help="只列出 family 与维度清单")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Windows 控制台默认 GBK，中文/特殊字符会炸 → 强制 utf-8
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - 非 TTY / 旧解释器
        pass

    if args.list_families:
        payload = {
            "families": [
                {"family": fam, "dimensions": list(DIMENSIONS.get(fam, ()))}
                for fam in FAMILIES
            ]
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None))
        return 0

    if args.input is None:
        parser.error("缺少 --input（或用 --list-families 查看维度清单）")

    try:
        families = _resolve_families(args.family)
    except ValueError as exc:
        parser.error(str(exc))

    variants = mutate(
        args.input,
        families,
        long_len=max(1, args.long_len),
        json_depth=max(1, args.json_depth),
    )
    payload: dict = {
        "input": args.input,
        "family": args.family,
        "families": families,
        "count": len(variants),
        "variants": variants,
    }
    if args.summary:
        payload["summary"] = summarize(variants)
    print(json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
