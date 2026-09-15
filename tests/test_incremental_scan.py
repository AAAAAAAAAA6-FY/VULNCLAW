# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""C3 验收：增量扫描与基线比较（core/baseline.py，纯离线确定性）。

覆盖：
  1. 指纹（确定性 / 排序稳定 / fail-closed）；
  2. 基线保存-加载 round-trip；
  3. compare 的 added / fixed / removed / changed / unchanged / reopened 判定；
  4. surface diff（资产 / 路由 / 参数 / 响应 / 引擎）；
  5. fail-closed 降级（current 坏 → 空 diff；baseline 坏 → 全量 added）；
  6. **核心等价性**：增量结果 ∪ 基线 ≈ 全量重扫结论（可执行形式）；
  7. 已知陷阱固化：部分扫描直接 compare 会把未扫范围的 finding 判 fixed
     —— 必须先用基线补齐未扫部分（见 test_merged_incremental_equals_full_rescan）。
"""
import pytest

from vulnclaw.core.baseline import (
    compare_with_baseline,
    default_baseline_path,
    diff_has_changes,
    diff_summary_text,
    fingerprint_scan,
    load_baseline,
    save_baseline,
)

BASE_TARGET = "http://app.example"


def _finding(url, vtype, parameter="id", status="", severity="High"):
    f = {"url": url, "type": vtype, "parameter": parameter, "severity": severity}
    if status:
        f["status"] = status
    return f


def _scan(target, *findings, **extra):
    return {"target": target, "vulnerabilities": list(findings), **extra}


def _fids(items):
    return {it.get("finding_id") for it in (items or [])}


# ============================================================
# 1. 指纹
# ============================================================
class TestFingerprint:
    def test_deterministic_and_sorted(self):
        scan = _scan(
            BASE_TARGET,
            _finding("http://app.example/a?id=1", "sqli"),
            _finding("http://app.example/b?file=x", "lfi"),
        )
        fp1 = fingerprint_scan(scan)
        fp2 = fingerprint_scan(scan)
        assert fp1 == fp2, "同输入指纹必须完全一致"
        assert fp1["assets"] == sorted(fp1["assets"])
        assert fp1["routes"] == sorted(fp1["routes"])
        assert "schema_version" in fp1
        assert len(fp1["findings"]) == 2

    def test_non_dict_fail_closed(self):
        with pytest.raises(ValueError):
            fingerprint_scan("not a dict")
        with pytest.raises(ValueError):
            fingerprint_scan(None)

    def test_empty_scan_yields_only_target_asset(self):
        fp = fingerprint_scan({"target": BASE_TARGET})
        assert fp["findings"] == {}
        assert fp["assets"] == ["app.example"]
        # target 自身的 path（"/"）也算一条路由（目标即被扫描面）
        assert fp["routes"] == ["/"]


# ============================================================
# 2. 保存 / 加载
# ============================================================
class TestSaveLoad:
    def test_roundtrip_equals_direct_fingerprint(self, tmp_path):
        scan = _scan(BASE_TARGET, _finding("http://app.example/a?id=1", "sqli"))
        path = str(tmp_path / "b.json")
        assert save_baseline(scan, path) == path
        loaded = load_baseline(path)
        assert loaded, "基线必须能读回"
        # 用加载的基线与用内存指纹比较，结论一致
        d1 = compare_with_baseline(scan, loaded)
        d2 = compare_with_baseline(scan, fingerprint_scan(scan))
        assert _fids(d1["unchanged"]) == _fids(d2["unchanged"])
        assert not diff_has_changes(d1)

    def test_load_missing_returns_none(self, tmp_path):
        assert load_baseline(str(tmp_path / "nope.json")) is None

    def test_default_baseline_path_deterministic_and_target_scoped(self):
        p1 = default_baseline_path("http://app.example")
        p2 = default_baseline_path("http://app.example")
        p3 = default_baseline_path("http://other.example")
        assert p1 == p2 and p1 != p3


# ============================================================
# 3. compare 核心判定
# ============================================================
class TestCompareCore:
    def test_added_fixed_unchanged(self):
        base = _scan(
            BASE_TARGET,
            _finding("http://app.example/a?id=1", "sqli"),
            _finding("http://app.example/b?file=x", "lfi"),
        )
        cur = _scan(
            BASE_TARGET,
            _finding("http://app.example/a?id=1", "sqli"),
            _finding("http://app.example/c?cmd=x", "cmdi"),
        )
        diff = compare_with_baseline(cur, base)
        assert [i["type"] for i in diff["added"]] == ["cmdi"]
        assert [i["type"] for i in diff["fixed"]] == ["lfi"]
        assert [i["type"] for i in diff["unchanged"]] == ["sqli"]
        assert diff["degraded"] is False
        assert diff_has_changes(diff) is True

    def test_no_changes_detected(self):
        base = _scan(BASE_TARGET, _finding("http://app.example/a?id=1", "sqli"))
        diff = compare_with_baseline(base, base)
        assert diff["added"] == [] and diff["fixed"] == [] and diff["changed"] == []
        assert diff_has_changes(diff) is False

    def test_severity_change_reported(self):
        base = _scan(BASE_TARGET, _finding("http://app.example/a?id=1", "sqli", severity="Medium"))
        cur = _scan(BASE_TARGET, _finding("http://app.example/a?id=1", "sqli", severity="Critical"))
        diff = compare_with_baseline(cur, base)
        assert len(diff["changed"]) == 1
        item = diff["changed"][0]
        assert item["severity_from"] == "medium" and item["severity_to"] == "critical"

    def test_governance_status_disappears_as_removed_not_fixed(self):
        base = _scan(BASE_TARGET, _finding("http://app.example/a?id=1", "sqli", status="accepted"))
        cur = _scan(BASE_TARGET)
        diff = compare_with_baseline(cur, base)
        assert diff["fixed"] == [], "已处置（治理态）的 finding 消失不得判为 fixed"
        assert len(diff["removed"]) == 1

    def test_reopened_when_fixed_finding_returns(self):
        base = _scan(BASE_TARGET, _finding("http://app.example/a?id=1", "sqli", status="fixed"))
        cur = _scan(BASE_TARGET, _finding("http://app.example/a?id=1", "sqli"))
        diff = compare_with_baseline(cur, base)
        assert len(diff["reopened"]) == 1


# ============================================================
# 4. surface diff
# ============================================================
class TestSurfaceDiff:
    def test_routes_params_assets_diff(self):
        base = _scan(BASE_TARGET, _finding("http://app.example/a?id=1", "sqli"))
        cur = _scan(
            BASE_TARGET,
            _finding("http://app.example/a?id=1&debug=1", "sqli"),
            _finding("http://app.example/new?q=x", "xss"),
        )
        diff = compare_with_baseline(cur, base)
        assert "/new" in diff["surface"]["routes"]["added"]
        changed_routes = {p["route"] for p in diff["surface"]["params"]["changed"]}
        assert "/a" in changed_routes, "同一路由新增参数必须出现在 params.changed"


# ============================================================
# 5. fail-closed 降级
# ============================================================
class TestDegraded:
    def test_bad_current_gives_empty_diff_and_degraded(self):
        diff = compare_with_baseline("garbage", _scan(BASE_TARGET))
        assert diff["degraded"] is True
        assert diff["added"] == [] and diff["fixed"] == []
        assert diff_has_changes(diff) is True, "degraded 一律视为有变化（不可静默判无事）"

    def test_bad_baseline_all_current_added(self):
        cur = _scan(BASE_TARGET, _finding("http://app.example/a?id=1", "sqli"))
        diff = compare_with_baseline(cur, "garbage")
        assert diff["degraded"] is True
        assert len(diff["added"]) == 1, "基线不可用 → current 全量视为新增（宁多报不漏报）"


# ============================================================
# 6. 核心等价性：增量 ∪ 基线 ≈ 全量
# ============================================================
class TestIncrementalEquivalence:
    def test_merged_incremental_equals_full_rescan(self):
        """基线 A(sqli)+B(lfi)；修复后只重扫 B（B 的 lfi 已消失）。

        正确用法 = 基线中未重扫部分（A）+ 本次重扫结果 → merged 视图，
        其与"全量重扫"视图对基线比较的结论必须完全一致。
        """
        base = _scan(
            BASE_TARGET,
            _finding("http://app.example/a?id=1", "sqli"),
            _finding("http://app.example/b?file=x", "lfi"),
        )
        # merged：A 沿用基线（未重扫）+ B 重扫零发现
        merged = _scan(BASE_TARGET, _finding("http://app.example/a?id=1", "sqli"))
        # 全量重扫：同样得到 A 存在、B 消失
        full = _scan(BASE_TARGET, _finding("http://app.example/a?id=1", "sqli"))

        d_inc = compare_with_baseline(merged, base)
        d_full = compare_with_baseline(full, base)
        for key in ("added", "removed", "changed", "unchanged", "fixed", "reopened"):
            assert _fids(d_inc[key]) == _fids(d_full[key]), f"增量视图与全量视图在 {key} 上不一致"
        assert len(d_full["fixed"]) == 1, "B 的 lfi 消失必须产出修复确认"

    def test_partial_scan_must_be_merged_before_compare(self):
        """已知陷阱固化：增量只重扫新目标、不补齐未扫范围时直接 compare，
        未扫范围的既有 finding 会被判 fixed —— 调用方必须先补齐（上一条测试）。"""
        base = _scan(BASE_TARGET, _finding("http://app.example/a?id=1", "sqli"))
        partial = _scan(BASE_TARGET, _finding("http://app.example/new?q=x", "xss"))
        diff = compare_with_baseline(partial, base)
        assert len(diff["added"]) == 1
        # 固化语义：未扫的 A 被当作消失 → fixed（提示：直接 compare 部分扫描不可信）
        assert len(diff["fixed"]) == 1


# ============================================================
# 7. 摘要文本
# ============================================================
def test_diff_summary_text_mentions_counts():
    base = _scan(BASE_TARGET, _finding("http://app.example/a?id=1", "sqli"))
    cur = _scan(BASE_TARGET, _finding("http://app.example/c?cmd=x", "cmdi"))
    text = diff_summary_text(compare_with_baseline(cur, base))
    assert isinstance(text, str) and text
    assert "新增" in text or "added" in text.lower()
