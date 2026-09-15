# -*- coding: utf-8 -*-
"""运行时引擎事实源的回归测试。"""

from vulnclaw.core.scanner import get_engine_inventory


def test_engine_inventory_has_consistent_runtime_counts():
    inventory = get_engine_inventory()

    assert set(inventory) >= {
        "discovered",
        "instantiated",
        "enabled",
        "failed",
        "abstract",
        "names",
    }
    assert inventory["discovered"] >= inventory["instantiated"]
    assert inventory["instantiated"] == inventory["enabled"]
    assert isinstance(inventory["failed"], list)
    assert isinstance(inventory["abstract"], list)
    assert isinstance(inventory["names"], list)
    assert len(inventory["names"]) == inventory["enabled"]
    assert inventory["names"] == sorted(set(inventory["names"]))


def test_engine_inventory_excludes_abstract_and_failed_engines_from_names():
    inventory = get_engine_inventory()
    names = set(inventory["names"])
    abstract_names = {item["name"] for item in inventory["abstract"]}
    failed_names = {item["name"] for item in inventory["failed"]}

    assert names.isdisjoint(abstract_names)
    assert names.isdisjoint(failed_names)
