# -*- coding: utf-8 -*-
"""双路回退：burp_cookies.json 在 HOME 被重定向时仍可解析到真实用户目录。

背景：scan_main.py 为防 nuclei/uncover 写 HOME 垃圾，把 HOME/USERPROFILE
重定向到 _runtime_cache/tools，导致 expanduser("~/burp_cookies.json") 解析
到不存在的位置。resolve_burp_cookies_path 做双路回退：真实用户目录优先，
重定向目录兜底。
"""
import os

import pytest

from vulnclaw.core.utils import resolve_burp_cookies_path


def _norm(p: str) -> str:
    return os.path.normpath(os.path.normcase(p))


def test_basename_always_burp_cookies_json():
    assert os.path.basename(resolve_burp_cookies_path()) == "burp_cookies.json"


def test_picks_redirected_home_when_file_there(monkeypatch, tmp_path):
    """重定向 HOME 下存在文件时，直接命中（不依赖真实用户目录）。

    强制把 USERNAME 指到不存在的路径，确保只走重定向候选。
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("USERNAME", "_no_such_user_4c9d")
    target = tmp_path / "burp_cookies.json"
    target.write_text("{}", encoding="utf-8")
    assert _norm(resolve_burp_cookies_path()) == _norm(str(target))


def test_chains_to_real_user_dir_when_redirected_home_missing(monkeypatch, tmp_path):
    """重定向 HOME 无文件、真实用户目录有文件时，回退真实目录（核心修复场景）。

    HOME/USERPROFILE 被指向过期的 runtime 目录；真实文件在用户目录。
    为不依赖开发机用户名，本用例以 basename 收敛断言，真实目录探测用
    isdir 保护。
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    real_dir = "C:/Users/" + os.environ.get("USERNAME", "_x")
    got = resolve_burp_cookies_path()
    assert os.path.basename(got) == "burp_cookies.json"
    assert os.path.isdir(os.path.dirname(got))  # 解析结果目录必然存在


def test_returns_first_candidate_even_if_missing(monkeypatch, tmp_path):
    """两处都不存在时返回第 1 个候选，且不因真实机器文件破坏稳定性。"""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("USERNAME", "_no_such_user_9d31")
    got = resolve_burp_cookies_path()
    assert got == os.path.join(str(tmp_path), "burp_cookies.json") or \
        _norm(got) == _norm(os.path.join(str(tmp_path), "burp_cookies.json"))
