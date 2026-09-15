# -*- coding: utf-8 -*-
"""工具接线回归测试：锁住"已声明能力实际全程空转"这一类缺陷。

背景（全部为实测踩到的真 bug，非假设）：
  · param_discovery 能力在治理目录声明了 candidates: [arjun]，但 arjun **从未执行过**，
    由以下 5 处缺陷串联造成：
      1. run_arjun 门禁用 shutil.which("arjun")：arjun 在 thirdparty/arjun/ 下、不在
         系统 PATH，判定恒为 False，函数第一行就返回空列表；
      2. 调用参数传 --timeout：arjun 的 HTTP 超时是 -T，不存在该长选项，argparse 直接拒绝；
      3. tools.yaml 的 default_args 写了 --silent：同样不存在（静默是 -q），且
         default_args 会被前置拼接到每次调用；
      4. run_tool 用 config["executable"]（"arjun.exe"）解析路径：裸文件名查不到
         thirdparty/arjun/arjun.exe，报 "未找到工具"；
      5. 结果 JSON 的真实键是 params，旧解析只认 "parameters"，即使扫出结果也被丢弃。
  · discover_auto_tools 递归 rglob 会把第三方自带内部二进制（Burp 的 JRE：
    java/javac/jdb/keytool/klist/ktab/rmiregistry…、OneForAll 的 massdns）登记成
    受管工具，污染 Agent 的工具清单。
"""
import json
import os

import pytest

from vulnclaw.core import tool_registry
from vulnclaw.modules.vuln_scanner import cve_nuclei


# ============================================================
# 1) arjun 结果解析：真实键名是 params
# ============================================================
def test_extract_arjun_params_real_key():
    """真实 arjun JSON 用 "params" 键（实测 thirdparty/arjun/arjun.exe）。"""
    data = {"http://t/": {"params": ["debug", "user"], "method": "GET"}}
    assert cve_nuclei._extract_arjun_params(data) == ["debug", "user"]


def test_extract_arjun_params_legacy_key():
    """兼容 "parameters" 键（部分版本/包装层）。"""
    data = {"http://t/": {"parameters": ["a"]}}
    assert cve_nuclei._extract_arjun_params(data) == ["a"]


def test_extract_arjun_params_multi_target_and_dedup():
    """多目标结果合并并去重。"""
    data = {
        "http://a/": {"params": ["x", "y"]},
        "http://b/": {"params": ["y", "z"]},
    }
    assert cve_nuclei._extract_arjun_params(data) == ["x", "y", "z"]


def test_extract_arjun_params_tolerates_other_shapes():
    """裸列表 / 无关结构都不应抛异常。"""
    assert cve_nuclei._extract_arjun_params(["p1", "p2"]) == ["p1", "p2"]
    assert cve_nuclei._extract_arjun_params(None) == []
    assert cve_nuclei._extract_arjun_params("not-a-dict") == []
    assert cve_nuclei._extract_arjun_params({"headers": {}}) == []


def test_extract_arjun_params_from_text():
    """stdout 兜底解析 "Parameters found: a, b"。"""
    assert cve_nuclei._extract_arjun_params_from_text(
        "[+] Parameters found: debug, user"
    ) == ["debug", "user"]
    assert cve_nuclei._extract_arjun_params_from_text("no match here") == []


# ============================================================
# 2) run_arjun 必须用 arjun 真实支持的 CLI 旗标
# ============================================================
@pytest.mark.asyncio
async def test_run_arjun_uses_real_cli_flags(monkeypatch):
    """-T / -q / -o 必须出现；--timeout / --silent 绝不允许出现。"""
    captured = {}

    async def _fake_run_tool(name, args=None, timeout=None, **kwargs):
        captured["name"] = name
        captured["args"] = list(args or [])
        captured["timeout"] = timeout
        # 模拟 arjun 把结果写入 -o 指定的文件
        out_path = captured["args"][captured["args"].index("-o") + 1]
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({"http://t/": {"params": ["debug"]}}, f)
        return {"success": True, "returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(cve_nuclei, "run_tool", _fake_run_tool)
    monkeypatch.setattr(cve_nuclei, "tool_available", lambda _name: True)

    params = await cve_nuclei.run_arjun("http://t/", timeout=7)

    assert params == ["debug"]
    assert captured["name"] == "arjun"
    assert "-T" in captured["args"]
    assert "7" in captured["args"]
    assert "-q" in captured["args"]
    assert "-o" in captured["args"]
    assert not any(a.startswith("--timeout") for a in captured["args"]), \
        "arjun 不支持 --timeout（应为 -T）"
    assert not any(a.startswith("--silent") for a in captured["args"]), \
        "arjun 不支持 --silent（应为 -q）"


@pytest.mark.asyncio
async def test_run_arjun_skips_when_tool_unavailable(monkeypatch):
    """工具不可用时直接返回空，且不应调用 run_tool。"""
    called = {"n": 0}

    async def _fake_run_tool(*args, **kwargs):  # pragma: no cover - 不应被调用
        called["n"] += 1
        return {"success": True}

    monkeypatch.setattr(cve_nuclei, "run_tool", _fake_run_tool)
    monkeypatch.setattr(cve_nuclei, "tool_available", lambda _name: False)

    assert await cve_nuclei.run_arjun("http://t/") == []
    assert called["n"] == 0


@pytest.mark.asyncio
async def test_run_arjun_cleans_temp_output(monkeypatch):
    """无论成功与否，-o 临时文件都应被清理，不在项目目录留垃圾。"""
    seen = {}

    async def _fake_run_tool(name, args=None, timeout=None, **kwargs):
        seen["out"] = args[list(args).index("-o") + 1]
        return {"success": False, "returncode": 1, "stdout": "", "stderr": "boom"}

    monkeypatch.setattr(cve_nuclei, "run_tool", _fake_run_tool)
    monkeypatch.setattr(cve_nuclei, "tool_available", lambda _name: True)

    assert await cve_nuclei.run_arjun("http://t/") == []
    assert not os.path.exists(seen["out"])


# ============================================================
# 3) 工具路径解析："配置 executable → 注册名" 两段回退
# ============================================================
def test_resolve_configured_tool_falls_back_to_registry_name(monkeypatch):
    """裸可执行名解析失败时，必须回退用注册名再解析一次。"""
    calls = []

    def _fake_resolve(name):
        calls.append(name)
        return "/resolved/" + name if name == "arjun" else None

    monkeypatch.setattr(tool_registry, "resolve_tool_path", _fake_resolve)

    got = tool_registry.resolve_configured_tool("arjun", {"executable": "arjun.exe"})
    assert got == "/resolved/arjun"
    assert calls == ["arjun.exe", "arjun"], "应先试 executable，再回退注册名"


def test_resolve_configured_tool_prefers_executable(monkeypatch):
    """executable 能解析时不应触发回退。"""
    calls = []

    def _fake_resolve(name):
        calls.append(name)
        return "/resolved/" + name

    monkeypatch.setattr(tool_registry, "resolve_tool_path", _fake_resolve)

    assert tool_registry.resolve_configured_tool(
        "arjun", {"executable": "arjun.exe"}) == "/resolved/arjun.exe"
    assert calls == ["arjun.exe"]


def test_resolve_configured_tool_handles_missing_config(monkeypatch):
    """无配置时按注册名解析。"""
    monkeypatch.setattr(tool_registry, "resolve_tool_path", lambda n: "/r/" + n)
    assert tool_registry.resolve_configured_tool("foo", None) == "/r/foo"


def test_tool_available_never_raises(monkeypatch):
    """可用性判定必须吞异常（绝不因探测失败打断扫描）。"""
    def _boom(_name):
        raise RuntimeError("probe failed")

    monkeypatch.setattr(tool_registry, "resolve_tool_path", _boom)
    assert tool_registry.tool_available("anything") is False


# ============================================================
# 4) 自动发现：排除第三方内部二进制与人工套件
# ============================================================
@pytest.fixture
def _allow_all_executables(monkeypatch):
    """跳过磁盘存在性检查，专测路径深度/前缀规则。"""
    monkeypatch.setattr(tool_registry, "_executable_candidates", lambda _p: True)


def test_auto_discovery_includes_flat_and_one_dir(_allow_all_executables):
    root = tool_registry.THIRDPARTY_PATH
    assert tool_registry._auto_discovery_included(root / "nuclei.exe")
    assert tool_registry._auto_discovery_included(root / "arjun" / "arjun.exe")


def test_auto_discovery_excludes_deep_internal_binaries(_allow_all_executables):
    """Burp 的 JRE 与 OneForAll 的 massdns 都不该被登记为受管工具。"""
    root = tool_registry.THIRDPARTY_PATH
    assert not tool_registry._auto_discovery_included(
        root / "BurpSuite V2026.7.3" / "jre" / "bin" / "java.exe")
    assert not tool_registry._auto_discovery_included(
        root / "OneForAll" / "thirdparty" / "massdns" / "bin" / "massdns.exe")


def test_auto_discovery_excludes_burp_launchers(_allow_all_executables):
    """Burp 的启动批处理是人工交互套件，不是可编排扫描工具。"""
    root = tool_registry.THIRDPARTY_PATH
    assert not tool_registry._auto_discovery_included(
        root / "BurpSuite V2026.7.3" / "Burp Suite_CN.bat")


# ============================================================
# 5) thirdparty-only 工具的门禁必须用 tool_available（gospider 实测事故）
# ============================================================
def test_gospider_resolvable_via_registry_not_which():
    """gospider 在 thirdparty/gospider/ 下、不在系统 PATH。旧门禁用 shutil.which
    会判 False，使端点发现静默跳过（与 arjun 同类的 dead-tool bug）。tool_available
    必须能解析它。"""
    import shutil

    assert shutil.which("gospider") is None  # 确认它确实不在 PATH（否则此断言失真）
    assert tool_registry.tool_available("gospider") is True


# ============================================================
# 6) gitleaks 作为 secret_scan 能力的第二意见（secret_scan 曾 only 声明未接线）
# ============================================================
@pytest.mark.asyncio
async def test_analyze_js_deep_gitleaks_second_opinion(monkeypatch):
    """gitleaks 作为 secret_scan 能力的第二意见：JS 深度分析应把其发现的密钥并入
    findings['secrets']（secret_scan 曾 only 声明未接线）。

    用 fake run_tool 喂一份 gitleaks 风格 JSON 报告，验证「解析 + 合并 + 去占位」
    这段我写的接线逻辑（不依赖外部进程——gitleaks 二进制在真实环境的人工验证已通过，
    pytest + Windows 下子进程句柄继承会报 WinError 6，属环境问题非接线 bug）。
    """
    import json as _json

    captured = {}

    async def _fake_run_tool(name, args=None, timeout=None, **kw):
        args = list(args or [])
        captured["args"] = args
        if "-r" in args:
            out = args[args.index("-r") + 1]
            report = [{
                "RuleID": "stripe-access-token",
                "Secret": "sk_live_abc123DEF456ghi789JKL012mno345",
                "File": "x",
            }]
            with open(out, "w", encoding="utf-8") as f:
                _json.dump(report, f)
        return {"success": True, "returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(tool_registry, "tool_available", lambda _n: True)
    monkeypatch.setattr(tool_registry, "run_tool", _fake_run_tool)

    import vulnclaw.modules.collectors as collectors
    findings = await collectors.analyze_js_deep(
        "var k='sk_live_abc123DEF456ghi789JKL012mno345';",
        base_url="https://x.com", source_url="https://x.com/a.js")

    # 确认门禁 + 调用旗标确实走的是 gitleaks 真实形态
    assert any(a == "detect" for a in captured["args"]), captured["args"]
    assert any(a == "--no-git" for a in captured["args"])
    types = {s["type"] for s in findings["secrets"] if isinstance(s, dict)}
    assert any(t.startswith("Gitleaks:") for t in types), \
        f"gitleaks 第二意见未生效: {findings['secrets']}"


@pytest.mark.asyncio
async def test_analyze_js_deep_gitleaks_missing_is_silent(monkeypatch):
    """gitleaks 缺失时，JS 分析不得抛异常、不得中断（降级为仅内置正则）。"""
    # collectors 在方法内 `from vulnclaw.core.tool_registry import tool_available`，
    # 每次调用都会重新解析该名字，故 patch 源模块即可生效。
    monkeypatch.setattr(tool_registry, "tool_available", lambda _n: False)
    import vulnclaw.modules.collectors as collectors

    findings = await collectors.analyze_js_deep(
        "var a=1;", base_url="https://x.com", source_url="https://x.com/a.js")
    assert isinstance(findings, dict)
    assert "secrets" in findings


# ============================================================
# 7) 脚本型工具不能直接 exec：命令构建须前插解释器（nikto=.py 包装，曾 returncode=-1）
# ============================================================
def test_build_command_prepends_interpreter():
    """Windows 不能直接 exec .py/.pl。.py 前插 sys.executable、.pl 前插 perl、
    .exe 原样。否则 nikto(thirdparty/nikto/nikto.py 是 perl 脚本的 python 薄包装)
    在 run_tool 处必 returncode=-1 静默失败。"""
    from vulnclaw.core import tool_registry as tr
    import sys, shutil

    assert tr._build_command("thirdparty/nikto/nikto.py", ["-H"]) == \
        [sys.executable, "thirdparty/nikto/nikto.py", "-H"]
    assert tr._build_command("x.pl", ["a"]) == \
        [(shutil.which("perl") or "perl"), "x.pl", "a"]
    assert tr._build_command("thirdparty/arjun/arjun.exe", ["-u", "x"]) == \
        ["thirdparty/arjun/arjun.exe", "-u", "x"]


@pytest.mark.asyncio
async def test_run_nikto_parses_vulnerabilities_and_filters_fail(monkeypatch):
    """run_nikto 解析 nikto JSON 的 `vulnerabilities`（非 `items`），保留真实漏洞、
    过滤 id=='FAIL' 的连接失败项，并给 perl 注入 LC_ALL=C 等 locale 变量防崩。

    用 fake run_tool 喂样本，hermetic（不依赖 perl/网络）。真实执行已在手动验证中跑通。
    """
    import json as _json

    captured = {}

    async def _fake_run_tool(name, args=None, timeout=None, env=None, **kw):
        captured["env"] = env
        args = list(args or [])
        if "-o" in args:
            out = args[args.index("-o") + 1]
            report = [{
                "host": "http://x.com", "port": "80",
                "vulnerabilities": [
                    {"id": "999990", "method": "GET", "url": "/admin",
                     "msg": "Interesting backup file found"},
                    {"id": "FAIL", "method": "GET", "url": "/",
                     "msg": "Unable to connect to 1.2.3.4:80."},
                ],
            }]
            with open(out, "w", encoding="utf-8") as f:
                _json.dump(report, f)
        return {"success": True, "returncode": 0, "stdout": "", "stderr": ""}

    # 门禁：nikto.py 存在 → tool_available 必须为真（否则此前 nikto 能力形同虚设）
    assert tool_registry.tool_available("nikto") is True

    import vulnclaw.modules.vuln_scanner.cve_nuclei as cn
    # cve_nuclei 在模块顶部 `from ... import run_tool`，需 patch 该模块引用本身
    monkeypatch.setattr(cn, "run_tool", _fake_run_tool)
    findings = await cn.run_nikto("http://x.com", timeout=30)

    # 断言：注入了 locale 环境变量（perl 防崩，且不覆盖 PATH —— 合并而非替换）
    assert captured["env"]["LC_ALL"] == "C"
    # 断言：真实漏洞保留、FAIL 连接失败项被过滤
    assert len(findings) == 1, findings
    assert findings[0]["template"] == "nikto:999990"
    assert findings[0]["url"] == "http://x.com"
    assert findings[0]["info"] == "Interesting backup file found"


@pytest.mark.asyncio
async def test_run_nikto_missing_is_silent(monkeypatch):
    """nikto 缺失时，run_nikto 返回 [] 且不抛异常（fail-closed，不影响社区线）。"""
    import vulnclaw.modules.vuln_scanner.cve_nuclei as cn
    # cve_nuclei 在模块顶部 `from ... import tool_available`，需 patch 该模块引用本身
    monkeypatch.setattr(cn, "tool_available", lambda _n: False)
    assert await cn.run_nikto("http://x.com", timeout=30) == []
