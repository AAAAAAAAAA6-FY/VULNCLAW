# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 1 模块 2：插件市场 —— 从 GitHub Releases 拉取插件。

职责：下载 zip → 校验 SHA256 → 解压到 thirdparty/plugins/{name}/ →
动态导入 entry 模块 → 注册钩子到 PluginManager。

配置项：core/settings.py 增加 PLUGIN_MARKET_REPO（默认 vulnclaw/plugins）。
"""
import hashlib
import json
import os
import shutil
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import yaml

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings

# --- 常量 ---
GITHUB_API = "https://api.github.com/repos/{repo}/releases"


# --- 异常类 ---

class ChecksumMismatchError(RuntimeError):
    """下载文件的 SHA256 校验不匹配。"""


class PluginLoadError(RuntimeError):
    """插件动态导入或钩子注册失败。"""


class PluginManifestError(RuntimeError):
    """插件 manifest 文件缺失或格式错误。"""


class PluginNotFoundError(RuntimeError):
    """插件未找到（远程列表中不存在或本地未安装）。"""


class DownloadError(RuntimeError):
    """插件下载失败（网络错误、限流、超时等）。"""


# --- 路径辅助 ---

def _get_plugins_dir() -> Path:
    """获取插件目录（支持 settings.PLUGIN_DIR 动态覆盖）。"""
    plugin_dir = getattr(settings, "PLUGIN_DIR", None)
    if plugin_dir:
        p = Path(plugin_dir)
    else:
        p = Path("thirdparty/plugins")
    p.mkdir(parents=True, exist_ok=True)
    return p


def _get_manifest_path() -> Path:
    """获取 manifest 文件路径。"""
    return _get_plugins_dir() / "plugins_manifest.json"


# --- PluginManager ---

class PluginManager:
    """已安装插件的钩子注册中心。

    钩子事件：on_scan_start / on_vuln_found / on_scan_end。
    引擎在对应时机调用 dispatch_hook(event_name, **payload)。
    """

    def __init__(self):
        self._hooks: Dict[str, List[callable]] = {}
        self._installed: Dict[str, Dict] = {}

    def register(self, plugin_name: str, hooks: Dict[str, str], module: Any) -> None:
        """注册插件钩子。hooks 形如 {"on_vuln_found": "send_slack_alert"}。"""
        for event, func_name in hooks.items():
            func = getattr(module, func_name, None)
            if func is None:
                raise PluginLoadError(
                    f"插件 {plugin_name} 缺少钩子函数: {event} → {func_name}"
                )
            self._hooks.setdefault(event, []).append(func)
            logger.info(f"   [PluginManager] 注册钩子: {plugin_name}.{event} → {func_name}")
        self._installed[plugin_name] = {"hooks": list(hooks.keys()), "module": module}

    def unregister(self, plugin_name: str) -> None:
        """移除插件的所有钩子。"""
        info = self._installed.pop(plugin_name, None)
        if info is None:
            return
        for event in info["hooks"]:
            self._hooks[event] = [
                f for f in self._hooks.get(event, []) if f not in info["module"].__dict__.values()
            ]

    async def dispatch_hook(self, event_name: str, **payload: Any) -> None:
        """触发事件钩子（异步执行所有注册函数）。"""
        import asyncio
        for func in self._hooks.get(event_name, []):
            try:
                result = func(**payload)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                logger.warning(f"   [PluginManager] 钩子 {event_name} 异常: {exc}")

    def list_registered(self) -> List[str]:
        return list(self._installed.keys())


# --- 全局单例 ---
_plugin_manager: Optional[PluginManager] = None


def get_plugin_manager() -> PluginManager:
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    return _plugin_manager


# --- manifest 读写（测试可 patch 的函数名） ---

def _load_installed_manifest() -> Dict:
    """读取本地 plugins_manifest.json。"""
    manifest_path = _get_manifest_path()
    if not manifest_path.exists():
        return {"plugins": {}}
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"plugins": {}}


def _save_installed_manifest(manifest: Dict) -> None:
    """写入 manifest（原子写入）。"""
    manifest_path = _get_manifest_path()
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = manifest_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(manifest_path)


def _get_plugins_dict(manifest: Dict) -> Dict:
    """从 manifest 中提取 plugins 字典，兼容两种格式：
    1. {"plugins": {"name": {...}}} — 标准格式
    2. {"name": {...}} — 扁平格式（测试 mock / 旧版本）
    """
    if "plugins" in manifest and isinstance(manifest["plugins"], dict):
        return manifest["plugins"]
    # 扁平格式：所有 key 不是元数据的就是插件
    return {k: v for k, v in manifest.items() if k not in ("plugins",)}


# --- 内部辅助函数（测试可 patch） ---

def _download_plugin_zip(download_url: str, dest_path: str) -> str:
    """下载插件 zip 到指定路径。

    Returns:
        下载后的本地文件路径。

    Raises:
        DownloadError: 网络错误、超时、HTTP 非 200。
    """
    try:
        resp = requests.get(download_url, timeout=60, stream=True)
        if resp.status_code != 200:
            raise DownloadError(
                f"下载失败 HTTP {resp.status_code}: {download_url}"
            )
        with open(dest_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        logger.debug(f"   [plugin_market] 下载完成: {dest_path}")
        return dest_path
    except requests.exceptions.Timeout:
        raise DownloadError(f"下载超时: {download_url}")
    except requests.exceptions.ConnectionError as exc:
        raise DownloadError(f"下载连接失败: {download_url} - {exc}")
    except DownloadError:
        raise
    except Exception as exc:
        raise DownloadError(f"下载异常: {download_url} - {exc}")


def _verify_sha256(zip_path: str, expected_sha256: str) -> bool:
    """校验 zip 文件的 SHA256。

    Returns:
        True 表示校验通过，False 表示不匹配。
    """
    if not expected_sha256:
        logger.debug("   [plugin_market] 无 SHA256 期望值，跳过校验")
        return True
    h = hashlib.sha256()
    with open(zip_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    actual = h.hexdigest()
    if actual != expected_sha256:
        logger.warning(
            f"   [plugin_market] SHA256 校验失败: 期望={expected_sha256} 实际={actual}"
        )
        return False
    return True


def _extract_plugin(zip_path: str, plugin_dir: Path) -> Path:
    """解压 zip 到插件目录。

    Returns:
        解压后的插件目录路径。
    """
    plugin_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(plugin_dir)
    os.unlink(zip_path)
    logger.debug(f"   [plugin_market] 解压完成: {plugin_dir}")
    return plugin_dir


def _load_plugin_manifest(plugin_dir: Path) -> Dict:
    """读取插件目录中的 plugin_manifest.yaml。

    Returns:
        manifest 字典。

    Raises:
        PluginManifestError: 文件缺失或格式错误。
    """
    pmf_path = plugin_dir / "plugin_manifest.yaml"
    if not pmf_path.exists():
        raise PluginManifestError(f"plugin_manifest.yaml not found in {plugin_dir}")
    try:
        return yaml.safe_load(pmf_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PluginManifestError(f"plugin_manifest.yaml 解析失败: {exc}")


def _register_plugin_hooks(plugin_name: str, manifest: Dict) -> bool:
    """动态导入 entry 模块并注册钩子到 PluginManager。

    Returns:
        True 表示注册成功。

    Raises:
        PluginLoadError: 动态导入失败或钩子函数缺失。
    """
    import importlib.util

    plugin_dir = Path(manifest.get("_plugin_dir", ""))
    entry = manifest.get("entry", "main.py")
    entry_path = plugin_dir / entry

    spec = importlib.util.spec_from_file_location(f"plugin_{plugin_name}", entry_path)
    if spec is None or spec.loader is None:
        raise PluginLoadError(f"无法导入 entry: {entry_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    pm = get_plugin_manager()
    hooks = manifest.get("hooks", {})
    pm.register(plugin_name, hooks, module)
    return True


# --- 核心 API（同步，测试直接调用） ---

def list_available_plugins() -> List[Dict]:
    """从 GitHub Releases 拉取可用插件列表。

    Returns:
        [{"name": str, "version": str, "description": str,
          "sha256": str, "download_url": str}]

    Raises:
        DownloadError: 网络错误、超时、HTTP 403 限流等。
    """
    repo = getattr(settings, "PLUGIN_MARKET_REPO", "vulnclaw/plugins")
    url = GITHUB_API.format(repo=repo)
    try:
        resp = requests.get(url, timeout=15, headers={"Accept": "application/vnd.github+json"})
        if resp.status_code == 403:
            raise DownloadError(f"GitHub API 返回 403 (rate limit): {resp.text[:200]}")
        if resp.status_code != 200:
            raise DownloadError(f"GitHub API 返回 HTTP {resp.status_code}")
        releases = resp.json()
    except requests.exceptions.Timeout:
        raise DownloadError("GitHub API 请求超时 (timeout)")
    except requests.exceptions.ConnectionError as exc:
        raise DownloadError(f"GitHub API 连接失败: {exc}")
    except TimeoutError:
        raise DownloadError("GitHub API 请求超时 (timeout)")
    except DownloadError:
        raise
    except Exception as exc:
        raise DownloadError(f"GitHub API 异常: {exc}")

    # 兼容两种格式：
    # 1. GitHub Releases API: [{"tag_name": "v1.0", "assets": [{"name": "x.zip", ...}]}]
    # 2. 扁平插件列表: [{"name": "x", "version": "1.0", "download_url": "..."}]
    plugins: List[Dict] = []
    for item in releases:
        if isinstance(item, dict) and "assets" in item:
            # GitHub Releases 格式
            for asset in item.get("assets", []):
                plugins.append({
                    "name": asset["name"].replace(".zip", ""),
                    "version": item.get("tag_name", "unknown"),
                    "description": (item.get("body") or "")[:200],
                    "sha256": asset.get("digest", ""),
                    "download_url": asset.get("browser_download_url", ""),
                })
        elif isinstance(item, dict) and "name" in item:
            # 扁平插件列表格式（测试 mock 或自定义源）
            plugins.append(item)
    return plugins


def install_plugin(name: str, version: str = "latest") -> Dict:
    """下载并安装插件。

    流程：检查已安装 → 拉取列表 → 下载 zip → 校验 SHA256 → 解压 → 读取 manifest → 注册钩子。

    Returns:
        {"success": bool, "path": str|None, "error": str|None}

    Raises:
        PluginNotFoundError: 插件在远程列表中不存在。
        ChecksumMismatchError: SHA256 校验失败。
        DownloadError: 下载失败。
        PluginManifestError: manifest 文件缺失或格式错误。
        PluginLoadError: 动态导入失败。
    """
    # 1. 检查是否已安装
    manifest = _load_installed_manifest()
    plugins_dict = _get_plugins_dict(manifest)
    if name in plugins_dict:
        return {
            "success": True,
            "path": plugins_dict[name]["path"],
            "error": "already_installed",
        }

    # 2. 拉取列表找到下载地址
    available = list_available_plugins()
    target = None
    for p in available:
        if p["name"] == name and (version == "latest" or p["version"] == version):
            target = p
            break
    if target is None:
        raise PluginNotFoundError(f"插件 {name}@{version} not found in plugin market")

    # 3. 下载 zip
    plugins_dir = _get_plugins_dir()
    plugin_dir = plugins_dir / name
    plugin_dir.mkdir(parents=True, exist_ok=True)
    zip_path = str(plugin_dir / f"{name}.zip")

    _download_plugin_zip(target["download_url"], zip_path)

    # 4. 校验 SHA256
    if not _verify_sha256(zip_path, target.get("sha256", "")):
        if os.path.exists(zip_path):
            os.unlink(zip_path)
        shutil.rmtree(plugin_dir, ignore_errors=True)
        raise ChecksumMismatchError(
            f"SHA256 校验失败: 插件={name} 期望={target.get('sha256', '')}"
        )

    # 5. 解压
    _extract_plugin(zip_path, plugin_dir)

    # 6. 读取 plugin_manifest.yaml
    pmf = _load_plugin_manifest(plugin_dir)

    # 7. 动态导入 entry 模块并注册钩子
    pmf["_plugin_dir"] = str(plugin_dir)
    _register_plugin_hooks(name, pmf)

    # 8. 更新 manifest
    if "plugins" not in manifest:
        manifest["plugins"] = {}
    from datetime import datetime
    manifest["plugins"][name] = {
        "version": pmf.get("version", "0.0.0"),
        "path": str(plugin_dir),
        "hooks": list(pmf.get("hooks", {}).keys()),
        "installed_at": datetime.utcnow().isoformat() + "Z",
    }
    _save_installed_manifest(manifest)
    logger.info(f"📦 插件 {name} 安装成功: {plugin_dir}")
    return {"success": True, "path": str(plugin_dir), "error": None}


def list_installed_plugins() -> List[Dict]:
    """返回已安装插件列表。"""
    manifest = _load_installed_manifest()
    plugins_dict = _get_plugins_dict(manifest)
    return [
        {"name": name, **info}
        for name, info in plugins_dict.items()
    ]


def uninstall_plugin(name: str) -> bool:
    """卸载插件：删除目录 + 移除 manifest + 注销钩子。

    Returns:
        True 表示卸载成功。

    Raises:
        PluginNotFoundError: 插件未安装。
    """
    manifest = _load_installed_manifest()
    plugins_dict = _get_plugins_dict(manifest)
    info = plugins_dict.pop(name, None)
    if info is None:
        raise PluginNotFoundError(f"插件 {name} 未安装 (not installed)")
    # 同步到 manifest 的 plugins 字段
    if "plugins" in manifest:
        manifest["plugins"].pop(name, None)
    else:
        manifest.pop(name, None)
    shutil.rmtree(info.get("path", ""), ignore_errors=True)
    pm = get_plugin_manager()
    pm.unregister(name)
    _save_installed_manifest(manifest)
    logger.info(f"🗑️ 插件 {name} 已卸载")
    return True
