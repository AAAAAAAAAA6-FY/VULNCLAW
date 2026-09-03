#!/usr/bin/env python3
"""VULNCLAW CLI 入口（薄壳）——实际逻辑在 src/vulnclaw/"""
import sys
from pathlib import Path
# 保证 src 优先于 site-packages（杜绝 egg-link 加载旧拷贝），并在任何 vulnclaw
# 导入前先装 numpy 兼容桩（Python 3.13+/Windows 防 import numpy 段错误）
_SRC = str((Path(__file__).parent / "src").resolve())
while _SRC in sys.path:
    sys.path.remove(_SRC)
sys.path.insert(0, _SRC)
from vulnclaw.core.numpy_compat import install_numpy_compat_stub_if_needed
install_numpy_compat_stub_if_needed()
from vulnclaw.cli import main
if __name__ == "__main__":
    main()
