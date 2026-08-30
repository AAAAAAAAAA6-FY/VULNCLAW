#!/usr/bin/env python3
"""VULNCLAW CLI 入口（薄壳）——实际逻辑在 src/vulnclaw/"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from vulnclaw.cli import main

if __name__ == "__main__":
    main()
