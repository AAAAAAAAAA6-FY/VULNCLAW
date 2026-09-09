"""pytest 共享夹具：项目根入 sys.path + 不依赖外网/真实 AI。"""
import os
import sys
# 1. 全局字节码
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
os.environ.setdefault("PYTHONPYCACHEPREFIX", "")
# 2. Nuclei/uncover HOME 垃圾重定向
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RT = os.path.join(PROJECT_ROOT, "_runtime_cache", "tools")
for _sub in ("", "nuclei", "uncover"):
    try:
        os.makedirs(os.path.join(_RT, _sub), exist_ok=True)
    except Exception:
        pass
os.environ["HOME"] = _RT
os.environ["USERPROFILE"] = _RT
os.environ["NUCLEI_CONFIG_DIR"] = os.path.join(_RT, "nuclei")
os.environ["UNCOVER_CONFIG_DIR"] = os.path.join(_RT, "uncover")
# 3. Windows 编码
sys.dont_write_bytecode = True
if sys.platform.startswith("win"):
    import io as _io
    for _n in ("stdout", "stderr"):
        _s = getattr(sys, _n)
        try:
            if hasattr(_s, "reconfigure"): _s.reconfigure(encoding="utf-8", errors="replace"); continue
        except Exception: pass
        if hasattr(_s, "buffer"):
            try:
                setattr(sys, _n, _io.TextIOWrapper(_s.buffer, encoding="utf-8", errors="replace", line_buffering=True))
            except Exception: pass
    os.environ.setdefault("TQDM_DISABLE", "1")

# 4. 屏蔽上次扫描残留的 .env 配置（ALLOWED_SCOPE/PROXY）对测试的影响：
#    本地靶场请求不被 E5 越界守卫拦截、不走代理；.env 文件内容原样保留。
os.environ["ALLOWED_SCOPE"] = ""
os.environ["PROXY"] = ""

import pytest

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
_SRC = os.path.join(PROJECT_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
del _RT, _sub, _n, _s, _SRC


@pytest.fixture
def anyio_backend():
    return "asyncio"
