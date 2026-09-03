# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
"""numpy 兼容桩：Python 3.13+/Windows 防止 import numpy 触发段错误（ACCESS_VIOLATION）。

必须在任何 vulnclaw 导入之前安装，因此被根 scan.py 薄壳最先调用。
仅依赖标准库（os/sys/platform/types/importlib.util），不触发 numpy。
"""
from __future__ import annotations

import os
import sys

def install_numpy_compat_stub_if_needed() -> None:
    import platform as _platform
    enable_ml = os.getenv("VULNCLAW_ENABLE_ML", "0").strip() in ("1", "true", "True", "yes")
    disable_stub = os.getenv("VULNCLAW_DISABLE_NUMPY_STUB", "0").strip() in ("1", "true", "True", "yes")
    if enable_ml or disable_stub:
        return
    high_risk = (
        sys.platform.startswith("win")
        and _platform.python_implementation() == "CPython"
        and sys.version_info >= (3, 13)
    )
    if not high_risk:
        return
    # 如果真实 numpy 已经被加载过（说明之前有人 import 过），没办法挽救了
    if "numpy" in sys.modules:
        return

    # --- 构造空 stub 对象工厂 ---
    class _StubAttr:
        """任意链属性访问都返回自身，调用返回 None。
        这样 `numpy.float32`, `numpy.array([1,2]).reshape(3,1)` 都不会 AttributeError，
        只会静默得到 None / 伪对象。VULNCLAW 的 ML 分支本身已被短路，
        第三方"import numpy 但运行时其实不用"的场景就会被兜住。"""
        __slots__ = ("_name",)

        def __init__(self, name: str = "stub"):
            object.__setattr__(self, "_name", name)

        def __repr__(self):
            return f"<NumpyStub {self._name}>"

        def __getattr__(self, item):  # type: ignore[override]
            # 拦截 dtype / float32 / int64 / random / array / ndarray 等所有属性
            if item in ("__path__", "__spec__", "__loader__"):
                raise AttributeError(item)
            return _StubAttr(f"{self._name}.{item}")

        def __setattr__(self, key, value):  # type: ignore[override]
            return None

        def __call__(self, *args, **kwargs):  # type: ignore[override]
            return _StubAttr(f"{self._name}()")

        def __iter__(self):
            return iter(())

        def __bool__(self):  # pragma: no cover
            return False

        def __eq__(self, other):  # type: ignore[override]
            return other is self

        def __hash__(self):
            return hash(self._name)

        # ---------- container / numeric dunder ----------
        # pydantic-settings 或第三方会把 numpy stub 当作 array 使用，
        # 典型用法：np[:, 0]、coef_[i]、X.reshape()[:,k]。
        # 全部返回 self，保持链式不抛异常。
        def __getitem__(self, item):
            return _StubAttr(f"{self._name}[{item!r}]")

        def __setitem__(self, key, value):
            return None

        def __delitem__(self, key):
            return None

        def __len__(self):
            return 0

        def __contains__(self, item):
            return False

        # ---------- numeric dunder ----------
        def __add__(self, other): return _StubAttr(f"{self._name}+")
        def __radd__(self, other): return _StubAttr(f"+{self._name}")
        def __sub__(self, other): return _StubAttr(f"{self._name}-")
        def __rsub__(self, other): return _StubAttr(f"-{self._name}")
        def __mul__(self, other): return _StubAttr(f"{self._name}*")
        def __rmul__(self, other): return _StubAttr(f"*{self._name}")
        def __truediv__(self, other): return _StubAttr(f"{self._name}/")
        def __floordiv__(self, other): return _StubAttr(f"{self._name}//")
        def __mod__(self, other): return _StubAttr(f"{self._name}%")
        def __pow__(self, other, modulo=None): return _StubAttr(f"{self._name}**")
        def __neg__(self): return _StubAttr(f"-{self._name}")
        def __pos__(self): return self
        def __abs__(self): return self
        def __lt__(self, other): return False
        def __le__(self, other): return False
        def __gt__(self, other): return False
        def __ge__(self, other): return False
        def __ne__(self, other):  # type: ignore[override]
            return not (other is self)
        def __and__(self, other): return False
        def __or__(self, other): return False
        def __invert__(self): return False
        def __float__(self): return 0.0
        def __int__(self): return 0
        def __complex__(self): return 0j
        def __index__(self): return 0
        def __round__(self, ndigits=None): return 0
        def __trunc__(self): return 0
        def __floor__(self): return 0
        def __ceil__(self): return 0
        # numpy 常用方法 shape / dtype / tolist / flatten / reshape / T 会走到 __getattr__
        # 已返回另一个 _StubAttr，所以 x.tolist() 返回可调用对象 → 返回 _StubAttr()
        # 已经 OK。显式补一个 flatten 让第三方不显式 import numpy 也能操作。
        def flatten(self, *a, **k):
            return self

        def tolist(self, *a, **k):
            return []

        def reshape(self, *a, **k):
            return self

        def astype(self, *a, **k):
            return self

        def copy(self, *a, **k):
            return self

        @property
        def shape(self):
            return (0,)

        @property
        def dtype(self):
            return type("dtype", (), {})()

        @property
        def ndim(self):
            return 1

        @property
        def size(self):
            return 0

        @property
        def T(self):
            return self

    # 顶层 numpy stub 模块
    import types as _types
    _stub_mod = _types.ModuleType("numpy")
    _stub_obj = _StubAttr("numpy")
    # 这些属性第三方通常 getattr 后直接比较：给一个明确的假值
    _stub_mod.__name__ = "numpy"
    # 伪装成一个合法的 numpy 版本号（pydantic-settings 会解析 __version__，带 -stub 会报错）
    _stub_mod.__version__ = "1.26.99"
    _stub_mod.__file__ = None
    _stub_mod.__path__ = []  # 让它看起来像 package（numpy/core 等子包 fallback 到我们 finder）
    _stub_mod.__spec__ = None
    # __getattr__ 拦截整个模块属性
    _stub_mod.__dict__.update(
        {
            # 常见常用符号显式赋值：避免 getattr(module, ...) 走模块的 __dict__ 查不到抛错
            "ndarray": type("ndarray", (), {}),
            "dtype": type("dtype", (), {}),
            "float32": "float32", "float64": "float64",
            "int8": "int8", "int16": "int16", "int32": "int32", "int64": "int64",
            "uint8": "uint8", "uint16": "uint16", "uint32": "uint32", "uint64": "uint64",
            "bool_": bool, "str_": str,
            "Inf": float("inf"), "inf": float("inf"),
            "NaN": float("nan"), "nan": float("nan"),
            "NINF": float("-inf"), "PINF": float("inf"),
            "pi": 3.141592653589793, "e": 2.718281828459045,
            # 常用函数
            "array": lambda *a, **k: None,
            "asarray": lambda *a, **k: None,
            "zeros": lambda *a, **k: None,
            "ones": lambda *a, **k: None,
            "empty": lambda *a, **k: None,
            "arange": lambda *a, **k: [],
            "linspace": lambda *a, **k: [],
            "concatenate": lambda *a, **k: None,
            "stack": lambda *a, **k: None,
            "reshape": lambda *a, **k: None,
            "sum": lambda *a, **k: 0,
            "mean": lambda *a, **k: 0,
            "exp": lambda *a, **k: 1,
            "log": lambda *a, **k: 0,
            "log10": lambda *a, **k: 0,
            "exp2": lambda *a, **k: 1,
            "sqrt": lambda *a, **k: 0,
            "nextafter": lambda *a, **k: a[0] if a else 0,
            "__stub_installed": True,
        }
    )

    def _stub_mod_getattr(name):  # type: ignore[override]
        # 模块级 __getattr__：一切未显式赋值属性返回 _stub_obj
        return _stub_obj

    _stub_mod.__getattr__ = _stub_mod_getattr  # type: ignore[assignment]
    sys.modules["numpy"] = _stub_mod

    # ================================================================
    # scipy / sklearn 也同样注入顶层 stub。
    # 原因：sklearn 1.3.x 的依赖链是 scikit-learn → scipy.sparse
    # scipy 是纯 C 扩展，import scipy.sparse 时会在 C 层调用
    # PyArray_ImportAPI()，这会要求真实 numpy 的 C-API PyCapsule
    # 对象存在。我们的 numpy stub 给不出这个对象 → scipy 会抛
    # "_ARRAY_API is not PyCapsule object"（虽然不是段错误，但也
    # 会让 VULNCLAW 启动失败）。
    # 由于 VULNCLAW 的 ML 分支已经在 high-risk 平台主动 disable，
    # 所以我们同样 stub scipy / sklearn，让第三方"import scipy"
    # 直接拿到空模块，永远不会去调 numpy C-API。
    # ================================================================
    def _install_pkg_stub(pkg_name: str) -> None:
        if pkg_name in sys.modules:
            return
        mod = _types.ModuleType(pkg_name)
        mod.__name__ = pkg_name
        mod.__version__ = "0.0.0-stub"
        mod.__file__ = None
        mod.__path__ = []
        mod.__spec__ = None
        so = _StubAttr(pkg_name)
        # 模块级 __getattr__ 兜底
        def _g(_name, _so=so):  # type: ignore[override]
            return _so
        mod.__getattr__ = _g  # type: ignore[assignment]
        sys.modules[pkg_name] = mod
        # 常见子包也先放进去（例如 scipy.sparse / sklearn.linear_model）
        # 我们用同一个 stub 对象就够了
        common_subs = ()
        if pkg_name == "scipy":
            common_subs = (
                "scipy.sparse", "scipy.linalg", "scipy.stats",
                "scipy.special", "scipy.optimize", "scipy.integrate",
                "scipy.signal", "scipy.interpolate", "scipy.ndimage",
                "scipy.cluster", "scipy.spatial", "scipy.fft",
                "scipy.io", "scipy.sparse.linalg",
            )
        elif pkg_name == "sklearn":
            common_subs = (
                "sklearn.linear_model", "sklearn.feature_extraction",
                "sklearn.feature_extraction.text",
                "sklearn.ensemble", "sklearn.tree", "sklearn.svm",
                "sklearn.neighbors", "sklearn.naive_bayes",
                "sklearn.model_selection", "sklearn.metrics",
                "sklearn.preprocessing", "sklearn.decomposition",
                "sklearn.pipeline", "sklearn.datasets",
                "sklearn.utils", "sklearn.utils._param_validation",
                "sklearn.base", "sklearn.exceptions", "sklearn.calibration",
                "sklearn.compose", "sklearn.covariance", "sklearn.cross_decomposition",
                "sklearn.discriminant_analysis", "sklearn.feature_selection",
                "sklearn.gaussian_process", "sklearn.inspection",
                "sklearn.isotonic", "sklearn.kernel_approximation",
                "sklearn.kernel_ridge", "sklearn.manifold",
                "sklearn.mixture", "sklearn.multiclass", "sklearn.multioutput",
                "sklearn.neural_network", "sklearn.quadratic_discriminant_analysis",
                "sklearn.random_projection", "sklearn.semi_supervised",
            )
        for sub_name in common_subs:
            if sub_name in sys.modules:
                continue
            sub = _types.ModuleType(sub_name)
            sub.__name__ = sub_name
            sub.__file__ = None
            sub.__path__ = []
            sub.__spec__ = None
            sub.__getattr__ = _g  # type: ignore[assignment]
            sys.modules[sub_name] = sub

    # 顺序：先装 scipy（sklearn import scipy），再装 sklearn
    _install_pkg_stub("scipy")
    _install_pkg_stub("sklearn")

    # --- 注册 meta path finder：拦截任何 "numpy*" / "scipy*" / "sklearn*" 开头的真实加载 ---
    class _BlockerFinder:
        @classmethod
        def _is_target(cls, name: str) -> bool:
            return (
                name == "numpy"
                or name.startswith("numpy.")
                or name == "scipy"
                or name.startswith("scipy.")
                or name == "sklearn"
                or name.startswith("sklearn.")
            )

        @classmethod
        def find_spec(cls, name, path=None, target=None):  # type: ignore[override]
            if not cls._is_target(name):
                return None
            if name in sys.modules:
                return None
            sub = _types.ModuleType(name)
            sub.__name__ = name
            sub.__file__ = None
            sub.__path__ = []
            sub.__spec__ = None
            so = _StubAttr(name)
            def _g(_name, _so=so): return _so  # type: ignore[override]
            sub.__getattr__ = _g  # type: ignore[assignment]
            sys.modules[name] = sub
            import importlib.util as _ilu
            return _ilu.spec_from_loader(name, _NullLoader(), is_package=True)

    class _NullLoader:
        def create_module(self, spec):  # type: ignore[override]
            return sys.modules.get(spec.name)

        def exec_module(self, module):  # type: ignore[override]
            return None

    # 把 blocker 放到 sys.meta_path 最前面
    sys.meta_path.insert(0, _BlockerFinder)  # type: ignore[arg-type]

    # --- sklearn / pandas 同级 stub（它们顶层 import numpy，现在 numpy 是 stub 就不会炸了）---
    # 注意：不需要真造 sklearn stub，因为 numpy=stub 已经在里面了，sklearn 初始化时
    # import numpy 会直接拿到我们的 stub 而不炸。对于 import sklearn 本身如果后续有报错
    # 由 vulnclaw.ai.core 的 try/except 正常降级。

    # 小提示（不占 stdout，不影响后续 CLI 输出格式）
    try:
        from vulnclaw.core.logger import _stub_note  # type: ignore
    except Exception:
        pass

