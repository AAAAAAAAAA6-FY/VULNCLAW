# CONTRIBUTING.md — 贡献指南

感谢参与 pentest_platform！本文档帮你快速上手开发。

---

## 目录

- [开发环境搭建](#开发环境搭建)
- [代码规范](#代码规范)
- [5 分钟写一个新引擎](#5-分钟写一个新引擎)
- [5 分钟写一个新测试](#5-分钟写一个新测试)
- [目录职责边界（红线）](#目录职责边界红线)
- [提交规范](#提交规范)
- [PR 检查清单](#pr-检查清单)

---

## 开发环境搭建

```bash
git clone <repo> && cd pentest_platform
python -m venv .venv && .venv\Scripts\activate    # Windows
pip install -e .[dev]
pre-commit install
```

验证环境 OK：

```bash
python scan.py --help        # 能打印参数表即环境正常
python -m py_compile scan.py
```

## 代码规范

- **格式化/静态检查**：ruff（line-length=140, target py312）。提交前 `pre-commit` 自动执行 `ruff-format` + `ruff` + `py_compile`。
- **路径**：任何运行时路径一律从 `core.settings.PROJECT_ROOT` / `PROJECT_CACHE_DIR` 派生，**禁止 `os.getcwd()` 假设**。
- **日志**：统一 `from core.logger import logger`；跨终端输出避免非 UTF-8 终端乱码，面向运行日志的消息优先 ASCII。
- **异步**：模块内 async 函数禁止裸 `asyncio.get_event_loop()`；用 `asyncio.get_running_loop()` 或 `asyncio.to_thread`。
- **AI 调用**：必须经 `ai.core.get_llm_client` 门面，禁止直接实例化 provider client。
- **提交门槛**：`pre-commit run -a` 全绿 + 新增功能附带 pytest 用例。

## 5 分钟写一个新引擎

引擎是插件：**新建一个类继承 `BaseEngine` 即可**，`core/scanner.py:_load_engines` 会自动扫描装配，无需改任何主流程。

**第 1 步**：在 `engines/` 下任选既有模块文件（或新建 `my_engines.py`），添加：

```python
# engines/my_engines.py
from typing import Dict, List, Optional, Tuple
from engines.base import BaseEngine


class DemoEngine(BaseEngine):
    name = "demo_leak"                       # 唯一标识（调度/打分用）
    description = "演示：检测响应头中的敏感信息泄露"
    priority_params = ["debug", "test"]       # 命中这些参数时优先使用全量 payload

    # (payload, 描述) 对；check 里按需消费
    payloads = [
        ("debug=1", "尝试开启调试模式"),
        ("test=1", "测试参数探测"),
    ]

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],   # (status, body, headers) 基线响应
        parsed_query: str,
        session,
        **kwargs,
    ) -> Optional[Dict]:
        """对单个参数执行检测；命中返回 finding dict，未命中返回 None。"""
        attack_url = f"{url}?{parsed_query}&debug=1"
        status, body, headers = await self.async_request(attack_url, session)  # 用基类工具发请求

        if "X-Debug-Info" in (headers or {}):
            return {
                "type": "InfoLeak",           # 漏洞类型
                "severity": "Medium",         # Critical/High/Medium/Low/Info
                "url": attack_url,
                "parameter": param,
                "evidence": f"响应头泄露调试信息: {headers['X-Debug-Info']}",
                "engine": self.name,
            }
        return None
```

**第 2 步**：验证加载：

```bash
python -c "from core.scanner import _load_engines; es,_ = _load_engines(); print([e.name for e in es if 'demo' in e.name])"
```

输出包含 `demo_leak` 即接入成功（引擎会被任务生成与 bundle 调度自动使用）。

**要点**：
- `check()` 是参数级检测入口（由 `_execute_engine_check` 驱动）；`scan()` 是全站级入口（可选，默认返回空）。
- 只返回"规则层命中"，AI 判定/去误报由编排器的验证阶段统一处理，引擎内不要调 LLM。
- payload 数量建议 ≤ `max_payloads`（默认 20），大字典走 `get_payloads()` 的缓存与裁剪。

## 5 分钟写一个新测试

测试放 `tests/`（pytest）：

```python
# tests/test_unit_engines.py
import pytest

def test_demo_engine_check_hits():
    from engines.my_engines import DemoEngine
    eng = DemoEngine()
    # ... 构造 mock session / 基线响应，断言 check() 返回 finding
```

运行：

```bash
pytest -q
pytest --cov -q          # 覆盖率报告
```

> 测试不得依赖外网与真实 AI API；LLM 相关测试一律 mock `ai.core.get_llm_client`。

## 目录职责边界（红线）

| 目录 | 职责 | 禁止 |
|---|---|---|
| `engines/` | 单点检测逻辑（规则层） | 调 LLM、依赖 orchestrator、跨引擎互相 import |
| `modules/` | 侦察/采集/外部工具封装 | import `ai.v100`（反向依赖） |
| `ai/v100/` | 编排、任务调度、AI 验证 | 直接 import modules 内部私有函数（走 `modules/__init__.py` 门面） |
| `core/` | 框架设施（日志/持久化/会话） | 包含任何目标特定业务逻辑 |
| `phases/` | orchestrator 阶段实现 | 新增方法必须加进该模块 `__all__`（`bind_phase_methods` 依赖它绑定） |

三条硬性红线（PR 不满足直接打回）：
1. `engines/` 每个引擎独立可测，不依赖运行中的扫描上下文。
2. `modules/` 不 import orchestrator。
3. 所有 AI 调用必须经 `ai.core.get_llm_client`。

## 提交规范

```
<type>: <简要描述>

<body: 改了什么、为什么、影响面>
```

常用 type：`feat`（新功能）/ `fix`（修复）/ `perf`（性能）/ `refactor`（重构）/ `test`（测试）/ `docs`（文档）/ `chore`（工程化）。

示例：

```
fix: 修复 ffuf 返回 dict 时目录拼接导致的 TypeError

run_ffuf_async 返回 List[Dict]，orchestrator 步骤 6/10 原先按 str
拼接报 "can only concatenate str (not dict) to str"。新增 _dir_path()
兼容 dict/str 两种形态。
```

## PR 检查清单

- [ ] `pre-commit run -a` 全绿
- [ ] 新增/修改的模块 `py_compile` 通过
- [ ] 新功能附带 pytest 用例（不依赖外网/真实 AI）
- [ ] 无 `os.getcwd()` 新增；运行时产物只写 `_runtime_cache/`
- [ ] 未引入新的跨层依赖（见红线）
- [ ] 敏感信息（api_key / cookie / 目标 URL）未提交；`.env` 保持 ignore
- [ ] 中文文档同步更新（README 相关段落）

---

再次感谢贡献！有问题先看 [README FAQ](README.md)，或在 Issue 中讨论方案后再动手。
