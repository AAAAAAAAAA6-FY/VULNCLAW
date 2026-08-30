# Quick Start：从零到第一份漏洞报告

本指南假定你在一台干净的机器上，目标是用最少步骤跑通一次完整扫描并拿到报告。

---

## 0. 前置条件

| 项 | 要求 |
|---|---|
| Python | ≥ 3.12 |
| 网络 | 能访问目标站点 + 至少一个 AI Provider API |
| 可选 | Redis（仅分布式模式需要）、Docker（仅容器化部署需要） |

> AI 是"降低误报"的环节，不是扫描的前置条件：没有 API Key 也能跑，只是漏洞全部为"未经验证"。

---

## 1. 安装（3 条命令）

```bash
git clone <your-repo-url> pentest_platform && cd pentest_platform

python -m venv venv
# Windows
venv\Scripts\python.exe -m pip install -e .
# Linux / macOS
venv/bin/python -m pip install -e .
```

验证安装：

```bash
python scan.py health
```

健康检查会报告 Python 版本、AI Provider、第三方工具（nuclei / ffuf / subfinder 等）可用性。
**缺失的第三方工具不会阻断运行**，对应检测能力自动降级（报告中会体现）。
若 AI 未配置，此处会提示关键项缺失——按下一节配置即可。

---

## 2. 配置 AI（可选但强烈建议）

复制模板并填入 Key：

```bash
cp .env.example .env
```

最简配置（单模型）：

```env
AI_API_KEY=your_api_key_here
AI_API_BASE=https://open.bigmodel.cn/api/paas/v4/
AI_MODELS=["1"]
```

推荐配置（多模型交叉验证，显著降低误报）：

```env
AI_MODEL_ALIASES={"1":"glm-4-flash","2":"qwen-plus-2025-07-28","4":"deepseek-ai/DeepSeek-V3.1-Terminus","5":"glm-4.7"}
AI_MODEL_CONFIGS={"glm-4-flash":{"api_key":"...","base_url":"https://open.bigmodel.cn/api/paas/v4/"}}
AI_MODELS=["1","2","4","5"]
PROVIDER_PRIORITY=["zhipu","aliyun","siliconflow"]
```

完整变量清单见 `.env.example`。`.env` 已被 gitignore，**切勿提交**。

---

## 3. 第一次扫描

```bash
python scan.py scan -t https://example.com
```

旧参数风格同样支持（两种写法等价）：

```bash
python scan.py -t https://example.com
```

### 关于测试靶场

请对你**有授权**的目标扫描。可用的练习靶场：

- `https://httpbin.org` —— 公开可达，适合冒烟验证整个链路
- 本地 DVWA / Juice Shop / VulnHub —— 推荐，漏洞样本丰富

> 注意：`testphp.vulnweb.com` 等 vulnweb.com 全系目标目前不可达（DNS 可解析但 TCP 不通），
> 老文档里的示例需要替换。

### 常用参数

```bash
python scan.py scan -t <目标URL> \
    --max-tasks 100 \              # 最大任务数
    --initial-qps 2 \              # 初始 QPS（对目标友好，默认 2）
    --deep \                       # 深度利用链（默认只生成 POC，不执行）
    --dangerous \                  # 危险模式：实际执行利用（见下方警告）
    --proxy http://127.0.0.1:8080 \ # 走 Burp 代理
    --dag --agents 6               # DAG 多 Agent 并行（单目标吞吐首选）
```

> ⚠️ `--deep` 默认**只生成 POC 不执行利用**。真正执行利用需要显式加 `--dangerous`，
> 且所有危险操作受权限门卫控制（见 `docs/mcp_integration.md` 的"危险操作门卫"一节）。

---

## 4. 查看报告

扫描结束后报告输出到 `_runtime_cache/reports/`：

```
_runtime_cache/reports/
├── report_<target>_<timestamp>.json    # 结构化数据（含 curl 复现命令、CWE、修复建议）
└── report_<target>_<timestamp>.html    # 可视化报告（严重性分布图 + 类型饼图 + 筛选）
```

浏览器直接打开 HTML 即可。每条漏洞包含：

- `curl_command` —— 可直接复制执行的复现命令
- `reproduction_steps` —— 人类可读的复现步骤
- `cwe` / `owasp` / `remediation` —— 分类与修复建议
- `confidence` —— AI 交叉验证后的置信度
- `cross_confirmed` —— 是否被双源确认（引擎 + Burp）

浏览器 Dashboard（查看历史扫描与发起新扫描）：

```bash
python -m vulnclaw.dashboard.server
```

---

## 5. 进阶场景

### 代码安全审计（Semgrep + CodeQL + 依赖 CVE）

```bash
# 本地仓库
python scan.py code --repo /path/to/repo --lang python

# 远程仓库
python scan.py code --repo https://github.com/org/repo.git --lang python
```

审计摘要落盘在 `_runtime_cache/reports/code_audit_summary.json`（MCP 与外部程序读取）。

### 分布式多节点（需 Redis）

```bash
python scan.py --distributed --master --redis-url redis://localhost:6379/0
python scan.py --distributed --worker --redis-url redis://localhost:6379/0
```

提交端（自动收集子域，<50 个自动降级单机）：

```bash
python scan.py --distributed -t https://example.com
```

### Docker 一键部署（Redis + Master + 2 Worker）

```bash
docker compose up -d --build
docker compose scale worker=4     # 扩容
docker compose down               # 停止
```

AI 凭证：把本机 `.env` 放到 compose 同目录即自动注入（`env_file` 为可选，没有也能启动，仅能力降级）。

---

## 6. 常见问题

**Q：没有 AI Key 能跑吗？**
能。扫描、引擎检测、报告全部正常，只是漏洞不会被 AI 交叉验证（置信度为空、误报率上升）。

**Q：第三方工具（nuclei/ffuf/sqlmap）缺失怎么办？**
自动降级跳过对应能力，`scan.py health` 会明确列出缺失项。引擎本身不依赖它们。

**Q：扫描很慢 / 目标被打挂？**
默认 QPS 为 2 且带 429 指数退避与冷却。调低用 `--initial-qps 1`，调高用 `--initial-qps 10`。

**Q：Windows 上中文输出乱码？**
设置 `PYTHONIOENCODING=utf-8`，或用项目提供的 `start_vulnclaw.ps1` 启动脚本。

**Q：危险操作被拒绝（danger_denied）？**
这是权限门卫的默认行为。加 `--dangerous`，或设置 `DANGEROUS_MODE=allow`，
或只放行单项 `DANGEROUS_ALLOW=exploit_verify`。
