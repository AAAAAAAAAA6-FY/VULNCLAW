# VULNCLAW 生产部署指南（Docker Compose）

> **重要声明**：以下所有容器操作（build / up / down / 重启恢复 / 健康检查实跑）**需在具备 Docker daemon 的环境执行**。本仓库当前开发机无 Docker CLI/daemon（`python scripts/lab_preflight.py` 如实返回 exit 2），未实跑 build/up，仅完成静态验收与离线测试（`tests/test_deployment_static.py`）。

## 1. 最小生产部署

```bash
# 1) 准备环境变量
cp .env.example .env
# 编辑 .env：填 AI_MODEL_CONFIGS / AI_API_KEY，按需设 DANGEROUS_MODE（默认 deny）
# 若有自部署 interactsh，填 OOB_INTERACTSH_SERVER=https://oob.example.com

# 2) 构建并启动（redis + master + 2 worker）
docker compose build
docker compose up -d

# 3) 健康检查
docker compose ps                          # redis 应显示 healthy
docker compose exec redis redis-cli ping   # PONG
docker compose logs --tail=50 master
docker compose logs --tail=50 worker

# 4) 提交一次扫描（单机模式示例）
docker compose run --rm master python scan.py -t https://TARGET.example.com

# 5) 停止 / 清理
docker compose down                        # 保留卷
docker compose down -v                     # 连同 redis 数据与扫描数据卷一起删除
```

扩容 worker：`docker compose up -d --scale worker=4`。

## 2. 环境变量注入

compose 对 master 与 worker 均做三层注入（优先级从高到低）：

| 层 | 内容 | 说明 |
|---|---|---|
| `environment:` | `REDIS_URL=redis://redis:6379/0` | 固定指向容器网络内的 redis 服务，**覆盖** `.env` 中默认的 `localhost:6379` |
| `environment:` | `DANGEROUS_MODE=${DANGEROUS_MODE:-deny}` | 危险操作总开关，默认 deny |
| `environment:` | `OOB_INTERACTSH_SERVER=${OOB_INTERACTSH_SERVER:-}` | OOB 自部署 interactsh 服务 |
| `env_file:` | `.env`（`required: false`，缺失可容忍） | AI 凭证与其余配置透传 |

**OOB 说明**：`OOB_INTERACTSH_SERVER` 同时传入 master 与 worker；实际带外回调探测发生在 **worker 侧**（`core/oob_channel.py` 消费该变量，`interactsh-client` 以 `-server` 指向自部署服务）。未配置时离线扫描不受影响（自动走公共/备用通道或降级）。**真实 OOB 回调可用性必须在授权环境中验证**——健康检查（`python scan.py health`）只做离线配置诊断，不会伪造 OOB 成功。

## 3. 日志 / 报告 / 临时文件位置与清理

master 与 worker 均挂载命名卷 `scan-data:/app/_runtime_cache`（与代码内 `PROJECT_CACHE_DIR` 对齐）：

| 路径（容器内） | 内容 |
|---|---|
| `/app/_runtime_cache/reports` | 扫描报告（`OUTPUT_DIR` 默认值） |
| `/app/_runtime_cache/logs` | 运行日志 |
| `/app/_runtime_cache/dag_dead_letter/` | DAG 死信队列（`<scan_id>.jsonl`） |
| `/app/_runtime_cache/cookies` | 运行时 Cookie 缓存 |

容器内进程退出时 `TMP_DIR`（mkdtemp）由 `atexit` 清理，容器销毁后随之消失；持久数据都在 `scan-data` 卷内。

清理策略：
- 单次扫描数据：`docker compose run --rm` 跑一次性任务，结束后容器自动删除。
- 卷整体清理：`docker compose down -v`（删除 `scan-data` 与 `redis-data`，**不可逆**）。
- 仅清死信队列：`docker compose exec master sh -c 'rm -f /app/_runtime_cache/dag_dead_letter/*.jsonl'`。
- 滚动日志：建议在宿主机 cron 中对卷内 `logs/` 按大小轮转，或限制 `DEBUG=false` 减少输出量。

## 4. 故障恢复

### 4.1 worker 崩溃自动拉起
master / worker / redis 均配置 `restart: unless-stopped`。验证步骤（需 Docker 环境）：
```bash
docker compose kill worker          # 模拟 worker 崩溃
docker compose ps                   # worker 应自动重启（Restarting/Up）
docker compose logs --tail=20 worker
```

### 4.2 死信队列（DAG 失败任务）
重试耗尽的 DAG 节点写入 `_runtime_cache/dag_dead_letter/<scan_id>.jsonl`（每行一条 JSON：node_id / error / retries / ts）。查看：
```bash
docker compose exec master sh -c 'ls /app/_runtime_cache/dag_dead_letter/'
docker compose exec master cat /app/_runtime_cache/dag_dead_letter/<scan_id>.jsonl
```
逻辑已被 `tests/test_dag_retry.py` 离线覆盖（重试成功 / 耗尽入 DLQ / 上游失败下游 SKIPPED）。

### 4.3 资源与并发控制
- 容器资源上限：redis `mem_limit: 512m` / master `2g` / worker `4g`；cpus 分别 1.0 / 2.0 / 3.0（compose 文件内调整）。
- 扫描并发：`.env` 中 `MAX_CONCURRENT`、`ADAPTIVE_CONCURRENCY_MAX`（默认 20）、`RPS` 限流、`MAX_SCAN_TIME` 单目标时长上限。
- worker 数量：`--scale worker=N`，注意宿主机内存（每 worker 上限 4g）。
- 阶段预算：`PHASE_TIMEOUT_*_S` 系列控制各扫描阶段墙钟上限。

## 5. 部署前自检（离线）
```bash
python scripts/lab_preflight.py   # 有 Docker 时 exit 0；无 Docker 时如实 exit 2（blocked）
python -m pytest tests/test_deployment_static.py tests/test_dag_retry.py -q
```

## 6. 待在 Docker 环境真实执行的验收清单（开发机 blocked）
- [ ] `docker compose build` 成功（python:3.11-slim + `.[full]` 依赖安装）
- [ ] `docker compose up -d` 后 redis healthy，master/worker 正常注册
- [ ] `docker compose kill worker` → 自动重启
- [ ] `docker compose down` / `down -v` 数据卷行为符合预期
- [ ] 配置 `OOB_INTERACTSH_SERVER` 后在授权目标上验证真实带外回调
- [ ] `--scale worker=4` 下分布式扫描负载均衡与结果汇总
