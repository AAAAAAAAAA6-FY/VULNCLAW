FROM python:3.11-slim

WORKDIR /app

# 系统依赖：git（模板/子模块更新）、nmap（内置主动检测引擎）
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# 先复制构建元数据与源码，利用层缓存
COPY pyproject.toml README.md scan.py ./
COPY src/ ./src/

# 安装项目与全部运行依赖（基于 pyproject，不依赖 requirements.txt）
# 注意：不 COPY thirdparty，避免镜像膨胀；引擎会通过 capability 探测自动降级缺失工具
RUN pip install --no-cache-dir .

# AI 模型凭证通过环境变量注入（compose 的 env_file / docker run -e），不进镜像
ENTRYPOINT ["python", "scan.py"]
