# syntax=docker/dockerfile:1.7
# ──────────────────────────────────────────────────────────────────────────────
# pcas_keepalive Dockerfile (uv multi-stage)
#
# 镜像分为 builder 与 runtime 两阶段：
#   builder：用 uv 官方镜像（含 uv + python 3.12）安装锁定依赖到 .venv
#   runtime：用纯 python:3.12-slim 把 .venv + 源码 copy 过来，仅运行 uvicorn
# ──────────────────────────────────────────────────────────────────────────────

#--- builder ------------------------------------------------------------------
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

# uv 调优
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

# 先 copy lock + manifest，最大化 docker layer 缓存
COPY pyproject.toml uv.lock ./

# 仅安装运行时依赖（--no-dev 跳过 ruff），--frozen 强制走 lock 文件
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

#--- runtime ------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

# 安装运行所需系统包（curl 仅给 healthcheck 用）+ 创建非 root 用户
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system app \
 && useradd  --system --gid app --home-dir /app --shell /usr/sbin/nologin app

WORKDIR /app

# 从 builder 拷贝预装好的 venv
COPY --from=builder --chown=app:app /app/.venv /app/.venv

# 拷贝源码（.dockerignore 会过滤掉本地 db / .env / .venv）
COPY --chown=app:app . /app

# 让容器内 python 直接走 venv 的解释器
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # 默认容器内绑全网卡 + 持久化目录
    HOST=0.0.0.0 \
    PORT=8765 \
    DB_PATH=/app/data/pcas.db

# 持久化目录（compose 通常会 volume 覆盖此处）
RUN install -d -o app -g app /app/data

USER app

EXPOSE 8765

# 用 curl 探活 /healthz；--fail 让非 2xx 直接退出非零
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl --fail --silent --show-error http://127.0.0.1:${PORT}/healthz || exit 1

# 直接走 main.py（内部读取 settings.host/port 启动 uvicorn）
CMD ["python", "main.py"]
