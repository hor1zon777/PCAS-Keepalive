#!/bin/sh
# pcas_keepalive docker entrypoint
#
# 目的：解决 docker-compose 用 bind mount (./data:/app/data) 时，
#   宿主机目录的 uid/gid 不等于容器内 app 用户的 uid/gid 而导致
#   "sqlite3.OperationalError: unable to open database file" 问题。
#
# 流程：
#   1. 以 root 身份启动（Dockerfile 里 USER 已改成 root）。
#   2. 创建 / 修正 /app/data 的所有权为 app:app。
#   3. 用 gosu 降权到 app 用户后执行 CMD。
#
# 这是 nginx / postgres 等官方镜像的通用模式，运行时仍然是非 root。

set -eu

DATA_DIR="${DATA_DIR:-/app/data}"

# 确保目录存在；bind mount 时通常已经被 docker 创建
mkdir -p "$DATA_DIR"

# 修正所有权（即便挂进来的目录原本是 root 或宿主 user，也归正到 app）
chown -R app:app "$DATA_DIR" 2>/dev/null || {
    echo "[entrypoint] warning: chown $DATA_DIR failed; sqlite 可能写不进去" >&2
}

# 降权运行 CMD
exec gosu app:app "$@"
