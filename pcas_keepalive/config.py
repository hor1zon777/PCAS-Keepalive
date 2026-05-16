from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8765

    session_secret: str = "change-me-to-a-random-32-char-string-please"
    local_key_hex: str = "00" * 32

    pcas_base_url: str = "https://cloudpc.ecloud.10086.cn"
    http_timeout: int = 15

    default_keepalive_interval: int = 20
    keepalive_window: str = ""

    debug_dump_payload: bool = False
    cem_rsa_enabled: bool = True

    # eCloud OpenAPI 签名（query string 形式：SignatureMethod=HmacSHA1, SignatureVersion=1.0）
    pcas_sign_enabled: bool = False
    ecloud_access_key: str = ""
    ecloud_secret_key: str = ""

    db_path: str = "pcas.db"
    base_dir: Path = Path(__file__).resolve().parent

    # ---------- 保活模式 ----------
    # 'forever': 每台 running 机器维持常驻 cem 长连接 + 25s REST 辅助心跳，断线指数退避重连
    # 'daily':   每 23h 跑一次 30s cem 短打卡（旧策略，资源敏感场景用）
    keepalive_default_mode: Literal["daily", "forever"] = "forever"

    # forever 模式相关参数
    forever_cem_heartbeat_sec: int = 5              # cem stream 心跳 5s 一次（与 Android 抓包一致）
    forever_rest_heartbeat_sec: int = 25            # REST 辅助心跳 25s 一次（接近 Go --forever 项目的节奏）
    forever_machine_perf_interval_sec: int = 300    # /machine/performance/batch 5min
    forever_device_perf_interval_sec: int = 1800    # /device/performance/batch 30min
    forever_desktop_status_interval_sec: int = 300  # /user/getDesktopStatus 5min
    forever_token_refresh_interval_sec: int = 6 * 3600  # 主动刷 token 6h
    forever_reconnect_initial_backoff_sec: float = 1.0
    forever_reconnect_max_backoff_sec: float = 60.0
    forever_machine_refresh_interval_sec: int = 300  # 5min 重拉机器列表 reconcile runners


@lru_cache
def get_settings() -> Settings:
    return Settings()
