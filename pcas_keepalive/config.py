from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8765

    session_secret: str = "change-me-to-a-random-32-char-string-please"
    local_key_hex: str = "00" * 32

    pcas_base_url: str = "https://cloudpc.ecloud.10086.cn"
    http_timeout: int = 15

    debug_dump_payload: bool = False
    cem_rsa_enabled: bool = True

    db_path: str = "pcas.db"
    base_dir: Path = Path(__file__).resolve().parent

    # ---------- 桌面保活参数 ----------
    # 每台 running 机器周期性建立 ZTEC 桌面连接（ZTEC + TLS + cs_suOperDesktop + 维持 TCP）
    # 断线指数退避重连（initial → max）
    forever_cmss_desktop_interval_sec: int = 600    # 每次桌面连接维持时长（10min）
    forever_reconnect_initial_backoff_sec: float = 1.0
    forever_reconnect_max_backoff_sec: float = 60.0
    forever_machine_refresh_interval_sec: int = 300  # 5min 重拉机器列表 reconcile runners


@lru_cache
def get_settings() -> Settings:
    return Settings()
