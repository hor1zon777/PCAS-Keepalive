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


@lru_cache
def get_settings() -> Settings:
    return Settings()
