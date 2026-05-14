"""SQLite 数据访问层（标准 sqlite3，不依赖 ORM）。

表结构：
  admin_users       平台管理员（页面访问鉴权）
  accounts          移动云账号 + 加密密码 + 当前 token
  machines          缓存的机器列表
  keepalive_tasks   每个机器一行；enabled/interval/last_run_at
  operation_logs    所有操作历史
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

DDL = """
CREATE TABLE IF NOT EXISTS admin_users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    last_login_at   INTEGER,
    created_at      INTEGER DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE TABLE IF NOT EXISTS accounts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mobile          TEXT UNIQUE NOT NULL,
    password_blob   TEXT NOT NULL,
    device_id       TEXT NOT NULL,
    cem_token       TEXT,
    access_ticket   TEXT,
    login_uid       TEXT,
    last_login_at   INTEGER,
    last_error      TEXT,
    created_at      INTEGER DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE TABLE IF NOT EXISTS machines (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id      INTEGER NOT NULL,
    machine_id      TEXT NOT NULL,
    machine_name    TEXT,
    instance_id     TEXT,
    resource_id     TEXT,
    vm_id           TEXT,
    status          TEXT,
    raw_json        TEXT,
    last_seen_at    INTEGER DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
    UNIQUE(account_id, machine_id)
);

CREATE TABLE IF NOT EXISTS keepalive_tasks (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id          INTEGER NOT NULL,
    machine_id          TEXT NOT NULL,
    enabled             INTEGER DEFAULT 1,
    interval_minutes    INTEGER DEFAULT 20,
    delay_minutes       INTEGER DEFAULT 1440,
    last_run_at         INTEGER,
    last_status         TEXT,
    last_message        TEXT,
    UNIQUE(account_id, machine_id)
);

CREATE TABLE IF NOT EXISTS operation_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id      INTEGER,
    machine_id      TEXT,
    op              TEXT NOT NULL,
    ok              INTEGER NOT NULL,
    detail          TEXT,
    created_at      INTEGER DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE INDEX IF NOT EXISTS idx_logs_acct_time ON operation_logs(account_id, created_at DESC);
"""


_DB_PATH: Path | None = None


def init(db_path: str | Path) -> None:
    global _DB_PATH
    _DB_PATH = Path(db_path)
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    # journal_mode=WAL 是持久设置（写入文件头），只需 init 时设一次。
    # WAL 模式下读写不互相阻塞，单写多读，比默认 DELETE 模式锁竞争小很多。
    with sqlite3.connect(_DB_PATH) as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
    with conn() as c:
        c.executescript(DDL)


@contextmanager
def conn():
    assert _DB_PATH is not None, "db.init() must be called first"
    c = sqlite3.connect(_DB_PATH)
    c.row_factory = sqlite3.Row
    # foreign_keys 是 per-connection 开关，必须每次 connect 后启用。
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    finally:
        c.close()


# ---------- admin users（平台访问鉴权） ----------

_PBKDF2_ITER = 200_000
_PBKDF2_ALGO = "sha256"
_SALT_LEN = 16


def _hash_password(password: str) -> str:
    """pbkdf2_hmac-sha256(200k) — 标准库即可，不引入 bcrypt 依赖。

    存储格式：pbkdf2$<algo>$<iterations>$<salt_hex>$<hash_hex>
    """
    salt = os.urandom(_SALT_LEN)
    digest = hashlib.pbkdf2_hmac(_PBKDF2_ALGO, password.encode("utf-8"), salt, _PBKDF2_ITER)
    return f"pbkdf2${_PBKDF2_ALGO}${_PBKDF2_ITER}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        scheme, algo, iters_str, salt_hex, hash_hex = stored.split("$", 4)
        if scheme != "pbkdf2":
            return False
        iters = int(iters_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        return False
    actual = hashlib.pbkdf2_hmac(algo, password.encode("utf-8"), salt, iters)
    return hmac.compare_digest(actual, expected)


def has_admin() -> bool:
    """是否已设置任何管理员（用于决定是否进入 setup 引导）。"""
    with conn() as c:
        row = c.execute("SELECT COUNT(*) AS n FROM admin_users").fetchone()
        return row["n"] > 0


def create_admin(username: str, password: str) -> int:
    username = username.strip()
    if not username or len(username) < 3:
        raise ValueError("用户名至少 3 个字符")
    if len(password) < 6:
        raise ValueError("密码至少 6 个字符")
    pwd_hash = _hash_password(password)
    with conn() as c:
        c.execute(
            "INSERT INTO admin_users(username, password_hash) VALUES(?, ?)",
            (username, pwd_hash),
        )
        return c.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]


def verify_admin(username: str, password: str) -> int | None:
    """凭证正确返回 admin id，错误返回 None。"""
    with conn() as c:
        row = c.execute(
            "SELECT id, password_hash FROM admin_users WHERE username=?",
            (username.strip(),),
        ).fetchone()
    if not row:
        return None
    if not _verify_password(password, row["password_hash"]):
        return None
    with conn() as c:
        c.execute(
            "UPDATE admin_users SET last_login_at=? WHERE id=?",
            (int(time.time()), row["id"]),
        )
    return row["id"]


def get_admin(admin_id: int) -> dict | None:
    with conn() as c:
        row = c.execute(
            "SELECT id, username, last_login_at, created_at FROM admin_users WHERE id=?",
            (admin_id,),
        ).fetchone()
        return dict(row) if row else None


def change_admin_password(admin_id: int, old_password: str, new_password: str) -> bool:
    with conn() as c:
        row = c.execute(
            "SELECT password_hash FROM admin_users WHERE id=?", (admin_id,)
        ).fetchone()
        if not row or not _verify_password(old_password, row["password_hash"]):
            return False
        if len(new_password) < 6:
            raise ValueError("新密码至少 6 个字符")
        c.execute(
            "UPDATE admin_users SET password_hash=? WHERE id=?",
            (_hash_password(new_password), admin_id),
        )
    return True


# ---------- accounts ----------

def upsert_account(
    mobile: str,
    password_blob: str,
    device_id: str,
) -> int:
    with conn() as c:
        row = c.execute(
            "SELECT id, device_id FROM accounts WHERE mobile=?", (mobile,)
        ).fetchone()
        if row:
            c.execute(
                "UPDATE accounts SET password_blob=?, device_id=COALESCE(device_id, ?) "
                "WHERE id=?",
                (password_blob, device_id, row["id"]),
            )
            return row["id"]
        c.execute(
            "INSERT INTO accounts(mobile, password_blob, device_id) VALUES(?,?,?)",
            (mobile, password_blob, device_id),
        )
        return c.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]


def update_account_session(
    account_id: int,
    cem_token: str | None,
    access_ticket: str | None,
    login_uid: str | None,
    last_error: str | None = None,
) -> None:
    with conn() as c:
        c.execute(
            "UPDATE accounts SET cem_token=?, access_ticket=?, login_uid=?, "
            "last_login_at=?, last_error=? WHERE id=?",
            (cem_token, access_ticket, login_uid, int(time.time()), last_error, account_id),
        )


def get_account(account_id: int) -> dict | None:
    with conn() as c:
        row = c.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        return dict(row) if row else None


def get_account_by_mobile(mobile: str) -> dict | None:
    with conn() as c:
        row = c.execute("SELECT * FROM accounts WHERE mobile=?", (mobile,)).fetchone()
        return dict(row) if row else None


def list_accounts() -> list[dict]:
    with conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT id, mobile, login_uid, last_login_at, last_error FROM accounts ORDER BY id"
        )]


def delete_account(account_id: int) -> None:
    with conn() as c:
        c.execute("DELETE FROM keepalive_tasks WHERE account_id=?", (account_id,))
        c.execute("DELETE FROM machines WHERE account_id=?", (account_id,))
        c.execute("DELETE FROM operation_logs WHERE account_id=?", (account_id,))
        c.execute("DELETE FROM accounts WHERE id=?", (account_id,))


# ---------- machines ----------

def upsert_machine(
    account_id: int,
    machine_id: str,
    machine_name: str | None,
    status: str | None,
    extras: dict[str, Any] | None = None,
    raw_json: str | None = None,
) -> None:
    extras = extras or {}
    with conn() as c:
        row = c.execute(
            "SELECT id FROM machines WHERE account_id=? AND machine_id=?",
            (account_id, machine_id),
        ).fetchone()
        now = int(time.time())
        if row:
            c.execute(
                "UPDATE machines SET machine_name=?, instance_id=?, resource_id=?, "
                "vm_id=?, status=?, raw_json=?, last_seen_at=? WHERE id=?",
                (
                    machine_name,
                    extras.get("instanceId"),
                    extras.get("resourceId"),
                    extras.get("vmId"),
                    status,
                    raw_json,
                    now,
                    row["id"],
                ),
            )
        else:
            c.execute(
                "INSERT INTO machines(account_id, machine_id, machine_name, "
                "instance_id, resource_id, vm_id, status, raw_json, last_seen_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    account_id, machine_id, machine_name,
                    extras.get("instanceId"), extras.get("resourceId"),
                    extras.get("vmId"), status, raw_json, now,
                ),
            )


def list_machines(account_id: int) -> list[dict]:
    with conn() as c:
        return [
            dict(r)
            for r in c.execute(
                "SELECT * FROM machines WHERE account_id=? ORDER BY machine_name",
                (account_id,),
            )
        ]


def get_machine(account_id: int, machine_id: str) -> dict | None:
    with conn() as c:
        row = c.execute(
            "SELECT * FROM machines WHERE account_id=? AND machine_id=?",
            (account_id, machine_id),
        ).fetchone()
        return dict(row) if row else None


# ---------- keepalive tasks ----------

def upsert_task(
    account_id: int,
    machine_id: str,
    enabled: bool = True,
    interval_minutes: int = 20,
    delay_minutes: int = 1440,
) -> None:
    with conn() as c:
        row = c.execute(
            "SELECT id FROM keepalive_tasks WHERE account_id=? AND machine_id=?",
            (account_id, machine_id),
        ).fetchone()
        if row:
            c.execute(
                "UPDATE keepalive_tasks SET enabled=?, interval_minutes=?, "
                "delay_minutes=? WHERE id=?",
                (int(enabled), interval_minutes, delay_minutes, row["id"]),
            )
        else:
            c.execute(
                "INSERT INTO keepalive_tasks(account_id, machine_id, enabled, "
                "interval_minutes, delay_minutes) VALUES(?,?,?,?,?)",
                (account_id, machine_id, int(enabled), interval_minutes, delay_minutes),
            )


def list_active_tasks() -> list[dict]:
    with conn() as c:
        return [
            dict(r)
            for r in c.execute(
                "SELECT t.*, a.mobile FROM keepalive_tasks t "
                "JOIN accounts a ON a.id = t.account_id WHERE t.enabled=1"
            )
        ]


def list_tasks_by_account(account_id: int) -> list[dict]:
    with conn() as c:
        return [
            dict(r)
            for r in c.execute(
                "SELECT * FROM keepalive_tasks WHERE account_id=? ORDER BY machine_id",
                (account_id,),
            )
        ]


def get_task(account_id: int, machine_id: str) -> dict | None:
    with conn() as c:
        row = c.execute(
            "SELECT * FROM keepalive_tasks WHERE account_id=? AND machine_id=?",
            (account_id, machine_id),
        ).fetchone()
        return dict(row) if row else None


def update_task_run_state(
    account_id: int, machine_id: str, status: str, message: str | None
) -> None:
    with conn() as c:
        c.execute(
            "UPDATE keepalive_tasks SET last_run_at=?, last_status=?, "
            "last_message=? WHERE account_id=? AND machine_id=?",
            (int(time.time()), status, message, account_id, machine_id),
        )


def set_task_enabled(account_id: int, machine_id: str, enabled: bool) -> None:
    with conn() as c:
        c.execute(
            "UPDATE keepalive_tasks SET enabled=? WHERE account_id=? AND machine_id=?",
            (int(enabled), account_id, machine_id),
        )


def delete_task(account_id: int, machine_id: str) -> None:
    with conn() as c:
        c.execute(
            "DELETE FROM keepalive_tasks WHERE account_id=? AND machine_id=?",
            (account_id, machine_id),
        )


# ---------- operation logs ----------

def add_log(
    account_id: int | None,
    machine_id: str | None,
    op: str,
    ok: bool,
    detail: str | None = None,
) -> None:
    with conn() as c:
        c.execute(
            "INSERT INTO operation_logs(account_id, machine_id, op, ok, detail) "
            "VALUES(?,?,?,?,?)",
            (account_id, machine_id, op, int(ok), detail),
        )


def list_logs(account_id: int | None = None, limit: int = 100) -> list[dict]:
    with conn() as c:
        if account_id is None:
            rows = c.execute(
                "SELECT * FROM operation_logs ORDER BY id DESC LIMIT ?",
                (limit,),
            )
        else:
            rows = c.execute(
                "SELECT * FROM operation_logs WHERE account_id=? "
                "ORDER BY id DESC LIMIT ?",
                (account_id, limit),
            )
        return [dict(r) for r in rows]
