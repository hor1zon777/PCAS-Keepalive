"""保活调度器 — 基于真实桌面会话连接。

通过 ZTEC/CAG 网关协议 + TLS + cs_suOperDesktop.action 建立真实桌面会话，
维持 TCP 连接作为"用户正在使用桌面"的保活信号。

## 链路（IDA 反编 + pcap AES 解密验证通过）

```
getDeviceInfo → SDK_AES_decrypt(adPassword) →
TCP connect CAG:8899 → ZTEC 5帧握手 (AES-256-CBC) → TLS 1.2 →
POST /cs/cs_suOperDesktop.action → 维持 TCP 连接 → 断开 → 重连
```

每台 running 机器开一个 MachineRunner，周期性建立桌面连接。
断线指数退避重连（1s → 2s → ... → 60s 上限）。
每 5min 刷新机器列表 reconcile runners。
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import db
from config import get_settings
from pcas.client import (
    PCASClient,
    PCASError,
    is_running,
)
from pcas.cmss_desktop import CmssDesktopClient, CmssDesktopResult
from pcas.crypto import aes_open, get_device_info

log = logging.getLogger("pcas.keepalive")

INITIAL_DELAY_SECONDS = 15
RUNNING_STATUS_KEYWORDS = ("running", "active", "connected", "on", "available")


def _is_machine_running(m: dict) -> bool:
    s = str(m.get("status") or "").lower()
    return any(k in s for k in RUNNING_STATUS_KEYWORDS)


@dataclass
class TaskStats:
    total: int = 0
    success: int = 0
    fail: int = 0
    consecutive_fail: int = 0
    last_time: str = ""
    last_status: str = ""
    last_error: str = ""
    last_machines_count: int = 0
    last_succeeded_machines: int = 0


@dataclass
class MachineRunnerStats:
    state: str = "starting"
    handshakes: int = 0
    desktop_connects: int = 0
    consecutive_failures: int = 0
    current_backoff_sec: float = 0.0
    connected_at: float = 0.0
    last_disconnect_at: float = 0.0
    last_error: str = ""


@dataclass
class AccountRuntime:
    account_id: int
    account_name: str
    mobile: str
    running: bool = False
    access_token: str = ""
    access_ticket: str = ""
    user_name: str = ""
    machines: list[dict] = field(default_factory=list)
    stats: TaskStats = field(default_factory=TaskStats)
    tasks_started_at: float = 0.0
    _runner_task: asyncio.Task | None = None
    runners: dict[str, "MachineRunner"] = field(default_factory=dict)
    _token_refresh_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class MachineRunner:
    """单台机器的桌面保活运行器。

    生命周期：建立 ZTEC 桌面连接 → 维持 TCP → 断开 → 退避 → 重连。
    """

    def __init__(
        self,
        rt: "AccountRuntime",
        machine: dict[str, Any],
        token_provider: Callable[[], tuple[str, str]],
        token_refresher: Callable[[], Awaitable[bool]],
    ) -> None:
        self.rt = rt
        self.machine = machine
        self.machine_id = machine.get("machineId") or machine.get("instanceId") or ""
        self.machine_name = machine.get("machineName", "") or self.machine_id
        self._token_provider = token_provider
        self._token_refresher = token_refresher
        self.stats = MachineRunnerStats()
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()

    def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stopping.clear()
        self._task = asyncio.create_task(
            self._supervisor(),
            name=f"runner-{self.rt.account_id}-{self.machine_id}",
        )

    async def stop(self) -> None:
        self._stopping.set()
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        self.stats.state = "stopped"

    def trigger_reconnect(self) -> None:
        self._stopping.set()

    def snapshot(self) -> dict[str, Any]:
        s = self.stats
        return {
            "machine_id": self.machine_id,
            "machine_name": self.machine_name,
            "state": s.state,
            "desktop_connects": s.desktop_connects,
            "consecutive_failures": s.consecutive_failures,
            "current_backoff_sec": s.current_backoff_sec,
            "connected_at": s.connected_at,
            "last_disconnect_at": s.last_disconnect_at,
            "last_error": s.last_error,
        }

    async def _supervisor(self) -> None:
        settings = get_settings()
        backoff = settings.forever_reconnect_initial_backoff_sec
        max_backoff = settings.forever_reconnect_max_backoff_sec

        while not self._stopping.is_set():
            self.stats.state = "starting"
            self.stats.current_backoff_sec = 0.0
            try:
                await self._run_desktop_session()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.stats.consecutive_failures += 1
                self.stats.last_error = repr(e)[:200]
                self.stats.last_disconnect_at = time.time()
                log.warning("[%s/%s] desktop session failed: %s",
                            self.rt.account_name, self.machine_name, e)
                db.add_log(self.rt.account_id, self.machine_id,
                           "desktop_session_error", False, repr(e)[:200])

            if self._stopping.is_set():
                break

            self.stats.state = "reconnecting"
            self.stats.current_backoff_sec = backoff
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=backoff)
                break
            except asyncio.TimeoutError:
                pass
            backoff = min(backoff * 2, max_backoff)

        self.stats.state = "stopped"

    async def _run_desktop_session(self) -> None:
        """一次完整桌面会话：ZTEC 握手 → TLS → cs_suOperDesktop → 维持 TCP。"""
        settings = get_settings()
        keep_seconds = settings.forever_cmss_desktop_interval_sec

        if not self.machine.get("adUser") or not self.machine.get("adPassword"):
            raise RuntimeError("machine 无 adUser/adPassword，无法建立桌面连接")
        if not self.machine.get("customLoginParams"):
            raise RuntimeError("machine 无 customLoginParams，无法获取 CAG 网关地址")

        log.info("[%s/%s] desktop session starting (keep=%ds)...",
                 self.rt.account_name, self.machine_name, keep_seconds)

        result = await CmssDesktopClient.connect_desktop(
            machine=self.machine,
            keep_alive_seconds=keep_seconds,
        )

        status = (
            f"ztec={result.ztec_auth_ok} tls={result.tls_ok} "
            f"cs_action={result.cs_action_ok} "
            f"cag={result.cag_addr}:{result.cag_port} "
            f"duration={result.duration_ms}ms"
        )

        if result.cs_action_ok:
            self.stats.desktop_connects += 1
            self.stats.state = "connected"
            self.stats.connected_at = time.time()
            self.stats.consecutive_failures = 0
            self.stats.last_error = ""
            log.info("[%s/%s] desktop session OK (%s)",
                     self.rt.account_name, self.machine_name, status)
            db.add_log(self.rt.account_id, self.machine_id,
                       "desktop_session", True, status)
        else:
            raise RuntimeError(f"desktop connect failed: {result.error} ({status})")


class KeepAliveService:
    """全局调度器 — 每账号一个保活 runtime。"""

    def __init__(self) -> None:
        self._runtimes: dict[int, AccountRuntime] = {}
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        log.info("keepalive service started (桌面保活模式)")
        for t in db.list_active_tasks():
            try:
                await self._begin_account(t["account_id"])
            except Exception as e:
                log.warning("account %s 重启保活失败: %s", t["account_id"], e)

    async def shutdown(self) -> None:
        for rt in list(self._runtimes.values()):
            await self._stop_account(rt)
        log.info("keepalive service stopped")

    async def start_for(self, account_id: int, mode: str | None = None) -> dict[str, Any]:
        async with self._lock:
            db.upsert_task(account_id, "_all_", True, 5, 1440, mode="forever")
            await self._begin_account(account_id)
        return {"ok": True, "task": "desktop_session", "mode": "forever"}

    async def set_mode(self, account_id: int, mode: str) -> dict[str, Any]:
        return await self.start_for(account_id, mode)

    async def stop_for(self, account_id: int) -> dict[str, Any]:
        async with self._lock:
            db.set_task_enabled(account_id, "_all_", False)
            rt = self._runtimes.get(account_id)
            if rt:
                await self._stop_account(rt)
        return {"ok": True}

    async def status_for(self, account_id: int) -> dict[str, Any]:
        rt = self._runtimes.get(account_id)
        if not rt:
            return {"running": False, "mode": "forever"}
        s = rt.stats
        return {
            "running": rt.running,
            "mode": "forever",
            "started_at": rt.tasks_started_at,
            "machines": rt.machines,
            "tasks": {
                "desktop_session": {
                    "total": s.total,
                    "success": s.success,
                    "fail": s.fail,
                    "consecutive_fail": s.consecutive_fail,
                    "last_time": s.last_time,
                    "last_status": s.last_status,
                    "last_error": s.last_error,
                    "last_machines_count": s.last_machines_count,
                    "last_succeeded_machines": s.last_succeeded_machines,
                },
            },
            "runners": [r.snapshot() for r in rt.runners.values()],
        }

    async def trigger_now(self, account_id: int) -> dict[str, Any]:
        rt = self._runtimes.get(account_id)
        if not rt or not rt.running:
            raise RuntimeError(f"account {account_id} 保活未启动")
        count = 0
        for r in rt.runners.values():
            r.trigger_reconnect()
            count += 1
        return {"ok": True, "triggered_runners": count}

    # ---------- 内部 ----------

    async def _begin_account(self, account_id: int) -> None:
        acct = db.get_account(account_id)
        if not acct:
            raise RuntimeError(f"account {account_id} 不存在")

        old = self._runtimes.get(account_id)
        if old:
            await self._stop_account(old)

        rt = AccountRuntime(
            account_id=account_id,
            account_name=acct["mobile"],
            mobile=acct["mobile"],
        )

        settings = get_settings()
        password = aes_open(acct["password_blob"], settings.local_key_hex)
        client = self._make_client(rt)
        client.access_ticket = acct.get("access_ticket") or ""
        client.access_token = acct.get("cem_token") or ""
        try:
            result: dict | None = None

            if client.access_ticket:
                try:
                    refreshed = await client.refresh_token()
                    result = {
                        "status": "success",
                        "accessTicket": client.access_ticket,
                        "accessToken": refreshed["accessToken"],
                        "userName": refreshed.get("userName", ""),
                        "machines": refreshed["machines"],
                    }
                    log.info("[%s] keepalive started via ticket refresh", rt.mobile)
                except PCASError as e:
                    log.info("[%s] ticket refresh failed (%s), fallback to password",
                             rt.mobile, e.msg)

            if result is None:
                if not password:
                    raise RuntimeError(
                        "此账号无密码且 ticket 过期。请回登录页用密码登录。"
                    )
                result = await client.login_by_password(rt.mobile, password)
                if result.get("status") != "success":
                    raise RuntimeError(
                        f"登录未完成（{result.get('challengeType')}）"
                    )

            rt.access_ticket = result["accessTicket"]
            rt.access_token = result["accessToken"]
            rt.user_name = result.get("userName", "")
            rt.machines = result["machines"]
            db.update_account_session(
                account_id, rt.access_token, rt.access_ticket,
                rt.user_name, None,
            )
        finally:
            await client.close()

        if not is_running(rt.machines):
            db.add_log(account_id, None, "keepalive_start",
                       False, "无运行中机器，保活仍启动等待开机")

        rt.tasks_started_at = time.time()
        rt.running = True
        rt._runner_task = asyncio.create_task(
            self._run_forever_top(rt),
            name=f"forever-top-{account_id}",
        )
        running_count = len([m for m in rt.machines if _is_machine_running(m)])
        self._runtimes[account_id] = rt
        db.add_log(account_id, None, "keepalive_start", True,
                   f"mode=desktop, {len(rt.machines)} machines, "
                   f"{running_count} running")

    async def _stop_account(self, rt: AccountRuntime) -> None:
        rt.running = False
        if rt.runners:
            await asyncio.gather(
                *(r.stop() for r in rt.runners.values()),
                return_exceptions=True,
            )
            rt.runners.clear()
        if rt._runner_task:
            rt._runner_task.cancel()
            try:
                await rt._runner_task
            except (asyncio.CancelledError, Exception):
                pass
            rt._runner_task = None
        self._runtimes.pop(rt.account_id, None)
        db.add_log(rt.account_id, None, "keepalive_stop", True, "")

    def _make_client(self, rt: AccountRuntime | None = None) -> PCASClient:
        s = get_settings()
        c = PCASClient(
            base_url=s.pcas_base_url,
            timeout=s.http_timeout,
            debug_dump=s.debug_dump_payload,
        )
        if rt:
            c.account_name = rt.account_name
            c.access_token = rt.access_token
            c.access_ticket = rt.access_ticket
        return c

    async def _run_forever_top(self, rt: AccountRuntime) -> None:
        try:
            await asyncio.sleep(INITIAL_DELAY_SECONDS)
            self._reconcile_machine_runners(rt)
            settings = get_settings()
            while rt.running:
                try:
                    await asyncio.sleep(settings.forever_machine_refresh_interval_sec)
                except asyncio.CancelledError:
                    raise
                if not rt.running:
                    break
                try:
                    await self._refresh_machines_with_retry(rt)
                except Exception as e:
                    log.warning("[%s] machine list refresh failed: %s", rt.account_name, e)
                    continue
                self._reconcile_machine_runners(rt)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.exception("[%s] forever top crashed: %s", rt.account_name, e)
            db.add_log(rt.account_id, None, "keepalive_crashed", False, repr(e)[:200])
            rt.running = False
            rt.stats.last_status = "CRASHED"
            rt.stats.last_error = repr(e)[:200]
            rt.stats.last_time = time.strftime("%Y-%m-%d %H:%M:%S")

    def _reconcile_machine_runners(self, rt: AccountRuntime) -> None:
        running_now = {
            (m.get("machineId") or m.get("instanceId") or ""): m
            for m in rt.machines if _is_machine_running(m)
        }
        running_now.pop("", None)

        for mid, m in running_now.items():
            if mid in rt.runners:
                continue
            runner = MachineRunner(
                rt=rt,
                machine=m,
                token_provider=self._make_token_provider(rt),
                token_refresher=self._make_token_refresher(rt),
            )
            runner.start()
            rt.runners[mid] = runner
            log.info("[%s] runner started for machine %s (%s)",
                     rt.account_name, m.get("machineName", ""), mid)

        gone = [mid for mid in rt.runners if mid not in running_now]
        for mid in gone:
            runner = rt.runners.pop(mid)
            asyncio.create_task(runner.stop(), name=f"stop-runner-{rt.account_id}-{mid}")
            log.info("[%s] runner stopped for offline machine %s", rt.account_name, mid)

        for mid, runner in rt.runners.items():
            if mid in running_now:
                runner.machine = running_now[mid]

        rt.stats.last_machines_count = len(running_now)
        rt.stats.last_succeeded_machines = sum(
            1 for r in rt.runners.values() if r.stats.state == "connected"
        )
        rt.stats.last_time = time.strftime("%Y-%m-%d %H:%M:%S")
        rt.stats.last_status = (
            f"DESKTOP {rt.stats.last_succeeded_machines}/{rt.stats.last_machines_count} connected"
        )

    def _make_token_provider(self, rt: AccountRuntime) -> Callable[[], tuple[str, str]]:
        def _provider() -> tuple[str, str]:
            return rt.access_token, rt.access_ticket
        return _provider

    def _make_token_refresher(self, rt: AccountRuntime) -> Callable[[], Awaitable[bool]]:
        async def _refresher() -> bool:
            async with rt._token_refresh_lock:
                return await self._refresh_account_token(rt)
        return _refresher

    async def _refresh_machines_with_retry(self, rt: AccountRuntime) -> None:
        client = self._make_client(rt)
        try:
            try:
                machines = await client.get_device_info_list()
                rt.machines = machines
            except PCASError as e:
                if not PCASClient.is_auth_failure(e):
                    raise
                log.info("[%s] machine list auth failed, refreshing token...", rt.account_name)
                if await self._refresh_account_token(rt):
                    client.access_token = rt.access_token
                    client.access_ticket = rt.access_ticket
                    rt.machines = await client.get_device_info_list()
                else:
                    raise
        finally:
            await client.close()

    async def _refresh_account_token(self, rt: AccountRuntime) -> bool:
        client = self._make_client(rt)
        try:
            try:
                result = await client.refresh_token()
                rt.access_token = result["accessToken"]
                rt.machines = result["machines"]
                db.update_account_session(
                    rt.account_id, rt.access_token, rt.access_ticket,
                    result.get("userName", ""), None,
                )
                db.add_log(rt.account_id, None, "token_refresh", True, "via ticket")
                return True
            except PCASError:
                pass

            settings = get_settings()
            acct = db.get_account(rt.account_id)
            password = aes_open(acct["password_blob"], settings.local_key_hex)
            if not password:
                db.add_log(rt.account_id, None, "token_refresh", False, "无密码")
                return False
            result = await client.login_by_password(rt.mobile, password)
            if result.get("status") != "success":
                db.add_log(rt.account_id, None, "token_refresh", False,
                           f"challenge: {result.get('challengeType')}")
                return False
            rt.access_token = result["accessToken"]
            rt.access_ticket = result["accessTicket"]
            rt.machines = result["machines"]
            db.update_account_session(
                rt.account_id, rt.access_token, rt.access_ticket,
                result.get("userName", ""), None,
            )
            db.add_log(rt.account_id, None, "token_refresh", True, "via password")
            return True
        except Exception as e:
            db.add_log(rt.account_id, None, "token_refresh", False, repr(e))
            return False
        finally:
            await client.close()


# ---------- 全局单例 ----------

_keepalive: KeepAliveService | None = None


def get_scheduler() -> KeepAliveService:
    global _keepalive
    if _keepalive is None:
        _keepalive = KeepAliveService()
    return _keepalive
