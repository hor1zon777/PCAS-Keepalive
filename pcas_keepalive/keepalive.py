"""24h 主动保活调度器 — 桌面会话模拟版。

## 设计

> 已知（用户告知 + 抓包验证）：**24h 内连接一次机器（进入桌面）即可保活**。
> 服务端按"用户活跃度"判断是否空闲关机；只要每 24 小时内触发一次完整的
> 桌面连接动作（machineConnect + cem stream 握手），机器就不会被关机。

策略变更（vs 旧版 4 路 REST 心跳）：
- ✗ 移除原 4 路 REST 心跳（5min/30min 间隔，效果未知）
- ✓ 单一任务：每 23 小时跑一次 `simulate_desktop_session`
- ✓ 每次循环对账号下**所有 running 机器**逐个模拟桌面连接（30s 心跳）
- ✓ 失败时 token 自动刷新 + 重试

## 调度

| 任务                         间隔        initialDelay
| daily_desktop_session       23h         15s (run_on_start=True)
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import db
from config import get_settings
from pcas.client import PCASClient, PCASError, is_running
from pcas.crypto import aes_open, get_device_info
from pcas.desktop_session import (
    resolve_cem_endpoint,
    simulate_desktop_session,
    DesktopSessionResult,
)

log = logging.getLogger("pcas.keepalive")


# 23 小时（留 1 小时 buffer，防止时钟漂移导致超过 24h）
DAILY_INTERVAL_SECONDS = 23 * 3600

# 第一次启动延迟 — 给登录留出时间
INITIAL_DELAY_SECONDS = 15

# 单台机器 cem stream 维持时长（秒）
CEM_KEEP_SECONDS = 30


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
class AccountRuntime:
    account_id: int
    account_name: str
    mobile: str
    running: bool = False
    access_token: str = ""
    access_ticket: str = ""
    user_name: str = ""
    machines: list[dict] = field(default_factory=list)
    cem_host: str = ""
    cem_port: int = 0
    stats: TaskStats = field(default_factory=TaskStats)
    tasks_started_at: float = 0.0
    _runner_task: asyncio.Task | None = None


class KeepAliveService:
    """全局调度器 — 每账号一个 daily 桌面会话循环。"""

    def __init__(self) -> None:
        self._runtimes: dict[int, AccountRuntime] = {}
        self._lock = asyncio.Lock()

    # ---------- 生命周期 ----------

    async def start(self) -> None:
        log.info("keepalive service started (daily desktop session strategy)")
        for t in db.list_active_tasks():
            try:
                await self._begin_account(t["account_id"])
            except Exception as e:
                log.warning("account %s 重启保活失败: %s", t["account_id"], e)

    async def shutdown(self) -> None:
        for rt in list(self._runtimes.values()):
            await self._stop_account(rt)
        log.info("keepalive service stopped")

    # ---------- 启停 ----------

    async def start_for(self, account_id: int) -> dict[str, Any]:
        async with self._lock:
            db.upsert_task(account_id, "_all_", True, 5, 1440)
            await self._begin_account(account_id)
        return {"ok": True, "task": "daily_desktop_session"}

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
            return {"running": False}
        s = rt.stats
        return {
            "running": rt.running,
            "started_at": rt.tasks_started_at,
            "machines": rt.machines,
            "cem_endpoint": f"{rt.cem_host}:{rt.cem_port}" if rt.cem_host else "",
            "tasks": {
                "daily_desktop_session": {
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
        }

    async def trigger_now(self, account_id: int) -> dict[str, Any]:
        """手动触发一次桌面会话（用于 UI 测试按钮）。"""
        rt = self._runtimes.get(account_id)
        if not rt or not rt.running:
            raise RuntimeError(f"account {account_id} 保活未启动")
        await self._execute_session_round(rt)
        s = rt.stats
        return {
            "ok": True,
            "last_time": s.last_time,
            "last_status": s.last_status,
            "succeeded_machines": s.last_succeeded_machines,
            "total_machines": s.last_machines_count,
        }

    # ---------- 内部 ----------

    async def _begin_account(self, account_id: int) -> None:
        """登录账号 → 拉机器 + cem 端点 → 启动 daily 调度协程。"""
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

        # 1. 登录：优先用现有 accessTicket 续期；失败回退到密码登录
        settings = get_settings()
        password = aes_open(acct["password_blob"], settings.local_key_hex)
        client = self._make_client(rt)
        # 把 DB 里现有 ticket / token 灌进来，给 refresh_token 用
        client.access_ticket = acct.get("access_ticket") or ""
        client.access_token = acct.get("access_token") or ""
        try:
            result: dict | None = None

            # 1a) accessTicket 续期路径（短信登录添加的账号也能走通）
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
                    log.info("[%s] keepalive started via accessTicket refresh", rt.mobile)
                except PCASError as e:
                    log.info("[%s] ticket refresh failed (%s), fallback to password login",
                             rt.mobile, e.msg)

            # 1b) 密码登录路径
            if result is None:
                if not password:
                    raise RuntimeError(
                        "此账号是短信登录添加的，本地未保存密码；"
                        "且现有 accessTicket 已过期。请回登录页用密码登录一次以补全凭据。"
                    )
                result = await client.login_by_password(rt.mobile, password)
                if result.get("status") != "success":
                    raise RuntimeError(
                        f"登录未完成（{result.get('challengeType')}）— "
                        f"UI 上完成可信设备验证后重试"
                    )

            rt.access_ticket = result["accessTicket"]
            rt.access_token = result["accessToken"]
            rt.user_name = result.get("userName", "")
            rt.machines = result["machines"]
            db.update_account_session(
                account_id, rt.access_token, rt.access_ticket,
                rt.user_name, None,
            )

            # 2. 解析 cem stream 端点（getSysConfig）
            client.access_token = rt.access_token  # ensure freshest token
            client.access_ticket = rt.access_ticket
            rt.cem_host, rt.cem_port = await resolve_cem_endpoint(client)
        finally:
            await client.close()

        if not is_running(rt.machines):
            db.add_log(account_id, None, "keepalive_start",
                       False, "无运行中机器，保活仍启动等待开机")

        # 3. 启动 daily 协程
        rt.tasks_started_at = time.time()
        rt.running = True
        rt._runner_task = asyncio.create_task(self._run_daily_loop(rt))

        self._runtimes[account_id] = rt
        db.add_log(account_id, None, "keepalive_start", True,
                   f"{len(rt.machines)} machines, cem={rt.cem_host}:{rt.cem_port}, "
                   f"interval={DAILY_INTERVAL_SECONDS}s")

    async def _stop_account(self, rt: AccountRuntime) -> None:
        rt.running = False
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

    async def _run_daily_loop(self, rt: AccountRuntime) -> None:
        """daily 保活循环：等 initialDelay → 第一次 → 每 23h 一次。"""
        try:
            await asyncio.sleep(INITIAL_DELAY_SECONDS)
            await self._execute_session_round(rt)
            while rt.running:
                await asyncio.sleep(DAILY_INTERVAL_SECONDS)
                if rt.running:
                    await self._execute_session_round(rt)
        except asyncio.CancelledError:
            log.debug("daily loop cancelled for account %s", rt.account_name)
            raise

    async def _execute_session_round(self, rt: AccountRuntime) -> None:
        """对账号下所有 running 机器逐个跑一次完整桌面会话。"""
        start = time.time()
        machine_results: list[DesktopSessionResult] = []

        # 始终先刷一次机器列表 + token（防止 ticket 过期）
        await self._refresh_machines_with_retry(rt)

        running_machines = [m for m in rt.machines
                            if (m.get("status") or "").lower() in ("running", "active")]
        rt.stats.last_machines_count = len(running_machines)

        if not running_machines:
            log.info("[%s] no running machines, skip session round", rt.account_name)
            self._mark_skipped(rt.stats, "no running machines")
            db.add_log(rt.account_id, None, "daily_session", True,
                       "no running machines, skipped")
            return

        device_uid = self._get_device_uid(rt)

        # 对每台机器跑一次 simulate_desktop_session
        client = self._make_client(rt)
        try:
            for m in running_machines:
                try:
                    res = await simulate_desktop_session(
                        client=client,
                        machine=m,
                        device_uid=device_uid,
                        cem_host=rt.cem_host,
                        cem_port=rt.cem_port,
                        keep_seconds=CEM_KEEP_SECONDS,
                    )
                    machine_results.append(res)
                    db.add_log(
                        rt.account_id, m.get("machineId"),
                        "desktop_session",
                        res.success,
                        f"handshake={res.cem_handshake_ok} "
                        f"hb={res.cem_heartbeats_sent} "
                        f"pushes={res.cem_pushes_received} "
                        f"duration={res.duration_ms}ms"
                        f"{' err='+res.error if res.error else ''}",
                    )
                except Exception as e:
                    log.exception("[%s/%s] desktop session crashed: %s",
                                  rt.account_name, m.get("machineId"), e)
                    db.add_log(rt.account_id, m.get("machineId"),
                               "desktop_session", False, repr(e))
                    machine_results.append(DesktopSessionResult(
                        machine_id=m.get("machineId", ""),
                        machine_name=m.get("machineName", ""),
                        success=False,
                        cem_handshake_ok=False,
                        cem_heartbeats_sent=0,
                        cem_pushes_received=0,
                        duration_ms=0,
                        error=repr(e),
                    ))
        finally:
            await client.close()

        ok_count = sum(1 for r in machine_results if r.success)
        rt.stats.last_succeeded_machines = ok_count
        elapsed_ms = int((time.time() - start) * 1000)

        if ok_count == len(machine_results) and ok_count > 0:
            self._mark_success(rt.stats, elapsed_ms)
            db.add_log(rt.account_id, None, "daily_session", True,
                       f"all {ok_count}/{len(machine_results)} machines ok, {elapsed_ms}ms")
        elif ok_count > 0:
            self._mark_partial(rt.stats, elapsed_ms,
                               f"{ok_count}/{len(machine_results)} machines ok")
            db.add_log(rt.account_id, None, "daily_session", True,
                       f"partial {ok_count}/{len(machine_results)}, {elapsed_ms}ms")
        else:
            errs = "; ".join(r.error for r in machine_results if r.error)[:200]
            self._mark_fail(rt.stats, errs or "all machines failed")
            db.add_log(rt.account_id, None, "daily_session", False,
                       f"all failed: {errs}")

    async def _refresh_machines_with_retry(self, rt: AccountRuntime) -> None:
        """刷新机器列表；token 失效时自动刷新 + 重试一次。"""
        client = self._make_client(rt)
        try:
            try:
                machines = await client.get_device_info_list()
                rt.machines = machines
                return
            except PCASError as e:
                if not PCASClient.is_auth_failure(e):
                    raise
            # token 失效 → 刷新后重试
            log.info("[%s] machine list auth failed, refreshing token...", rt.account_name)
            if await self._refresh_account_token(rt):
                client.access_token = rt.access_token
                client.access_ticket = rt.access_ticket
                rt.machines = await client.get_device_info_list()
        finally:
            await client.close()

    def _get_device_uid(self, rt: AccountRuntime) -> str:
        """获取本账号绑定的稳定 deviceId（与登录时一致）。"""
        info = get_device_info(rt.account_name)
        return str(info.get("deviceUid", "")).upper()

    async def _refresh_account_token(self, rt: AccountRuntime) -> bool:
        """token 失效时的被动刷新：accessTicket 优先，密码登录降级。"""
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
                db.add_log(rt.account_id, None, "token_refresh", False,
                           "ticket 已过期且本地无密码（短信登录账号）；需回登录页用密码补登一次")
                return False
            result = await client.login_by_password(rt.mobile, password)
            if result.get("status") != "success":
                db.add_log(rt.account_id, None, "token_refresh", False,
                           f"challenge required: {result.get('challengeType')}")
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

    # ---------- stats helpers ----------

    @staticmethod
    def _mark_success(stats: TaskStats, elapsed_ms: int) -> None:
        stats.total += 1
        stats.success += 1
        stats.consecutive_fail = 0
        stats.last_time = time.strftime("%Y-%m-%d %H:%M:%S")
        stats.last_status = f"OK ({elapsed_ms}ms)"
        stats.last_error = ""

    @staticmethod
    def _mark_partial(stats: TaskStats, elapsed_ms: int, msg: str) -> None:
        stats.total += 1
        stats.success += 1
        stats.consecutive_fail = 0
        stats.last_time = time.strftime("%Y-%m-%d %H:%M:%S")
        stats.last_status = f"PARTIAL ({elapsed_ms}ms)"
        stats.last_error = msg[:200]

    @staticmethod
    def _mark_skipped(stats: TaskStats, reason: str) -> None:
        stats.last_time = time.strftime("%Y-%m-%d %H:%M:%S")
        stats.last_status = "SKIP"
        stats.last_error = reason[:200]

    @staticmethod
    def _mark_fail(stats: TaskStats, err: str) -> None:
        stats.total += 1
        stats.fail += 1
        stats.consecutive_fail += 1
        stats.last_time = time.strftime("%Y-%m-%d %H:%M:%S")
        stats.last_status = "ERR"
        stats.last_error = err[:200]


# ---------- 全局单例 ----------

_keepalive: KeepAliveService | None = None


def get_scheduler() -> KeepAliveService:
    global _keepalive
    if _keepalive is None:
        _keepalive = KeepAliveService()
    return _keepalive
