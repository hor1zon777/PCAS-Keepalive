"""保活调度器 — 双模式：forever (持续在线) / daily (23h 短打卡)。

## forever 模式（默认）

参考 Go 版 `cloud-computer-keepalive` 的 `--forever` 思路：每台 running 机器
开一条 `MachineRunner`，并发维持：

1. **cem stream 长连接**：5s 一次心跳（与 PCAS_App 抓包一致）
2. **REST 辅助心跳**：25s 一次 /session/updateSessionStatus + 5min 一次
   /machine/performance/batch + /user/getDesktopStatus + 30min 一次
   /device/performance/batch
3. **主动 token refresh**：6h 一次（防 ticket 超时）
4. **断线指数退避重连**：1s → 2s → 4s → ... → 60s 上限

`KeepAliveService` 每 5min reconcile 一次机器列表：新增 running 机器开 runner，
消失机器停 runner。

## daily 模式（原策略，账号级可选）

> 已知（用户告知 + 抓包验证）：**24h 内连接一次机器（进入桌面）即可保活**。
> 服务端按"用户活跃度"判断是否空闲关机；只要每 24 小时内触发一次完整的
> 桌面连接动作（machineConnect + cem stream 握手），机器就不会被关机。

- 每 23 小时跑一次 `simulate_desktop_session`（30s cem stream 短连接）
- 失败时 token 自动刷新 + 重试

## 调度

| 模式      | 任务名                  间隔         initialDelay
| forever  | forever_cem_session     常驻         15s
| daily    | daily_desktop_session   23h          15s (run_on_start=True)
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
    SessionContext,
    build_connect_list_for_keepalive,
    is_running,
    make_session_context,
)
from pcas.cmss_desktop import (
    AUTH_TYPE_RADIUS,
    CagParam,
    CmssDesktopClient,
    CmssDesktopResult,
)
from pcas.crypto import aes_open, get_device_info
from pcas.desktop_session import (
    cem_stream_session,
    resolve_cem_endpoint,
    simulate_desktop_session,
    DesktopSessionResult,
)

log = logging.getLogger("pcas.keepalive")


# 23 小时（留 1 小时 buffer，防止时钟漂移导致超过 24h）
DAILY_INTERVAL_SECONDS = 23 * 3600

# 第一次启动延迟 — 给登录留出时间
INITIAL_DELAY_SECONDS = 15

# 单台机器 cem stream 维持时长（秒）— 仅 daily 模式使用
CEM_KEEP_SECONDS = 30

# 服务端"机器在线"状态关键词集合 — 与 pcas.client.is_running 保持一致。
# 注意：开机后服务端返回的是 'available'（"可连接"），不是 'running'。
RUNNING_STATUS_KEYWORDS = ("running", "active", "connected", "on", "available")

VALID_MODES = ("forever", "daily")


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
    """每台机器 runner 的运行时统计（snapshot 给 UI）。"""

    state: str = "starting"           # starting | connected | reconnecting | paused | stopped
    handshakes: int = 0
    cem_heartbeats: int = 0
    rest_heartbeats: int = 0
    server_pushes: int = 0
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
    cem_host: str = ""
    cem_port: int = 0
    stats: TaskStats = field(default_factory=TaskStats)
    tasks_started_at: float = 0.0
    _runner_task: asyncio.Task | None = None
    # forever 模式专属
    mode: str = "forever"
    runners: dict[str, "MachineRunner"] = field(default_factory=dict)
    machine_refresh_task: asyncio.Task | None = None
    # token 失效并发刷新保护
    _token_refresh_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    # 会话上下文（对齐 Node 项目 commonParams） — 用于 connectId / pushConnectEventData 上报
    session_ctx: SessionContext = field(default_factory=SessionContext)


class MachineRunner:
    """单台机器的 forever 模式运行器。

    生命周期由 supervisor 协程驱动：建连接 → 三 loop 并发 → 任一退出 → 重连。
    断开时指数退避（1s/2s/.../60s 上限）；token 失效时通过 token_refresher
    刷新（账号级单刷，所有 runner 共享）。
    """

    def __init__(
        self,
        rt: "AccountRuntime",
        machine: dict[str, Any],
        cem_host: str,
        cem_port: int,
        token_provider: Callable[[], tuple[str, str]],
        token_refresher: Callable[[], Awaitable[bool]],
    ) -> None:
        self.rt = rt
        self.machine = machine
        self.machine_id = (
            machine.get("machineId") or machine.get("instanceId") or ""
        )
        self.machine_name = machine.get("machineName", "") or self.machine_id
        self.cem_host = cem_host
        self.cem_port = cem_port
        self._token_provider = token_provider
        self._token_refresher = token_refresher
        self.stats = MachineRunnerStats()
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()
        self._force_reconnect = asyncio.Event()

    # ---------- 生命周期 ----------

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
        """请求 runner 立刻断开并重连（用于手动 trigger）。"""
        self._force_reconnect.set()

    def snapshot(self) -> dict[str, Any]:
        s = self.stats
        return {
            "machine_id": self.machine_id,
            "machine_name": self.machine_name,
            "state": s.state,
            "handshakes": s.handshakes,
            "cem_heartbeats": s.cem_heartbeats,
            "rest_heartbeats": s.rest_heartbeats,
            "server_pushes": s.server_pushes,
            "consecutive_failures": s.consecutive_failures,
            "current_backoff_sec": s.current_backoff_sec,
            "connected_at": s.connected_at,
            "last_disconnect_at": s.last_disconnect_at,
            "last_error": s.last_error,
        }

    # ---------- 核心 supervisor ----------

    async def _supervisor(self) -> None:
        settings = get_settings()
        backoff = settings.forever_reconnect_initial_backoff_sec
        max_backoff = settings.forever_reconnect_max_backoff_sec

        while not self._stopping.is_set():
            self.stats.state = "starting"
            self.stats.current_backoff_sec = 0.0
            was_connected = False
            try:
                await self._run_one_session()
                was_connected = self.stats.handshakes > 0
                # 正常返回 == 主动 stop 或 trigger reconnect
                if self._force_reconnect.is_set():
                    self._force_reconnect.clear()
                    backoff = settings.forever_reconnect_initial_backoff_sec
                    continue
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.stats.consecutive_failures += 1
                self.stats.last_error = repr(e)[:200]
                self.stats.last_disconnect_at = time.time()
                log.warning(
                    "[%s/%s] runner session failed: %s",
                    self.rt.account_name, self.machine_name, e,
                )
                db.add_log(
                    self.rt.account_id, self.machine_id,
                    "forever_session_error", False, repr(e)[:200],
                )
                # 仅在曾经握手成功后失败时上报 connect.failure
                # （首次握手就失败时还没"连上"，不能上报 disconnect 事件）
                if self.stats.handshakes > 0:
                    try:
                        await self._report_connect_failure_standalone(repr(e)[:120])
                    except Exception as cb_err:
                        log.debug("[%s/%s] connect.failure post-runner failed: %s",
                                  self.rt.account_name, self.machine_name, cb_err)

            if self._stopping.is_set():
                break

            self.stats.state = "reconnecting"
            self.stats.current_backoff_sec = backoff
            try:
                await asyncio.wait_for(
                    self._stopping.wait(), timeout=backoff,
                )
                break  # stopping during backoff → 退出
            except asyncio.TimeoutError:
                pass
            backoff = min(backoff * 2, max_backoff)

        self.stats.state = "stopped"

    async def _report_connect_failure_standalone(self, err_msg: str) -> None:
        """在 supervisor 异常分支里调，需要新开一个临时 client（因为原 client 已 close）。"""
        if not self.machine.get("connectId"):
            return  # 没建过会话就没必要上报 failure
        settings = get_settings()
        access_token, access_ticket = self._token_provider()
        if not access_token or not access_ticket:
            return
        c = PCASClient(
            base_url=settings.pcas_base_url,
            timeout=settings.http_timeout,
            debug_dump=settings.debug_dump_payload,
        )
        c.account_name = self.rt.account_name
        c.access_token = access_token
        c.access_ticket = access_ticket
        try:
            await self._report_connect_event(
                c, "connect.failure",
                error_code="ERR_DISCONNECT",
                error_msg=err_msg,
            )
        finally:
            await c.close()

    async def _run_one_session(self) -> None:
        """跑一次完整会话：握手 → 三 loop 并发 → 任一退出 → cleanup。"""
        settings = get_settings()
        access_token, access_ticket = self._token_provider()
        if not access_ticket or not access_token:
            raise RuntimeError("missing access_ticket/access_token")

        device_uid = str(
            get_device_info(self.rt.account_name).get("deviceUid", "")
        ).upper()

        client = PCASClient(
            base_url=settings.pcas_base_url,
            timeout=settings.http_timeout,
            debug_dump=settings.debug_dump_payload,
        )
        client.account_name = self.rt.account_name
        client.access_token = access_token
        client.access_ticket = access_ticket

        async def on_disconnect(exc: Exception | None) -> None:
            self.stats.last_disconnect_at = time.time()
            if exc is not None:
                self.stats.last_error = repr(exc)[:200]

        async def on_push(cmd_id: int, data: dict) -> None:
            if cmd_id == 2:
                return
            self.stats.server_pushes += 1
            log.info(
                "[%s/%s] server push cmd=%d data=%s",
                self.rt.account_name, self.machine_name, cmd_id, str(data)[:200],
            )

        try:
            async with cem_stream_session(
                client=client,
                machine=self.machine,
                device_uid=device_uid,
                cem_host=self.cem_host,
                cem_port=self.cem_port,
                heartbeat_interval=settings.forever_cem_heartbeat_sec,
                on_push=on_push,
                on_disconnect=on_disconnect,
            ) as cem:
                self.stats.handshakes += 1
                self.stats.state = "connected"
                self.stats.connected_at = time.time()
                self.stats.consecutive_failures = 0
                self.stats.last_error = ""
                db.add_log(
                    self.rt.account_id, self.machine_id,
                    "forever_session_open", True,
                    f"cem={self.cem_host}:{self.cem_port}",
                )

                # cem stream 握手成功后立刻上报 connect.result，
                # 让服务端认为"用户已建立桌面会话"（对齐 Node 项目）。
                # 该事件必须有真实 connectId（来自 establish_session）。
                await self._report_connect_event(client, "connect.result")

                cem_task = asyncio.create_task(cem.run(), name="cem_run")
                rest_task = asyncio.create_task(
                    self._rest_heartbeat_loop(client),
                    name="rest_hb",
                )
                refresh_task = asyncio.create_task(
                    self._token_refresh_loop(),
                    name="token_refresh",
                )
                force_task = asyncio.create_task(
                    self._force_reconnect.wait(),
                    name="force_reconnect",
                )
                stop_task = asyncio.create_task(
                    self._stopping.wait(),
                    name="stop_signal",
                )
                # CMSS 桌面层模拟（可选，默认禁用）
                # 只对 companyCode=CMSS/ZTE 的机器启用；且必须在 settings 里显式打开。
                cmss_task: asyncio.Task | None = None
                if (settings.forever_enable_cmss_desktop
                        and self._is_cmss_desktop_machine()):
                    cmss_task = asyncio.create_task(
                        self._cmss_desktop_loop(),
                        name="cmss_desktop",
                    )

                all_tasks = [cem_task, rest_task, refresh_task, force_task, stop_task]
                if cmss_task is not None:
                    all_tasks.append(cmss_task)

                try:
                    done, _ = await asyncio.wait(
                        all_tasks, return_when=asyncio.FIRST_COMPLETED,
                    )
                finally:
                    for t in all_tasks:
                        if not t.done():
                            t.cancel()
                    cleanup_tasks = [cem_task, rest_task, refresh_task]
                    if cmss_task is not None:
                        cleanup_tasks.append(cmss_task)
                    for t in cleanup_tasks:
                        try:
                            await t
                        except (asyncio.CancelledError, Exception):
                            pass

                # 把 cem stream 的 counters 转到 stats
                self.stats.cem_heartbeats = cem.heartbeats_sent
                self.stats.server_pushes = max(
                    self.stats.server_pushes, cem.pushes_received,
                )

                # 判断退出原因
                for t in done:
                    if t in (force_task, stop_task):
                        return
                    if t.exception():
                        raise t.exception()
                if cem_task in done or rest_task in done:
                    raise RuntimeError("session task ended unexpectedly")
        finally:
            await client.close()

    async def _report_connect_event(
        self,
        client: PCASClient,
        event_type: str,
        *,
        error_code: str = "",
        error_msg: str = "",
    ) -> None:
        """上报 pushConnectEventData（CloudEvents 1.0）。失败仅记日志，不抛异常。

        - connect.result：cem stream 握手成功后调，等价于"H3C 桌面客户端已就绪"
        - connect.failure：runner 失败/断开时调

        connect.result 需要真实 connectId（来自 establish_session）；如果机器还没
        建会话，跳过上报。
        """
        if event_type == "connect.result" and not self.machine.get("connectId"):
            log.info(
                "[%s/%s] skip %s: machine has no connectId (establish_session 未成功)",
                self.rt.account_name, self.machine_name, event_type,
            )
            return
        try:
            self.rt.session_ctx.session_started_at = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(),
            )
            resp = await client.push_connect_event_cloud(
                machine=self.machine,
                session_ctx=self.rt.session_ctx,
                event_type=event_type,
                error_code=error_code,
                error_msg=error_msg,
            )
            code = str(resp.get("errorCode", ""))
            if code == "200":
                db.add_log(
                    self.rt.account_id, self.machine_id,
                    f"push_connect_event_{event_type}", True, "",
                )
                log.info("[%s/%s] %s reported ok",
                         self.rt.account_name, self.machine_name, event_type)
            else:
                db.add_log(
                    self.rt.account_id, self.machine_id,
                    f"push_connect_event_{event_type}", False,
                    f"errorCode={code} msg={resp.get('errorMessage', '')[:120]}",
                )
                log.warning("[%s/%s] %s reported failure: %s",
                            self.rt.account_name, self.machine_name,
                            event_type, resp.get("errorMessage", ""))
        except Exception as e:
            log.warning("[%s/%s] %s push failed: %s",
                        self.rt.account_name, self.machine_name, event_type, e)
            db.add_log(
                self.rt.account_id, self.machine_id,
                f"push_connect_event_{event_type}", False, repr(e)[:200],
            )

    # ---------- CMSS 桌面层模拟（实验性，默认禁用） ----------

    def _is_cmss_desktop_machine(self) -> bool:
        """判断这台机器是否需要 CMSS 桌面层模拟（companyCode 是 CMSS/ZTE）。"""
        cc = str(self.machine.get("companyCode") or
                 self.machine.get("originCompanyCode") or "").upper()
        return cc in ("CMSS", "CMSSZTE", "ZTE")

    def _resolve_cmss_desktop_endpoint(self) -> tuple[str, int]:
        """从 machine 字典里挖 CMSS 桌面服务器地址。

        ⚠️ 当前实现是占位：machine 字典里没有"桌面服务器地址"字段，
        需要 cs_sysConfig.action 或 customParams 才能拿到。
        默认返回 machine.ip + 8899（不一定对）。
        """
        settings = get_settings()
        ip = (self.machine.get("ip") or "").strip()
        return ip, settings.cmss_desktop_default_port

    async def _cmss_desktop_loop(self) -> None:
        """周期性尝试 CMSS 桌面层连接（ZTEC + TLS + cs_suOperDesktop）。

        失败仅打 warning + add_log；不影响主流程。
        间隔由 forever_cmss_desktop_interval_sec 控制（默认 10min）。

        ⚠️ 已知限制（截至 2026-05-18）：
        - ZTEC AuthPacket 里的 RSA token 明文格式是推测，首次握手大概率被服务端拒绝
        - CMSS 桌面服务器地址来源未明（machine.ip 是私网地址，不通；真实地址需要服
          务端下发，可能在 cs_sysConfig.action 响应里）
        - 即使握手成功，TLS 升级后的 cs_suOperDesktop.action 也可能 param 字段格式不对
        """
        settings = get_settings()
        # 启动后先等一会
        try:
            await asyncio.wait_for(self._stopping.wait(), timeout=60.0)
            return
        except asyncio.TimeoutError:
            pass

        while not self._stopping.is_set():
            try:
                await self._attempt_cmss_desktop()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("[%s/%s] CMSS desktop loop error: %s",
                            self.rt.account_name, self.machine_name, e)

            try:
                await asyncio.wait_for(
                    self._stopping.wait(),
                    timeout=settings.forever_cmss_desktop_interval_sec,
                )
                return
            except asyncio.TimeoutError:
                continue

    async def _attempt_cmss_desktop(self) -> None:
        """执行一次 CMSS 桌面层尝试（ZTEC 握手 + TLS + cs_suOperDesktop）。

        ⚠️ 当前仅能完成 ZTEC frame 116 + 124 阶段。
        Frame 125 AuthPacket 的 AES 加密尚未完整还原，预期 ack 失败。
        """
        server_ip, server_port = self._resolve_cmss_desktop_endpoint()
        if not server_ip:
            log.info("[%s/%s] CMSS desktop skipped: 没有桌面服务器地址",
                     self.rt.account_name, self.machine_name)
            return

        vm_id = (self.machine.get("instanceId") or self.machine.get("machineId") or "")
        if not (isinstance(vm_id, str) and len(vm_id) == 36 and vm_id.count("-") == 4):
            log.info("[%s/%s] CMSS desktop skipped: machineId 不是 UUID 格式 (%s)",
                     self.rt.account_name, self.machine_name, vm_id)
            return

        company_code = str(self.machine.get("companyCode")
                           or self.machine.get("originCompanyCode") or "CMSSZTE").upper()
        if company_code == "CMSS":
            company_code = "CMSSZTE"

        log.info("[%s/%s] CMSS desktop attempt: server=%s:%d vmId=%s",
                 self.rt.account_name, self.machine_name,
                 server_ip, server_port, vm_id)

        # 构造 cag_param（⚠️ username/password 是占位 — 真实内容来源待反编 libvdconn）
        try:
            cag_param = CagParam.from_machine_connect(
                server_ipv6=server_ip,
                vm_id=vm_id,
                spice_proxy_port=5100,           # 客户端 SPICE proxy 监听端口
                guest_user="",                    # ⚠️ 待补
                guest_password="",                # ⚠️ 待补
            )
        except Exception as e:
            log.warning("[%s/%s] CMSS cag_param 构造失败: %s",
                        self.rt.account_name, self.machine_name, e)
            db.add_log(self.rt.account_id, self.machine_id,
                       "cmss_desktop", False, f"cag_param: {e!r}"[:200])
            return

        async with CmssDesktopClient(
            server_ipv6=server_ip,
            server_port=server_port,
            company_code=company_code,
        ) as cli:
            result = await cli.connect_and_handshake_only(cag_param)

        status = (
            f"hello={result.ztec_hello_ok} "
            f"pong={result.ztec_pong_ok} "
            f"auth_ack={result.ztec_auth_ok} "
            f"server_key=0x{result.server_key:08x} "
            f"duration={result.duration_ms}ms "
            f"sent={result.bytes_sent}B recv={result.bytes_received}B"
        )
        if result.ztec_auth_ok:
            log.info("[%s/%s] CMSS desktop ZTEC OK (%s)",
                     self.rt.account_name, self.machine_name, status)
            db.add_log(self.rt.account_id, self.machine_id,
                       "cmss_desktop", True, status)
        else:
            log.warning("[%s/%s] CMSS desktop ZTEC FAILED: %s (%s)",
                        self.rt.account_name, self.machine_name,
                        result.error, status)
            db.add_log(self.rt.account_id, self.machine_id,
                       "cmss_desktop", False,
                       f"{result.error[:120]} | {status}")

    # ---------- REST 辅助心跳 ----------

    async def _rest_heartbeat_loop(self, client: PCASClient) -> None:
        """每 25 秒并行调一组 REST 保活接口（最佳努力，失败仅记日志）。

        参考 Node 项目 keep-alive：在 cem stream 长连接外，并行刷一组
        服务端记的"近期活跃"信号。token 失效时触发账号级 refresh。

        关键修正：connectList 用 establish_session 拿到的真实 connectId，
        不再用 machineId 替代。session/updateSessionStatus 的 loginUid 也用
        服务端返回的真实值（来自 recordDeviceInfo body.loginUid）。
        """
        settings = get_settings()
        machine_id = self.machine_id
        instance_id = self.machine.get("instanceId") or machine_id

        last_machine_perf = 0.0
        last_device_perf = 0.0
        last_desktop_status = 0.0

        # 启动后等一会，避免握手刚成功就并发刷 REST
        try:
            await asyncio.wait_for(
                self._stopping.wait(),
                timeout=settings.forever_rest_heartbeat_sec,
            )
            return
        except asyncio.TimeoutError:
            pass

        while not self._stopping.is_set():
            try:
                tok, tic = self._token_provider()
                client.access_token = tok
                client.access_ticket = tic

                now = time.time()
                pending: list[Awaitable[Any]] = []

                # 关键：从 machine 字典里拿真实 connectId（来自 establish_session）
                connect_id = self.machine.get("connectId") or ""
                conn_list: list[dict[str, Any]] = []
                if connect_id:
                    conn_list.append({
                        "connectId": connect_id,
                        "connectStatus": True,
                        "machineId": machine_id,
                        "companyCode": self.machine.get("companyCode", "ZTE"),
                    })
                # 用服务端确认的 loginUid；回退到 ticket[:32] 仅在尚未建会话时
                login_uid = (
                    self.rt.session_ctx.login_uid
                    or (self.rt.access_ticket[:32] if self.rt.access_ticket else "")
                )
                pending.append(client.task_session_heartbeat(
                    login_uid=login_uid,
                    connect_list=conn_list,
                    login_status="0",
                ))

                if now - last_machine_perf >= settings.forever_machine_perf_interval_sec:
                    pending.append(client.task_machine_performance_batch(machine_id))
                    last_machine_perf = now
                if now - last_desktop_status >= settings.forever_desktop_status_interval_sec:
                    pending.append(client.task_get_desktop_status([instance_id]))
                    last_desktop_status = now
                if now - last_device_perf >= settings.forever_device_perf_interval_sec:
                    pending.append(client.task_device_performance())
                    last_device_perf = now

                results = await asyncio.gather(*pending, return_exceptions=True)
                ok = sum(1 for r in results if not isinstance(r, Exception))
                if ok > 0:
                    self.stats.rest_heartbeats += 1

                # auth failure → 账号级 refresh
                auth_failed = any(
                    isinstance(r, PCASError) and PCASClient.is_auth_failure(r)
                    for r in results
                )
                if auth_failed:
                    log.info(
                        "[%s/%s] REST heartbeat hit auth failure, refreshing token",
                        self.rt.account_name, self.machine_name,
                    )
                    refreshed = await self._token_refresher()
                    if not refreshed:
                        raise RuntimeError("REST token refresh failed")

            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning(
                    "[%s/%s] REST heartbeat error: %s",
                    self.rt.account_name, self.machine_name, e,
                )
                if isinstance(e, PCASError) and PCASClient.is_auth_failure(e):
                    raise

            try:
                await asyncio.wait_for(
                    self._stopping.wait(),
                    timeout=settings.forever_rest_heartbeat_sec,
                )
                return
            except asyncio.TimeoutError:
                continue

    # ---------- 主动 token 刷新（6h 一次防 ticket 过期） ----------

    async def _token_refresh_loop(self) -> None:
        settings = get_settings()
        while not self._stopping.is_set():
            try:
                await asyncio.wait_for(
                    self._stopping.wait(),
                    timeout=settings.forever_token_refresh_interval_sec,
                )
                return
            except asyncio.TimeoutError:
                pass

            try:
                refreshed = await self._token_refresher()
                if refreshed:
                    log.info(
                        "[%s/%s] proactive token refresh ok",
                        self.rt.account_name, self.machine_name,
                    )
                    self._force_reconnect.set()
                    return
                else:
                    log.warning(
                        "[%s/%s] proactive token refresh returned False",
                        self.rt.account_name, self.machine_name,
                    )
            except Exception as e:
                log.warning(
                    "[%s/%s] proactive token refresh error: %s",
                    self.rt.account_name, self.machine_name, e,
                )


class KeepAliveService:
    """全局调度器 — 每账号一个保活 runtime（forever 或 daily）。"""

    def __init__(self) -> None:
        self._runtimes: dict[int, AccountRuntime] = {}
        self._lock = asyncio.Lock()

    # ---------- 生命周期 ----------

    async def start(self) -> None:
        log.info("keepalive service started (forever + daily 双模式)")
        for t in db.list_active_tasks():
            try:
                mode = t.get("mode") or db.get_account_default_mode(t["account_id"]) or "forever"
                await self._begin_account(t["account_id"], mode=mode)
            except Exception as e:
                log.warning("account %s 重启保活失败: %s", t["account_id"], e)

    async def shutdown(self) -> None:
        for rt in list(self._runtimes.values()):
            await self._stop_account(rt)
        log.info("keepalive service stopped")

    # ---------- 启停 ----------

    async def start_for(
        self, account_id: int, mode: str | None = None,
    ) -> dict[str, Any]:
        async with self._lock:
            if mode is None:
                mode = db.get_account_default_mode(account_id)
            if mode not in VALID_MODES:
                raise ValueError(f"invalid mode {mode!r}, expected {VALID_MODES}")
            db.set_account_default_mode(account_id, mode)
            db.upsert_task(account_id, "_all_", True, 5, 1440, mode=mode)
            await self._begin_account(account_id, mode=mode)
        task_name = "forever_cem_session" if mode == "forever" else "daily_desktop_session"
        return {"ok": True, "task": task_name, "mode": mode}

    async def set_mode(self, account_id: int, mode: str) -> dict[str, Any]:
        """切换账号的保活模式 — 先停当前，再以新模式起。"""
        if mode not in VALID_MODES:
            raise ValueError(f"invalid mode {mode!r}, expected {VALID_MODES}")
        async with self._lock:
            db.set_account_default_mode(account_id, mode)
            db.upsert_task(account_id, "_all_", True, 5, 1440, mode=mode)
            rt = self._runtimes.get(account_id)
            if rt:
                await self._stop_account(rt)
            await self._begin_account(account_id, mode=mode)
        return {"ok": True, "mode": mode}

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
            return {"running": False, "mode": db.get_account_default_mode(account_id)}
        s = rt.stats
        task_id = "forever_cem_session" if rt.mode == "forever" else "daily_desktop_session"
        return {
            "running": rt.running,
            "mode": rt.mode,
            "started_at": rt.tasks_started_at,
            "machines": rt.machines,
            "cem_endpoint": f"{rt.cem_host}:{rt.cem_port}" if rt.cem_host else "",
            "tasks": {
                task_id: {
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
        """手动触发一次桌面会话：daily 模式跑一次短打卡；forever 模式强制所有 runner 重连。"""
        rt = self._runtimes.get(account_id)
        if not rt or not rt.running:
            raise RuntimeError(f"account {account_id} 保活未启动")
        if rt.mode == "forever":
            count = 0
            for r in rt.runners.values():
                r.trigger_reconnect()
                count += 1
            return {
                "ok": True,
                "mode": "forever",
                "triggered_runners": count,
                "last_status": "RECONNECTING",
            }
        # daily 模式：原有逻辑
        await self._execute_session_round(rt)
        s = rt.stats
        return {
            "ok": True,
            "mode": "daily",
            "last_time": s.last_time,
            "last_status": s.last_status,
            "succeeded_machines": s.last_succeeded_machines,
            "total_machines": s.last_machines_count,
        }

    # ---------- 内部 ----------

    async def _begin_account(self, account_id: int, mode: str = "forever") -> None:
        """登录账号 → 拉机器 + cem 端点 → 按 mode 启动调度。"""
        if mode not in VALID_MODES:
            raise ValueError(f"invalid mode {mode!r}, expected {VALID_MODES}")
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
            mode=mode,
        )

        # 1. 登录：优先用现有 accessTicket 续期；失败回退到密码登录
        settings = get_settings()
        password = aes_open(acct["password_blob"], settings.local_key_hex)
        client = self._make_client(rt)
        # 把 DB 里现有 ticket / token 灌进来，给 refresh_token 用
        # ⚠️ db 列名是 cem_token（历史叫法），不是 access_token；
        # 与 main.py _make_client_for 保持一致。
        client.access_ticket = acct.get("access_ticket") or ""
        client.access_token = acct.get("cem_token") or ""
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

            # 3. 建立 cem-webapi 会话（recordDeviceInfo + machineConnect）
            #    对齐 Node 项目 establishSessionConnection — 服务端把后续 REST 心跳和
            #    pushConnectEventData connect.result 绑定到这个 connectId 上。
            rt.session_ctx = make_session_context(seed=rt.mobile)
            await self._establish_sessions_for_running_machines(rt, client)
        finally:
            await client.close()

        if not is_running(rt.machines):
            db.add_log(account_id, None, "keepalive_start",
                       False, "无运行中机器，保活仍启动等待开机")

        # 3. 按 mode 启动调度
        rt.tasks_started_at = time.time()
        rt.running = True
        if rt.mode == "forever":
            rt._runner_task = asyncio.create_task(
                self._run_forever_top(rt),
                name=f"forever-top-{account_id}",
            )
            extra = f"forever runners={len([m for m in rt.machines if _is_machine_running(m)])}"
        else:
            rt._runner_task = asyncio.create_task(
                self._run_daily_loop(rt),
                name=f"daily-loop-{account_id}",
            )
            extra = f"daily interval={DAILY_INTERVAL_SECONDS}s"

        self._runtimes[account_id] = rt
        db.add_log(account_id, None, "keepalive_start", True,
                   f"mode={rt.mode}, {len(rt.machines)} machines, "
                   f"cem={rt.cem_host}:{rt.cem_port}, {extra}")

    async def _stop_account(self, rt: AccountRuntime) -> None:
        rt.running = False
        # 先停所有 forever runner（避免主任务 cancel 时仍在尝试访问 token）
        if rt.runners:
            await asyncio.gather(
                *(r.stop() for r in rt.runners.values()),
                return_exceptions=True,
            )
            rt.runners.clear()
        if rt.machine_refresh_task:
            rt.machine_refresh_task.cancel()
            try:
                await rt.machine_refresh_task
            except (asyncio.CancelledError, Exception):
                pass
            rt.machine_refresh_task = None
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
        """forever 顶层任务：启动所有 running 机器的 runner，定时 reconcile。"""
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
                    log.warning("[%s] machine list refresh failed: %s",
                                rt.account_name, e)
                    continue
                self._reconcile_machine_runners(rt)
        except asyncio.CancelledError:
            log.debug("forever top cancelled for account %s", rt.account_name)
            raise
        except Exception as e:
            log.exception("[%s] forever top crashed: %s", rt.account_name, e)
            db.add_log(rt.account_id, None, "keepalive_crashed", False, repr(e)[:200])
            rt.running = False
            rt.stats.last_status = "CRASHED"
            rt.stats.last_error = repr(e)[:200]
            rt.stats.last_time = time.strftime("%Y-%m-%d %H:%M:%S")

    def _reconcile_machine_runners(self, rt: AccountRuntime) -> None:
        """对账号下机器列表做 diff，启动/停止 runner。"""
        running_now = {
            (m.get("machineId") or m.get("instanceId") or ""): m
            for m in rt.machines if _is_machine_running(m)
        }
        running_now.pop("", None)

        # 启动新增机器的 runner
        for mid, m in running_now.items():
            if mid in rt.runners:
                continue
            runner = MachineRunner(
                rt=rt,
                machine=m,
                cem_host=rt.cem_host,
                cem_port=rt.cem_port,
                token_provider=self._make_token_provider(rt),
                token_refresher=self._make_token_refresher(rt),
            )
            runner.start()
            rt.runners[mid] = runner
            log.info("[%s] runner started for machine %s (%s)",
                     rt.account_name, m.get("machineName", ""), mid)

        # 停掉已下线机器的 runner
        gone = [mid for mid in rt.runners if mid not in running_now]
        for mid in gone:
            runner = rt.runners.pop(mid)
            asyncio.create_task(runner.stop(),
                                name=f"stop-runner-{rt.account_id}-{mid}")
            log.info("[%s] runner stopped for offline machine %s",
                     rt.account_name, mid)

        # 更新存活 runner 的 machine 引用（status 可能变化但 id 没变）
        for mid, runner in rt.runners.items():
            if mid in running_now:
                runner.machine = running_now[mid]

        # 同步任务统计（让 dashboard 的 last_machines_count 反映当前 runner 数）
        rt.stats.last_machines_count = len(running_now)
        rt.stats.last_succeeded_machines = sum(
            1 for r in rt.runners.values() if r.stats.state == "connected"
        )
        rt.stats.last_time = time.strftime("%Y-%m-%d %H:%M:%S")
        rt.stats.last_status = (
            f"FOREVER {rt.stats.last_succeeded_machines}/{rt.stats.last_machines_count} connected"
        )

    def _make_token_provider(
        self, rt: AccountRuntime,
    ) -> Callable[[], tuple[str, str]]:
        """返回闭包：拿 (access_token, access_ticket) — runner 每次重连都取最新。"""

        def _provider() -> tuple[str, str]:
            return rt.access_token, rt.access_ticket

        return _provider

    def _make_token_refresher(
        self, rt: AccountRuntime,
    ) -> Callable[[], Awaitable[bool]]:
        """返回闭包：账号级单刷 token（用 lock 防止 N 个 runner 并发刷）。"""

        async def _refresher() -> bool:
            async with rt._token_refresh_lock:
                return await self._refresh_account_token(rt)

        return _refresher

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
        except Exception as e:
            # silent failure 守卫：循环本身意外退出时，UI 必须能看到。
            # 否则 rt.running=True、task.done()=True，status_for 仍然回 running，
            # 用户以为机器在保活，实际从第 1 分钟就已经停了。
            log.exception("[%s] daily loop crashed: %s", rt.account_name, e)
            db.add_log(rt.account_id, None, "keepalive_crashed", False, repr(e)[:200])
            rt.running = False
            rt.stats.last_status = "CRASHED"
            rt.stats.last_error = repr(e)[:200]
            rt.stats.last_time = time.strftime("%Y-%m-%d %H:%M:%S")

    async def _execute_session_round(self, rt: AccountRuntime) -> None:
        """对账号下所有 running 机器逐个跑一次完整桌面会话。"""
        start = time.time()
        machine_results: list[DesktopSessionResult] = []

        # 始终先刷一次机器列表 + token（防止 ticket 过期）
        await self._refresh_machines_with_retry(rt)

        running_machines = [m for m in rt.machines if _is_machine_running(m)]
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
        """刷新机器列表；token 失效时自动刷新 + 重试一次。

        刷新后会重新对所有 running 机器调 establish_session（拿新 connectId），
        因为 reconcile 后 runner 需要新的 connectId 才能正确做 REST 心跳。
        """
        client = self._make_client(rt)
        try:
            try:
                machines = await client.get_device_info_list()
                rt.machines = machines
            except PCASError as e:
                if not PCASClient.is_auth_failure(e):
                    raise
                # token 失效 → 刷新后重试
                log.info("[%s] machine list auth failed, refreshing token...", rt.account_name)
                if await self._refresh_account_token(rt):
                    client.access_token = rt.access_token
                    client.access_ticket = rt.access_ticket
                    rt.machines = await client.get_device_info_list()
                else:
                    raise

            # 机器列表刷新后，重新做一遍 establish_session（拿新 connectId）。
            # forever 模式下 reconcile 会用到 m["connectId"] 构造 REST 心跳的 connectList。
            await self._establish_sessions_for_running_machines(rt, client)
        finally:
            await client.close()

    async def _establish_sessions_for_running_machines(
        self, rt: AccountRuntime, client: PCASClient,
    ) -> None:
        """对账号下所有 running 机器调 establish_session 拿 connectId。

        失败的机器 connectId 留空，后续 REST 心跳的 connectList 会自动剔除它。
        这个方法只用于建立 cem-webapi 业务层会话；真实桌面流走 SPICE/VDP 是另一层。
        """
        for m in rt.machines:
            if not _is_machine_running(m):
                continue
            mid = m.get("machineId") or m.get("instanceId") or ""
            mname = m.get("machineName") or mid
            try:
                res = await client.establish_session(m, rt.session_ctx)
                if res["ok"]:
                    log.info("[%s/%s] establish_session ok: connectId=%s",
                             rt.account_name, mname, res["connectId"][:12])
                    db.add_log(rt.account_id, mid, "establish_session", True,
                               f"loginUid={res['loginUid'][:12]} connectId={res['connectId'][:12]}")
                    rt.session_ctx.session_connect_ok = True
                    rt.session_ctx.session_connect_error = ""
                else:
                    log.warning("[%s/%s] establish_session failed: %s",
                                rt.account_name, mname, res["error"])
                    db.add_log(rt.account_id, mid, "establish_session", False, res["error"])
                    rt.session_ctx.session_connect_ok = False
                    rt.session_ctx.session_connect_error = res["error"]
            except Exception as e:
                log.warning("[%s/%s] establish_session crashed: %s",
                            rt.account_name, mname, e)
                db.add_log(rt.account_id, mid, "establish_session", False, repr(e)[:200])

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
