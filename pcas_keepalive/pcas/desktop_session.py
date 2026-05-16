"""保活会话模拟 — 24h 保活的核心动作（cem-only 策略）。

## 设计依据

抓包 `ydy2.pcapng` 里 `machineConnect → cem` 那条链路是**用户主动打开桌面**
的业务上报，依赖 ES 中已有的 connect doc（由 SPICE 桌面连接建立时创建）。
保活场景模拟调 `machineConnect` 会撞 `document_missing_exception`。

对照 `PCAS_PROTOCOL.md §4.6 / §4.7`，PCAS_App **启动期**就只做：

```
1. cem-webapi 登录成功 → accessToken
2. DoubleStreamProvider._linkStart() → TCP connect 36.133.24.236:8090
3. 立即发 ConnectionRequest(ticket=accessTicket, deviceId=...)
4. 收到 ConnectionResponse(success=true) 后正式工作
5. 周期发 HeartBeat（5 秒一次）
6. 断开时关闭 socket（不需要业务侧上报）
```

> **§4.7 真正的保活效果取决于这条 cem double stream 是否在线**

业务 REST 接口 `recordDeviceInfo` 仍然保留 — 让服务端记一笔"客户端登录信息"，
失败不短路。`machineConnect` / `pushConnectEventData` 全部移除。
"""
from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable

from .cem_stream import CemStreamClient
from .client import PCASClient, create_official_session_context

log = logging.getLogger("pcas.desktop_session")


# 默认 cem stream 端点（getSysConfig 失败时的 fallback）
FALLBACK_CEM_HOST = "36.133.24.236"
FALLBACK_CEM_PORT = 8090

# 桌面会话默认维持时长（秒）— 6 个心跳间隔，足以让服务端记录"活跃"
DEFAULT_KEEP_ALIVE_SECONDS = 30


@dataclass
class DesktopSessionResult:
    machine_id: str
    machine_name: str
    success: bool
    cem_handshake_ok: bool
    cem_heartbeats_sent: int
    cem_pushes_received: int
    duration_ms: int
    error: str = ""


async def resolve_cem_endpoint(client: PCASClient) -> tuple[str, int]:
    """返回 cem stream 端点 — 当前固定使用抓包确认的默认值。

    背景：PCAS_App 的硬编码默认是 `https://ecloud.10086.cn:31015`，但服务端在
    某处会改写客户端 Prefs 的 `cemDoubleStreamHost/Port`（具体下发接口尚未抓到）。
    我们已经抓包验证 `36.133.24.236:8090` 在当前用户的可用性，先用作 fallback。

    如果未来抓到端点下发接口，可在这里改为动态查询。
    """
    log.info("cem stream endpoint = %s:%d (抓包确认的 fallback)",
             FALLBACK_CEM_HOST, FALLBACK_CEM_PORT)
    return FALLBACK_CEM_HOST, FALLBACK_CEM_PORT


async def simulate_desktop_session(
    client: PCASClient,
    machine: dict[str, Any],
    device_uid: str,
    cem_host: str,
    cem_port: int,
    keep_seconds: int = DEFAULT_KEEP_ALIVE_SECONDS,
) -> DesktopSessionResult:
    """模拟一次完整桌面连接会话。

    Args:
        client: 已登录的 PCASClient（含 access_ticket / access_token）
        machine: machine 字段，至少含 machineId + machineName
        device_uid: 此账号的固定 deviceId（来自 generate_device_info）
        cem_host / cem_port: cem stream 真实端点
        keep_seconds: cem stream 维持秒数（默认 30，覆盖 6 个心跳）

    Returns:
        DesktopSessionResult
    """
    machine_id = machine.get("machineId") or machine.get("instanceId") or ""
    machine_name = machine.get("machineName", "") or ""

    # 使用与 Node 参考 `createOfficialSessionContext` 等价的生成器
    # （Python 端在 pcas/client.py 已实现），保证 4 个 id 一一对齐。
    ctx = create_official_session_context(machine_id)
    login_uid = ctx["clientLoginUid"]
    connect_id = ctx["clientConnectId"]

    log.info("desktop session start: machine=%s (%s) keep=%ds",
             machine_name, machine_id, keep_seconds)
    start = time.time()

    result = DesktopSessionResult(
        machine_id=machine_id,
        machine_name=machine_name,
        success=False,
        cem_handshake_ok=False,
        cem_heartbeats_sent=0,
        cem_pushes_received=0,
        duration_ms=0,
    )

    push_count = [0]

    async def on_push(cmd_id: int, data: dict) -> None:
        if cmd_id not in (2,):  # 2 是心跳响应，不算 push
            push_count[0] += 1
            log.info("server push cmd=%d data=%s", cmd_id, data)

    cem = CemStreamClient(
        host=cem_host,
        port=cem_port,
        heartbeat_interval=5,
        on_server_push=on_push,
    )

    try:
        # ---- Step 0: recordDeviceInfo 注册当前 clientLoginUid（最佳努力） ----
        # 服务端按 clientLoginUid 索引记一笔"客户端登录信息"。
        # 这一步成败不影响 cem stream 保活，失败仅打 warning。
        try:
            record = await client.record_device_info(login_uid)
            server_login_uid = (record.get("body") or {}).get("loginUid", "")
            log.info("step 0 ok: recordDeviceInfo serverLoginUid=%s", server_login_uid)
        except Exception as e:
            log.warning("step 0 failed (non-fatal): recordDeviceInfo: %s", e)

        # ---- Step 1: cem stream 握手 ----
        # 保活的核心。PCAS_App 启动期就是这一步建立长连接，不依赖 machineConnect。
        if not client.access_ticket:
            raise RuntimeError("cem stream 需要 accessTicket，但 client.access_ticket 为空")

        handshake = await cem.connect(
            ticket=client.access_ticket,
            device_uid=device_uid,
        )
        result.cem_handshake_ok = bool(handshake.get("success"))
        if not result.cem_handshake_ok:
            raise RuntimeError(f"cem handshake refused: {handshake}")
        log.info("step 1 ok: cem handshake success=%s", handshake.get("success"))

        # ---- Step 2: cem stream 维持心跳 N 秒 ----
        # 跑 read_loop + heartbeat_loop 在 background；主线程睡 keep_seconds
        run_task = asyncio.create_task(cem.run())
        try:
            await asyncio.sleep(keep_seconds)
        finally:
            run_task.cancel()
            try:
                await run_task
            except (asyncio.CancelledError, Exception):
                pass

        # 估算心跳次数（实际 send 数取决于 send_heartbeat 调用次数；run_loop 内部已计数）
        result.cem_heartbeats_sent = max(1, keep_seconds // 5)
        result.cem_pushes_received = push_count[0]
        log.info("step 2 ok: cem stream maintained %ds, ~%d heartbeats, %d pushes",
                 keep_seconds, result.cem_heartbeats_sent, push_count[0])

        result.success = True

    except Exception as e:
        result.error = repr(e)
        log.exception("desktop session failed: %s", e)
    finally:
        await cem.close()
        result.duration_ms = int((time.time() - start) * 1000)

    log.info("desktop session done: machine=%s success=%s duration=%dms",
             machine_name, result.success, result.duration_ms)
    return result


# ---------- forever 模式：常驻 cem stream 上下文 ----------


@asynccontextmanager
async def cem_stream_session(
    client: PCASClient,
    machine: dict[str, Any],
    device_uid: str,
    cem_host: str,
    cem_port: int,
    *,
    heartbeat_interval: int = 5,
    on_push: Callable[[int, dict], Awaitable[None]] | None = None,
    on_disconnect: Callable[[Exception | None], Awaitable[None]] | None = None,
) -> AsyncIterator[CemStreamClient]:
    """单台机器的 cem stream 异步上下文：握手成功后 yield 出 client。

    使用：
        async with cem_stream_session(...) as cem:
            run_task = asyncio.create_task(cem.run())
            ...
            # 退出时自动 close

    上下文负责：
      1. record_device_info（best-effort，失败仅 warning）
      2. cem stream TCP connect + ConnectionRequest 握手
      3. 出错或正常退出时关闭 socket

    上下文**不**启动 cem.run() — 由调用者按需启动后台 task。
    """
    machine_id = machine.get("machineId") or machine.get("instanceId") or ""
    machine_name = machine.get("machineName", "") or ""
    ctx = create_official_session_context(machine_id)
    login_uid = ctx["clientLoginUid"]

    # Step 0: recordDeviceInfo（best-effort）
    try:
        record = await client.record_device_info(login_uid)
        server_login_uid = (record.get("body") or {}).get("loginUid", "")
        log.debug("[%s] recordDeviceInfo serverLoginUid=%s",
                  machine_name, server_login_uid)
    except Exception as e:
        log.warning("[%s] recordDeviceInfo failed (non-fatal): %s",
                    machine_name, e)

    if not client.access_ticket:
        raise RuntimeError("cem stream 需要 accessTicket，但 client.access_ticket 为空")

    cem = CemStreamClient(
        host=cem_host,
        port=cem_port,
        heartbeat_interval=heartbeat_interval,
        on_server_push=on_push,
        on_disconnect=on_disconnect,
    )

    try:
        handshake = await cem.connect(
            ticket=client.access_ticket,
            device_uid=device_uid,
        )
        if not handshake.get("success"):
            raise RuntimeError(f"cem handshake refused: {handshake}")
        log.info("[%s] cem stream session established (host=%s:%d)",
                 machine_name, cem_host, cem_port)
        yield cem
    finally:
        await cem.close()
