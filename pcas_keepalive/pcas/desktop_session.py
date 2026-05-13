"""完整桌面会话模拟 — 24h 保活的核心动作。

## 设计依据

抓包 `ydy2.pcapng` 显示官方 PCAS_App 进入云电脑桌面时的完整动作链：

```
T+0.00s  POST /session/machineConnect       告诉服务端"用户开始连接 X 号机器"
T+0.10s  TCP connect 36.133.24.236:8090     建立 cem double stream
T+0.15s  → ConnectionRequest (cmd_id=3)      RSA 加密 ticket+deviceId
T+0.20s  ← ConnectionResponse  (cmd_id=4)    {"success":true,"reason":null}
T+5.10s  → HeartBeat (cmd_id=1)              {"command":"1","timeStamp":...}
T+5.13s  ← HeartBeat resp (cmd_id=2)         {"timeStamp":0}
... (持续期间每 5 秒一次心跳，桌面像素流走 SPICE 端口)
T+End    断开 cem stream                     连接结束
T+End    POST /machine/pushConnectEventData  上报"会话结束"事件
```

## 已知

- **24h 内调用一次完整会话即可触发"用户活跃"标记**，足以阻止云电脑空闲关机
- cem stream **不需要持续 24h 在线** —— 短暂会话也能让服务端记一笔
- machineConnect 必须配合 cem stream 握手，单调 API 不够
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .cem_stream import CemStreamClient
from .client import PCASClient

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


def _new_session_ids(machine_id: str) -> tuple[str, str]:
    """生成 clientConnectId + clientLoginUid（与官方客户端格式接近的 UUID）。"""
    base = f"{machine_id}-{int(time.time()*1000)}"
    connect_id = uuid.uuid5(uuid.NAMESPACE_DNS, "connect-" + base).hex
    login_uid = uuid.uuid5(uuid.NAMESPACE_DNS, "login-" + base).hex
    return connect_id, login_uid


async def resolve_cem_endpoint(client: PCASClient) -> tuple[str, int]:
    """从 getSysConfig 接口拿真实 cem stream 端点；失败时用抓包默认值。"""
    try:
        resp = await client.get_sys_config()
        body = resp.get("body") or {}
        host = body.get("cemDoubleStreamHost") or FALLBACK_CEM_HOST
        port = int(body.get("cemDoubleStreamPort") or FALLBACK_CEM_PORT)
        log.info("cem stream endpoint from server: %s:%d", host, port)
        return host, port
    except Exception as e:
        log.warning("getSysConfig failed (%s), using fallback %s:%d",
                    e, FALLBACK_CEM_HOST, FALLBACK_CEM_PORT)
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
    connect_id, login_uid = _new_session_ids(machine_id)

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
        # ---- Step 1: machineConnect 上报"开始连接" ----
        try:
            await client.machine_connect(
                machine_id=machine_id,
                machine_name=machine_name,
                client_login_uid=login_uid,
                client_connect_id=connect_id,
            )
            log.info("step 1 ok: machineConnect")
        except Exception as e:
            log.warning("step 1 failed: machineConnect: %s", e)
            # 继续 — 即使 machineConnect 失败，cem stream 握手也可能让服务端记录活跃

        # ---- Step 2: cem stream 握手 ----
        if not client.access_ticket:
            raise RuntimeError("cem stream 需要 accessTicket，但 client.access_ticket 为空")

        handshake = await cem.connect(
            ticket=client.access_ticket,
            device_uid=device_uid,
        )
        result.cem_handshake_ok = bool(handshake.get("success"))
        if not result.cem_handshake_ok:
            raise RuntimeError(f"cem handshake refused: {handshake}")
        log.info("step 2 ok: cem handshake success=%s", handshake.get("success"))

        # ---- Step 3: cem stream 维持心跳 N 秒 ----
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
        log.info("step 3 ok: cem stream maintained %ds, ~%d heartbeats, %d pushes",
                 keep_seconds, result.cem_heartbeats_sent, push_count[0])

        # ---- Step 4: pushConnectEventData 上报"会话结束" ----
        try:
            await client.push_connect_event_data(
                machine_id=machine_id,
                client_connect_id=connect_id,
                client_login_uid=login_uid,
                event_type="desktop_disconnect",
                success=True,
                extra={"durationSeconds": keep_seconds},
            )
            log.info("step 4 ok: pushConnectEventData (disconnect)")
        except Exception as e:
            log.warning("step 4 failed: pushConnectEventData: %s", e)

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
