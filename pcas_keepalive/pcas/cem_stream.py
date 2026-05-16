"""cem double stream — 真实协议实现（基于 ydy.pcapng / ydy2.pcapng 抓包字节级对照修正）。

## 抓包验证结果（2026-05-13）

服务端真实地址：`36.133.24.236:8090`（不是 31015；服务端通过 `getSysConfig`
返回的 `cemDoubleStreamHost` / `cemDoubleStreamPort` 动态下发，每个区域不同）。

裸 TCP，**无 TLS**。

### 帧格式（客户端 ↔ 服务端，方向对称）

```
+--------------------------------------------------------------------+
| offset 0-3:    magic = 0x12345678 (BE uint32)                      |
| offset 4-5:    field_7 = 0x01 0x01  (2 bytes 常量)                  |
| offset 6-7:    field_b = 0x00 0x00  (2 bytes 常量)                  |
| offset 8-11:   cmd_id (BE uint32)                                  |
| offset 12-13:  payload_length (BE uint16)                          |
+--------------------------------------------------------------------+
| offset 14+:    payload = utf8(                                     |
|                  base64( RSA1024-PKCS1v15(jsonEncode(data))_blocked ))   |
+--------------------------------------------------------------------+
                            总 header = 14 字节
```

RSA 加密分块：明文超过 117 字节时按 117 字节分块，每块 PKCS1v15 加密产出 128
字节密文，然后所有密文 concat → base64。握手包明文 124 字节 → 2 块 → 256 字节
密文 → 344 base64 chars → 14+344 = 358 字节帧。

### cmd_id 真实编码（pcapng 字节级实测，2026-05-14）

cmd_id 字段是 4 字节 BE，但实际值在**高 16 位**（低 16 位恒为 0）：

| 方向 | 用途              | header cmd_id 字段 | 数值          | 业务编号 |
|------|-------------------|--------------------|---------------|----------|
| C→S  | HeartBeat         | `00 01 00 00`      | `0x00010000`  | 1        |
| S→C  | HeartBeat resp    | `00 02 00 00`      | `0x00020000`  | 2        |
| C→S  | ConnectionRequest | `00 03 00 00`      | `0x00030000`  | 3        |
| S→C  | ConnectionResp.   | `00 04 00 00`      | `0x00040000`  | 4        |

之前的代码用 `struct.pack(">I", 3)` 生成 `00 00 00 03`，服务端不识别就 silent drop
（TCP 连接保持，但完全不响应），导致 cem 握手 hang 满超时。

### 心跳间隔

实测 **5 秒**（每 5.0 秒一次，jitter ≈ ±10ms），固定不可协商。

### ticket 字段格式（实测）

`ticket:2027638495013183490:49d35ead0601400889b57898be4759aeaccountPwd`

- `ticket:` 前缀
- 19 位 userId (long)
- 32 hex （会话哈希）
- `accountPwd` 后缀 = loginType（用户名密码登录）；其他可能：`sms` / `qrCode`

来源：cem-webapi `/login/verifyAccessTicket` 响应 body 中可能的字段
（与 accessToken 并列；具体字段名待 client.py 调用时实测）。

### deviceId 字段（实测）

`R1NRKD00804004A` — Windows 主板序列号格式（15 字符，可能源自
`wmic baseboard get serialnumber` 或 WMI Win32_BaseBoard.SerialNumber）。
"""
from __future__ import annotations

import asyncio
import json
import logging
import struct
import time
from typing import Any, Awaitable, Callable

from .crypto import decrypt_to_json, encrypt_json

log = logging.getLogger("pcas.cem_stream")

# 默认值：通过 client.getSysConfig 接口的 cemDoubleStreamHost/Port 动态覆盖
DEFAULT_HOST = "36.133.24.236"
DEFAULT_PORT = 8090

# 抓包确认：固定 magic
PROTOCOL_MAGIC = 0x12345678

# 抓包确认：固定 header 常量字段
FIELD_7 = b"\x01\x01"
FIELD_B = b"\x00\x00"

# cmd_id 枚举 — 业务编号（编/解码时与 wire 格式 0xNNNN_0000 互转）
CMD_HEARTBEAT_CLIENT = 1       # C→S 心跳        wire=0x00010000
CMD_HEARTBEAT_SERVER = 2       # S→C 心跳响应    wire=0x00020000
CMD_CONNECTION_REQUEST = 3     # C→S 握手        wire=0x00030000
CMD_CONNECTION_RESPONSE = 4    # S→C 握手响应    wire=0x00040000


def _cmd_to_wire(cmd: int) -> int:
    """业务 cmd 编号 → wire u32（高 16 位放 cmd，低 16 位 reserved=0）。"""
    return (cmd & 0xFFFF) << 16


def _cmd_from_wire(wire: int) -> int:
    """wire u32 → 业务 cmd 编号。低 16 位丢弃（reserved）。"""
    return (wire >> 16) & 0xFFFF

# 抓包确认：14 字节 header，双向对称
HEADER_LEN = 14

# 抓包确认：5 秒心跳
HEARTBEAT_INTERVAL_SEC = 5

# 最大 payload 长度（u16 上限）
MAX_PAYLOAD_LEN = 0xFFFF


# ---------------- 编码 ----------------

def encode_frame(cmd_id: int, data: dict[str, Any]) -> bytes:
    """构造 cem stream 帧。

    Args:
        cmd_id: 命令 ID（1=HeartBeat, 3=ConnectionRequest）
        data: 明文 JSON 字典，会先 jsonEncode → 分块 RSA1024-PKCS1v15 → base64 → utf8
    """
    encrypted_b64 = encrypt_json(data)   # 已含 RSA 分块 + base64
    utf8_payload = encrypted_b64.encode("utf-8")
    if len(utf8_payload) > MAX_PAYLOAD_LEN:
        raise ValueError(f"payload too large: {len(utf8_payload)} > {MAX_PAYLOAD_LEN}")

    header = (
        struct.pack(">I", PROTOCOL_MAGIC)       # 4 bytes magic
        + FIELD_7                                # 2 bytes 0x0101
        + FIELD_B                                # 2 bytes 0x0000
        + struct.pack(">I", _cmd_to_wire(cmd_id)) # 4 bytes cmd_id (wire = cmd<<16)
        + struct.pack(">H", len(utf8_payload))   # 2 bytes payload length (u16)
    )
    assert len(header) == HEADER_LEN
    return header + utf8_payload


async def decode_frame(reader: asyncio.StreamReader) -> tuple[int, dict[str, Any]]:
    """从 stream 读取一帧并解密。

    返回 (cmd_id, plaintext_dict)。
    """
    header = await reader.readexactly(HEADER_LEN)
    magic = struct.unpack(">I", header[0:4])[0]
    if magic != PROTOCOL_MAGIC:
        raise ValueError(
            f"bad magic: expected 0x{PROTOCOL_MAGIC:08x}, got 0x{magic:08x} "
            f"(stream desync or wrong port?)"
        )
    cmd_id_wire = struct.unpack(">I", header[8:12])[0]
    cmd_id = _cmd_from_wire(cmd_id_wire)
    payload_len = struct.unpack(">H", header[12:14])[0]

    if payload_len == 0:
        return cmd_id, {}

    body = await reader.readexactly(payload_len)
    encrypted_b64 = body.decode("utf-8", errors="strict")
    try:
        data = decrypt_to_json(encrypted_b64)
    except Exception as e:
        log.warning("decrypt failed (cmd=%d, payload[:60]=%r): %s",
                    cmd_id, encrypted_b64[:60], e)
        return cmd_id, {"_raw_b64": encrypted_b64[:200]}
    return cmd_id, data


# ---------------- Command payload 工厂 ----------------

def build_heartbeat_data() -> dict[str, Any]:
    """构造心跳明文。

    抓包实测格式：{"command":"1","timeStamp":<13位毫秒时间戳>}

    注意：明文里 command 字段是 **字符串 "1"** 而不是数字 1。
    """
    return {
        "command": "1",
        "timeStamp": int(time.time() * 1000),
    }


def build_connection_request_data(ticket: str, device_uid: str) -> dict[str, Any]:
    """构造握手明文。

    抓包实测格式：
      {
        "command": "3",
        "ticket":  "ticket:<userId>:<32hex>accountPwd",
        "deviceId":"<wmic baseboard serialnumber>"
      }

    字段顺序：command, ticket, deviceId（json 字段顺序在 RSA 加密后无影响）
    """
    return {
        "command": "3",
        "ticket": ticket,
        "deviceId": device_uid,
    }


# ---------------- 客户端 ----------------

class CemStreamClient:
    """cem double stream 客户端 — 维持 TCP 长连接的真实保活通道。

    生命周期：
      1. open_connection(host, port)
      2. send ConnectionRequest(ticket, deviceId)
      3. recv ConnectionResponse — 验证 success=true
      4. 进入 heartbeat 循环（5 秒/次）
      5. 并发处理服务端 push
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        heartbeat_interval: int = HEARTBEAT_INTERVAL_SEC,
        on_server_push: Callable[[int, dict], Awaitable[None]] | None = None,
        on_disconnect: Callable[[Exception | None], Awaitable[None]] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.heartbeat_interval = heartbeat_interval
        self.on_server_push = on_server_push
        self.on_disconnect = on_disconnect
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.connected = False
        self._tasks: list[asyncio.Task] = []
        # 心跳/推送统计（forever 模式 runner 拿来展示）
        self.heartbeats_sent = 0
        self.pushes_received = 0

    async def connect(self, ticket: str, device_uid: str) -> dict[str, Any]:
        """建立 TCP 连接 + ConnectionRequest 握手。

        Args:
            ticket: cem-webapi 接口返回的 cem stream 票据（不是 accessToken；
                    格式 `ticket:<userId>:<32hex><loginType>`）
            device_uid: 主板序列号格式 deviceId
        """
        log.info("cem_stream: connect %s:%d (deviceUid=%s, ticket=%s...)",
                 self.host, self.port, device_uid, ticket[:30])
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

        data = build_connection_request_data(ticket, device_uid)
        frame = encode_frame(CMD_CONNECTION_REQUEST, data)
        log.info("cem_stream → ConnectionRequest (%d bytes), header=%s",
                 len(frame), frame[:HEADER_LEN].hex())
        self.writer.write(frame)
        await self.writer.drain()

        cmd, resp_data = await asyncio.wait_for(decode_frame(self.reader), timeout=15)
        log.info("cem_stream ← handshake cmd=%d data=%s",
                 cmd, json.dumps(resp_data, ensure_ascii=False)[:200])

        if cmd != CMD_CONNECTION_RESPONSE:
            raise RuntimeError(f"unexpected handshake cmd: {cmd} (want {CMD_CONNECTION_RESPONSE})")
        if not resp_data.get("success"):
            raise RuntimeError(f"handshake refused by server: {resp_data}")

        self.connected = True
        return resp_data

    async def send_heartbeat(self) -> None:
        if not self.writer:
            raise RuntimeError("not connected")
        data = build_heartbeat_data()
        frame = encode_frame(CMD_HEARTBEAT_CLIENT, data)
        self.writer.write(frame)
        await self.writer.drain()
        self.heartbeats_sent += 1
        log.debug("cem_stream → heartbeat (ts=%d)", data["timeStamp"])

    async def run(self) -> None:
        """主循环：心跳 + 接收推送，任一异常都会终止两个 task。

        无论正常返回还是异常退出，都会触发 on_disconnect 回调（forever 模式靠它
        感知掉线进入重连）。
        """
        self._tasks = [
            asyncio.create_task(self._heartbeat_loop(), name="cem_hb"),
            asyncio.create_task(self._read_loop(), name="cem_rx"),
        ]
        exc: Exception | None = None
        try:
            await asyncio.gather(*self._tasks)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            exc = e
            log.warning("cem_stream: run exited: %s", e)
        finally:
            for t in self._tasks:
                t.cancel()
            self.connected = False
            if self.on_disconnect is not None:
                try:
                    await self.on_disconnect(exc)
                except Exception as cb_err:
                    log.exception("cem_stream: on_disconnect callback failed: %s", cb_err)

    async def _heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(self.heartbeat_interval)
            try:
                await self.send_heartbeat()
            except Exception as e:
                log.warning("cem_stream: heartbeat failed: %s", e)
                raise

    async def _read_loop(self) -> None:
        assert self.reader is not None
        while True:
            cmd, data = await decode_frame(self.reader)
            log.debug("cem_stream ← cmd=%d data=%s",
                      cmd, json.dumps(data, ensure_ascii=False)[:200])
            # cmd_id == 2 是心跳响应，不打 info；其他都是 push
            if cmd != CMD_HEARTBEAT_SERVER:
                self.pushes_received += 1
                log.info("cem_stream ← push cmd=%d data=%s",
                         cmd, json.dumps(data, ensure_ascii=False)[:200])
            if self.on_server_push:
                try:
                    await self.on_server_push(cmd, data)
                except Exception as e:
                    log.exception("on_server_push failed: %s", e)

    async def close(self) -> None:
        self.connected = False
        for t in self._tasks:
            t.cancel()
        if self.writer:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass
