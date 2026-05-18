"""CMSS / ZTE 桌面会话高层客户端（实验性骨架）。

⚠️ **当前状态：不可用**

完整 ZTEC 协议层有几个还没还原的关键点：
1. `libcag.dll::sub_100026C0` — AES key schedule 算法
2. `libcag.dll::sub_10002C00` / `sub_10003760` — AES 块加密的精确模式
3. `libvdconn.dll::AddCagAndInternalParm` — cag_param 字段填充逻辑
   （特别是 username/password 应该填什么 ticket）

在这些还原之前，本类的 `connect_and_request_desktop()` 会失败在 frame 125
ack 检查（服务端拒绝 AES 加密错的 AuthPacket）。

代码保留是为了：
- 让 keepalive.py 的 import 不破
- 提供清晰的骨架，以便后续填充
- 验证已实现的字节布局部分（frame 116 hello 已字节级对齐 IDA 反编）
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import Any

from .ztec_protocol import (
    AUTH_TYPE_RADIUS,
    CagParam,
    decode_ztec_ack,
    decode_ztec_pong,
    encode_ztec_auth_packet,
    encode_ztec_hello,
)

log = logging.getLogger("pcas.cmss_desktop.client")


@dataclass
class CmssDesktopResult:
    """一次 CMSS 桌面会话尝试的结果。"""

    ztec_hello_ok: bool = False
    ztec_pong_ok: bool = False        # frame 124 received and parsed
    ztec_auth_ok: bool = False        # frame 134 ack status == 200
    tls_handshake_ok: bool = False
    cs_action_ok: bool = False
    connect_str: str = ""
    server_key: int = 0
    error: str = ""
    duration_ms: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0


class CmssDesktopClient:
    """CMSS / ZTE 桌面会话客户端 — ZTEC 握手 → TLS → cs_action。

    ⚠️ 实验性：见模块 docstring 已知 limitation。
    """

    def __init__(
        self,
        server_ipv6: str,
        server_port: int = 8899,
        *,
        company_code: str = "CMSSZTE",
        connect_timeout: float = 15.0,
        verify_tls: bool = False,
    ):
        self.server_ipv6 = server_ipv6
        self.server_port = server_port
        self.company_code = company_code
        self.connect_timeout = connect_timeout
        self.verify_tls = verify_tls
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self.bytes_sent = 0
        self.bytes_received = 0

    async def __aenter__(self) -> "CmssDesktopClient":
        return self

    async def __aexit__(self, *_a) -> None:
        await self.close()

    async def close(self) -> None:
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None

    async def ztec_handshake(self, cag_param: CagParam) -> int:
        """完成 ZTEC 5 帧握手。

        ⚠️ 在 AES 算法完整还原前，AuthPacket (frame 125) 服务端 ack 会失败。

        Returns:
            server_key (32-bit) on success
        Raises:
            RuntimeError: 任何一步失败
        """
        family = socket.AF_INET6 if ":" in self.server_ipv6 else socket.AF_INET
        log.info("[ztec] TCP connect %s:%d ...", self.server_ipv6, self.server_port)
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(host=self.server_ipv6, port=self.server_port,
                                    family=family),
            timeout=self.connect_timeout,
        )

        # ---- frame 116: client → server hello ----
        client_key = int.from_bytes(os.urandom(4), "little")
        hello = encode_ztec_hello(cag_param, client_key)
        self._writer.write(hello)
        await self._writer.drain()
        self.bytes_sent += len(hello)
        log.info("[ztec] → hello (50B, client_key=0x%08x)", client_key)

        # ---- frame 124: server → client pong ----
        pong = await asyncio.wait_for(self._reader.readexactly(50), timeout=10)
        self.bytes_received += len(pong)
        pong_info = decode_ztec_pong(pong)
        log.info("[ztec] ← pong (server_key=0x%08x aes_flag=0x%x)",
                 pong_info.server_key, pong_info.aes_flag)

        # ---- frame 125: client → server AuthPacket ----
        auth_pkt = encode_ztec_auth_packet(
            cag_param, client_key, pong_info.server_key, pong_info.aes_flag,
        )
        self._writer.write(auth_pkt)
        await self._writer.drain()
        self.bytes_sent += len(auth_pkt)
        log.info("[ztec] → AuthPacket (%dB)", len(auth_pkt))

        # ---- frame 134: server → client ack ----
        ack = await asyncio.wait_for(self._reader.readexactly(36), timeout=10)
        self.bytes_received += len(ack)
        ack_info = decode_ztec_ack(ack)
        log.info("[ztec] ← ack (status=%d ok=%s)",
                 ack_info["status"], ack_info["is_ok"])
        if not ack_info["is_ok"]:
            raise RuntimeError(
                f"ZTEC AuthPacket 被服务端拒绝（status={ack_info['status']}）。"
                f"原因大概率：AES 加密 username/password 算法尚未完整还原。"
            )

        return pong_info.server_key

    async def tls_upgrade(self) -> None:
        """ZTEC 握手成功后在同一 TCP 上升级 TLS 1.2。"""
        if not self._writer:
            raise RuntimeError("must call ztec_handshake() first")

        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            await self._writer.start_tls(ctx, server_hostname=self.server_ipv6)
            log.info("[ztec→tls] TLS upgrade ok")
        except AttributeError:
            raise RuntimeError(
                "Python < 3.11 不支持 StreamWriter.start_tls"
            )

    async def connect_and_handshake_only(
        self, cag_param: CagParam,
    ) -> CmssDesktopResult:
        """只做 ZTEC 握手 — 用于验证 hello/pong/AuthPacket 字节布局。

        因为 AuthPacket 的 AES 加密尚未完整还原，预期会在 frame 134 失败，
        但能验证 frame 116 + frame 124 走通了。
        """
        start = time.time()
        result = CmssDesktopResult()

        try:
            result.server_key = await self.ztec_handshake(cag_param)
            result.ztec_hello_ok = True
            result.ztec_pong_ok = True
            result.ztec_auth_ok = True
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
            log.warning("[%s] ZTEC handshake failed: %s",
                        cag_param.extra_40[:36].decode("ascii", "replace"), e)

        result.bytes_sent = self.bytes_sent
        result.bytes_received = self.bytes_received
        result.duration_ms = int((time.time() - start) * 1000)
        return result


__all__ = [
    "CmssDesktopClient",
    "CmssDesktopResult",
]
