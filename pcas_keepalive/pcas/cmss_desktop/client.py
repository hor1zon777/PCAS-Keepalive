"""CMSS / ZTE 桌面会话客户端 — 完整实现（ZTEC 握手 + TLS + cs_suOperDesktop）。

## 完整链路（IDA 反编 + pcap 字节级验证通过）

```
1. cem-webapi getDeviceInfo → adUser + adPassword(encrypted) + customLoginParams.cagList
2. SDK AES-256-CBC 解密 adPassword → 密码明文
3. TCP connect CAG 网关 (cagList[i].addr : port)
4. ZTEC frame 116 hello (50B)
5. ZTEC frame 124 pong (50B) → server_key + aes_flag
6. ZTEC frame 125 AuthPacket (220B) = AES-256-CBC(adUser, password, session_key)
7. ZTEC frame 134 ack = 200 OK
8. TLS 1.2 升级
9. HTTP POST /cs/cs_suOperDesktop.action → connectStr
10. 维持 TCP 连接（桌面保活信号）
```
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any

from .cs_action import CsResponse, decode_cs_response_body, encode_cs_request_body, encode_su_oper_inner_payload
from .ztec_protocol import (
    AUTH_TYPE_RADIUS,
    CagParam,
    aes_decrypt_sdk,
    decode_ztec_ack,
    decode_ztec_pong,
    encode_ztec_auth_packet,
    encode_ztec_hello,
)

log = logging.getLogger("pcas.cmss_desktop.client")


@dataclass
class CmssDesktopResult:
    ztec_hello_ok: bool = False
    ztec_pong_ok: bool = False
    ztec_auth_ok: bool = False
    tls_ok: bool = False
    cs_action_ok: bool = False
    connect_str: str = ""
    server_key: int = 0
    cag_addr: str = ""
    cag_port: int = 0
    error: str = ""
    duration_ms: int = 0


class CmssDesktopClient:
    """CMSS/ZTE 桌面会话完整客户端。

    用法:
        result = await CmssDesktopClient.connect_from_device_info(machine, custom_login_params)
    """

    def __init__(self, cag_addr: str, cag_port: int = 8899, *, verify_tls: bool = False):
        self.cag_addr = cag_addr
        self.cag_port = cag_port
        self.verify_tls = verify_tls
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def close(self) -> None:
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None

    @staticmethod
    def resolve_cag_params(
        machine: dict[str, Any],
        cag_index: int = -1,
    ) -> tuple[CagParam, str, int]:
        """从 cem-webapi getDeviceInfo 机器字典构造 CagParam + 选 CAG 网关。

        Args:
            machine: machineList[i]（必须含 adUser/adPassword/customLoginParams/machineId）
            cag_index: cagList 里选哪个网关（-1=自动选：优先 IPv6，fallback IPv4）

        Returns:
            (cag_param, cag_addr, cag_port)
        """
        ad_user = machine.get("adUser", "")
        ad_password_hex = machine.get("adPassword", "")
        clp_raw = machine.get("customLoginParams")
        if isinstance(clp_raw, str):
            clp = json.loads(clp_raw)
        elif isinstance(clp_raw, dict):
            clp = clp_raw
        else:
            raise ValueError(f"customLoginParams 格式异常: {type(clp_raw)}")

        cag_list = clp.get("cagList", [])
        if not cag_list:
            raise ValueError("customLoginParams.cagList 为空")

        if cag_index < 0:
            # 优先 IPv4（兼容性好），fallback IPv6
            ipv4_gateways = [c for c in cag_list if ":" not in c.get("addr", "")]
            chosen = ipv4_gateways[0] if ipv4_gateways else cag_list[0]
        else:
            chosen = cag_list[min(cag_index, len(cag_list) - 1)]

        cag_addr = chosen["addr"]
        cag_port = chosen.get("port", 8899)

        ad_password_plain = aes_decrypt_sdk(bytes.fromhex(ad_password_hex)).decode("utf-8")

        cag_param = CagParam.from_device_info(
            machine=machine,
            custom_login_params=clp,
            ad_user=ad_user,
            ad_password_plaintext=ad_password_plain,
        )
        return cag_param, cag_addr, cag_port

    async def ztec_handshake(self, cag_param: CagParam) -> tuple[int, int]:
        """完成 ZTEC 5 帧握手。

        Returns:
            (client_key, server_key) on success
        """
        family = socket.AF_INET6 if ":" in self.cag_addr else socket.AF_INET
        log.info("[ztec] TCP connect %s:%d", self.cag_addr, self.cag_port)
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(host=self.cag_addr, port=self.cag_port, family=family),
            timeout=15.0,
        )

        client_key = int.from_bytes(os.urandom(4), "little")
        hello = encode_ztec_hello(cag_param, client_key)
        self._writer.write(hello)
        await self._writer.drain()
        log.info("[ztec] -> hello (client_key=0x%08x) cag_data=%s",
                 client_key, hello[18:34].hex())

        pong = await asyncio.wait_for(self._reader.readexactly(50), timeout=10)
        pong_info = decode_ztec_pong(pong)
        log.info("[ztec] <- pong (server_key=0x%08x aes_flag=0x%x)",
                 pong_info.server_key, pong_info.aes_flag)

        auth_pkt = encode_ztec_auth_packet(
            cag_param, client_key, pong_info.server_key, pong_info.aes_flag,
        )
        self._writer.write(auth_pkt)
        await self._writer.drain()
        log.info("[ztec] -> AuthPacket (%dB) hex[0:20]=%s ipv6=%s vmid=%s",
                 len(auth_pkt), auth_pkt[:20].hex(),
                 auth_pkt[4:20].hex(), auth_pkt[20:56].decode("ascii", "replace"))

        ack = await asyncio.wait_for(self._reader.readexactly(36), timeout=5)
        ack_info = decode_ztec_ack(ack)
        log.info("[ztec] <- ack (status=%d)", ack_info["status"])
        if not ack_info["is_ok"]:
            raise RuntimeError(f"ZTEC ack status={ack_info['status']} (expected 200)")

        # frame 135: ZTEC cmd 帧（pcap 实测：ack 后、TLS 前必须发这个）
        from .ztec_protocol import encode_ztec_cmd_post_auth
        cmd = encode_ztec_cmd_post_auth()
        self._writer.write(cmd)
        await self._writer.drain()
        log.info("[ztec] -> cmd (%dB)", len(cmd))

        return client_key, pong_info.server_key

    async def tls_upgrade(self) -> None:
        if not self._writer:
            raise RuntimeError("call ztec_handshake first")
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        await self._writer.start_tls(ctx, server_hostname=self.cag_addr)
        log.info("[ztec->tls] TLS upgrade ok")

    async def request_su_oper_desktop(
        self, vm_id: str, csap_host: str = "",
    ) -> CsResponse:
        """在 TLS 上发 HTTP POST /cs/cs_suOperDesktop.action。"""
        if not self._writer or not self._reader:
            raise RuntimeError("call tls_upgrade first")

        ts_ms = int(time.time() * 1000)
        inner = encode_su_oper_inner_payload(vm_id, ts_ms)
        body = encode_cs_request_body(inner, timestamp_ms=ts_ms)

        host = f"[{self.cag_addr}]:{self.cag_port}" if ":" in self.cag_addr else \
               f"{self.cag_addr}:{self.cag_port}"
        headers = [
            "POST /cs/cs_suOperDesktop.action HTTP/1.1",
            f"Host: {host}",
            "Accept: */*",
            "Content-Type:application/xml",
            f"Content-Length: {len(body)}",
        ]
        if csap_host:
            headers.append(f"X-Ap-sHost: {csap_host}")
        headers.extend(["", ""])

        full_req = "\r\n".join(headers).encode("ascii") + body
        self._writer.write(full_req)
        await self._writer.drain()
        log.info("[cs] -> POST cs_suOperDesktop (%dB body)", len(body))

        resp = await self._read_http_response()
        sep = resp.find(b"\r\n\r\n")
        if sep < 0:
            raise RuntimeError("bad HTTP response")
        return decode_cs_response_body(resp[sep + 4:])

    async def _read_http_response(self) -> bytes:
        buf = bytearray()
        while True:
            chunk = await asyncio.wait_for(self._reader.read(4096), timeout=15)
            if not chunk:
                raise RuntimeError("connection closed")
            buf.extend(chunk)
            if b"\r\n\r\n" in buf:
                break
        head_end = buf.find(b"\r\n\r\n") + 4
        head = buf[:head_end].decode("iso-8859-1")
        clen = 0
        for line in head.split("\r\n"):
            if line.lower().startswith("content-length:"):
                clen = int(line.split(":", 1)[1].strip())
                break
        remaining = clen - (len(buf) - head_end)
        while remaining > 0:
            chunk = await asyncio.wait_for(self._reader.read(remaining), timeout=15)
            if not chunk:
                break
            buf.extend(chunk)
            remaining -= len(chunk)
        return bytes(buf)

    @classmethod
    async def connect_desktop(
        cls,
        machine: dict[str, Any],
        *,
        cag_index: int = -1,
        keep_alive_seconds: int = 0,
    ) -> CmssDesktopResult:
        """一步到位：从 cem-webapi 机器字典 → ZTEC → TLS → cs_suOperDesktop。

        自动遍历 cagList 里的所有网关（优先 IPv4），直到有一个连通。

        Args:
            machine: getDeviceInfo 返回的 machineList[i]
            cag_index: 指定网关索引（-1=自动遍历全部，优先 IPv4）
            keep_alive_seconds: 连接成功后维持 TCP 的秒数（0=不维持）
        """
        start = time.time()
        result = CmssDesktopResult()

        try:
            # 解析 customLoginParams
            clp_raw = machine.get("customLoginParams")
            if isinstance(clp_raw, str):
                clp = json.loads(clp_raw)
            elif isinstance(clp_raw, dict):
                clp = clp_raw
            else:
                raise ValueError(f"customLoginParams 格式异常: {type(clp_raw)}")

            cag_list = clp.get("cagList", [])
            if not cag_list:
                raise ValueError("cagList 为空")
            csap_host = clp.get("csapip", "")

            # 排序：IPv4 优先
            if cag_index >= 0:
                ordered = [cag_list[min(cag_index, len(cag_list) - 1)]]
            else:
                ipv4 = [c for c in cag_list if ":" not in c.get("addr", "")]
                ipv6 = [c for c in cag_list if ":" in c.get("addr", "")]
                ordered = ipv4 + ipv6

            last_error = ""
            for gw in ordered:
                cag_addr = gw["addr"]
                cag_port = gw.get("port", 8899)
                result.cag_addr = cag_addr
                result.cag_port = cag_port

                try:
                    cag_param, _, _ = cls.resolve_cag_params(machine, cag_list.index(gw))

                    client = cls(cag_addr, cag_port)
                    try:
                        client_key, server_key = await client.ztec_handshake(cag_param)
                        result.ztec_hello_ok = True
                        result.ztec_pong_ok = True
                        result.ztec_auth_ok = True
                        result.server_key = server_key

                        await client.tls_upgrade()
                        result.tls_ok = True

                        vm_id = machine.get("machineId", "")
                        resp = await client.request_su_oper_desktop(vm_id, csap_host)
                        result.cs_action_ok = resp.success
                        result.connect_str = resp.connect_str
                        if not resp.success:
                            result.error = f"cs_action: result={resp.result} mesg={resp.mesg}"

                        if keep_alive_seconds > 0 and resp.success:
                            log.info("[desktop] keepalive %ds on %s:%d...",
                                     keep_alive_seconds, cag_addr, cag_port)
                            await asyncio.sleep(keep_alive_seconds)

                        # 成功，跳出网关循环
                        break
                    finally:
                        await client.close()

                except (OSError, asyncio.TimeoutError) as e:
                    err_msg = str(e) or type(e).__name__
                    last_error = f"{cag_addr}:{cag_port} -> {err_msg}"
                    log.info("[ztec] %s 失败，尝试下一个: %s", cag_addr, err_msg)
                    continue
                except Exception as e:
                    last_error = f"{cag_addr}:{cag_port} -> {e}"
                    log.warning("[ztec] %s 握手异常: %s", cag_addr, e)
                    continue
            else:
                # 所有网关都失败
                result.error = f"所有 {len(ordered)} 个 CAG 网关均不可达: {last_error}"

        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
            log.warning("[cmss_desktop] connect failed: %s", e)

        result.duration_ms = int((time.time() - start) * 1000)
        return result


__all__ = ["CmssDesktopClient", "CmssDesktopResult"]
