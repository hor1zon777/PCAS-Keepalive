"""ZTEC / CAG 网关协议 — 来自 IDA 反编 `libcag.dll` + pcap 字节级验证的完整实现。

## AES-256-CBC 加密验证（2026-05-18 IDA + pcap 闭环）

pcap frame 125 bytes 60-187 AES-256-CBC 解密验证：
  key = sprintf("%08x%08x%02x...", client_key, server_key, ...) 的 32 ASCII bytes（不做 hex→binary！）
  IV  = sprintf("02x%02X%02X...", v10, ...) 的前 16 ASCII bytes
  mode = AES-256-CBC
  解密结果: "Admin\\0\\0..." + "R6-FSxlf\\0\\0..." ✓ 与 cem-webapi adUser + SDK_AES_decrypt(adPassword) 一致

## cem-webapi → ZTEC AuthPacket 完整链路

1. getDeviceInfo → adUser="Admin", adPassword="75A3A41CAAFDDE8F7153F95D401888E0"
2. SDK AES-256-CBC 解密 adPassword → "R6-FSxlf" (密码明文)
3. adUser / 密码明文 各自 zero-pad 到 64 bytes
4. session AES-256-CBC 加密 (key=ASCII hex of client_key+server_key, IV=sprintf hex)
5. 填入 frame 125 bytes 60-187
"""
from __future__ import annotations

import base64
import json
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .const import (
    SDK_AES_IV,
    SDK_AES_KEY,
    ZTEC_MAGIC,
    get_vendor_pubkey_pem,
)


# ==================== RSA (cem-webapi/SDK 厂商公钥) ====================

def rsa_encrypt_with_vendor_pubkey(plaintext: bytes, company_code: str = "CMSSZTE") -> bytes:
    if len(plaintext) > 117:
        raise ValueError(f"RSA-1024 PKCS1v15 单块最大 117 字节，输入 {len(plaintext)}")
    pem = get_vendor_pubkey_pem(company_code)
    pub = serialization.load_pem_public_key(pem)
    return pub.encrypt(plaintext, asym_padding.PKCS1v15())


# ==================== AES-256-CBC (cs_*.action param 字段 — SDK 全局 key) ====================

def aes_encrypt_sdk(plaintext: bytes) -> bytes:
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(SDK_AES_KEY), modes.CBC(SDK_AES_IV))
    return cipher.encryptor().update(padded) + cipher.encryptor().finalize()


def aes_decrypt_sdk(ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(SDK_AES_KEY), modes.CBC(SDK_AES_IV))
    padded = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def aes_encrypt_sdk_base64(plaintext_str: str) -> str:
    return base64.b64encode(aes_encrypt_sdk(plaintext_str.encode("utf-8"))).decode("ascii")


def aes_decrypt_sdk_base64(b64: str) -> str:
    return aes_decrypt_sdk(base64.b64decode(b64)).decode("utf-8", errors="replace")


# ==================== AES-256-CBC (ZTEC session key — IDA 反编 + pcap 验证) ====================

def derive_session_key_and_iv(client_key: int, server_key: int) -> tuple[bytes, bytes]:
    """从 client_key + server_key 派生 AES-256-CBC 的 key 和 IV。

    IDA 反编 libcag.dll sub_10001640 + sub_100026C0 + pcap 字节级解密验证通过。

    key = sprintf("%08x%08x%02x%02x%02x%02x%02x%02x%02x%02x", ...) 的 32 ASCII bytes
    IV  = sprintf("02x%02X%02X%02x%02X%02x%02x%02X", ...) 的前 16 ASCII bytes

    Returns:
        (key_32bytes, iv_16bytes)
    """
    v10 = (client_key >> 16) & 0xABAC
    v9 = (server_key | 0x98979798) & 0xFFFFFFFF

    iv_str = "02x"
    iv_str += "%02X" % (v10 & 0xFF)
    iv_str += "%02X" % (client_key & 0xAB)
    iv_str += "%02x" % (((client_key & 0xACAB) >> 8) & 0xFF)
    iv_str += "%02X" % ((v10 >> 8) & 0xFF)
    iv_str += "%02x" % ((v9 >> 8) & 0xFF)
    iv_str += "%02x" % ((v9 >> 16) & 0xFF)
    iv_str += "%02X" % ((v9 >> 24) & 0xFF)

    key_str = "%08x%08x" % (client_key & 0xFFFFFFFF, server_key & 0xFFFFFFFF)
    key_str += "%02x" % (v9 & 0xFF)
    key_str += "%02x" % ((v9 >> 24) & 0xFF)
    key_str += "%02x" % ((v9 >> 16) & 0xFF)
    key_str += "%02x" % ((v9 >> 8) & 0xFF)
    key_str += "%02x" % ((v10 >> 8) & 0xFF)
    key_str += "%02x" % (((client_key & 0xACAB) >> 8) & 0xFF)
    key_str += "%02x" % (client_key & 0xAB)
    key_str += "%02x" % (v10 & 0xFF)

    return key_str.encode("ascii"), iv_str[:16].encode("ascii")


def ztec_aes256_cbc_encrypt(plaintext: bytes, client_key: int, server_key: int) -> bytes:
    """ZTEC AuthPacket AES-256-CBC 加密。pcap 验证通过。"""
    key, iv = derive_session_key_and_iv(client_key, server_key)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    return cipher.encryptor().update(plaintext)


def ztec_aes256_cbc_decrypt(ciphertext: bytes, client_key: int, server_key: int) -> bytes:
    """对应解密。"""
    key, iv = derive_session_key_and_iv(client_key, server_key)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    return cipher.decryptor().update(ciphertext)


# ==================== ZTEC 5 帧编码 ====================

AUTH_TYPE_RADIUS = 1
AUTH_TYPE_UAC = 2


@dataclass
class CagParam:
    """CAG 网关参数。"""

    socket_fd: int = 0
    auth_type: int = AUTH_TYPE_RADIUS
    cag_data_16: bytes = b"\x00" * 16
    server_ipv6_binary: bytes = b"\x00" * 16
    spice_proxy_port: int = 5100
    extra_40: bytes = b"\x00" * 40
    sub_version: int = 0x8b
    extra_flag: int = 0x01
    username: bytes = b""
    password: bytes = b""

    @classmethod
    def from_device_info(
        cls,
        machine: dict,
        custom_login_params: dict,
        ad_user: str,
        ad_password_plaintext: str,
        cag_index: int = 0,
    ) -> "CagParam":
        """从 cem-webapi getDeviceInfo 响应构造。

        frame 125 bytes 4-19 是桌面 VM 的 IPv6 地址（不是 CAG 网关地址！）
        来源：machineAddress 字段的 IPv6 部分 或 customLoginParams.csapipv6。
        """
        cag_list = custom_login_params.get("cagList", [])
        if not cag_list:
            raise ValueError("customLoginParams.cagList 为空")

        vm_id = machine.get("machineId", "")
        if len(vm_id) != 36:
            raise ValueError(f"machineId 应为 36 字符 UUID, got {len(vm_id)}")

        # frame 125 bytes 4-19: 桌面 VM 的 IPv6（不是 CAG 网关）
        # 优先从 machineAddress 里提取 IPv6
        machine_addr = machine.get("machineAddress") or machine.get("ip") or ""
        vm_ipv6 = ""
        for part in machine_addr.replace(",", ";").split(";"):
            part = part.strip()
            if ":" in part and not part.startswith("["):
                vm_ipv6 = part
                break
        # fallback: customLoginParams.csapipv6 (去掉端口)
        if not vm_ipv6:
            csap_v6 = custom_login_params.get("csapipv6", "")
            if csap_v6:
                # "2409:...:30087" → 去掉末尾端口号
                parts = csap_v6.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    vm_ipv6 = parts[0]
                else:
                    vm_ipv6 = csap_v6

        if vm_ipv6:
            server_ipv6_bin = socket.inet_pton(socket.AF_INET6, vm_ipv6)
        else:
            server_ipv6_bin = b"\x00" * 16

        extra_40 = vm_id.encode("ascii") + b"\x00" * 4

        return cls(
            cag_data_16=os.urandom(16),
            server_ipv6_binary=server_ipv6_bin,
            spice_proxy_port=5100,
            extra_40=extra_40,
            sub_version=0x8b,
            extra_flag=0x01,
            username=ad_user.encode("ascii"),
            password=ad_password_plaintext.encode("ascii"),
        )


def encode_ztec_hello(cag_param: CagParam, client_key: int) -> bytes:
    """frame 116 — 50 字节 hello。pcap 字节级验证通过。"""
    v14 = 220 if cag_param.auth_type == AUTH_TYPE_RADIUS else 126

    buf = bytearray(50)
    buf[0:6] = b"ZTEC,\x00"
    struct.pack_into("<I", buf, 6, cag_param.auth_type + 100)
    struct.pack_into("<I", buf, 10, client_key & 0xFFFFFFFF)
    struct.pack_into("<I", buf, 14, v14)
    buf[18:34] = cag_param.cag_data_16
    struct.pack_into("<I", buf, 34, ((cag_param.sub_version & 0xFF) << 16) | 3)
    return bytes(buf)


@dataclass
class ZtecPongInfo:
    server_key: int
    aes_flag: int


def decode_ztec_pong(frame: bytes) -> ZtecPongInfo:
    """frame 124 — 50 字节 pong。IDA 反编 sub_10001CE0 字节级对齐。"""
    if len(frame) != 50:
        raise ValueError(f"pong 应为 50 字节，收到 {len(frame)}")
    if frame[:4] != b"ZTEC":
        raise ValueError(f"bad magic: {frame[:4]!r}")
    payload = frame[6:]
    server_key = struct.unpack_from("<I", payload, 4)[0]
    v16 = struct.unpack_from("<I", payload, 28)[0]
    v4 = 1 if (v16 & 1) else 0
    v5 = (v16 & 2) << 7
    aes_flag = v5 | (v4 + 1)
    return ZtecPongInfo(server_key=server_key, aes_flag=aes_flag)


def encode_ztec_auth_packet(
    cag_param: CagParam, client_key: int, server_key: int, aes_flag: int,
) -> bytes:
    """frame 125 — 220 字节 AuthPacket。IDA + pcap AES 解密验证通过。

    加密链路（实测闭环）：
      1. username = adUser ("Admin"), zero-pad 到 64 bytes
      2. password = SDK_AES_decrypt(adPassword) ("R6-FSxlf"), zero-pad 到 64 bytes
      3. AES-256-CBC 加密 (key=ASCII hex of client_key+server_key, IV=sprintf hex)
    """
    buf = bytearray(220)
    struct.pack_into("<H", buf, 0, cag_param.spice_proxy_port & 0xFFFF)
    buf[4:20] = cag_param.server_ipv6_binary
    buf[20:60] = cag_param.extra_40

    user_plain = cag_param.username.ljust(64, b"\x00")[:64]
    pass_plain = cag_param.password.ljust(64, b"\x00")[:64]

    buf[60:124] = ztec_aes256_cbc_encrypt(user_plain, client_key, server_key)
    buf[124:188] = ztec_aes256_cbc_encrypt(pass_plain, client_key, server_key)

    buf[188] = cag_param.extra_flag & 0xFF
    return bytes(buf)


def decode_ztec_ack(frame: bytes) -> dict:
    """frame 134 — 36 字节 ack。"""
    if len(frame) < 4:
        raise ValueError("ack 太短")
    status = struct.unpack_from("<I", frame, 0)[0]
    return {"status": status, "is_ok": status == 200, "raw_hex": frame.hex()}


def build_http_connect_request(target_host: str, target_port: int) -> bytes:
    is_ipv6 = ":" in target_host
    host_str = f"[{target_host}]:{target_port}" if is_ipv6 else f"{target_host}:{target_port}"
    lines = [f"CONNECT {host_str} HTTP/1.1", f"Host: {host_str}", "Proxy-Connection: keep-alive", "", ""]
    return "\r\n".join(lines).encode("ascii")


__all__ = [
    "CagParam", "AUTH_TYPE_RADIUS", "AUTH_TYPE_UAC",
    "encode_ztec_hello", "ZtecPongInfo", "decode_ztec_pong",
    "encode_ztec_auth_packet", "decode_ztec_ack",
    "derive_session_key_and_iv", "ztec_aes256_cbc_encrypt", "ztec_aes256_cbc_decrypt",
    "build_http_connect_request",
    "rsa_encrypt_with_vendor_pubkey",
    "aes_encrypt_sdk", "aes_decrypt_sdk", "aes_encrypt_sdk_base64", "aes_decrypt_sdk_base64",
]
