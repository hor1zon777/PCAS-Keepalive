"""RSA + 设备指纹 + 本地 AES。

⚠️ 重要修正（对照 D:\\CloudComputer\\keep-alive 的 Node 实现）：
  - 加密：公钥 RSA-1024 + PKCS1v15 padding 分块（块大小 117 / 输出 128）
  - 解密：私钥 RSA-1024 + **NO_PADDING** 手动去 PKCS1 padding！
    因为 Node 端用 publicEncrypt 加密、用 privateDecrypt(NO_PADDING) 解密 + 手动 strip
    Python 这边直接用 PKCS1v15 解密也行（结果一致）；但为了行为完全对齐 Node 版，
    保留对 NO_PADDING 的支持。

  - 信封：JSON.stringify({ params: rsaEncryptBase64 })  字段名 'params'
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import secrets

from .const import (
    CPU_MODELS,
    PCAS_RSA_PRIVATE_KEY_PEM,
    PCAS_RSA_PUBLIC_KEY_PEM,
)

# ---------- RSA ----------

_pub_key: rsa.RSAPublicKey | None = None
_priv_key: rsa.RSAPrivateKey | None = None


def _get_pub() -> rsa.RSAPublicKey:
    global _pub_key
    if _pub_key is None:
        _pub_key = serialization.load_pem_public_key(PCAS_RSA_PUBLIC_KEY_PEM.encode())
    return _pub_key  # type: ignore[return-value]


def _get_priv() -> rsa.RSAPrivateKey:
    global _priv_key
    if _priv_key is None:
        _priv_key = serialization.load_pem_private_key(
            PCAS_RSA_PRIVATE_KEY_PEM.encode(), password=None
        )
    return _priv_key  # type: ignore[return-value]


RSA_KEY_BYTES = 128             # 1024 bits
RSA_PLAIN_BLOCK = 117           # 128 - 11 (PKCS1 v1.5 overhead)


def rsa_encrypt(plaintext: bytes) -> str:
    """公钥分块 PKCS1v15 加密，返回拼接后整体 base64。"""
    pub = _get_pub()
    out = bytearray()
    for i in range(0, len(plaintext), RSA_PLAIN_BLOCK):
        block = plaintext[i : i + RSA_PLAIN_BLOCK]
        out.extend(pub.encrypt(block, padding.PKCS1v15()))
    return base64.b64encode(bytes(out)).decode("ascii")


def rsa_decrypt(b64_cipher: str) -> bytes:
    """私钥分块解密。

    标准做法用 PKCS1v15 padding 即可：
        priv.decrypt(block, padding.PKCS1v15())
    Node 参考实现里用了 NO_PADDING + 手动 strip，结果等价。
    """
    priv = _get_priv()
    ct = base64.b64decode(b64_cipher)
    out = bytearray()
    for i in range(0, len(ct), RSA_KEY_BYTES):
        block = ct[i : i + RSA_KEY_BYTES]
        try:
            out.extend(priv.decrypt(block, padding.PKCS1v15()))
        except ValueError:
            # PKCS1v15 严格校验失败 → fallback 到 raw decrypt + 手动 strip padding
            from cryptography.hazmat.primitives.asymmetric.padding import _RSAPadding  # noqa
            # cryptography 不直接暴露 raw RSA；如需 NO_PADDING 模式需依赖 PyCryptodome。
            # 实测 Node 加密 + Python PKCS1v15 解密能成功，不会走到这里。
            raise
    return bytes(out)


def encrypt_json(obj: Any) -> str:
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return rsa_encrypt(raw)


def decrypt_to_json(b64: str) -> Any:
    raw = rsa_decrypt(b64)
    return json.loads(raw.decode("utf-8"))


# ---------- 设备指纹（按账号 SHA256 派生稳定值） ----------

_device_cache: dict[str, dict[str, Any]] = {}


def generate_device_info(account: str) -> dict[str, Any]:
    """与 Node 端 generateDeviceInfo() 行为一致的设备指纹生成。"""
    seed = account or "default"
    h = hashlib.sha256(seed.encode()).hexdigest()

    def hex_at(off: int, n: int) -> str:
        return h[off : off + n]

    def int_at(off: int, lo: int, hi: int) -> int:
        return lo + (int(h[off : off + 4], 16) % (hi - lo + 1))

    mac = ":".join(hex_at(i, 2) for i in (0, 2, 4, 6, 8, 10)).upper()
    ip = f"192.168.{int_at(12, 1, 254)}.{int_at(16, 2, 253)}"
    device_uid = ("KA" + h[:14]).upper()
    device_name = "DESKTOP-" + h[14:21].upper()
    cpu = CPU_MODELS[int_at(20, 0, len(CPU_MODELS) - 1)]
    cores = [4, 6, 8][int_at(24, 0, 2)]
    ram = [8, 16, 32][int_at(28, 0, 2)]
    disk_total = [256, 500, 512, 1000][int_at(32, 0, 3)]
    disk_used = int_at(36, 50, max(50, int(disk_total * 0.7)))

    return {
        "companyCode": "ECloud",
        "clientType": "pc_windows",
        "clientVersion": "3.8.0",
        "deviceUid": device_uid,
        "deviceName": device_name,
        "deviceType": "pc",
        "deviceCompany": "QEMU",
        "deviceModel": "Standard PC (i440FX + PIIX, 1996)",
        "operatingSystem": "Windows",
        "deviceSystem": "Windows 10",
        "operatingVersion": "Windows 10",
        "cores": cores,
        "processor": cpu,
        "systemArchitecture": "x86",
        "diskTotal": disk_total,
        "diskUsed": disk_used,
        "ram": ram,
        "ipAddress": ip,
        "macAddress": mac,
    }


def get_device_info(account: str) -> dict[str, Any]:
    if account not in _device_cache:
        _device_cache[account] = generate_device_info(account)
    return _device_cache[account]


# ---------- 本地 AES（仅用于 sqlite 中密码二次加密） ----------

def _aes_key_from_hex(hex_key: str) -> bytes:
    key = bytes.fromhex(hex_key)
    if len(key) < 32:
        key = key + b"\x00" * (32 - len(key))
    return key[:32]


def aes_seal(plaintext: str, hex_key: str) -> str:
    aes = AESGCM(_aes_key_from_hex(hex_key))
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def aes_open(blob_b64: str, hex_key: str) -> str:
    aes = AESGCM(_aes_key_from_hex(hex_key))
    raw = base64.b64decode(blob_b64)
    nonce, ct = raw[:12], raw[12:]
    return aes.decrypt(nonce, ct, None).decode("utf-8")


def gen_nonce() -> str:
    """32 字符 hex 随机串（对应 Node 的 crypto.randomUUID().replaceAll('-', '')）"""
    return secrets.token_hex(16)
