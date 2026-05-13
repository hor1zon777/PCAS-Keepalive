"""从 pcapng 二进制流里直接扫 cem stream 帧（不依赖 pcap 解析库）。

cem stream 帧格式（PCAS_PROTOCOL.md §4.1）：
    14 字节 header: magic(0x12345678) + 0x0101 + 0x0000 + cmd_id(4) + payload_len(2)
    payload_len 字节 payload: utf8(base64( RSA1024-PKCS1v15(plaintext)_blocked ))

由于 pcapng 是分包格式（每个 TCP 段一段 capture record），同一帧可能跨多个
record。但 magic 字节序列足够独特，我们直接 scan 整个文件取出每个 magic 命中处
往后 HEADER_LEN+payload_len 字节，能容忍一定 noise。
"""
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "pcas_keepalive"))
from pcas.crypto import decrypt_to_json

MAGIC = b"\x12\x34\x56\x78"
FIELD7 = b"\x01\x01"
FIELDB = b"\x00\x00"
HEADER_LEN = 14


def scan_cem_frames(path: Path, max_frames: int = 200):
    data = path.read_bytes()
    print(f"== {path.name} ({len(data):,} bytes) ==")
    pos = 0
    seen = 0
    while pos < len(data) - HEADER_LEN and seen < max_frames:
        idx = data.find(MAGIC, pos)
        if idx < 0:
            break
        pos = idx + 4
        # 检查 field_7 / field_b
        if data[idx + 4:idx + 6] != FIELD7 or data[idx + 6:idx + 8] != FIELDB:
            continue
        cmd_wire = struct.unpack(">I", data[idx + 8:idx + 12])[0]
        cmd_id = (cmd_wire >> 16) & 0xFFFF   # 真实业务 cmd（高 16 位）
        cmd_reserved = cmd_wire & 0xFFFF     # 低 16 位应为 0
        payload_len = struct.unpack(">H", data[idx + 12:idx + 14])[0]
        if payload_len > 0xFFFF or idx + HEADER_LEN + payload_len > len(data):
            continue
        payload = data[idx + HEADER_LEN: idx + HEADER_LEN + payload_len]
        if payload_len > 0:
            try:
                b64 = payload.decode("ascii", errors="strict")
            except UnicodeDecodeError:
                continue
            # 简单合理性校验
            if not all(c.isalnum() or c in "+/=" for c in b64[:50]):
                continue
        else:
            b64 = ""
        seen += 1
        print(f"\n-- frame #{seen} @ offset 0x{idx:x} cmd={cmd_id} (wire=0x{cmd_wire:08x}, reserved=0x{cmd_reserved:04x}) payload_len={payload_len} --")
        if payload_len == 0:
            print("  (empty payload)")
        else:
            print(f"  b64[:60]={b64[:60]!r}")
            try:
                obj = decrypt_to_json(b64)
                print(f"  PLAIN: {json.dumps(obj, ensure_ascii=False)[:300]}")
            except Exception as e:
                print(f"  decrypt fail: {e}")
        pos = idx + HEADER_LEN + payload_len


if __name__ == "__main__":
    for f in [Path("ydy.pcapng"), Path("ydy2.pcapng")]:
        if f.exists():
            scan_cem_frames(f, max_frames=30)
            print()
