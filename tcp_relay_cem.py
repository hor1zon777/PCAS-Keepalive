"""cem stream TCP 透明转发抓包工具。

用法：
1. 管理员权限运行 PowerShell
2. python tcp_relay_cem.py
3. 改 hosts 添加：  127.0.0.1  ecloud.10086.cn
   （编辑 C:\\Windows\\System32\\drivers\\etc\\hosts）
4. 启动官方 PCAS_App，登录，进入云电脑桌面
5. 看本脚本的控制台输出，复制前几个 C→S 数据包的 hex 贴给我
6. 抓完后恢复 hosts（删除那一行）

⚠️ 改 hosts 后 cem-webapi 的 HTTPS API 也会被劫持到 127.0.0.1。
为了不影响登录，推荐：
   - 先正常登录 PCAS_App（不改 hosts）
   - 进入云电脑桌面（cem stream 已建立）
   - 此时改 hosts
   - PCAS_App 检测到 cem stream 断开会 _tryReconnect()，约 2 秒后重连本地 relay
   - 重连成功就能抓到完整握手 + 心跳

抓包足够后立即恢复 hosts。
"""
import socket
import threading
import datetime
import sys
import subprocess
import re


# ---- 拿到 ecloud.10086.cn 的真实 IP（避免 hosts 劫持） ----

def resolve_real_ip(host: str) -> str:
    """绕过 hosts 文件，直接用 DNS 查真实 IP。"""
    # 优先用 nslookup 指定公共 DNS
    for dns_server in ("223.5.5.5", "8.8.8.8", "114.114.114.114"):
        try:
            result = subprocess.run(
                ["nslookup", host, dns_server],
                capture_output=True, text=True, timeout=5,
            )
            ips = re.findall(r"Address:\s*(\d+\.\d+\.\d+\.\d+)", result.stdout)
            # 第一个 Address 通常是 DNS 服务器自己，从第二个开始才是真实 IP
            for ip in ips:
                if not ip.startswith("127.") and not ip.startswith("198.18"):
                    return ip
        except Exception:
            pass
    # fallback: socket.gethostbyname（可能被 hosts 劫持）
    return socket.gethostbyname(host)


REAL_IP = resolve_real_ip("ecloud.10086.cn")
REAL_PORT = 31015
LISTEN_PORT = 31015

print(f"=== cem stream relay ===")
print(f"  Real upstream: {REAL_IP}:{REAL_PORT}")
print(f"  Listen:        0.0.0.0:{LISTEN_PORT}")
print(f"  Hosts hint:    add `127.0.0.1 ecloud.10086.cn` to redirect PCAS_App here")
print()


def hex_dump(direction: str, data: bytes, conn_id: int) -> None:
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    arrow = "→" if direction == "C->S" else "←"
    print(f"[{ts}] conn#{conn_id} {direction} {len(data):5d} bytes  {arrow}")
    # 完整 hex（多行，每行 32 字节）
    for i in range(0, min(len(data), 256), 32):
        chunk = data[i:i + 32]
        ascii_repr = "".join(c if 32 <= ord(c) < 127 else "." for c in chunk.decode("latin1"))
        print(f"  {i:04x}  {chunk.hex():64s}  {ascii_repr}")
    if len(data) > 256:
        print(f"  ... ({len(data) - 256} more bytes)")
    sys.stdout.flush()


def relay(src: socket.socket, dst: socket.socket, direction: str, conn_id: int) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            hex_dump(direction, data, conn_id)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            src.shutdown(socket.SHUT_RD)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


conn_counter = 0


def handle_client(client: socket.socket, peer: tuple) -> None:
    global conn_counter
    conn_counter += 1
    cid = conn_counter
    print(f"\n[NEW] conn#{cid} from {peer[0]}:{peer[1]} → relay → {REAL_IP}:{REAL_PORT}")
    try:
        upstream = socket.create_connection((REAL_IP, REAL_PORT), timeout=10)
    except Exception as e:
        print(f"  upstream connect failed: {e}")
        client.close()
        return
    t1 = threading.Thread(target=relay, args=(client, upstream, "C->S", cid), daemon=True)
    t2 = threading.Thread(target=relay, args=(upstream, client, "S->C", cid), daemon=True)
    t1.start()
    t2.start()


def main() -> None:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", LISTEN_PORT))
    s.listen(8)
    print(f"Listening on :{LISTEN_PORT} — Ctrl+C 退出")
    try:
        while True:
            client, peer = s.accept()
            handle_client(client, peer)
    except KeyboardInterrupt:
        print("\n[stop]")
    finally:
        s.close()


if __name__ == "__main__":
    main()
