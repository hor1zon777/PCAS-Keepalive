# ZTEC / CAG 网关协议字节级规范

> 来源：IDA 反编 `D:\CloudComputer\drivers\CMSS\client\libcag.dll`（2026-05-18）
> 验证：`2.pcapng` frame 116/124/125/134 字节级对照通过

---

## 0. 一句话总结

CMSS / ZTE 桌面客户端用 **CAG (Central Access Gateway)** 网关协议接入桌面服务器。
CAG 协议在 TCP 上做 **5 帧明文握手**（带 ZTEC magic），然后建立 HTTP CONNECT 隧道 +
TLS 升级，承载后续 HTTPS 应用层流量。

完整链路：
```
TCP connect → ZTEC 5 帧握手 → HTTP CONNECT 隧道 → TLS 1.2 → HTTPS POST /cs/cs_*.action
```

---

## 1. 函数调用图（libcag.dll）

```
connectToGateWay(cag_param):                    @ 0x10001950
    client_key = rand_s()                       # 32位随机
    sub_100017E0(cag_param)                     # 参数校验
    sub_10001B00(client_key)         → frame 116 (50B hello)        @ 0x10001b00
    sub_10001CE0(socket, &server_key, &aes_flag) ← frame 124 (50B pong) @ 0x10001ce0
    sub_10001DF0(client_key, aes_flag, server_key)                  @ 0x10001df0
        ↓
        sub_10001640(64, client_key, server_key, aes_flag)  # 加密 username  @ 0x10001640
        sub_10001640(64, client_key, server_key, aes_flag)  # 加密 password
        send(frame 125, 220B)
        recv(frame 134, 36B ack)
    create_http_tunnel_proxy(socket, host, port) ← 发 CONNECT + 收 200    @ 0x10002450
```

辅助函数：
- `sub_10001430(socket, buffer)` — 带 timeout 的 recv（基于 select）@ 0x10001430
- `sub_100023D0(host, port, auth)` — 拼装 CONNECT 请求字符串 @ 0x100023d0
- `sub_100026C0` — AES key schedule（待完整反编）
- `sub_10002C00` — AES 块加密 ECB？（看 T-box 实现）
- `sub_10003760` — AES 块加密 CBC？

---

## 2. Frame 116 — Hello (50 字节 client→server)

### IDA 反编（`sub_10001B00 @ 0x10001b00`）

```cpp
int sub_10001B00(uint32_t client_key) {
    char Source[6] = "ZTEC,\0";
    int v14 = cag_param[4] + 100;        // auth_type + 100
    int v15 = client_key;
    int v16 = (auth_type==1) ? 220 : (pwd_aligned + 126);
    int v17 = 0; // (后续 12 字节 0 padding 前的字段)
    int v18 = (cag_param[88] << 16) | 3;
    int v19, v20, v21 = 0, 0, 0;
    
    memcpy(buf+0,  "ZTEC,", 6);          // bytes 0-5
    memcpy(buf+18, cag_param+8, 16);     // bytes 18-33 (Destination 16字节)
    memcpy(buf+6,  &v14, 44);            // bytes 6-49 (44字节)
    send(socket, buf, 50, 0);
}
```

### 字节布局

| offset | size | 字段 | 来源 |
|---|---|---|---|
| 0-5 | 6 | `"ZTEC,\0"` | hardcoded |
| 6-9 | 4 | `auth_type + 100` (LE u32) | cag_param[4] + 100 |
| 10-13 | 4 | `client_key` (LE u32) | rand_s() |
| 14-17 | 4 | AuthPacket total len | 220 (radius) or pwd_aligned + 126 (uac) |
| 18-33 | 16 | Destination data | cag_param[8..23] |
| 34-37 | 4 | flags + version | `(cag_param[88] << 16) \| 3` |
| 38-49 | 12 | 全 0 | padding |

### 实测对照 `2.pcapng` frame 116

```
hex:  5a544543 2c00       65000000       96c9e6f0        dc000000        1d5f69baaf088f438f8807656dcf1cf9       03008b00       00000000000000000000000000
解码: "ZTEC,"+\0          0x65 (=101)    0xf0e6c996      0xdc (=220)     Destination 16字节                     0x008b0003     padding
含义: magic               auth_type=1    client_key      auth_pkt_len    "session token"?                       sub_version=0x8b, flag=3  ✓
                          (radius +100)                   (radius=220)
```

✅ Python 实现 `encode_ztec_hello()` 字节级完全匹配。

---

## 3. Frame 124 — Pong (50 字节 server→client)

### IDA 反编（`sub_10001CE0 @ 0x10001ce0`）

```cpp
int sub_10001CE0(SOCKET sock, int *out_server_key, int *out_aes_flag) {
    char header[6];
    char payload[44];
    
    if (recv(sock, header, 6) == 6 &&        // magic + null
        *(uint16_t*)(header+4) == 44 &&      // payload len 标记
        recv(sock, payload, 44) == 44) {
        
        *out_server_key = *(int*)payload;     // bytes 6-9 of frame
        uint32_t v16 = *(int*)(payload+16);   // bytes 22-25 of frame
        *out_aes_flag = ((v16 & 2) << 7) | ((v16 & 1) ? 1 : 0);
        return 0;
    }
    return 1010;
}
```

### 字节布局

| offset | size | 字段 |
|---|---|---|
| 0-3 | 4 | `"ZTEC"` magic |
| 4-5 | 2 | payload len = 44 (LE u16) |
| 6-9 | 4 | **`server_key` (LE u32)** ⭐ |
| 10-13 | 4 | ? |
| 14-21 | 8 | ? |
| 22-25 | 4 | flags (bit0/bit1 派生 `aes_flag`) |
| 26-49 | 24 | 其他 |

---

## 4. Frame 125 — AuthPacket (220 字节 client→server, auth_type=1 radius)

### IDA 反编（`sub_10001DF0 @ 0x10001df0`，auth_type==1 路径）

```cpp
char buf[220];
memset(buf, 0, 220);

*(uint16_t*)(buf+0) = cag_param[40..41];         // spice_proxy_port
// buf[2..3] = 0
memcpy(buf+4, cag_param+24, 16);                  // server IPv6
memcpy(buf+20, cag_param+42, 40);                 // vmId UUID + extra

// 加密 username (实际数据来自 cag_param[152..215])
sub_10001640(64, buf+60_address, max_total=64, client_key, server_key, aes_flag);

// 加密 password (实际数据来自 *cag_param[220])
sub_10001640(64, buf+124_address, max_total=64, client_key, server_key, aes_flag);

buf[188] |= cag_param[89];                        // flag

send(socket, buf, 220, 0);
```

### 字节布局

| offset | size | 字段 | 来源 |
|---|---|---|---|
| 0-1 | 2 | **spice_proxy_port** (LE u16) | cag_param[40..41] |
| 2-3 | 2 | 全 0 | padding |
| 4-19 | 16 | **server IPv6** (binary) | cag_param[24..39] |
| 20-55 | 36 | **vmId UUID** (ASCII) | cag_param[42..77] |
| 56-59 | 4 | extra (实测全 0) | cag_param[78..81] |
| 60-123 | 64 | **AES(username)** | encrypted via key derived from client_key+server_key |
| 124-187 | 64 | **AES(password)** | encrypted via key derived from client_key+server_key |
| 188 | 1 | flag | `cag_param[89]` |
| 189-219 | 31 | 全 0 | padding |

### 实测对照 `2.pcapng` frame 125

```
bytes 0-3:   ec 13 00 00                       → port=0x13ec=5100 ✓
bytes 4-19:  24 09 8c 85 54 00 3b d1 ...       → IPv6 2409:8c85:5400:3bd1:e445:2249:65cf:41c3 ✓
bytes 20-55: 37 38 66 31 33 32 37 32 2d ...    → "78f13272-e749-4995-b762-fea808376787" ✓
bytes 56-59: 00 00 00 00                       → padding ✓
bytes 60-123 (64B): 31 d8 7e 82 c4 b2 bc 34 ... → AES(username)  ← 待还原算法
bytes 124-187 (64B): 8d c2 f9 05 4f e6 ...      → AES(password)  ← 待还原算法
byte 188:    01                                  → flag = 0x01 ✓
bytes 189-219: 全 0                              → padding ✓
```

---

## 5. AES 会话 key 派生（来自 `sub_10001640 @ 0x10001640`）

### 完整反编

```cpp
int sub_10001640(int data_len, int buf_end, uint32_t max_total,
                 uint32_t client_key, uint32_t server_key, uint32_t aes_flag) {
    char keystr1[244];   // 主 key string (实际只用前 36 字符)
    char keystr2[20];    
    char keystr3[40];    
    
    uint16_t v10 = (client_key >> 16) & 0xABAC;
    uint32_t v9  = server_key | 0x98979798;
    
    // 第 1 段（IV 候选, 16 hex chars）
    sprintf(temp, "%02x%02X%02X%02x%02X%02x%02x%02X",
            v10 & 0xFF,                       // [0]
            client_key & 0xAB,                // [1]
            (client_key & 0xACAB) >> 8,       // [2]
            (v10 >> 8) & 0xFF,                // [3]
            (v9 >> 8) & 0xFF,                 // [4]
            (v9 >> 16) & 0xFF,                // [5]
            (v9 >> 24) & 0xFF,                // [6]
            v10 & 0xFF);                       // [7] — 实际是栈空读
    
    // 第 2 段（主 key, 36 hex chars）
    sprintf(keystr1, "%08x%08x%02x%02x%02x%02x%02x%02x%02x%02x",
            client_key,                       // [0..3]
            server_key,                       // [4..7]
            v9 & 0xFF,                        // [8]
            (v9 >> 24) & 0xFF,                // [9]
            (v9 >> 16) & 0xFF,                // [10]
            (v9 >> 8) & 0xFF,                 // [11]
            (v10 >> 8) & 0xFF,                // [12]
            (client_key & 0xACAB) >> 8,       // [13]
            client_key & 0xAB,                // [14]
            v10 & 0xFF);                       // [15]
    
    // 通过 sub_100026C0 加工出最终 key schedule
    keystr3[39] = 0;
    sub_100026C0(keystr3, (aes_flag & 0xFF) << 7, keystr1);  // ⚠️ 待还原
    
    // 分块 16 字节加密
    if (max_total >= 16) {
        int pos = data_len;
        int delta = buf_end - data_len;
        do {
            if ((aes_flag >> 8) & 1)
                sub_10003760(pos, pos + delta, 16, keystr1, keystr2, 1);  // CBC?
            else
                sub_10002C00(pos, pos + delta, keystr1);                  // ECB? (T-box impl)
            pos += 16;
        } while (pos + 16 - data_len <= max_total);
    }
}
```

### Python 实现状态

```python
# pcas_keepalive/pcas/cmss_desktop/ztec_protocol.py
def derive_aes_key_material(client_key: int, server_key: int) -> tuple[str, str]:
    # 已实现 → 输出两段 hex 字符串
    # keystr1 = 16 hex (IV material)
    # keystr2 = 36 hex (key material)
```

### 待还原（关键卡点）

1. `sub_100026C0(keystr3, flags, keystr1)` — key schedule 算法
2. `sub_10002C00(in, out, key_schedule)` — AES ECB-like 块加密
3. `sub_10003760(in, out, len, key_schedule, ?, 1)` — AES CBC-like 块加密

`sub_10002C00` 已经看到是标准 AES T-box（4 个 dword 表 `dword_10005140` / `_10005540` /
`_10005940` / `_10005D40`），轮数取自 `key_schedule[60]`。如果是 AES-128 应该有 10 轮，
轮数字段 = 22 (= 10*2 + 2)。

---

## 6. Frame 134 — Ack (36 字节 server→client)

```cpp
// recv 36 bytes
char ack[36];
recv(sock, ack, 36, 0);
int status = *(int*)ack;        // LE u32
if (status == 200) return SUCCESS;
```

| offset | size | 字段 |
|---|---|---|
| 0-3 | 4 | **status** (LE u32, 200 = OK) |
| 4-35 | 32 | 其他 |

---

## 7. HTTP CONNECT 隧道（成功 ZTEC 握手后）

来自 `sub_100023D0 @ 0x100023d0`：

```
CONNECT [<server_ipv6>]:<port> HTTP/1.1\r\n
Host: [<server_ipv6>]:<port>\r\n
Proxy-Connection: keep-alive\r\n
Proxy-Authorization: Basic <base64-auth>\r\n
\r\n
```

服务端响应 `200 Connection established` 后开始 TLS 握手。

---

## 8. cag_param 结构字段映射（推断 + 实测）

| offset | size | 字段 | 来源（实测/推测） |
|---|---|---|---|
| 0-3 | 4 | socket fd | runtime |
| 4-5 | 2 | auth_type | 1=radius, 2=uac（macOS V3.6.5 = 1） |
| 8-23 | 16 | session token | ? |
| 24-39 | 16 | server IPv6 (binary) | 桌面服务器地址 |
| 40-41 | 2 | spice_proxy_port | 5100（实测） |
| 42-77 | 36 | vmId UUID (ASCII) | 实测 `78f13272-e749-4995-b762-fea808376787` |
| 78-81 | 4 | extra | 实测 0 |
| 88 | 1 | sub_version | 实测 0x8b |
| 89 | 1 | flag | 实测 0x01 |
| 152-215 | 64 | username (max) | ⚠️ 来源待挖 libvdconn::AddCagAndInternalParm |
| 216-217 | 2 | password len | |
| 220 | 4 | password 指针 | ⚠️ 同上 |

---

## 9. 实现完成度

| 项 | 状态 |
|---|---|
| frame 116 字节布局 | ✅ Python 完全对齐 pcap |
| frame 124 解析 | ✅ |
| frame 125 字节布局 | ✅ 除 AES 加密载荷外 |
| frame 134 解析 | ✅ |
| AES key material 生成 | ✅ 两段 hex 字符串 |
| **AES key schedule 算法** | ❌ sub_100026C0 待反编 |
| **AES 块加密** | ❌ sub_10002C00 / sub_10003760 待反编 |
| **cag_param.username/password 来源** | ❌ libvdconn::AddCagAndInternalParm 待反编 |
| HTTP CONNECT 隧道 | ✅ 编码已实现 |
| TLS 升级 | ✅ Python ssl 标准 API |
| cs_suOperDesktop body | ✅ |

---

## 10. 实测向前推进路径

1. **挖 sub_100026C0 + sub_10002C00** — 完整 AES 算法
2. **挖 libvdconn::AddCagAndInternalParm** — cag_param 内容来源
3. 用真实账号 + 抓包参数跑 Python ZTEC → 看服务端 frame 134 ack 是否返回 200
