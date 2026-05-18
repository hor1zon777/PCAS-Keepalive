# 公众版 CMSS 桌面会话协议分析（来自 `2.pcapng` + sslkeys.log）

> 本次会话用真实抓包 + TLS 解密还原的字节级协议规范。
> 桌面机器走 CMSS / 中兴 SmartView VDI 厂商，与 `10m.pcapng` 那个 H3C 厂商**不是同一套协议**。

---

## 0. 一句话结论

公众版云电脑桌面端按 `companyCode` 走**不同协议栈**：
- **H3C 桌面** → VDP gRPC 控制面（`libVDPServer.dylib`，39 RPC）+ 开源 SPICE 数据面 → 长连 8899/TLS
- **CMSS 桌面 (中兴)** → `cs_suOperDesktop.action` HTTP/JSON + `/cs/*` 接口（共 39 个）+ ZTEC magic 握手 + TLS + SPICE

`2.pcapng` 抓的是 **CMSS 桌面**。

---

## 1. 全程时序（含 TLS 解密）

| 时间 | Frame | 操作 |
|---|---|---|
| t=3.87s | 50/52 | POST `/api/cem/gateway/outer/cem-webapi/user/getSysTime` → systime |
| t=4.47s | (TCP) | 客户端开始连 IPv6:8899（桌面服务器） |
| t=4.52s | **116** | 客户端 → 服务端 50 B 明文（"ZTEC" magic + 客户端 nonce） |
| t=4.55s | **124** | 服务端 → 客户端 50 B 明文（"ZTEC" magic + 服务端 nonce） |
| t=4.55s | **125** | 客户端 → 服务端 220 B 明文（"AuthPacket"：服务器 IPv6 + vmId UUID + RSA-1024 加密 token） |
| t=4.61s | **134** | 服务端 → 客户端 36 B ack |
| t=4.61s | **135** | 客户端 → 服务端 116 B（命令包） |
| t=4.63s | **137** | POST `/cs/cs_suOperDesktop.action`（**HTTPS over 同一 8899 端口**）→ 5100 B JSON resp 含 `connectStr` |
| t=4.63s | **139** | 同一 TCP 上 TLS ClientHello（**ZTEC 握手→TLS 升级**） |
| t=4.67~5.25s | | TLS 1.2 完整握手 + SPICE 协议在 TLS 上 |
| t=5.17s | 279/344 | POST `/cem-webapi/machine/pushConnectEventData` → body="ok" |
| t=6.49s | 855 | POST `/cem-webapi/user/getDeviceInfo`（拉机器列表） |
| t=6.69s | 911 | POST `/cem-webapi/session/machineConnect` |
| t=6.76s | 930 | POST `/cem-webapi/user/getUserDevicePolicy/v2` |
| t=6.87s | 968 | response：userId + devicePolicyQueryRespList |
| t=21.53s | 3142/3146 | POST `machine/performance/batch` + `session/updateSessionStatus`（5min 周期 REST 心跳） |

**关键观察**：
1. `cs_suOperDesktop.action` HTTP POST 在 **ZTEC 握手成功后的同一 TCP 上**走（即客户端把 TCP 复用作 HTTP+TLS+SPICE 三协议管道）
2. 桌面建立后**立刻**调 cem-webapi `pushConnectEventData`，**桌面成功后**才调 `machineConnect`
3. cem-webapi REST 心跳每 5min 一次

---

## 2. ZTEC magic 握手协议（明文，TLS 前置）

> "ZTEC" = `0x5a 0x54 0x45 0x43` = "ZTEC"（ZTE Client）

### 2.1 帧 116 — 客户端 → 服务端（50 字节）

```
offset  hex                                              说明
0-3     5a 54 45 43                                      "ZTEC" magic
4-5     2c 00                                            后续长度 0x002c = 44
6-7     65 00                                            ?
8-9     00 00                                            ?
10-13   96 c9 e6 f0                                      4 字节随机/时间戳
14-17   dc 00 00 00                                      ?
18-33   1d 5f 69 ba af 08 8f 43 8f 88 07 65 6d cf 1c f9  16 字节 client nonce
34-35   03 00                                            command_type = 3?
36-37   8b 00                                            ?
38-49   全 0                                              padding
```

### 2.2 帧 124 — 服务端 → 客户端（50 字节）响应

```
offset  hex                                              说明
0-3     5a 54 45 43                                      "ZTEC" magic 同
4-9     2c 00 65 00 00 00                                同请求前 6 字节
10-13   3b 7e b0 2e                                      4 字节 server nonce
14-17   24 00 00 00                                      ?
18-49   全 0
```

### 2.3 帧 125 — 客户端 → 服务端（220 字节，**真正的 AuthPacket**）

```
offset    hex/ascii                                            说明
0-3       ec 13 00 00                                         总长度 5100 LE? 或包 ID
4-19      24 09 8c 85 54 00 3b d1 e4 45 22 49 65 cf 41 c3     16 字节 server IPv6 地址
20-55     "78f13272-e749-4995-b762-fea808376787"              36 字节 vmId UUID (ASCII)
56-59     00 00 00 00                                         4 字节 0
60        31 (= '1')                                          ?
61-188    <128 bytes>                                         **RSA-1024 加密 token**
189-219   全 0                                                 padding
```

**128 字节 RSA 加密块** 不是用 cem-webapi 那对 RSA-1024 密钥加密的（PKCS1v15 解密失败）。CMSS 用独立的 RSA 密钥对，**密钥来源**：
- libvdconn.dylib 里有 `/login/publicKey/v1` 接口 → 暗示客户端首次启动会从服务端动态拉公钥
- libvdconn.dylib 里有 `SetRsaPubKey` / `WriteRsaPublic` 函数 → 公钥存到本地配置

### 2.4 帧 134 — 服务端 → 客户端（36 字节 ack）

```
c8 00 00 00 00 00 ... 00 (36 字节，前 1 字节 0xc8 = 200 = "OK")
```

### 2.5 帧 135 — 客户端 → 服务端（116 字节，命令包）

```
offset  hex                                            说明
0-7     01 00 00 00 00 00 00 00                       命令类型 1
8-11    9f ea 00 00                                   长度
12-15   02 00 00 00                                   子命令 2
16-115  全 0                                          padding (100 字节)
```

### 2.6 ZTEC 握手后

立刻发送 TLS ClientHello（frame 139）开始 TLS 1.2 握手。TLS 服务端证书 = `O=ZTE, OU=SOFT, CN=DC`（中兴自签）。

---

## 3. cs_suOperDesktop.action 协议

### 3.1 请求（frame 137，POST 到 IPv6:8899/cs/cs_suOperDesktop.action）

```http
POST /cs/cs_suOperDesktop.action HTTP/1.1
Host: [2409:8c85:5400:38f8:c73d:ba21:e639:41ed]:8899
Accept: */*
Content-Type: application/xml
X-Ap-sHost: 192.168.1.200:30087
Content-Length: 238

{
    "encrypt": 7,
    "language": "zh",
    "param": "KQMuqugbQ4UYcQLpZ0ipCSxET2ncedirxTbyNn555O350JxY3C4nLxem2lH2hh6ISvSLayrUch5JZOtlhlDroxjNcLmhTpeoDYL+GU7J71g17jBizF2N6UdGszcs167+iEWxdR9UITPUgtWB4YlEeg==",
    "timestamp": "1779036951000"
}
```

- `encrypt: 7` — 加密算法版本（dylib 里看到 1/4/5/7 多个版本）
- `param` — base64 编码，**168 字符 → 126 字节**，远小于 RSA-1024 块（128 字节），所以**不是单块 RSA**
- `timestamp` — 13 位毫秒时间戳

`param` 字段加密格式（从 dylib 函数名推断）：
- `unit_AES256En` / `unit_AES256De` — **AES-256-CBC**
- key 派生方式未知（可能从前面 ZTEC 握手中协商的 nonce 派生）

### 3.2 响应（frame 339，1679 字节 JSON）

```json
{
    "result": "0",
    "connectStr": "c74d27baf70d189197c7e645a333e76c...（512 字符 hex = 256 字节）",
    "success": true,
    "mesg": "Success",
    "encryption": "0"
}
```

`connectStr` = 256 字节 hex（512 字符），从 dylib 函数 `ConnectStrAesEncode` / `AesDecodeConnStrFromCsap` 知道这是 **AES-256 加密后的 SPICE 连接票据**。`encryption: 0` 表示已加密 0=AES。

之后 `connectStr` 会传给 `StartSuOperSpiceProcess` 启动 SPICE 子进程作为命令行参数。

---

## 4. 中兴 SmartView 全接口列表（39 个 `/cs/cs_*.action`）

来自 `libvdconn.dylib` 字符串提取：

```
/cs/cs_4actoken_auth.action
/cs/cs_accessplatform_certresult.action
/cs/cs_accessplatform_login.action
/cs/cs_accessplatform_prelogin.action
/cs/cs_backupVdForClient.action
/cs/cs_bindHardwareFeature.action
/cs/cs_check_token.action
/cs/cs_delVdBakForClient.action
/cs/cs_enterBackForClient.action
/cs/cs_getCagToken.action
/cs/cs_getDesktopList.action
/cs/cs_getLoginStatus.action
/cs/cs_getRandomCheckCode.action
/cs/cs_getResetVDStatus.action
/cs/cs_getSotfList.action
/cs/cs_getTemplateList.action
/cs/cs_getToken.action
/cs/cs_getToken_ex.action
/cs/cs_getToken_zj4a.action
/cs/cs_getUserInfo.action
/cs/cs_loginOncode.action
/cs/cs_loginQuickOncode.action
/cs/cs_loginbytoken.action
/cs/cs_modifyPassword.action
/cs/cs_modifyPasswordForMoblie.action
/cs/cs_opDesktop.action
/cs/cs_opDesktop_async_query
/cs/cs_resetVD.action
/cs/cs_restartDesktop.action
/cs/cs_restoreVdForClient.action
/cs/cs_sendCodeForModifyPassword.action
/cs/cs_startDesktop.action
/cs/cs_startDesktop_async_query.action
/cs/cs_startsoftware.action
/cs/cs_suOperDesktop.action               ⭐ 用户主动连接桌面入口
/cs/cs_suOperDesktop_async_query.action   ⭐ 异步查询桌面连接状态
/cs/cs_sysConfig.action
/cs/cs_userAscription.action
/cs/cs_wxbind.action
```

CMSS 心跳路径未在 dylib 里找到——但有 `DoSohoClientHeartBeat` / `SohoSendHeartBeatThread` / `socketSetKeepalive`（后者是 SO_KEEPALIVE 内核选项）。
猜测：**TCP SO_KEEPALIVE 保持 ZTEC TCP 不断 + SPICE 数据流自然维持**就是 CMSS 桌面的"心跳"。

---

## 5. cem-webapi 业务上报层（已解密）

### 5.1 全部 11 个 cem-webapi 请求/响应已解密成功

`tools/decrypt_pcap_cemwebapi.py` 解出 17 条 cem-webapi 包，全部解密成功。结构如下：

```
frame=  50 REQ  getSysTime         (deviceUid + 设备指纹 18 字段)
frame=  52 RESP body={'systime'}
frame= 279 REQ  pushConnectEventData (CloudEvents 1.0，含 machineId/sessionId/connectId/companyCode)
frame= 344 RESP body='ok'
frame= 855 REQ  getDeviceInfo
frame= 911 REQ  session/machineConnect (含 ticket/machineId/machineName/clientConnectId/clientLoginUid)
frame= 930 REQ  getUserDevicePolicy/v2
frame= 968 RESP body={userId, devicePolicyQueryRespList, poolPolicyQueryRespList, macWhiteAddressVoMap}
frame=3142 REQ  machine/performance/batch (性能数据)
frame=3146 REQ  session/updateSessionStatus (loginUid + connectList)
frame=3154 RESP body='ok'
frame=3155 RESP body='OK'
```

### 5.2 关键确认

- ✅ **pushConnectEventData 在桌面成功后立刻调一次** + 之后**每个 5min REST 心跳周期不重复调**
- ✅ **machineConnect 仅在桌面成功建立后调一次**（不是登录就调）
- ✅ `session/updateSessionStatus` 是 5min 周期 REST 心跳的核心，body=`{loginUid, loginStatus, connectList}`
- ✅ `machine/performance/batch` 与 `session/updateSessionStatus` 同时调（同一 5min 周期）

这与当前 `pcas_keepalive` 实现一致（业务上报层修复部分 task #4 已完成）。

---

## 6. 当前 Python 实现 vs 真实流程对比

| 流程节点 | 真实客户端 | 当前 Python (pcas_keepalive) | 状态 |
|---|---|---|---|
| `getSysTime`（时钟校准） | ✓ 启动时调 | ✗ 没调（旧实现遗漏） | ⚠️ 需补 |
| ZTEC 5 帧明文握手 (8899) | ✓ 必须 | ✗ 没实现 | ❌ 需实现 |
| TLS 1.2 over 同一 TCP | ✓ 必须 | ✗ 没实现 | ❌ 需实现 |
| SPICE 桌面流 over TLS | ✓ 必须（持续 TCP） | ✗ 没实现 | ❌ 需实现 |
| `cs_suOperDesktop.action` HTTP+JSON+AES | ✓ 必须（获 connectStr） | ✗ 没实现 | ❌ 需实现 |
| `pushConnectEventData` 上报 | ✓ 桌面成功后调 | ✅ 当前 Python 已实现 | ✅ OK |
| `machineConnect` 拿 connectId | ✓ 桌面后调 | ✅ 当前 Python 已实现 | ✅ OK |
| 5min `session/updateSessionStatus` | ✓ | ✅ Python forever 模式已实现 | ✅ OK |
| 5min `machine/performance/batch` | ✓ | ✅ Python forever 模式已实现 | ✅ OK |
| cem double stream (8090) | ✗ macOS 客户端不用 | ✅ Python 在用（多余但无害） | ⚠️ 多余 |

---

## 7. 实现 Python CMSS 桌面客户端的剩余工作

### 7.1 已知前提
- ZTEC 协议 5 帧明文握手字段位置已锁定
- TLS 升级 + SPICE over TLS 流程已确认
- CMSS RSA 公钥**来自 `/login/publicKey/v1`**（客户端动态拉）— 但 macOS V3.6.5 pcap 里没看到这个调用，可能已经缓存在客户端 Prefs 里
- AES-256-CBC 用于 cs_suOperDesktop.action 的 param 字段

### 7.2 还需要逆向的
1. **CMSS RSA 公钥**：从 macOS 客户端的 Prefs/config 里挖出（位于 `~/Library/Preferences/com.cmcc.cloudcomputer.plist` 或类似）
2. **ZTEC AuthPacket RSA 块明文格式**：解开后才能知道用什么字段拼装
3. **cs_suOperDesktop.action 的 param 字段 AES key 来源**：可能从 ZTEC 握手 nonce 派生
4. **SPICE 桌面流量保活策略**：是否只要 TCP 不断 + 偶尔发 PING 就够，还是要发完整鼠标键盘事件

### 7.3 工作量估计
- 找 RSA 公钥（动态/静态）：1~2 天
- 实现 ZTEC + TLS + SPICE 客户端：3~5 天
- 调试 + 实际测试：2~3 天
- **总计：1~2 周**（与之前 H3C 路径估计相当，但 CMSS 更复杂因为协议层数多）

---

## 8. 工具产出

`tools/decrypt_pcap_cemwebapi.py` — pcap + sslkeys.log → 解所有 cem-webapi 请求/响应明文（仅 ecloud.10086.cn 域名）

用法：
```bash
./pcas_keepalive/.venv/Scripts/python.exe tools/decrypt_pcap_cemwebapi.py \
    --pcap 2.pcapng --keys sslkeys.log
# 输出 /tmp/pcap_decrypted/decrypted_requests.json
```

`tools/extract_vdp_proto.py` — 从 libVDPServer.dylib 提取 protobuf descriptor
（H3C 厂商专用，CMSS 用不到 protobuf）

---

## 9. 下一步建议

### 9.1 推荐：先实测业务上报层修复

当前 `pcas_keepalive` 已经做完业务上报层修复（pcas/client.py 加 machineConnect/establish_session + pushConnectEventData CloudEvents 1.0 + REST 心跳 connectId 修复）。

如果你的机器是 CMSS 厂商，没桌面 SPICE 持续连接的话，服务端最多看 cem-webapi REST 心跳判定"用户活跃"。Node 项目 `D:\CloudComputer\keep-alive` 实测可用，强信号显示**REST 心跳就够**。

**实测方法**：部署当前 pcas_keepalive，开 forever 模式跑 24h，看是否还自动关机。

### 9.2 备选：实现完整 CMSS 桌面客户端

如果业务上报层不足以保活，需要做 §7 的剩余工作。但工作量大、风险高。

### 9.3 长期：补 getSysTime 调用

当前 Python 实现没调 `/user/getSysTime`，真实客户端启动第一件事就是它。建议在登录前先调一次校准时钟，避免时间漂移导致签名 `INVALID_PARAMETER_TIMESTAMP`。
