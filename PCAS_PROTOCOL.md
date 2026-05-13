# PCAS_App 完整协议规范（全反编）

> 通过 jadx + apktool + blutter + libcag.so 字符串分析得出的完整协议规范。
> 涵盖：网关、登录、cem-webapi、保活（cem double stream）、密钥与加密、设备指纹。

---

## 1. 应用元信息

| 项 | 值 |
|---|---|
| 应用名 | 中国移动「移动云电脑」 |
| Android 包名 | `com.cmss.cloudcomputer` |
| 版本 | V3.6.2.v1 / versionCode 260403 |
| 真实业务名 | PCAS = Personal Cloud Access System |
| Flutter 工程名 | `pcas_app`（Dart AOT 内 673 个 Dart 文件） |
| 桌面客户端版本（参考） | 3.8.0（pc_windows） |
| 签名证书 | `CN=cpa, O=中国移动通信有限公司, L=suzhou` SHA256withRSA-2048 |
| 加固 | 爱加密 SecLLVM 1.7.4.20 VMP（Java 主 DEX 被保护） |
| 反编工具链 | blutter（Dart 3.5.4 / arm64 / compressed-pointers） |

---

## 2. 服务端拓扑

| Host | 用途 | 端口 |
|---|---|---|
| `ecloud.10086.cn` | 移动云电脑业务 API 主域 | 443（HTTPS） |
| `ecloud.10086.cn:31015` | **cem double stream**（保活通道）| 31015（裸 TCP） |
| `pcas.cloudtrust.com.cn` | SPA 前端 / 客户端下载站（非业务 API） | 443 |
| `pcas-test-back.cloudtrust.com.cn` | 测试后端（APISIX/3.6.0 网关） | 443 |
| `cloud-computer-h3-admin01-dongguan.cmecloud.cn` | 东莞 H3C 管理节点（生产 APK 内泄露） | - |
| `wap.cmpassport.com` | 中国移动统一身份认证 | 443 |

cem stream 的 host/port 在 Dart 端通过 `_serverHost` / `_serverPort` 两个 LoadStaticField 引用，会被 `Prefs` 缓存的 `cemDoubleStreamPort` / `cemUpdatePort` 动态覆盖（来源 `getSysConfig` 等接口）。

---

## 3. cem-webapi（HTTPS REST 控制面）

### 3.1 共用网关

```
POST https://ecloud.10086.cn/api/cem/gateway/outer/cem-webapi/<module>/<action>
  ?<eCloud OpenAPI v2.0 签名 query>
Content-Type: application/json
User-Agent: Mozilla/5.0 ... Ecloud-Cloud-Computer-Application/<ver> ...

{ "params": "<base64(RSA-1024-PKCS1v15-blocked(jsonEncode(<biz_params>)))>" }
```

### 3.2 eCloud OpenAPI 签名

| Query 参数 | 值 |
|---|---|
| `AccessKey` | `53bb79015a3f47c4be166d9371f68f14`（PCAS_App 内嵌应用级凭据）|
| `SignatureMethod` | `HmacSHA1` |
| `SignatureNonce` | 32 hex random |
| `SignatureVersion` | **`V2.0`** |
| `Timestamp` | 北京时间 ISO8601 + `Z`（看起来像 UTC 但实际是 +8h） |
| `Signature` | `hmacSHA1_hex( "BC_SIGNATURE&" + SecretKey, stringToSign )` |

SecretKey 硬编码：`6b0d3b93f3aa4c7ea076c841bead1ddd`

`stringToSign` 构造：
```
"POST\n" +
percent_encode("/api/cem/gateway/outer/cem-webapi" + endpoint) + "\n" +
sha256_hex( querystring(signParams_excluding_Signature) )
```

### 3.3 RSA 信封

**请求加密**（`pcas_app/common/cem_rsa.dart` 反编）：
```dart
cemRsaEncode(json) async {
  var utf8 = Utf8Encoder.convert(jsonEncode(json));
  var blocks = splitUint8ListByLength(utf8, 117);   // PKCS1v15 最大 117 字节
  var encrypted = blocks.map((b) => rsa.encrypt(b)).join();  // 用 encrypt 包
  return base64Encode(encrypted);
}
```

**响应解密**：对称逆向（128 字节块 / PKCS1v15 unpad / utf8 decode / jsonDecode）。

**RSA 密钥对**（PCAS_App 内嵌，RSA-1024 PKCS#1 v1.5）：
```
公钥 SPKI Base64:
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqisJL7YvdPC/gJA7fLrr1G+t6
J0arJr0sVfieVJTXTclm/2afP/fjNYY/CFcg1MUx8KPmPC2CqsUHRMZq6Ev1/UNX
E74I1TfJC/2b8aexcdZ+Lokj7AwzrM9yPy2qfV6vXtxyRrTs+JcFHVXtV6phNkor
NyIahyfy46+iNB+FSQIDAQAB

私钥（PKCS#8）见 pcas/const.py
```

### 3.4 响应包格式

```json
{
  "state": "OK | ERROR | EXCEPTION",
  "errorCode": "200 | <错误码>",
  "errorMessage": "<text>",
  "requestId": "...",
  "body": <加密前明文 dict 或 null>,
  "params": "<base64-RSA-加密后的 body 字段，部分接口返回>"
}
```

成功判定：`errorCode == "200"` 且 `body != null`。

### 3.5 80 个 cem-webapi endpoints

| module | endpoint 数 | 关键方法 |
|---|---|---|
| login | 23 | verify / verifySms / sendVerifySms / loginByCode / trustDevice / trustOrTemporaryDevice / verifyAccessTicket / recordDeviceInfo / verifyTwoFactorAuthSms / verifyUniToken / verifyQRCode(Isv/FromSmartDisk) / logout |
| user | 27 | getDeviceInfo / getDesktopStatus / getLoginUserInfo / setShutDownTime / changeMachineName / changePwd / bindMobile / unbindMobile / getHourInstanceDurationInfo / getUserDevicePolicy/v2 / deleteTrustDevice / getTrustDeviceList / ... |
| resource | 6 | operate / reloadResource / transferResource / checkTransferResource / getTransferPoolList / occupiedResourcePool |
| client | 6 | getSysConfig / getVersionUpgradeList / versionControl / getClientFileInfo / getBroadcastInfos / errorMsgReport |
| extPolicy | 5 | add / permission / query / retry / update |
| session | 2 | machineConnect / updateSessionStatus |
| machine | 2 | performance/batch / pushConnectEventData |
| device | 1 | performance/batch |
| userMessage | 3 | delete / list / read |
| clientlog | 3 | getLogUploadPath / sendLogUploadRes(V2) |
| sso | 1 | getAuthCode |
| malfunction | 1 | getIntegrationMalQrCode |

### 3.6 关键登录流程

```
密码登录两步：
  POST /login/verify { username, password, clientNeedTwoFactor: true }
    → 成功: body.accessTicket
    → 失败: errorCode="UntrustedDevice" 或 "可信认证" → 需要短信验证设备
  POST /login/verifyAccessTicket { accessTicket }
    → body.accessToken（后续 API 鉴权用）+ body.userName

短信登录两步（首次/新设备）：
  POST /login/sendVerifySms { mobile, imageCode? }
  POST /login/verifySms { mobile, verificationCode, isNeedTemporaryDeviceSelection: true }
    → body.accessTicket
    若 body.isCurrentDeviceTrustBeforeLogin == false:
       POST /login/trustOrTemporaryDevice { accessTicket, isTemporary: 0|1 }
  POST /login/verifyAccessTicket → body.accessToken

设备未受信短信验证：
  POST /login/trustDevice { mobile, verificationCode, code, loginUserName? }
    → body.accessTicket
  POST /login/verifyAccessTicket → ...

登出：POST /login/logout { accessToken, companyCode: "ECloud" }
```

### 3.7 设备指纹（merge 到所有 cem-webapi 请求 body）

通过 `pcas_app/common/common.dart::getDeviceInfo()` 派生：

| 字段 | 来源 |
|---|---|
| companyCode | 固定 `ECloud` |
| clientType | `pc_windows` / `pc_mac` / `android` |
| clientVersion | `3.8.0`（pc_windows）|
| deviceUid | `Prefs["deviceUid"]` 或 PlatformChannel `getDeviceUid()` |
| deviceName | 系统主机名 |
| deviceType | `pc` / `tablet` / `phone` |
| deviceCompany | 主板厂商 |
| deviceModel | 主板型号 |
| operatingSystem | `Windows` / `Linux` / `Android` |
| operatingVersion / deviceSystem | OS 版本 |
| cores / processor / systemArchitecture | CPU 信息 |
| diskTotal / diskUsed / ram | 磁盘和内存 |
| ipAddress / macAddress | 网络 |

---

## 4. cem double stream（裸 TCP 真实保活通道）

> **2026-05-13 抓包字节级修正**：blutter 反编出的几个关键常量与实际不符，
> 已根据 `ydy.pcapng` 抓包对照重新写定。本节内容**全部基于实测字节**。

### 4.1 接入

```
TCP connect → 36.133.24.236:8090
(无 TLS，无 HTTP wrapping，无 CAG 隧道)
```

⚠️ host/port **不是** `ecloud.10086.cn:31015`。客户端启动后先调用
`/client/getSysConfig`，服务端返回 `cemDoubleStreamHost`/`cemDoubleStreamPort`
两个字段，再由 `Prefs` 缓存覆盖默认值。31015 只是默认 fallback，生产环境实际
走 8090（且不同区域 IP 不同）。

Dart 端调用：
```dart
socket = await Socket.connect(host, port, timeout: Duration(seconds: ...));
socket.listen(_onMessage, onDone: _onDone, onError: _onError);
```

### 4.2 帧格式（C↔S 完全对称）

```
偏移  长度  字段                值
0     4    magic              0x12345678 (BE u32)
4     2    field_7            0x01 0x01      （固定）
6     2    field_b            0x00 0x00      （固定）
8     4    cmd_id             BE u32         （1=HBClient, 2=HBServer, 6=ConnReq）
12    2    payload_length     BE u16
14+   N    utf8(base64(RSA1024-PKCS1v15(jsonEncode(data))))
```

总 header = **14 字节**（不是 20，也不是 8；服务端帧布局完全相同）。

抓包样例（客户端心跳）：
```
hex:    12 34 56 78 01 01 00 00 00 00 00 01 00 ac  67 72 4a ...
        └── magic ──┘ └field_7┘ └field_b┘ └─ cmd_id ─┘ └len┘ └─ payload ──>
明文:   {"command":"1","timeStamp":1778633298979}
```

抓包样例（服务端心跳响应）：
```
hex:    12 34 56 78 01 01 00 00 00 00 00 02 00 ac  6b 37 4c ...
明文:   {"timeStamp":0}
```

### 4.3 cmd_id 枚举（实测）

| 方向 | Command                       | cmd_id | data |
|------|-------------------------------|--------|------|
| C→S  | HeartBeatClient               | **1**  | `{"command":"1","timeStamp":<millis>}` |
| S→C  | HeartBeatServerModel          | **2**  | `{"timeStamp":0}` |
| C→S  | ConnectionRequestClient       | **3**  | `{"command":"3","ticket":<accessTicket>,"deviceId":<getDeviceUid()>}` |
| S→C  | ConnectionRequestServerModel  | **4**  | `{"success":true,"reason":null}` 或 `{"success":false,"reason":"<错误说明>"}` |

注意：blutter 反编 `getCommand()` 看到 `r16 = 6` 是 Map literal allocation 的 size hint，
**不是** cmd_id 值。所有 cmd_id 均通过抓包字节级验证。

### 4.4 ConnectionRequest 字段详解（实测）

**ticket** 字段格式：
```
ticket:<userId>:<32hex><loginType>
```
- 前缀：固定字符串 `ticket:`
- userId：19 位十进制（cem-webapi 内部用户主键 ID）
- `:` 分隔符
- 32 hex：会话哈希（推测是 sha128 / random nonce）
- loginType 后缀（紧贴 32 hex，无分隔）：
  - `accountPwd`：用户名密码登录
  - `sms`：短信登录（推测）
  - `qrCode`：扫码登录（推测）

来源：`/login/verify` 接口响应 body 中的 `accessTicket` 字段。
注意这与 `/login/verifyAccessTicket` 返回的 `accessToken` 不同 ——
- `accessTicket`：cem stream 握手用 + verifyAccessTicket 换 token 的临时凭证
- `accessToken`：REST API Bearer 鉴权用

抓包实例：
```
ticket:2027638495013183490:49d35ead0601400889b57898be4759aeaccountPwd
```

**deviceId** 字段格式：

来自 `getDeviceUid()`，Windows 端走 WMI `Win32_BaseBoard.SerialNumber`，
形如 15 字符主板序列号：
```
R1NRKD00804004A
```

Linux/Mac 端走 `device_info_plus.deviceId`。

**重要**：cem stream 用的 deviceId **必须**和登录时 `/login/trustDevice` 把当前设备标记
为可信用的 deviceId 一致；服务端按 deviceId 校验登录设备可信状态。

### 4.5 心跳间隔

实测 **5 秒**（每 5.0 秒一次，时间 jitter ≈ ±10ms），固定不可协商：
```
4.275s → C→S heartbeat
4.307s ← S→C response
9.278s → C→S heartbeat   (差 5.003s)
9.310s ← S→C response
14.274s → C→S heartbeat  (差 4.996s)
...
```

### 4.6 RSA 多块加密

明文超过 117 字节时按 117 字节切块，每块独立 RSA-1024 PKCS1v15 加密产出
128 字节密文，所有密文 concat 后 base64 编码。

抓包实例：
- 心跳明文 = 41 字节 → 1 块 → 128 字节 cipher → 172 b64 chars
- 握手明文 = 124 字节 → 2 块 → 256 字节 cipher → 344 b64 chars

### 4.7 抓包字节级样例

**C→S ConnectionRequest（实测）**：
```
hex:    12 34 56 78 01 01 00 00 00 00 00 03 01 58
        └── magic ──┘ └field_7┘ └field_b┘ └─ cmd_id=3 ──┘ └─ len=344 ─┘
        47 4d 66 73 72 69 39 64 6d 56 38 67 65 6d 4a 78 ...
        └─── 344 字节 base64 payload (2 块 RSA = 256 cipher → b64) ──>
明文:   {"command":"3","ticket":"ticket:2027638495013183490:49d35ead0601400889b57898be4759aeaccountPwd","deviceId":"R1NRKD00804004A"}
```

**S→C ConnectionResponse（实测）**：
```
hex:    12 34 56 78 01 01 00 00 00 00 00 04 00 ac
                                  └─ cmd_id=4 ──┘ └─ len=172 ─┘
        6d 79 4a 53 49 43 5a 63 7a 59 72 35 31 76 69 35 ...
明文:   {"success":true,"reason":null}
```

### 4.5 服务端 push 模型（15 类）

收到对应 cmd_id 时把 payload 路由到对应 Stream。**真实 cmd_id 到 model 的映射
需要再抓包验证**（已确认 1=HBClient, 2=HBServer）：

| ServerModel | 用途 |
|---|---|
| `HeartBeatServerModel` | 心跳应答（`{"timeStamp": ...}`） |
| `ConnectionRequestServerModel` | 连接确认（`{"success": true, ...}`） |
| `MachineRefreshServerModel` | 机器列表需刷新 |
| `MachineStatusChangeServerModel` | 机器状态变化（开关机等） |
| `MachineDisconnectServerModel` | 桌面会话断开 |
| `MachineExpireServerModel` | 机器到期 |
| `MachineUnsubscribeServerModel` | 机器退订 |
| `MachineOperateServerModel` | 用户主动操作回执 |
| `HourlyPackageSurplusModel` | 小时包余量更新 |
| `MessageCenterUnreadModel` | 消息未读数 |
| `MessageCenterChangedModel` | 消息内容变化 |
| `AccessTicketInvalidServerModel` | ticket 失效（需重登录） |
| `PhoneUnbindOperateModel` | 解绑手机 |
| `PopupPromptMessageModel` | 服务端要求客户端弹窗 |
| `PeripheralsStatusModel` | 外设状态 |
| `TransferResultModel` | 资源转移结果 |
| `TicketLogInfoModel` | 登录日志 |

### 4.6 连接生命周期

```
1. 用户登录成功 → cem-webapi 返回 accessToken
2. DoubleStreamProvider._linkStart()
   - 读 _serverHost / _serverPort（带 proxy 处理）
   - Socket.connect → got TCP socket
   - socket.listen(_onMessage, _onError, _onDone)
3. 立即发 ConnectionRequestClientCommand(ticket=accessTicket)
4. 收到 ConnectionRequestServerModel 后正式工作
5. 周期发 HeartBeatClientCommand（间隔未在 Dart 端硬编码，疑似服务端下发或固定）
6. 异常 → _tryReconnect()（指数退避）
```

### 4.7 与 REST 心跳的关系

`/session/updateSessionStatus`、`/machine/performance/batch` 等 REST 心跳是辅助上报，
**不能**单独阻止云电脑空闲关机。**真正的保活效果取决于这条 cem double stream 是否在线**。

---

## 5. 客户端加密资料汇总

| 用途 | 算法 | 密钥/参数 |
|---|---|---|
| cem-webapi 请求/响应 body | RSA-1024 PKCS#1 v1.5 + Base64 | 同一对内嵌密钥 |
| cem-webapi 签名 | HMAC-SHA1 / Base64 | AK + SK 硬编码 |
| cem stream 帧 payload | 同 cem-webapi RSA | 同密钥 |
| DESUtil (purchase 模块) | DES（3DES）| `_fixKeyTo8Bytes` 处理 |
| `libcag.so`（USB 透传）| AES-256-CBC + 随机 key 协商 | server/client key swap |
| 本地存储 deviceUid / sessionTicket | Prefs（明文）| - |
| 本地存储用户登录态 | Prefs / SecureStorage | - |

---

## 6. 业务能力总览

### 6.1 桌面协议
- **SPICE**（H3C / CMSS / 通用三定制版）— `libspice*.so`
- **RustDesk**（备用 / 文件传输 / 端口转发）— `assets/flutter_assets/assets/rustdesk/librustdesk.so` 19 MB
- **VDP**（H3C 自有协议）— `libVdpServer.so` 11 MB

### 6.2 USB 透传
- **USB/IP**（中兴 EveUSB）— `libeveusb*.so` + `assets/usbconfig/usbip.conf`
- **SPICE usbredir**（libusbredirect*.so）走 libcag HTTP CONNECT 隧道

### 6.3 外设重定向
- 打印（libprintredir.so）
- 摄像头（libcamrdr.so）
- 设备（libdevredir.so）
- 视频（libvideoRedirect.so）

### 6.4 媒体
- FFmpeg 全套（avcodec/avfilter/avformat/avutil/swresample/swscale）
- GStreamer（android + H3C 定制版 + gstplayer）
- MPV
- SDL2 + OpenH264

### 6.5 多协议网络栈
- HTTPS（cem-webapi）
- 裸 TCP（cem double stream）
- gRPC over TLS（libVdpServer，用于桌面控制面）
- SPICE 二进制（桌面像素流）
- RustDesk hbbs/hbbr（备用桌面流）
- MQTT（com.cmic.promopush 推送）

---

## 7. 已知安全风险（用于自身加固，不导向攻击）

| 风险 | 评级 |
|---|---|
| 客户端硬编码 RSA-1024 私钥 → 业务层加密无效 | 高 |
| 生产 APK 泄露测试环境与内网 IP（`pcas-test-back` / `10.253.198.194:8089` / 东莞 admin 节点） | 高 |
| AccessKey/SecretKey 硬编码全局共享 | 中高 |
| network_security_config 信任 user CA + 允许明文 | 中 |
| 无 SPKI pinning（mitm 抓包零门槛） | 中 |
| 三套 OpenSSL（1.x / 1.1 / 3.x）同进程共存 | 中 |
| DESUtil 用 DES（已不安全） | 低（仅 purchase 模块） |
| H3C grpcserver.pem 是 demo 证书 (`CN=justtest.h3c.com`) | 低 |

---

## 8. 当前 Python 实现状态

| 子系统 | 状态 |
|---|---|
| `pcas/const.py` 常量 | ✓ 完全对齐（baseUrl/apiPath/AK/SK/RSA 密钥） |
| `pcas/crypto.py` RSA + 设备指纹 | ✓ 与 Dart 端 cemRsaEncode/Decode 行为一致 |
| `pcas/sign.py` eCloud V2.0 签名 | ✓ 实测打通 `/login/checkMobile` 等 |
| `pcas/client.py` cem-webapi | ✓ 登录 / 拉机器 / 开关机 / 4 路 REST 保活 |
| `pcas/cem_stream.py` cem double stream | ✓ 抓包字节级对齐（magic/header/cmd_id/payload 全部实测） |

---

## 9. 全协议已实测 / 字节级闭环

> **2026-05-13 更新**：cem stream 完整协议已通过 `ydy.pcapng` + `ydy2.pcapng`
> 两次抓包字节级闭环。所有关键字段均经 RSA 私钥解密验证。

| 项 | 状态 |
|---|---|
| magic = 0x12345678 | ✓ 字节级 |
| header 14 字节布局 | ✓ 字节级 |
| field_7 = 0x0101, field_b = 0x0000 | ✓ 字节级 |
| cmd_id 1 / 2 / 3 / 4 | ✓ 字节级 |
| RSA1024-PKCS1v15 + 多块拼接 + base64 | ✓ 字节级 |
| Heartbeat 明文格式 | ✓ 明文级 |
| ConnectionRequest 明文格式 | ✓ 明文级 |
| ConnectionResponse 明文格式 | ✓ 明文级 |
| 心跳间隔 5 秒 | ✓ 时序级 |
| ticket 字段 `ticket:<uid>:<32hex>accountPwd` | ✓ 实测值 |
| deviceId 来源（Windows BaseBoard.SerialNumber） | ✓ 实测值 |

唯一剩余推测项：服务端 push 帧的 cmd_id 5..N 与各 ServerModel 的具体映射
（机器状态变化、消息推送等 15 类）—— 需要在 cem stream 长期运行期间触发对应业务
行为（开关机、收消息等）才能抓到。

---

## 附录 A：blutter 反编命令（解决 Windows 上无 MSVC Build Tools）

```powershell
cd E:\Desktop\foldder\Code\Claude\ydy\blutter-main
pip install pyelftools requests ninja
python scripts\init_env_win.py    # 装 ICU + Capstone

# 关键：用 LLVM clang-cl + lld-link 替代 MSVC
$env:CC = 'clang-cl.exe'
$env:CXX = 'clang-cl.exe'
$env:RC = 'llvm-rc.exe'
$env:CMAKE_LINKER = 'lld-link.exe'

python blutter.py `
  E:\Desktop\foldder\Code\Claude\ydy\pcas_out\apktool_out\lib\arm64-v8a `
  E:\Desktop\foldder\Code\Claude\ydy\blutter_out
```

成功后产出：
- `blutter_out/asm/` 195 MB Dart 反编源码（pcas_app/* + rustdesk_plugin/*）
- `blutter_out/blutter_frida.js` 632 KB Frida hook 模板
- `blutter_out/pp.txt` 4.5 MB Object Pool dump
- `blutter_out/objs.txt` 1.3 MB Object dump
- `blutter_out/ida_script` 29 MB IDA Python script
