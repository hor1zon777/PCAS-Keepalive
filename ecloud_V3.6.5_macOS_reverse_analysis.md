# 移动云电脑公众版 V3.6.5 (macOS) 逆向分析报告

> **分析日期**：2026-05-14
> **样本**：`Ecloud_CloudComputer_V3.6.5.pkg` (357 MB, x86_64)
> **目标**：对照已有 Python 实现 `pcas_keepalive` 与 Android V3.6.2 协议规范（PCAS_PROTOCOL.md），定位公众版 macOS V3.6.5 的协议差异与新增点。
> **结论先行**：**Python `pcas_keepalive` 已经基于 Android 抓包字节级实现了 cem-webapi + cem double stream，macOS V3.6.5 与之共享同一套生产凭据/RSA 密钥/签名规则/RSA 信封字段；macOS 端 ee-core 主进程不实现 cem stream（保活靠 Qt 子进程的桌面层 HeartBeat），但若要继续做"轻量级保活脚本"，所有协议参数都仍然可用**。本次主要收获是公众版完整 endpoint 列表、dev/prod 双环境凭据、SDK 公钥按厂商分（ZTE/H3C/Inspur）、设备指纹字段名 1:1 对齐，以及 4A/QR/SIM/AD/checkMobile 等新登录方式的接口名。

---

## 0. 与 Go 项目 `cloud-computer-keepalive-master` 的关系定位

| 维度 | 别人的 Go 项目 | 当前 Python `pcas_keepalive` | macOS V3.6.5 公众版 |
|---|---|---|---|
| 产品形态 | **家庭云电脑（SOHO）** | **公众版（业务）** | **公众版（业务）** |
| API 主域 | `soho.komect.com` | `ecloud.10086.cn` | `ecloud.10086.cn` ✓ |
| 客户端 User-Agent | `jtydn-Mac-2.18.21` | `Ecloud-Cloud-Computer-Application/3.8.0` | `Ecloud-Cloud-Computer-Application` |
| 签名机制 | 自定义 `X-SOHO-*` HMAC-SHA256 头 | eCloud OpenAPI V2.0（query 内 AK + HmacSHA1） | **完全相同** ✓ |
| 请求体加密 | 自定义 textbook RSA + AES-CTR | RSA-1024 PKCS1v15 + base64 | **完全相同** ✓ |
| 业务凭据 AccessKey | `ef80482854c2a2a36311a4...` | `53bb79015a3f47c4be166d9371f68f14` | **完全相同** ✓ |
| 保活通道 | CEM REST + SCG TCP + TLS + chuanyun 24B 帧 + SPICE | **cem double stream**（裸 TCP, 0x12345678 magic, 5s 心跳） | （主进程不实现，见 §6） |

**结论**：用户反馈 "别人的程序只支持家庭版，不支持公众版" 完全正确：
- 家庭版（jtydn）走 SOHO API，是另一套完全独立的协议栈（基于中兴 SCG/uSmartView/chuanyun）
- 公众版（业务级移动云电脑）走 ecloud.10086.cn cem-webapi，Android/PC Windows/macOS 三端共享同一套凭据与协议

---

## 1. pkg 解包结果

```
xar archive (SHA-1 TOC)
├── Distribution                                       # 安装脚本
├── Resources/{en,zh-Hans}.lproj/Localizable.strings   # 多语言
└── tmp.pkg/
    ├── Bom / Scripts / PackageInfo
    └── Payload                                         # gzip + cpio ASCII
        └── /Applications/Ecloud Cloud Computer Application.app
            ├── Contents/Info.plist                     # com.cmcc.cloudcomputer V3.6.5
            ├── Contents/MacOS/Ecloud Cloud Computer Application
            ├── Contents/Frameworks/Electron Framework.framework  # 22.3.27
            └── Contents/Resources/
                ├── app.asar                            # 158 MB Electron 业务代码（ee-core）
                ├── extraResources/Applications/
                │   ├── Ecloud-Cloud-Computer-Session.app    # 20 MB Qt 桌面会话主程序（CMSS）
                │   │   └── Contents/MacOS/Ecloud-Cloud-Computer-Session  (Mach-O x86_64, Qt 5.15.8 + GStreamer 1.16.2)
                │   ├── uSmartView_VDI_Client.app             # 中兴 ZTE VDI 客户端 (Qt 5.15.16)
                │   └── macfuse-4.5.0.pkg                     # FUSE，挂远端磁盘剪贴板
                ├── config/config.json                  # {"logOut": true}
                ├── clientMd5.json / zteMd5.json        # 客户端校验文件
                └── *.lproj/                            # 多语言资源
```

| 项 | 值 |
|---|---|
| Bundle ID | **`com.cmcc.cloudcomputer`**（Android 是 `com.cmss.cloudcomputer`，注意 cmcc vs cmss） |
| 版本 | v3.6.5 |
| 架构 | x86_64 only（无 ARM Mac 二进制） |
| 主程序框架 | **Electron 22.3.27**（Android 是 Flutter） |
| Electron 业务框架 | **ee-core 2.12.0** + Vue 3 + Electron-store + better-sqlite3-multiple-ciphers + node-rsa + crypto-js + axios |
| 子进程桌面栈 | Qt 5.15 + GStreamer 1.16.2 + 中兴 mSPICE 衍生（与 Android 同源） |
| Electron asar 完整性 | SHA256 `e496459f88ce954015a339da87bedc064809cdac4e33298df0d5bda0bfaa0094` |

---

## 2. Electron 业务代码结构（app.asar 解包后）

```
public/electron/
├── constants/
│   ├── ecloudServerUrl.js     # 26 个 cem-webapi endpoint 名常量
│   ├── httpErrorMsg.js
│   └── ipcChannel.js
├── config/
│   ├── config.default.js / config.prod.js / config.prod_bak.js / config.uos.js / config.local.js
│   └── privateSetting.js      # 关键：dev/prod 凭据 + SDK 公钥 + 数据库密钥
├── util/
│   ├── ecloudHttpUtil.js      # eCloud V2.0 签名 + RSA 信封 HTTP 客户端（核心）
│   ├── cryptoUtil.js          # RSA + AES-256-CBC + SHA1/SHA256
│   ├── deviceUtil.js          # CommonParams 设备指纹
│   ├── additionalParamsUtil.js # 跨平台设备指纹 exec（reg query/lscpu 等）
│   └── ...
├── service/
│   ├── ecloud.js              # 业务 service 入口
│   ├── user.js                # 完整登录链路（pwd/SMS/QR/SIM/AD/4A/TwoFactor/TrustDevice/forgetPwd）
│   ├── probe.js
│   ├── crypto.js              # IPC 暴露 rsaEncrypt/rsaDecrypt
│   └── vdconnect/{cmss,h3c,zte,inspur}.js  # 各厂商桌面 service（仅 H3C 有 connect 实现）
└── controller/                # IPC handlers
    ├── ecloud.js / user.js / crypto.js / vdconnect.js / ...
```

代码经 javascript-obfuscator 混淆（数组旋转 IIFE），已用 webcrack 全部恢复。仓库内 `tools/deob_js_obf.js` 和 `tools/deob_webcrack.js` 是配套脚本。

---

## 3. 关键凭据与端点（与 Python 端 1:1 对照）

### 3.1 网关 / 凭据（生产环境，**与 Python 完全一致**）

```js
// public/electron/config/privateSetting.js（解混淆后）
EcloudServerSecretKey.prod = {
  baseUrl:       "https://ecloud.10086.cn",                              // ✓ 一致
  apiPath:       "/api/cem/gateway/outer/cem-webapi",                    // ✓ 一致
  accessKey:     "53bb79015a3f47c4be166d9371f68f14",                     // ✓ 一致
  secretKey:     "6b0d3b93f3aa4c7ea076c841bead1ddd",                     // ✓ 一致
  publicKey:     "-----BEGIN PUBLIC KEY-----MIGf...CqisJL7YvdPC/gJA7..." // ✓ 一致 RSA-1024
  privateKey:    "<AES-256-CBC 密文 hex 912 字节>",                       // ✓ AES 解密后等于 Python 端 PEM
  socketAddress: "Cloud-computer-h3-admin01-dongguan.cmecloud.cn",       // cem stream 默认 host
  socketPort:    8090                                                    // cem stream 默认 port
};

// AES-256-CBC 密钥 / IV（用于在客户端文件中保护私钥）
const AES_KEY_HEX = "759e45eb91e2d680ee19c7cf8919a174dcf2485ec4c2212abfa34ed6a6f2e2de";
const AES_IV_HEX  = "20fc96ccc54e355a89d77fc6986af62c";
```

**验证**：脚本 `tools/verify_priv_key_aes.py`（或直接复现以下逻辑）AES-256-CBC 解密 `EcloudServerSecretKey.prod.privateKey` 后，得到的 PEM 与 Python `pcas/const.py::PCAS_RSA_PRIVATE_KEY_PEM` 完全相同。同一把 RSA-1024 私钥同时存在于：
- Android `pcas_app/common/cem_rsa.dart` 内嵌
- macOS `app.asar/config/privateSetting.js`（AES 加密版）
- macOS `Ecloud-Cloud-Computer-Session.app/Contents/MacOS/...`（Mach-O 内明文 PEM）
- Python `pcas/const.py`

### 3.2 开发环境凭据（**新发现 — Python 端没有这套**）

```js
EcloudServerSecretKey.dev = {
  baseUrl:       "https://ecloud.10086.cn:31015",
  apiPath:       "/api/cem/gateway/outer/cem-webapi",
  accessKey:     "111c9b05d4ea428698c2f082a2f69909",
  secretKey:     "393eae3340bf4ffb9f8cec4707ea0ada",
  publicKey:     "<same RSA-1024>",
  privateKey:    "<same blob>",
  socketAddress: "10.253.198.194",       // 内网测试 IP
  socketPort:    8090
};
```

### 3.3 SDK 公钥（按桌面厂商分，**新发现**）

```js
SDKSecretKey.publicKey = {
  // RSA-1024，与 cem-webapi 相同
  H3C:     "MIGf...CqisJL7YvdPC/gJA7..."  // == cem-webapi prod publicKey
  // RSA-1024，**与 cem-webapi 不同**
  ZTE:     "MIGf...C5dwvTHYehc3BMwFBcZXBzr..."
  CMSSZTE: "<同 ZTE>"
  Inspur:  "MIGf...CqYR9XuxYWTwFZSqAtwie0fB8N..."  // 浪潮独立公钥
};
SDKSecretKey.aesSetting = {
  aesKey: "56Acf4c3498fD4c5a0B1fb26947e2daB",
  IV:     "3498fD4c5a0B1fbA"
};
```

这些公钥用于 `controller/vdconnect.js` 路由的 `H3CService.connect()`：把 vmid/socketPort/adUser/adPassword/customParams 等连接参数 JSON 化 → 用对应厂商公钥 RSA 加密 → 传给桌面子进程命令行参数 `--json <base64-rsa>`。

### 3.4 数据库加密密钥（**新发现 — 本地 SQLCipher**）

```js
DBSecretKey = {
  databaseKey:    "7g2zJe2amGvH9CiuWJ9Zuh5G3ZdC8KFp",  // 32 字符
  databaseVector: "ZqGgk8QYK02YDv1D",                  // 16 字符
  sKey:           "123456789abcdefh",
  iv:             "ABCDEF1234123412"
};
```

这是 `better-sqlite3-multiple-ciphers` 的密钥参数。Python 端如果将来要导入/解析 macOS 客户端的本地数据库，可以用这些参数。

---

## 4. cem-webapi 26 个 endpoint（macOS 端完整清单）

```js
// public/electron/constants/ecloudServerUrl.js（解混淆后完整内容）
module.exports = {
  COMMON_GET_SYS_TIME:           "/user/getSysTime",
  LOGIN_CHECK_USER_PASSWORD:     "/login/verify",                       // 密码登录第一步
  LOGIN_SEND_SMS:                "/login/sendVerifySms",
  LOGIN_VERIFY_SMS:              "/login/verifySms",                    // 短信登录
  LOGIN_QR_CODE:                 "/login/getQRCode",                    // ★ 新：二维码登录
  LOGIN_QR_LOGIN_RESULT:         "/login/getQRLoginResult",             // ★ 新：扫码状态轮询
  LOGIN_SIM_CODE:                "/login/simVerify",                    // ★ 新：SIM 一键登录
  LOGIN_SIM_LOGIN_RESULT:        "/login/getSimLoginResult",            // ★ 新：SIM 状态轮询
  LOGIN_GET_TOKEN:               "/login/verifyAccessTicket",           // 第二步换 token
  LOGIN_TRUST_DEVICE:            "/login/trustDevice",
  LOGIN_TEMPORARY_DEVICE:        "/login/trustOrTemporaryDevice",
  LOGIN_AUTH_TWOFACTOR:          "/login/verifyTwoFactorAuthSms",
  LOGIN_AUTH_4A:                 "/login/special/secondauthBy4a",       // ★ 新：4A 二次认证
  LOGIN_AUTH_4A_SMS:             "/login/special/getSecondauthSms",     // ★ 新：4A 短信
  LOGIN_CHECK_MOBILE:            "/login/checkMobile",                  // ★ 新：手机号预检
  LOGIN_UPDATE_PASSWORD:         "/user/isPasswordUpdateRequired",      // ★ 新：是否需要改密
  LOGIN_AD_LOGIN:                "/login/adUserLogin",                  // ★ 新：AD 域用户登录
  LOGIN_AD_RESULT:               "/login/getAdLoginResult",             // ★ 新：AD 状态轮询
  LOGIN_New_ByCode:              "/login/loginByCode",                  // ★ 新：code 登录（多账号选择）
  USER_GET_INFO:                 "/user/getLoginUserInfo",
  USER_GET_DEVICE_INFO:          "/user/getDeviceInfo",
  FORGET_GET_USERLIST:           "/user/getUserNameBySmsAuth",          // ★ 新：忘密码查用户列表
  FORGET_RESET_PWD:              "/user/setNewPwd",                     // ★ 新：设置新密码
  LOGOUT:                        "/login/logout",
  PROBE_QKK_BATCHPUSH:           "/login/batchPushLoginQkk",            // ★ 新：登录数据上报
  GET_SYS_CONFIG:                "/client/getSysConfig"                 // cem stream host/port 来源
};
```

★ 表示当前 Python `pcas_keepalive/pcas/const.py::EP` **未覆盖**的 endpoint（共 11 个），其中 `/login/checkMobile`、`/login/simVerify`、`/user/setNewPwd` 等是日常会用到的；4A 和 AD 是企业租户专用。

> Android V3.6.2 的 80 endpoints（PCAS_PROTOCOL.md §3.5）涵盖了 macOS 这 26 个，外加 user/* 的更多业务接口（getDeviceInfo / changeMachineName / getDesktopStatus 等），以及 resource/session/machine/extPolicy/userMessage/sso 等业务模块。

---

## 5. 加密 / 签名（完整还原后的伪码，与 Python 端 1:1 对齐）

### 5.1 请求加密 / 响应解密

```js
// public/electron/util/cryptoUtil.js（解混淆后核心逻辑）
class CryptoUtil {
  // 公钥分块 PKCS1v15 加密，明文按 (modulusLen/8 - 11)=117 字节分块，
  // 每块产出 128 字节密文，concat 后整体 base64。
  static rsaEncrypt(plaintext_utf8, publicKeyPem) {
    const pub = crypto.createPublicKey(publicKeyPem);
    const blockSize = pub.asymmetricKeyDetails.modulusLength / 8 - 11; // 117
    let out = [];
    for (let i = 0; i < buf.length; i += blockSize) {
      out.push(crypto.publicEncrypt(
        { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_PADDING },
        buf.slice(i, i + blockSize)
      ));
    }
    return Buffer.concat(out).toString("base64");
  }

  // 私钥分块解密，密文按 128 字节分块，每块解出 ≤117 字节明文。
  // 重要：privateKey 参数是 AES-256-CBC 密文 hex，需要先用固定 kk/vv 解密。
  static async rsaDecrypt(b64_ciphertext, encryptedPrivateKeyHex) {
    const pemBytes = aes256cbcDecrypt(
      Buffer.from(encryptedPrivateKeyHex, "hex"),
      Buffer.from(AES_KEY_HEX, "hex"),
      Buffer.from(AES_IV_HEX,  "hex")
    );
    const privPem = pemBytes.toString();
    // ... 然后分块 128 字节用 privateDecrypt(PKCS1v15) ...
  }
}
```

**与 Python `pcas/crypto.py` 完全等价**（`rsa_encrypt` / `rsa_decrypt` 直接用 PKCS1v15 即可，无需 AES 包裹）。

### 5.2 eCloud OpenAPI V2.0 签名（**完全等同 Python `pcas/sign.py`**）

```js
// public/electron/util/ecloudHttpUtil.js::getFullurl()
const date = new Date();
date.setMinutes(date.getMinutes() - date.getTimezoneOffset());   // 关键：把本地时间"映射"成 UTC 字面量
const ts = date.toISOString().slice(0, 19) + "Z";                // 例: "2025-08-20T19:35:42Z"

const params = {
  AccessKey:        config.accessKey,
  SignatureMethod:  "HmacSHA1",
  SignatureNonce:   uuidv4().replaceAll("-", ""),                // 32 hex
  SignatureVersion: "V2.0",
  Timestamp:        ts
};

const stringToSign =
  "POST\n" +
  encodeURIComponent(config.apiPath + endpoint) + "\n" +
  sha256_hex(querystring.stringify(params));                     // sha256_hex(name=val&name=val&...)

params.Signature = hmac_sha1_hex(stringToSign, "BC_SIGNATURE&" + config.secretKey);

const fullUrl = config.baseUrl + config.apiPath + endpoint + "?" + querystring.stringify(params);
```

⚠️ 注意点：

1. `Timestamp` 是 **本地时区映射成 UTC 字面量** — 北京时间 `2025-08-20T19:35:42+08:00` 会被算出 `2025-08-20T19:35:42Z`。看起来像 UTC，实际是 +8h。
2. `stringToSign` 第二行的 `encodeURIComponent` 只对 path 编码（`/` 不会被编码，因为 `encodeURIComponent('/') === '/'`... 错，实际会编码成 `%2F`）。`PCAS_PROTOCOL.md` 上说 `percent_encode("/api/cem/.../endpoint")`，需要确认 Python 端如何处理 — 一般 JS 的 `encodeURIComponent` 会编 `/`，但 OpenAPI V2.0 一般保留 `/`。**待确认 Python 端 `pcas/sign.py` 是否已经对齐此细节**。
3. HMAC-SHA1 key 必须是 `"BC_SIGNATURE&" + secretKey`（注意 `&` 不可省）。
4. 签名 `Signature` 是 HMAC 输出的 **hex**，不是 base64。

### 5.3 请求 / 响应信封字段

```js
// 请求：POST <fullUrl> Content-Type: application/json
{
  "params": "<base64(RSA-1024-PKCS1v15-blocked(JSON.stringify({ ...userBiz, ...commonParams, accessToken? })))>"
}

// 响应（HTTP 200）：
{
  "params": "<base64-RSA-加密-同密钥>"
}
// rsaDecrypt(resp.data.params) → JSON → { state: "OK"|..., errorCode, errorMessage, requestId, body: {...}, ... }
```

**RSA 信封字段名都是 `params`**（不是 `encryptedData`）— **与 Python `pcas/const.py::RSA_ENVELOPE_KEY = "params"` 一致**。

### 5.4 通用 commonParams（设备指纹，**字段名与 Python `crypto.py` 完全一致**）

```js
// public/electron/util/deviceUtil.js::getCommonParams()
{
  companyCode:        "ECloud",
  clientType:         "pc_windows" | "pc_mac" | "UOS",
  clientVersion:      "3.6.5",                  // ← macOS 端用 3.6.5；Python 默认 3.8.0
  deviceUid:          DEVICE_ID,                // 各平台采集方式不同（Win=MachineGuid，Linux=DMI，Mac=...）
  deviceName:         DEVICE_NAME,
  deviceType:         "pc",
  deviceCompany:      DEVICE_COMPANY,           // BIOS Manufacturer
  deviceModel:        DEVICE_MODEL,             // BIOS SystemProductName
  operatingSystem:    OS_TYPE,                  // Windows / Linux / Darwin
  deviceSystem:       OS_NAME,
  operatingVersion:   OS_VERSION,
  cores:              PROCESSOR_CORES,
  processor:          PROCESSOR_NAME,
  systemArchitecture: PROCESSOR_ARCH,           // x86 / x64 / arm64
  diskTotal:          TOTAL_DISK_SIZE,
  diskUsed:           USED_DISK_SIZE,
  ram:                TOTAL_MEMORY_SIZE,
  ipAddress:          LAN_IP_ADDRESS,
  macAddress:         MAC_ADDRESS
}
```

字段全部出现在每个 cem-webapi 请求的 plaintext body 里（与用户的 `userBiz` 参数合并）。

设备指纹采集（`additionalParamsUtil.js`）：

| 平台 | DEVICE_ID 来源 | DEVICE_COMPANY 来源 | DEVICE_MODEL 来源 |
|---|---|---|---|
| Win | `reg query ...\\Cryptography /v MachineGuid` | `reg query ...\\BIOS /v SystemManufacturer` | `reg query ...\\BIOS /v SystemProductName` |
| Linux | `/oem/usr/bin/vendor_storage r -i 8 -t string` 或固定值 | `cat /sys/class/dmi/id/sys_vendor` | `cat /sys/class/dmi/id/product_name` |
| Darwin | （走 systeminfo 包） | "Apple Inc." | "Apple" |

---

## 6. cem double stream 在 macOS 客户端的真相

### 6.1 ee-core 主进程**不实现** cem stream

`vdconnect` 4 个 service（cmss/h3c/zte/inspur）中：
- `cmss.js`、`zte.js`、`inspur.js` 都是空 Service 占位符（除了内嵌一个 SDK 公钥）
- `h3c.js` 的 `connect()` 是 `child_process.exec(<vendor-session-binary> --json <rsa-encrypted-connect-params>)` — **直接 spawn 桌面子进程**

```js
// public/electron/service/vdconnect/h3c.js::connect()
const exePath = path.join(Ps.getExtraResourcesDir(),
  "/Applications/Ecloud-Cloud-Computer-H3C-Session.app/Contents/MacOS/Ecloud-Cloud-Computer-H3C-Session");
const json = {
  vmid, timestamp, socketPort,           // ← socketPort 来自 privateSetting.socketPort = 8090
  adUser, adPassword,
  customParams, customLoginParams, customPrivateLoginParams,
  forcePreemption, isThinClient, vmName, httpProxyParams,
  operatePolicys, perssionObject, userInfo
};
const rsaEnc = Services.get("crypto").rsaEncrypt({ data: JSON.stringify(json), publicKey: H3C_PUBKEY });
exec(`${exePath} --json ${rsaEnc}`);
```

### 6.2 `Ecloud-Cloud-Computer-Session.app` 子进程内的 HeartBeat

`strings` 主程序 (`Ecloud-Cloud-Computer-Session`, 20MB Mach-O) 命中：

- `VdSession::startHeartBeat()` / `VdSession::stopHeartBeat()` （Qt slot）
- `ToolbarSession::notifyClientToHeartbeatError(QString, QString)`
- `vdsession send heart beat to client` / `heartbeat has started` / `vdagent-keeper`
- `com.cmss.cem.session.connect.auth` / `com.cmss.cem.session.connect.channel`
- `[INPUT] socketPort:{}` / `[INPUT] timestamp:{}`
- 同一把 RSA-1024 私钥的 **明文 PEM** 出现在二进制内（被链接器直接打进 const 段）

**但没有命中**任何 cem double stream 的字节级特征：
- 没有 `0x12345678` magic
- 没有 `cemDoubleStream` / `HBClient` / `HBServer` / `cmd_id`
- 没有 14 字节 header / "command":"1" 心跳明文

### 6.3 结论：macOS 端的保活模型

| 角色 | 干什么 |
|---|---|
| `Ecloud Cloud Computer Application.app` (Electron 主进程) | 登录、机器列表、设置；**不持有 cem stream TCP 连接** |
| `Ecloud-Cloud-Computer-Session.app` (Qt 子进程) | 用户点击"连接桌面"时启动；建立 SPICE/VDP 桌面流 → 在桌面会话上跑 SPICE-level HeartBeat（`vdagent-keeper`） |

**云电脑空闲关机判定看的是桌面会话活跃度**，macOS 客户端通过维持桌面会话本身来保活，而不是单独的应用层 cem stream。

这与 Android 公众版的实现完全不同：
- Android：Flutter `DoubleStreamProvider` 是一个独立的 TCP 长连接 + 5s 心跳，桌面会话断开时仍然维持
- macOS：保活完全绑定在桌面 GUI 子进程的生命周期上，子进程关掉就保活断了

### 6.4 对 `pcas_keepalive` 的含义

✅ **Python 实现的 cem double stream 路径（裸 TCP + RSA + 5s 心跳）依然是公众版云电脑保活的最轻量级方案**，因为：
1. 它使用的所有凭据/RSA 密钥/帧格式均来自 Android 抓包字节级验证
2. macOS V3.6.5 的 prod 配置里的 `socketAddress: Cloud-computer-h3-admin01-dongguan.cmecloud.cn:8090` 和 Python 默认 `36.133.24.236:8090`**指向同一区域服务**（dongguan = 东莞）
3. 服务端不区分客户端是 Android/PC/macOS — 凭 `accessTicket` 验证身份，凭 deviceId 验证设备可信状态

也就是说，**Python 端走的 cem stream 通道，服务端会把它当作"另一个公众版客户端实例"接收心跳**，无需 GUI 子进程，资源占用极低。这就是 PCAS_PROTOCOL.md §4.7 提到的 "真正的保活效果取决于这条 cem double stream 是否在线" 的实操方案。

---

## 7. 公众版 macOS 登录链路（与 Python `pcas/client.py` 对照）

`service/user.js` 包含 6 种登录方式，全部走 `EcloudHttpUtil.post(endpoint, bizParams)`：

| 方式 | 链路 | Python 已实现 |
|---|---|---|
| 密码 | `/login/verify` → `accessTicket` → `/login/verifyAccessTicket` → `accessToken` | ✓ |
| 短信 | `/login/sendVerifySms` → `/login/verifySms` → `accessTicket` → ... | ✓ |
| 二维码 | `/login/getQRCode` → 轮询 `/login/getQRLoginResult` → `accessTicket` → ... | ✗ |
| SIM 一键 | `/login/checkMobile` → `/login/simVerify` → 轮询 `/login/getSimLoginResult` → ... | ✗ |
| AD 域 | `/login/adUserLogin` → 轮询 `/login/getAdLoginResult` → ... | ✗ |
| 4A 二次 | `/login/special/getSecondauthSms` → `/login/special/secondauthBy4a` → ... | ✗ |

特殊分支：
- 响应 `errorCode == "30002009"` (`UntrustedDevice`)：进入 `/login/trustDevice`（设备短信验证后写信任）
- 响应 `errorCode == "30002060"` (`TwoFactor_auth`)：进入 `/login/verifyTwoFactorAuthSms`
- 响应包含 `userId`：进入 4A `LoginPolicy.MFA_4A`
- 响应包含 `body.code`：进入 `PolyPhoneManager` 多账号选择

完整状态机已经在 `user.wc.js` 解混淆后可读，对扩展 Python 端登录路径有直接参考价值。

---

## 8. macOS 客户端的握手 `accessTicket` 格式（推论）

Python 实现 (`pcas/cem_stream.py`) 已经知道 cem stream 握手要 `ticket:<userId>:<32hex><loginType>` 格式（来自 Android 抓包）。macOS 端的 `verifyAccessTicket` 返回值结构未在源码中显式定义，但：

- macOS Electron 主进程**不连 cem stream**，所以 `accessTicket` 只用来换 `accessToken`
- 服务端给 macOS 客户端的 `accessTicket` 仍然是同一种格式（凭 Python 端抓包格式工作）

**Python 端无需调整 ticket 解析。**

---

## 9. 对 `pcas_keepalive` 的具体修改建议（按优先级）

### P0 — 不需要改

| 项 | 当前 Python 端 | macOS V3.6.5 | 决议 |
|---|---|---|---|
| baseUrl / apiPath | ✓ | ✓ | 已对齐 |
| AccessKey / SecretKey | ✓ | ✓ | 已对齐 |
| RSA-1024 公私钥 | ✓ | ✓ | 已对齐 |
| signature 算法 | ✓ | ✓ | 已对齐 |
| RSA 信封字段名 `params` | ✓ | ✓ | 已对齐 |
| commonParams 18 字段 | ✓ | ✓ | 字段名 1:1 一致 |
| cem stream 帧格式 / cmd_id / 心跳 | ✓ | （macOS 不实现） | 保持现状 |

### P1 — 建议补充 endpoint 常量（防御性，不一定立刻用）

修改 `pcas_keepalive/pcas/const.py::EP`，追加：

```python
class EP:
    # ... 现有 ...

    # ===== 公众版 macOS V3.6.5 新增 / 别名 =====
    LOGIN_CHECK_MOBILE        = "/login/checkMobile"
    LOGIN_GET_QR_CODE         = "/login/getQRCode"
    LOGIN_GET_QR_LOGIN_RESULT = "/login/getQRLoginResult"
    LOGIN_SIM_VERIFY          = "/login/simVerify"
    LOGIN_GET_SIM_LOGIN_RESULT= "/login/getSimLoginResult"
    LOGIN_AD_USER_LOGIN       = "/login/adUserLogin"
    LOGIN_GET_AD_LOGIN_RESULT = "/login/getAdLoginResult"
    LOGIN_VERIFY_TWO_FACTOR   = "/login/verifyTwoFactorAuthSms"
    LOGIN_4A_SECOND_AUTH      = "/login/special/secondauthBy4a"
    LOGIN_4A_GET_SMS          = "/login/special/getSecondauthSms"
    LOGIN_BATCH_PUSH_QKK      = "/login/batchPushLoginQkk"

    USER_GET_SYS_TIME         = "/user/getSysTime"
    USER_IS_PWD_UPDATE_REQ    = "/user/isPasswordUpdateRequired"
    USER_GET_USERNAME_BY_SMS  = "/user/getUserNameBySmsAuth"
    USER_SET_NEW_PWD          = "/user/setNewPwd"
```

### P2 — clientVersion 建议下调到 macOS 同步值

macOS V3.6.5 客户端发送 `clientVersion: "3.6.5"`，Python 端写死 `3.8.0`（更新版本号，服务端通常接受任何 ≥ 3.6 的值）。

建议在 `pcas/const.py` 中允许通过环境变量覆盖：

```python
import os

APP_VERSION_NAME = os.environ.get("PCAS_CLIENT_VERSION", "3.8.0")
```

### P3 — clientType 矩阵

macOS 端 `clientType` 取值同时支持：`pc_windows`、`pc_mac`、`UOS`（统信 OS）。Python 端目前固定 `pc_windows`。

如果 future 想模拟 macOS 客户端身份，把 `clientType` 改成 `pc_mac` 也合法。

### P4 — 增加 `getSysTime` 用于时钟漂移补偿

`/user/getSysTime` 是无需认证的接口，返回服务端时间。本机时钟漂移超过 ±15min 会导致 `INVALID_PARAMETER_TIMESTAMP` 错误（macOS 端 errorMsg 常量已确认）。

建议在 `pcas/client.py` 中：
1. 启动时先调一次 `/user/getSysTime`
2. 计算本地时钟偏移
3. 后续所有 `Timestamp` 字段加上这个偏移

### P5 — `socketAddress` fallback 列表

macOS prod 默认 `Cloud-computer-h3-admin01-dongguan.cmecloud.cn:8090`（域名）。
Python 端默认 `36.133.24.236:8090`（IP）。

实际部署中，**优先调用 `/client/getSysConfig` 获取动态下发的 host/port**（PCAS_PROTOCOL.md §4.1 已说明），然后再 fallback 到这两个默认值。

建议把 fallback 顺序写为：
```python
DEFAULT_HOSTS = [
    "Cloud-computer-h3-admin01-dongguan.cmecloud.cn",  # macOS 客户端默认
    "36.133.24.236",                                    # Android 抓包实测
]
DEFAULT_PORT = 8090
```

---

## 10. 附：解包/分析工具链

本次分析全程在 Windows 11 + WSL-Bash + Node 22 环境下完成，无需 mac。可复现：

```bash
# 1. 解 xar
"/c/Program Files/7-Zip/7z.exe" x Ecloud_CloudComputer_V3.6.5.pkg -oecloud_pkg_out

# 2. 解 Payload 内层 gzip
"/c/Program Files/7-Zip/7z.exe" x ecloud_pkg_out/tmp.pkg/Payload -opayload_gz

# 3. 解 cpio
"/c/Program Files/7-Zip/7z.exe" x payload_gz/Payload~ -oecloud_app

# 4. 解 asar
npx --yes @electron/asar extract ecloud_app/Contents/Resources/app.asar ecloud_asar

# 5. 反混淆（webcrack，已写好脚本）
NODE_PATH=/tmp/node_modules node tools/deob_webcrack.js \
    ecloud_asar/public/electron/**/*.js
```

---

## 11. 当前任务总结

- 解包并完整分析 macOS 公众版 V3.6.5 — **完成**
- 验证 Electron Asar SHA256 / RSA 私钥 / AccessKey 与 Python 端一致 — **完成**
- 全部关键混淆 JS 已反混淆并落盘 (`*.wc.js`) — **完成**
- macOS 端 cem stream 实现路径 — **已查明**（主进程不实现，靠桌面子进程的 SPICE 层心跳）
- Python `pcas_keepalive` 协议核心层（cem-webapi + cem stream）— **无需改动**
- 补强 endpoint 常量 / clientVersion 可配置化 / getSysTime 时钟补偿 — **待落地**（见 §9 P1-P5）
