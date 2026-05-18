# Frida Hook 指引：dump CMSS 桌面层 RSA / AES 加密明文

> 目标：在用户真实点"连接桌面"时，把 `vdconn.dll` 里 RSA / AES 加密函数的**输入明文**和**输出密文**全部 dump 出来，
> 用于：
> - 推出 ZTEC AuthPacket RSA token 的精确字段格式
> - 推出 `cs_suOperDesktop.action` param 字段的精确字段格式
> - 验证我们 Python 端 `pcas/cmss_desktop/` 的实现是否与官方客户端字节级一致

抓出来后，Python 客户端就能精确构造同样的请求。

---

## 0. 前置准备

### 环境
- Windows 10/11（你的开发环境，pcap 抓的也是 Windows 客户端）
- Python 3.8+（推荐 32 位，因为 `uSmartView_VDI_Client.exe` 是 32-bit PE）
- 已安装的官方客户端：`D:\CloudComputer\Ecloud Cloud Computer Application.exe`
- 子进程：`D:\CloudComputer\drivers\CMSS\client\uSmartView_VDI_Client.exe`（32-bit）

### 安装 Frida

```powershell
# 用 32 位 Python（一定要 32 位，因为目标 .exe 是 i386）
# 如果你只有 64 位 Python，用 frida-tools 的 CLI 也可以，但 frida-python attach 需要架构匹配
pip install frida frida-tools

# 验证
frida --version  # 应该输出 16.x 或更新
```

## 1. 一键启动（推荐）

```powershell
# 1. 先用 Electron 主程序登录你的账号
D:\CloudComputer\Ecloud Cloud Computer Application.exe

# 2. 在主程序里选好"我的电脑"页面（看到要连的机器，但**先不要点连接**）

# 3. 在另一个 PowerShell 窗口，准备好 frida attach（等 spawn）
cd E:\Desktop\foldder\Code\Claude\ydy
python tools\frida\run_hook.py --mode attach

# 看到 "❌ 进程未找到" 是正常的，因为 uSmartView_VDI_Client.exe 还没起来
# 准备好这个命令，等它能成功后再继续下一步
```

## 2. 触发桌面连接

```powershell
# 在 Electron 主程序里点"连接桌面"
# Electron 主进程会 spawn uSmartView_VDI_Client.exe，
# 此时立刻在另一个 PowerShell 跑：
python tools\frida\run_hook.py --mode attach
```

**时机非常关键**：要在 uSmartView_VDI_Client.exe 启动后**几秒内** attach，
否则 RSA/AES 加密可能已经完成。如果错过了，关掉桌面会话重来。

## 3. 期望看到的 hook 日志

成功 hook 后会输出类似：

```
[12:34:56.789] INFO: vdconn.dll loaded @ base=0x10000000 size=0x500000
[12:34:56.790] INFO: 挂钩 vdconn.dll!RsaEncrypt @ 0x10123456
[12:34:56.790] INFO: 挂钩 vdconn.dll!AesEncodeForCsap @ 0x10234567
[12:34:56.790] INFO: 挂钩 vdconn.dll!AesDecodeConnStrFromCsap @ 0x10345678
... (其他函数)
[12:34:56.795] INFO: frida hook_vdconn.js 已启动

[12:34:57.123] DoGetSuOperConnectStr: === ENTER (主流程入口) ===
[12:34:57.124]   args[0] = 0x12345678
[12:34:57.124]   args[1] = 0x87654321
...

[12:34:57.234] SetRsaPassword: === ENTER ===
[12:34:57.234]   args[0] = 0x12300000
[12:34:57.234]     utf8="-----BEGIN PUBLIC KEY-----MIGfMA0GCSqG...-----END PUBLIC KEY-----"
                  ★ 这里能确认实际用的是哪个公钥（ZTE/CMSSZTE）

[12:34:57.345] RsaEncrypt: === ENTER ===
[12:34:57.345]   args[0] = 0x12340000
[12:34:57.345]   RsaEncrypt args[0].deref: len=256 hex=7b22766d6964223a223...
                            utf8="{\"vmid\":\"78f13272-e749-4995-b762-fea808376787\",\"ts\":1779...
                  ★★★ 这里能看到 RSA 加密前的明文 JSON 完整字段！
[12:34:57.346]   args[1] = 0x66 (decimal: 102 字节明文长度)
[12:34:57.346]   args[2] = 0x12350000  ← 输出缓冲区
[12:34:57.346]   args[3] = 0x12360000  ← 输出长度变量
[12:34:57.350] RsaEncrypt: === LEAVE retval=0 ===

[12:34:57.420] AesEncodeForCsap: === ENTER ===
[12:34:57.421]   args[0] = 0x12370000
[12:34:57.421]     utf8="{\"vmid\":\"78f13272-...\",\"userId\":\"...\",\"ticket\":\"ticket:...\",\"ts\":1779036951000}"
                  ★★★ 这里能看到 cs_suOperDesktop.action param 字段的明文！
```

**关键产物**：每个 `args[N].deref utf8="..."` 行就是加密前明文。把这些片段对照
`pcas_keepalive/docs/CMSS_DESKTOP_PROTOCOL.md` §2.3 / §3.1 推测的字段格式校对。

## 4. 收尾 + 反向应用到 Python 端

1. **保存 hook 日志**：`tools/frida/hook_output_<ts>.log` 自动生成
2. **解析**：把日志里 `RsaEncrypt args[0].deref utf8="..."` 的 JSON 完整抠出来，
   这就是 ZTEC AuthPacket 的 RSA token 明文格式
3. **修正 Python 实现**：
   - 改 `pcas/cmss_desktop/ztec_protocol.py::_build_rsa_token_plaintext` 用真实字段
   - 改 `pcas/cmss_desktop/client.py::request_su_oper_desktop` 的 payload 字段
4. **验证**：把 `forever_enable_cmss_desktop=True` 打开，跑一次 forever 模式，看 ZTEC 握手是否能过

## 5. 高级技巧

### 5.1 用 frida-trace 一键 trace 所有目标函数

```powershell
frida-trace -p <pid> -i "vdconn.dll!Rsa*" -i "vdconn.dll!*Aes*" -i "vdconn.dll!CBC_*" -i "vdconn.dll!DoGet*"
```

frida-trace 会自动生成模板 JS 在 `__handlers__/` 目录，你可以编辑模板让它 dump 参数明文。

### 5.2 hook OpenSSL 底层函数（备用）

如果 `vdconn.dll` 的 wrapper 函数没拿到完整明文（比如它把 plaintext 传给 OpenSSL 之前做了变换），
直接 hook `libcrypto-1_1.dll`：

```javascript
const rsaEncDirect = Module.findExportByName('libcrypto-1_1.dll', 'RSA_public_encrypt');
Interceptor.attach(rsaEncDirect, {
    onEnter(args) {
        const flen = args[0].toInt32();
        const from = args[1];
        log('RSA_public_encrypt', `flen=${flen}`);
        dumpData('plaintext', from, flen);
    }
});

const aesEnc = Module.findExportByName('libcrypto-1_1.dll', 'AES_cbc_encrypt');
Interceptor.attach(aesEnc, {
    onEnter(args) {
        log('AES_cbc_encrypt', `in=${args[0]} out=${args[1]} len=${args[2]} key=${args[3]} iv=${args[4]} enc=${args[5]}`);
        dumpData('plaintext', args[0], args[2].toInt32());
        dumpData('key', args[3], 32);  // AES-256 = 32 字节
        dumpData('iv', args[4], 16);
    }
});
```

### 5.3 trace 网络调用（看实际发出的字节）

```javascript
// hook ws2_32!send (Windows socket send)
const sendFn = Module.findExportByName('ws2_32.dll', 'send');
Interceptor.attach(sendFn, {
    onEnter(args) {
        const sock = args[0].toInt32();
        const buf = args[1];
        const len = args[2].toInt32();
        log('ws2_32!send', `sock=${sock} len=${len}`);
        dumpData('payload', buf, len);
    }
});
```

通过这个能直接看到 ZTEC 5 帧的字节，验证我们的实现。

## 6. 故障排查

| 问题 | 原因 | 解决 |
|---|---|---|
| `frida.ProcessNotFoundError` | uSmartView 还没启动 | 先在 Electron 点"连接桌面"让它 spawn |
| `Module 'vdconn.dll' not found` | DLL 还没加载 | 等几秒，脚本里有 LoadLibrary hook 自动补 |
| `Failed to read memory` | 指针解读错了 | x86 cdecl/stdcall 参数布局有差异，看 IDA 反编更准 |
| hook 后客户端崩溃 | 接口签名假设错 | 减少 dumpData 调用，先只看 args[0] |
| 没看到任何 hook 日志 | 进程架构不匹配 | 32-bit Python 配 32-bit 进程；64-bit Python 配 64-bit 进程 |

## 7. 下一步

dump 到 RSA 明文 + AES 明文后：

1. **回填到 Python 实现**：改 `pcas/cmss_desktop/ztec_protocol.py::_build_rsa_token_plaintext`
2. **跑真实测试**：把 `forever_enable_cmss_desktop=True`，对你的真实账号跑一次
3. **观察服务端响应**：
   - frame 134 ack 首字节是 0xc8 → ZTEC 认证通过 ✅
   - 任何其他值 → 说明 RSA token 格式仍不对，回到 §3 dump 更多场景
4. **SPICE 桌面流**：如果 ZTEC + cs_action 都通了，下一步还需要实现 SPICE 协议
   保持 TCP 连接，但服务端可能只需要 TCP 不断 + 偶尔 PING

---

## 附录 A：vdconn.dll 已知导出函数（来自 strings + symbols）

```
RsaEncrypt              — RSA 加密入口（ZTEC token 用）
RsaEncryptForSaaS       — SaaS 路径 RSA 加密
SetRsaPassword          — 设置 RSA 公钥/密码
SetRsaPubKey            — 设置 RSA 公钥
WriteRsaPublic          — 写公钥到本地

AesEncodeForCsap        — 给 cs_*.action 的 AES 加密（param 字段）
AesDecodeConnStrFromCsap — 解 cs_suOperDesktop 响应的 connectStr
CBC_AESEncryptStr       — 通用 AES-CBC
ConnectStrAesEncode     — connectStr AES 加密

DoGetConnectStr         — 主流程：拿 connectStr
DoGetConnectSessionVdStr — 拿桌面会话 VD 连接串
DoGetSuOperConnectStr   — su 用户主流程入口（用户主动点连接）
GetConnectSYC           — SYC 路径
GetSohoConnectStr       — Soho（家庭版）路径
RetryDoGetSycConnectStr — 重试

StartSpiceProcess       — 启动 SPICE 进程
SetVDConnectStr         — 设置 VD 连接串
```

最有用的 hook 目标顺序：
1. `RsaEncrypt` — 直接拿 ZTEC token 明文（**必须**）
2. `AesEncodeForCsap` — 直接拿 cs_suOperDesktop param 明文（**必须**）
3. `SetRsaPassword` — 确认用的是哪个公钥
4. `DoGetSuOperConnectStr` — trace 整个主流程的调用栈

## 附录 B：手工反编路径（Frida 失败的备用方案）

如果 Frida hook 因 anti-debug / 完整性校验失败，用 IDA Pro：

1. 打开 `D:\CloudComputer\drivers\CMSS\client\vdconn.dll`
2. 找 export `RsaEncrypt` 双击进函数
3. F5 反编（HexRays）
4. 看 RSA 加密前的 buffer 来源（trace 调用栈，找到构造明文的函数）
5. 反编明文构造函数，记录字段顺序、序列化方式（JSON / binary）

之前桌面端开发者在 `D:/CloudComputer/IDAHook.log` 里有 IDA 操作痕迹，
说明 IDA 在这台机器上能跑得动。
