# H3C VDP gRPC + SPICE 桌面会话协议分析

> 基于 `Ecloud_CloudComputer_V3.6.5.pkg` macOS 客户端 + `10m.pcapng` 真实桌面会话抓包逆向得出。
> 这份文档记录公众版云电脑"打开桌面→维持桌面→断开桌面"完整时序中的字节级协议规范。

---

## 0. 一句话结论

公众版云电脑客户端"用户真在使用桌面"的判定不在 cem-webapi 业务层（HTTPS REST），
而是在 **`H3C VDP gRPC` 控制面**（gRPC over TLS）+ **标准开源 SPICE 桌面流**两层。
保活想真正生效，必须模拟 gRPC 层的 `client.ClientCore/Heartbeat` 周期上报。

---

## 1. macOS 客户端桌面会话技术栈

`Ecloud_CloudComputer_V3.6.5.pkg` 解开后的桌面子进程：

```
extraResources/Applications/Ecloud-Cloud-Computer-Session.app
├── Contents/MacOS/Ecloud-Cloud-Computer-Session     (Qt5 主程序，3.7MB Mach-O x86_64)
├── Contents/Frameworks/
│   ├── libVDPServer.{1.0.0,1.0,1,}.dylib            ⭐ H3C VDP gRPC 控制面（13.8 MB）
│   ├── libvdcore.{1.0.0,1.0,1,}.dylib               H3C VDP 核心
│   ├── libnebula.dylib                              H3C Nebula 接入网关
│   ├── libspice-client-glib-2.0.8.dylib            ⭐ 开源 SPICE 客户端库
│   ├── libcag.dylib                                 中兴 CAG USB 隧道
│   ├── libeveusb*.dylib                             USB/IP 透传
│   ├── libVDLog.dylib                               H3C 日志
│   ├── libVDPriv.dylib                              H3C 权限
│   ├── libVdsessionShared.dylib                    会话共享层
│   └── GStreamer.framework                          媒体管线
└── Contents/sdk.json                                文件清单（934 个文件）
```

注意：与之前推测不同——macOS **没有** `Ecloud-Cloud-Computer-H3C-Session.app`
（那个是 Windows 端的命名），公众版 macOS 把 H3C / CMSS / Inspur 桌面客户端
统一打包在一个 Session.app 里，由命令行参数 + 厂商 SDK 切换。

---

## 2. 桌面会话完整时序（来自 `10m.pcapng` 真实抓包）

抓包基线：用户在 `t=131.94s` 点了"连接桌面"按钮，桌面持续 ~640s，主动断开。

### 2.1 控制面（HTTPS REST，cem-webapi @ `ecloud.10086.cn:443`）

| 时间 | 事件 |
|---|---|
| `t=5~6s` | 启动客户端，5 个 TCP 连接同时建立（HTTP/2 多路复用 + 应用并发）— 登录链路 |
| `t=71~80s` | 第二批 7 个 TCP，**拉机器列表 + 拉桌面状态 + 拉详情**（前端进入"我的电脑"页面） |
| `t=109s, 125s` | 用户已选好要连接的机器，再调一次 ecloud.10086.cn 拉最新状态 |
| **`t=131.94s`** | **用户点"连接桌面"按钮** |
| `t=137.83s` | 桌面已连上后，再调 ecloud.10086.cn — 这是 `/session/machineConnect` + `/machine/pushConnectEventData` |
| `t=380, 448, 470, 537, 680, 748, 837, 896s` | 每 67~100s 一次 ecloud.10086.cn 请求（保活心跳） |

### 2.2 数据面（VDP gRPC + SPICE @ `36.212.224.100:8899`）

**所有 TCP 通道都是 TLS 1.2 加密**（证书 CN=DC, O=ZTE, OU=SOFT）：

| TCP 通道 | 起始时间 | 用途（推断） |
|---|---|---|
| 13707 | t=131.937 | **TCP probe**（0 字节后立刻 RST，探测连通性） |
| 13710 | t=131.956 | **VDP gRPC 主通道**（517 B ClientHello → 服务端 cert ~ 925 B → ClientKeyExchange ~93 B → Finished → 应用数据） |
| 13711 | t=132.758 | SPICE main channel |
| 13717 | t=136.716 | SPICE display channel |
| 13725 | t=137.760 | SPICE inputs channel |
| 13730, 13732, 13733 | t=138.86~91 | SPICE cursor / playback / record |
| 13734, 13735, 13737, 13738 | t=138.96~139.13 | 其他 SPICE 子通道 |
| 13764, 13766 | t=152~154 | 慢启动后追加的 SPICE 通道 |
| 4156 | t=284.69 | 中途新增（USB/打印重定向通道？） |

**总流量**：12.7 分钟会话期 → 客户端发 1.3 MB / 服务端发 3.9 MB（典型 SPICE 比例：桌面像素流为主）。

### 2.3 关键观察

1. **桌面成功后才调 `/session/machineConnect`**（先 t=131.94 连桌面，再 t=137.83 调 REST 上报）。
   说明 Node 项目 `D:\CloudComputer\keep-alive` 在登录时就调 `machineConnect` 的做法属于"裸 REST 模拟"——
   服务端不一定区分"用户真连了桌面"还是"客户端伪装在线"。
2. 桌面服务器 IP `36.212.224.100` **没有 DNS 解析**——它是从某个 `ecloud.10086.cn` 接口
   响应的 JSON 字段里直接拿到的（最可能在 `customParams` 或 `customLoginParams` 字段里，
   也可能是 `loginIp` / `serverIp`，需要 sslkeys.log 才能确认）。
3. 服务端发的流量是客户端发的 3 倍——典型像素流，证明这是 SPICE 桌面数据。

---

## 3. VDP gRPC 服务（client.ClientCore）

`libVDPServer.1.0.0.dylib` 内含完整的 gRPC service 定义。从二进制符号表提取的 RPC 列表：

### 3.1 完整 gRPC method 列表（从 dylib 字符串提取，39 个）

```
/client.ClientCore/Login                            登录主入口
/client.ClientCore/RegisterDevice                   注册设备
/client.ClientCore/ApplyForDeviceInfo               申请设备信息
/client.ClientCore/DeviceExisted                    设备是否已注册
/client.ClientCore/ApplyForEmailInfo                申请邮箱注册
/client.ClientCore/ApplyForVm                       申请 VM 实例
/client.ClientCore/ClientReleasePassword            释放密码
/client.ClientCore/CheckPassword                    验证 VM 密码
/client.ClientCore/ModifyPassword                   修改 VM 密码
/client.ClientCore/ModifyVmName                     修改 VM 名
/client.ClientCore/OperateForVm                     VM 电源操作
/client.ClientCore/RecoverVm                        恢复 VM（同 OperateForVm 但响应不同）
/client.ClientCore/Heartbeat                        ⭐ 桌面会话心跳（真正的保活！）
/client.ClientCore/ReportSuccess                    上报桌面成功打开
/client.ClientCore/Snapshot                         快照管理
/client.ClientCore/Upgrade                          客户端升级查询
/client.ClientCore/USBNotify                        USB 设备通知
/client.ClientCore/GetDesktopPoolById               桌面池查询
/client.ClientCore/GetLearningspaceDesktopPoolById  学习空间桌面池
/client.ClientCore/GetLsUserInfo                    学习空间用户信息
/client.ClientCore/GetTemplatesOrIsos               模板/ISO 列表
/client.ClientCore/SaveTemplateInfo                 保存模板
/client.ClientCore/GetNextCloudInfo                 NextCloud 信息
/client.ClientCore/GetDeviceConfigInfo              设备配置查询
/client.ClientCore/TermBootTaskInfo                 终端启动任务
/client.ClientCore/TermBootTaskReceipt              启动任务回执
/client.ClientCore/TermDataBackupInfo               数据备份信息
/client.ClientCore/TermBKFileUploadReceipt          备份文件上传回执
/client.ClientCore/QueryVoiRunningMode              VOI 模式查询
... (约 39 个 method)
```

### 3.2 心跳路径（重点）

`/client.ClientCore/Heartbeat`：

```proto
message HeartbeatReq {
  string vm_ip = 1;
  client.ClientBaseInfo client_base_info = 2;
  client.ClientExtendInfo client_extend_info = 3;
}

message HeartbeatResp {
  common.ErrorData error = 1;
}
```

调用方式：unary RPC（非 streaming）。客户端周期性发 HeartbeatReq，服务端回 HeartbeatResp。
心跳间隔尚待 sslkeys.log 解密 pcap 后确认（粗估 30s 一次，因为对应 ecloud.10086.cn
REST 心跳 67~100s/次 的频率，gRPC 心跳应该更频繁）。

### 3.3 完整桌面建立 gRPC 调用顺序（来自 `Ecloud-Cloud-Computer-Session` 字符串 `[vdsession](preConnectVm)`）

```
1. initVdpServer        建立 gRPC over TLS 连接到 36.212.224.100:8899
                        证书：config/grpcserver.pem (H3C 自签 ZTE/SOFT/DC)
2. (query server type)  小握手，应该不是 gRPC 而是协议自检
3. Login                ClientBaseInfo (含 username/password/ticket/deviceId 等)
                        → LoginResp (含 pool_list/auth_type/domain)
4. RegisterDev          ClientBaseInfo + 设备 IP/MAC/device_id/SN
                        → RegisterDevResp.register_id
5. CheckPassword        ClientBaseInfo (含 vmId/password)
                        → CheckPasswordResp (含 user_id, username)
6. ApplyForVm           ClientBaseInfo + pool_name + start_domain + token_flag
                        → ApplyForVmResp (含 name, password, host_ip, host_ips,
                                           spice_password ⭐, user_group, vm)
7. (连接 SPICE 桌面)     用 ApplyForVmResp 里的 host_ip + spice_password 起 SPICE
8. ReportSuccess        ClientBaseInfo + vm_ip + client_extend_info
                        → ReportSuccessResp (告诉服务端 SPICE 桌面已连通)
9. Heartbeat (循环)     vm_ip + ClientBaseInfo + ClientExtendInfo
                        → HeartbeatResp (循环至断开)
```

### 3.4 关键 message 字段（用于 Python 端实现）

#### ClientBaseInfo (30 字段)
```proto
message ClientBaseInfo {
  string name = 1;                 // username (手机号)
  string password = 2;             // 用户密码（明文）
  string domain = 3;               // 域名（公众版填空）
  string ip = 4;                   // 客户端 IP
  string mac = 5;                  // 客户端 MAC
  string device_id = 6;            // 设备 UID（对应 cem-webapi 的 deviceUid）
  string device_name = 7;          // 设备名（对应 cem-webapi 的 deviceName）
  int64 vm_id = 8;                 // 机器 ID
  string auth_type = 9;            // 鉴权方式
  string sms_code = 10;
  string refresh_flag = 11;
  string client_type = 12;         // 'pc_windows' / 'pc_mac' / 'UOS'
  string protocol_type = 13;       // 'spice' / 'spice-tls'
  int32 computer_type = 14;        // pc=0
  string vmUuid = 15;              // VM UUID
  int32 isOpenldap = 16;
  int32 connect_type = 17;
  string h5_clientUuid = 18;
  int32 ssoLogin = 19;
  bytes encryptPassword = 20;      // RSA 加密后的密码（用 cem-webapi 那对 RSA-1024 密钥）
  string spmId = 21;
  string ticket = 22;              // accessTicket，与 cem stream 一致
  int32 desktop_type = 23;
  int64 auth_stg_id = 24;
  string codeSource = 25;
  string dynaToken = 26;           // accessToken (cem-webapi 的)
  string googleSecretKey = 27;
  string inputGoogleCode = 28;
  bool isOffCampus = 29;
  string fingerPrintCode = 30;
}
```

#### ClientExtendInfo (18 字段)
```proto
message ClientExtendInfo {
  string client_language = 1;      // 'zh_CN'
  string client_version = 2;       // '3.8.0'
  string vendor = 3;               // 主板厂商
  string model = 4;                // 机型
  string os_type = 5;              // 'Windows' / 'Darwin' / 'Linux'
  string os_version = 6;
  int32 computer_type = 7;
  int64 classroom_id = 8;          // 0
  string cpu_arch = 9;             // 'x86_64' / 'arm64'
  bool forceLogin = 10;
  int32 classroom_num = 11;        // 0
  string spaceagent_version = 12;
  string v_app_name = 13;
  int32 scene = 14;
  string osDetail = 15;            // 'Darwin Version 14.6.1 ...'
  string compatible_item = 16;
  string v_app_group = 17;
  int32 flag_reconnection_network = 18;
}
```

---

## 4. SPICE 桌面流层

### 4.1 协议

`libspice-client-glib-2.0.8.dylib` — **标准开源 SPICE 协议**（来自 freedesktop.org，不是 H3C 私有改造）。

主要参考：
- https://www.spice-space.org/spice-protocol.html
- libspice-client-glib API 文档

### 4.2 连接参数（推断）

`ApplyForVmResp` 返回的字段：
- `host_ip` / `host_ips` — SPICE 服务器地址列表（很可能就是 `36.212.224.100`）
- `spice_password` — SPICE 通道认证密码

SPICE 通道：
- main (端口 8899, TLS) — 控制
- display (新 TCP, 同端口) — 桌面像素流（最大流量）
- inputs — 鼠标键盘
- cursor — 光标
- playback — 音频回放
- record — 音频录制

### 4.3 与开源 SPICE 的差异

`Ecloud-Cloud-Computer-Session` 字符串里出现 `spiceTls` / `spicePreferProto` / `spiceUdp` 等
配置项，意味着支持 TLS-only / UDP-fallback 双模式。pcap 显示**全程 TCP+TLS**（10 个端口都
在 8899）。

---

## 5. 当前 Python 实现的可用性

### 5.1 已实现（pcas_keepalive，2026-05-17 更新）

| 层 | 实现 | 备注 |
|---|---|---|
| cem-webapi 登录链路 | ✅ | password/sms 登录、UntrustedDevice 处理 |
| cem-webapi 业务接口 | ✅ | getDeviceInfo, getDesktopStatus, operate 等 |
| recordDeviceInfo + machineConnect | ✅ | 登录后立即调，拿真 connectId |
| pushConnectEventData (CloudEvents 1.0) | ✅ | connect.result / connect.failure |
| REST 心跳 (4 路) | ✅ | session/updateSessionStatus, machine/performance/batch 等 |
| cem double stream (8090) | ✅ | 裸 TCP + RSA + 5s 心跳 |
| **VDP gRPC 控制面** | ❌ | **本次未实现** |
| **SPICE 桌面流** | ❌ | **本次未实现** |

### 5.2 业务上报层应该已经能"骗过"服务端

Node 项目 `D:\CloudComputer\keep-alive` 在 README 自称"对齐官方客户端"且**没有** VDP gRPC / SPICE 层，
只做 cem-webapi 业务上报，且实测有效。如果服务端"用户在线判定"只看业务上报层，那么**当前 Python
实现已经够用**——观察 24 小时看是否还自动关机即可。

如果业务上报层不足以保活，那必须实现 VDP gRPC 客户端（至少 Heartbeat 这一条）。

---

## 6. 完整 VDP gRPC 客户端实现工作量评估

### 6.1 已完成（本次会话）

- ✅ 从 `libVDPServer.1.0.0.dylib` 提取 `client/client_core.proto`（195 个 message，含 HeartbeatReq/LoginReq 等）
- ✅ 提取 `common/error_data.proto`、`common/common_messages.proto`、`common/stream_message.proto`、`service/service_stream.proto`、`common/common_core.proto`（service descriptor 在此）
- ✅ 工具脚本 `tools/extract_vdp_proto.py` 可重复使用
- ✅ 完整 gRPC method 列表（39 个）从符号表提取

文件位置：
```
pcas_keepalive/pcas/vdp_grpc/
├── client_core.proto        37 KB, 195 messages
├── common_core.proto        518 B (部分)
├── common_messages.proto    9.5 KB
├── error_data.proto         144 B
├── service_stream.proto     1.7 KB
└── stream_message.proto     113 B
```

### 6.2 还需要做的（如果决定走 VDP gRPC 路径）

1. **手工补 `client_core_grpc.proto`** — service ClientCore { rpc Login / Heartbeat / ... }
   （services 没嵌在 file descriptor 里，但 method 名 + 输入/输出 message 类型已知，5 分钟手补完）
2. **生成 Python protobuf + gRPC stub** — `python -m grpc_tools.protoc ...`
3. **发现 SPICE 服务器地址**（这一步必须有 sslkeys.log）：
   - 用 sslkeys.log 解 pcap，确认 ecloud.10086.cn 哪个接口的响应里返回了 `36.212.224.100:8899`
   - 字段名可能是 `loginIp` / `host_ip` / `serverIp` / `customParams.gridServer`
4. **实现 VDP gRPC 客户端**（grpcio + 自签证书 + h2c-over-TLS）：
   - Login → 拿 LoginResp.update_interval（心跳间隔）
   - RegisterDev → 拿 register_id
   - CheckPassword → 验证 vm 密码
   - ApplyForVm → 拿 host_ip + spice_password
   - **进入 Heartbeat 循环** ⭐ 关键保活
   - ReportSuccess → 上报桌面打开（伪装）
5. **(可选) SPICE 客户端骨架** — 不用真显示，只要建立 main channel + 偶尔回 PING 响应

总工作量估计：**2~3 天**（在拿到 sslkeys.log 前提下）。

---

## 7. 下一步推荐路径

### 选项 A：先观察现有修复是否够用（推荐先做）

部署当前 `pcas_keepalive` 跑 24 小时，验证以下情况：
- 是否还自动关机？
- 如果不关机：业务上报层就是充分条件，VDP gRPC / SPICE 不必做
- 如果关机：必须走选项 B

### 选项 B：完整 VDP gRPC 客户端实现

前提：你要先提供 `sslkeys.log` 才能解 pcap 里的 ecloud.10086.cn 流量
（参考 `docs/CAPTURE_DESKTOP_SESSION.md` §2 设置 `SSLKEYLOGFILE`）。

实现路径见上文 §6.2。

### 选项 C：纯客户端 spawn（最保守的"模仿桌面会话"）

直接在 Python 端 spawn macOS Session.app 子进程（如果云电脑跑在 mac 上）或者
Windows 客户端的 Ecloud-Cloud-Computer-Session.exe。这等价于"用 Python 当 Electron 主进程"。
但需要 macOS / Windows 客户端运行环境，不适合 Linux 服务器部署。

---

## 8. 附：抓包 vs 实现对照表

| 抓包发现 | Python 实现状态 | 实现路径 |
|---|---|---|
| ecloud.10086.cn login 链路 | ✅ 已实现 | `pcas/client.py::login_by_password` |
| ecloud.10086.cn machineConnect | ✅ 已实现 | `pcas/client.py::establish_session` |
| ecloud.10086.cn pushConnectEventData | ✅ 已实现 | `pcas/client.py::push_connect_event_cloud` |
| ecloud.10086.cn session/updateSessionStatus | ✅ 已实现 | `pcas/client.py::task_session_heartbeat` |
| ecloud.10086.cn 5min 周期 REST 心跳 | ✅ 已实现 | `keepalive.py::MachineRunner._rest_heartbeat_loop` |
| **36.212.224.100:8899 VDP gRPC Login** | ❌ 未实现 | 见 §6.2 |
| **36.212.224.100:8899 VDP gRPC Heartbeat** | ❌ 未实现 | 见 §6.2 |
| **36.212.224.100:8899 SPICE 多通道** | ❌ 未实现 | 见 §6.2 |
| cem double stream (8090) | ✅ 已实现 | `pcas/cem_stream.py` |

---

## 9. 附：完整 protobuf 文件清单（从 libVDPServer 提取）

| .proto 文件 | dylib offset | 状态 |
|---|---|---|
| `client/client_core.proto` | 0x610590 | ✅ 提取 (195 messages) |
| `common/broadcast_cmd.proto` | 0x61ce90 | 待重提（脚本未稳） |
| `common/common_core.proto` | 0x61f1d0 | ✅ 提取 (7 messages + 1 service) |
| `common/common_messages.proto` | 0x620720 | ✅ 提取 |
| `common/common_stream.proto` | 0x6262b0 | 待重提 |
| `common/error_data.proto` | 0x6263c0 | ✅ 提取 |
| `common/stream_message.proto` | 0x6265a0 | ✅ 提取 |
| `common/watermark_policy.proto` | 0x626d50 | 待重提 |
| `service/service_stream.proto` | 0x627de0 | ✅ 提取 |
| `google/protobuf/descriptor.proto` | 0x66bab0 | 标准 protobuf，忽略 |
| `google/protobuf/empty.proto` | 0x66daf0 | 标准 protobuf，忽略 |

重提工具：`tools/extract_vdp_proto.py --proto-name <name> --out <path>`
