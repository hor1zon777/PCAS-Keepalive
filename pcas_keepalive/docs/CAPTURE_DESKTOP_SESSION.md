# 抓取公众版桌面会话流量指引

> 目的：拿到官方移动云电脑客户端打开桌面、保持桌面、断开桌面三个阶段的完整网络流量，
> 用于逆向 H3C SPICE/VDP 桌面层协议，让 Python 端能模拟"真实桌面会话"。

---

## 0. 为什么需要这份 pcap

当前 `pcas_keepalive` 已实现的层：
- ✅ `ecloud.10086.cn` 上的 cem-webapi（HTTPS REST）— 登录 / 拉机器 / 业务上报
- ✅ `36.133.24.236:8090` 上的 cem double stream（裸 TCP + 5s 心跳）
- ✅ `recordDeviceInfo` + `machineConnect` + `pushConnectEventData` 业务上报层

但服务端"机器空闲判定"很可能还看一个独立信号：**真实的桌面像素流连接**。
公众版 macOS 客户端 spawn `Ecloud-Cloud-Computer-H3C-Session` 子进程跑这一层，
协议细节藏在子进程 Mach-O 里。pcap 是低成本拿到字节级真相的唯一方式。

---

## 1. 抓什么

**三个阶段，全程一次抓完**：

| 阶段 | 时长 | 要捕获的内容 |
|---|---|---|
| ① 打开桌面 | 0~30s | 用户在客户端点"连接桌面"按钮 → 看到云电脑桌面 |
| ② 保持桌面 | 5~10 min | 桌面持续显示，**不要操作鼠标键盘**（更接近"空闲"，让心跳/keepalive 自然发生） |
| ③ 断开桌面 | 关闭客户端窗口 | 客户端主动断开桌面 |

> ⚠️ 不要中间最小化 / 黑屏 / 锁屏，会触发额外协议事件污染 pcap。
> ⚠️ 单次抓包覆盖**完整生命周期**，不要分段。

---

## 2. 用什么工具

### 推荐：Wireshark + SSLKEYLOGFILE

桌面流是**裸 TCP**（不一定是 TLS），但 `ecloud.10086.cn` 那部分是 HTTPS。
两层都要解，所以最简方案：

```powershell
# 设置 TLS key log，浏览器/Electron 都会写到这里
setx SSLKEYLOGFILE "%USERPROFILE%\Desktop\sslkeys.log"
# 关键：必须重启 Windows 客户端进程让环境变量生效
```

Wireshark → Edit → Preferences → Protocols → TLS → `(Pre)-Master-Secret log filename`
填上面的路径，HTTPS 流量就能解密了。

### 备选：mitmproxy（HTTPS 透明代理）

如果 Wireshark 的 SSLKEYLOGFILE 太麻烦，可以用 mitmproxy：
```bash
mitmproxy --mode transparent --listen-port 8888
```
但 mitmproxy 只能解 HTTPS，**裸 TCP 桌面流量它看不到**，所以仍然要 Wireshark 并存。

### 桌面端如果是 macOS

```bash
# macOS 设 SSLKEYLOGFILE（重启 client 后生效）
launchctl setenv SSLKEYLOGFILE ~/sslkeys.log

# Wireshark 同样配置 TLS Master Secret log file
```

---

## 3. 抓包流程

1. **关掉所有不相关的程序**（浏览器、IM、其他 VPN），避免噪音
2. 启动 Wireshark，捕获接口选**有线网卡或 Wi-Fi**（不要选 loopback）
3. 应用过滤器（可选，减小文件大小）：
   ```
   tcp and (host ecloud.10086.cn or host 36.133.24.236 or
            ip.dst_host == cloud-computer-h3-admin01-dongguan.cmecloud.cn)
   ```
   或更宽松地不加过滤、抓全部，事后再过滤
4. 启动官方客户端、登录
5. **开始抓包（Ctrl+E）**
6. 点击"连接桌面"
7. 等桌面出现后**保持 5~10 分钟**（不要操作）
8. 关闭客户端
9. **停止抓包（Ctrl+E）**
10. File → Save As → `ydy3_desktop_session.pcapng`

---

## 4. 怎么发给我

需要发送：
- ✅ `ydy3_desktop_session.pcapng` （完整抓包）
- ✅ `sslkeys.log`（TLS 解密 key，没这个 HTTPS 看不到内容）
- ✅ 一份简单的时间标注，比如：
  ```
  19:32:10 — 点了"连接桌面"按钮
  19:32:18 — 看到桌面显示出来
  19:42:18 — 关闭客户端
  ```

放到项目目录 `E:\Desktop\foldder\Code\Claude\ydy\` 下，下次会话告诉我文件名。

---

## 5. 我拿到 pcap 后会做什么

1. **解 HTTPS**：用 sslkeys.log 解密 `ecloud.10086.cn` 流量，看 macOS 客户端打开桌面前调了什么接口（最重要的是有没有比 `machineConnect` / `pushConnectEventData` 更隐蔽的接口）
2. **追桌面流**：找出 TCP 三次握手后 client 主动发的第一个数据包，确认端口、目标 IP、是否有 TLS 升级
3. **分析协议帧**：从第一个数据包开始按字节解析，定位 magic / cmd_id / payload 的字段顺序和编码
4. **对比家庭版 Go 项目的 chuanyun + SPICE**：判断公众版是否同源，能否直接复用 Go 项目的 SPICE handshake 实现
5. **写 Python 移植**：把握手 + 心跳 + 桌面层 PING/PONG 移植到 pcas_keepalive，作为新的"真实桌面会话保活"策略

---

## 6. 可能遇到的坑

- **TLS Pinning**：客户端可能做了证书钉，导致 SSLKEYLOGFILE 不写入 key。这时 HTTPS 流量看不到内容；只能靠 cem-webapi 接口名 + 端口推断，准确度下降。
- **桌面层走 UDP**：SPICE 可能跑在 UDP 上。Wireshark 默认全协议都抓不需要单独配置。
- **流量超大**：5~10 min 桌面流可能产生 50~500MB pcap。压缩后发给我（zip / 7z）。

---

## 7. 当前可以先做的事（不用等 pcap）

- 部署最新版 `pcas_keepalive`（已修复业务上报层：machineConnect + pushConnectEventData）
- 观察现在是否还自动关机；如果 24h 内不关机，说明业务上报层修复就够了，SPICE 实现可以暂缓
- 如果还是会关机，那 SPICE 层就是必做的，那时 pcap 必不可少
