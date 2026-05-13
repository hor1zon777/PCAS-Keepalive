# PCAS Keepalive — 移动云电脑 24h 保活 Web 程序

基于对 **PCAS_App V3.6.2**（中国移动「移动云电脑」Android 客户端）的离线静态逆向构造，
让你用浏览器登录自己的中国移动云电脑账号，查看机器、开关机、并让机器 **24 小时持续不被自动关机**。

> 本程序**只能用于操作你自己的账号**。它调用的是 PCAS_App 内部 cem-webapi 接口，
> 没有公开文档，可能违反服务条款，使用风险自担。

---

## 保活策略（重点）

**不是关机后再唤起**（那样数据会丢失）。这里采用「**主动延寿**」：

每隔 N 分钟向服务端发 4 个"显示活跃"信号，让服务端推迟「长时间无操作自动关机」倒计时：

| 调用 | endpoint | 作用 |
|---|---|---|
| 1 | `POST /user/setShutDownTime` | 把"断连后多久关机"刷成 24 小时 |
| 2 | `POST /session/updateSessionStatus` | 上报会话仍 `active` |
| 3 | `POST /machine/pushConnectEventData` | 心跳事件 `keepalive` |
| 4 | `POST /machine/performance/batch` | 上报 CPU/内存（让监控显示在用） |

每次任一成功就算一次有效心跳；4 个都失败则记为本次 keepalive 失败（写日志、暂停下一次）。

> ⚠️ 如果服务端确实强制要求"必须建立 SPICE/VDP 桌面连接才能算用户在使用"，纯 API 心跳可能不够。
> 这时需要保留官方 PCAS_App 客户端实际打开桌面，本程序作为辅助。建议先用「立刻跑一次」按钮试一下，
> 看几次 keepalive 后机器是否被服务端关掉。

---

## 快速开始

### 1. 环境要求

- Windows / Linux / macOS
- **[uv](https://docs.astral.sh/uv/)** ≥ 0.5 — Python 包管理器
  - Windows: `winget install --id=astral-sh.uv -e` 或 `irm https://astral.sh/uv/install.ps1 | iex`
  - macOS/Linux: `curl -LsSf https://astral.sh/uv/install.sh | sh`

Python 版本由 `.python-version`（3.12）固定；uv 会按需自动下载对应 Python，**不需要先装 Python**。

### 2. 安装依赖

```powershell
cd E:\Desktop\foldder\Code\Claude\ydy\pcas_keepalive
uv sync
```

`uv sync` 会一次完成：
- 创建 `.venv/`
- 按 `pyproject.toml` 装锁定版本的依赖（`uv.lock`）
- 如果 Python 3.12 未安装，自动下载

### 3. 配置

```powershell
copy .env.example .env
notepad .env        # 或 code .env
```

至少改这两项：

```env
SESSION_SECRET=随机的 32 字符以上字符串
LOCAL_KEY_HEX=64 位十六进制 (32 字节)
```

生成方法：

```powershell
uv run python -c "import secrets; print(secrets.token_urlsafe(32))"
uv run python -c "import secrets; print(secrets.token_hex(32))"
```

### 4. 运行

```powershell
uv run python main.py
```

或者用 uvicorn 直接跑（开发模式带热重载）：

```powershell
uv run uvicorn main:app --host 127.0.0.1 --port 8765 --reload
```

控制台显示：

```
INFO  pcas.main | PCAS Keepalive ready — listening on 127.0.0.1:8765
```

浏览器打开 [http://127.0.0.1:8765](http://127.0.0.1:8765)，用手机号 + 密码登录。

---

## Docker 部署

镜像基于 `python:3.12-slim` + 多阶段 uv 构建，最终约 200 MB。

### 1. 准备配置

```bash
cd pcas_keepalive
cp .env.example .env

# 至少修改两项随机值：
# SESSION_SECRET：32+ 字符随机串
# LOCAL_KEY_HEX：python -c "import secrets; print(secrets.token_hex(32))"
```

### 2. 启动

```bash
docker compose up -d --build
```

容器内强制绑 `0.0.0.0:8765`，宿主机端口可通过 `HOST_PORT` 环境变量改：

```bash
HOST_PORT=18765 docker compose up -d
```

数据持久化在宿主机 `./data/pcas.db`（首次启动自动创建）。

### 3. 探活

```bash
curl http://127.0.0.1:8765/healthz
# {"ok":true}

docker compose ps          # 看健康状态
docker compose logs -f     # 跟日志
```

### 4. 升级

```bash
git pull
docker compose up -d --build       # 重新 build + 替换容器（数据保留）
```

### 5. 备份 / 迁移

```bash
# 备份
tar czf pcas-backup.tar.gz data/ .env

# 迁移：把 pcas-backup.tar.gz 复制到新机器解压后再 docker compose up -d
```

### Docker 文件清单

```
Dockerfile              # 多阶段镜像构建（builder + runtime）
.dockerignore           # 排除 .venv / *.db / .env 等
docker-compose.yml      # 单服务 + volume + healthcheck
.env.example            # 配置模板（注意：默认 DB_PATH 是 /app/data/pcas.db）
data/                   # 持久化目录（compose 启动后自动创建）
```

---

## 使用流程

1. **登录**：默认走 `/login/verify`（密码登录）。如果失败，切换到「短信登录」走 `/login/loginByCode`。
2. **刷新机器列表**：点右上角「↻ 刷新」按钮，调 `/user/getDeviceInfo` 拉机器。
3. **开关机**：每张机器卡片有「开机 / 重启 / 关机 / 重置」按钮，对应 `/resource/operate` 的 op 字段。
4. **启用 24h 保活**：点机器卡底部的「+ 启用 24h 保活」，填间隔（建议 20 分钟）。
   - 任务持久化到 SQLite，**重启程序也会自动恢复**。
   - 想立即验证一次效果，点「立刻跑一次」。

---

## 协议字段不匹配怎么办

**重要**：本程序的默认 `base_url` 经过实测调整为 `https://cloudpc.ecloud.10086.cn`
（中国移动云电脑真实接入域名）。**如果你的 `.env` 是旧版本（指向 `pcas.cloudtrust.com.cn`），
登录会得到「返回 HTML 不是 JSON — base_url 错了」错误**。请编辑 `.env`：

```env
PCAS_BASE_URL=https://cloudpc.ecloud.10086.cn
```

### 当前已知的剩余阻塞

调通到 `cloudpc.ecloud.10086.cn` 后，服务器会回 JSON：

```json
{
  "errorMessage": "Input parameter AccessKey missing",
  "errorCode": "MISSING_PARAMETER",
  "state": "ERROR"
}
```

这是中国移动 **eCloud OpenAPI v1.0 签名**机制（query 参数：`AccessKey` /
`SignatureMethod=HmacSHA1` / `SignatureVersion=1.0` / `SignatureNonce` /
`Timestamp` / `Signature`）。本程序在 `pcas/sign.py` 实现了一个**占位版**的签名
算法（基于 eCloud 公开文档推断），但**两个关键参数未知**：

1. **AccessKey / SecretKey 是什么**：PCAS_App 客户端内嵌了一对 AK/SK，但这对
   AK/SK 被爱加密保护，藏在 `ijiami.dat` 里（参见逆向分析报告 §4）。需要运行时
   脱壳才能拿到。或者：你在 [ecloud.10086.cn 控制台](https://ecloud.10086.cn/portal)
   开通自己的 OpenAPI 凭证（个人版可能没有这个能力）。
2. **stringToSign 的精确拼接规则**：`pcas/sign.py` 用的是 eCloud 公开文档版（候选 A），
   但 PCAS_App 可能用了自有简化版（候选 B）。

### 唯一可靠的修复方法：抓包

PCAS_App 的 `network_security_config` 信任 user CA 且无 SPKI pinning（逆向报告 §8.3），
mitmproxy 抓包零门槛。

#### 用 mitmproxy 抓 PCAS_App 一次登录请求

1. 安卓手机装 [HttpCanary](https://www.httpcanary.com/) 或电脑跑 [mitmproxy](https://mitmproxy.org/)
2. 在手机上装 mitmproxy 的 CA 证书（**用户证书**位，不需要 root）
3. 手机连同 Wi-Fi，设置 HTTP 代理指向 mitmproxy
4. 打开官方 PCAS_App，用你自己的账号登一次
5. 在 mitmproxy 里找一个对 `cloudpc.ecloud.10086.cn` 的 POST 请求

复制以下字段到 `.env` 或代码中：

| 抓到的内容 | 对应改哪里 |
|---|---|
| 请求 URL 完整 path | 如和 `pcas/const.py` 的 `EP.LOGIN_VERIFY` 不同，改 const |
| query 中的 `AccessKey` 值 | 写到 `.env` `ECLOUD_ACCESS_KEY=` |
| query 中的 `Signature` 与你发的 stringToSign | 对照 `pcas/sign.py` _build_string_to_sign，校验候选 A/B |
| 请求 body 中加密前后的字段（如有别字段不止 `encryptedData`） | 改 `pcas/const.py` `RSA_ENVELOPE_KEY` 或 client.send 包装逻辑 |
| 请求 header 中的 `User-Agent` / `X-*` 自定义 header | 改 `pcas/client.py` `_build_headers` |
| 响应 body 中的 `data` 字段是否被加密 | 调 `decrypt_to_json` 已自动处理 |

填好 `ECLOUD_ACCESS_KEY` 和 `ECLOUD_SECRET_KEY` 后，把 `.env` 里：

```env
PCAS_SIGN_ENABLED=true
ECLOUD_ACCESS_KEY=<抓包到的 AK>
ECLOUD_SECRET_KEY=<抓包到的 SK 或固定值>
```

#### Web 内置诊断工具

登录页底部「🔧 登录失败？跑一次"诊断"」按钮（或调用 `POST /api/diag`）会用 4 个候选
host × 5 个 path 前缀做 20 次自动探测，按响应类型评分。响应类型：

- **HTML (SPA)** rating=0  → host 是 SPA 前端，根本不是 API
- **JSON 404 + `error_msg`** rating=2  → host 是 API 网关但 path 没配
- **JSON 4xx 业务错误**（如 `MISSING_PARAMETER` / `404 page not found`）rating=5  → host 对，正在调真实业务服务

### A. 打开 debug 日志

`.env` 里把 `DEBUG_DUMP_PAYLOAD=true` 打开，重启程序。控制台会打印每个请求的**加密前**和**响应解密后**的 JSON：

```
INFO  pcas.client | → POST /api/cem/.../login/verify plain={"mobile":"...","password":"...",...}
INFO  pcas.client | ← /api/cem/.../login/verify envelope={"code":1003,"msg":"参数 deviceUid 不能为空"}
```

→ 看 `msg` 提示什么字段缺，加到 `pcas/client.py` 对应方法里。

### B. 关掉 cem_rsa 加密临时调试

```env
CEM_RSA_ENABLED=false
```

会以明文 JSON 发请求，便于 mitmproxy 看到完整 body。如果服务端返回 400，说明 RSA 是必需的，再打开。

### C. 修改字段名

如果抓包发现真实字段名不一样（比如 `phoneNumber` 而不是 `mobile`），直接编辑：

- `pcas/client.py`: 比如 `login_by_password` 里 `"mobile"` → `"phoneNumber"`
- `pcas/const.py`: `SCHEMA` 字典文档里同步改一下

---

## 已确认 vs 待验证

| 部分 | 状态 | 说明 |
|---|---|---|
| **endpoint URL** | ✅ 100% 确认 | 从 libapp.so 字节流直接 grep 出来 |
| **RSA 密钥对** | ✅ 100% 确认 | 从 libapp.so 提取的 PKCS#1 v1.5 RSA-1024 |
| **响应包格式** `{code,msg,data}` | ✅ 字段都在 libapp.so 中 | 实际 code 成功值需抓包确认（0 / "0" / "00000000" / 200 都有可能）|
| **加密信封字段** `encryptedData` | ✅ 字符串确认 | 但 wrapper 结构是 `{encryptedData: ...}` 还是直接 string，需抓包验 |
| **登录字段** `mobile`/`password`/`loginType`/`deviceId`/`clientType`/`clientVersion` | 🟡 单字段存在确认，组合推断 | |
| **操作 op enum** `start`/`shutdown`/`restart`/`reset` | ✅ 字符串存在确认 | 个别 op 值（"poweron" 等）不存在，已用最可能值 |
| **保活字段** `shutdownTime`/`sessionId`/`connectId`/`status: active` | 🟡 字段名确认，组合推断 | |

---

## 文件结构

```
pcas_keepalive/
├── README.md                     ← 本文件
├── pyproject.toml                ← uv / Python 项目元数据 + 依赖列表
├── uv.lock                       ← uv 锁定的精确依赖版本
├── .python-version               ← 固定 Python 3.12
├── .env.example
├── .gitignore
├── config.py                     ← pydantic-settings 配置
├── pcas/                         ← PCAS 协议客户端
│   ├── __init__.py
│   ├── const.py                  ← endpoint + RSA 密钥 + SCHEMA 文档
│   ├── crypto.py                 ← RSA-1024 + AES-GCM
│   └── client.py                 ← httpx 异步客户端 + cem_rsa 拦截器
├── db.py                         ← sqlite3 DAO
├── keepalive.py                  ← APScheduler 调度器 + keepalive pulse
├── main.py                       ← FastAPI 入口
├── templates/                    ← Jinja2
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   └── partials/machine_card.html
└── static/style.css
```

### uv 常用命令

```powershell
uv sync                    # 装依赖到 .venv（按 lock 文件）
uv sync --upgrade          # 升级到允许范围内的最新版本，重写 lock
uv add httpx               # 添加依赖
uv remove httpx            # 移除依赖
uv add --dev ruff          # 添加开发依赖
uv run python main.py      # 在项目 venv 里跑命令
uv run ruff check .        # 在 venv 里跑代码检查
uv tree                    # 查看依赖树
uv lock --upgrade-package httpx   # 单独升级某个包
```

---

## 常见问题

### Q1. 登录提示 "不支持的请求"
大概率是 cem_rsa 协议方向不对。换 `CEM_RSA_ENABLED=false` 试一次。

### Q2. 登录提示 "密码错误" 但我密码是对的
PCAS 可能要求密码做一次 MD5/SM3。在 `pcas/client.py` 的 `login_by_password` 里把：

```python
"password": password,
```

改成：

```python
import hashlib
"password": hashlib.md5(password.encode()).hexdigest(),
```

服务端实际算法没有公开线索，常见候选：明文 / MD5 / SM3 / 拼盐 MD5。先试明文，再试 MD5。

### Q3. 登录成功但 getDeviceInfo 返回 "token 已失效"
- 检查 `Authorization: Bearer <cemToken>` header 是否带上（debug 日志里看）
- 服务端可能用别的 header 名（如 `cem-token`），本程序已经 3 个都带
- token TTL 可能很短（小时级），可以缩短 keepalive 间隔到 5 分钟

### Q4. 保活跑了几次后机器还是被关了
说明纯 API 心跳服务端不认。两种应对：

1. **改成"机器被关后自动开机"模式**（数据已丢失，但起码机器在线）：
   修改 `keepalive.py` 的 `_run_keepalive_once`，先调 `get_desktop_status`，如果状态 ≠ running 则调 `start`。
2. **保留官方 PCAS_App 在另一台手机/平板上跑桌面**，本程序辅助延寿。

### Q5. 我能用它操作别人的云电脑吗
**不能**。本程序只用你登录的账号能看到的机器。私下扫别人账号 = 违法。

---

## 安全

- 你的手机号密码用 AES-256-GCM 加密后存 `pcas.db`（key 在 `.env LOCAL_KEY_HEX`），**别提交 .env 和 .db 到 git**。
- session cookie 用 `SESSION_SECRET` 签名。
- 默认监听 `127.0.0.1`，不会暴露到公网。要远程访问的话**自己加 nginx + basic auth + TLS**，不要直接开 `HOST=0.0.0.0`。

---

## 致谢与许可

本程序基于对 PCAS_App V3.6.2 的离线静态逆向，逆向分析报告见
`E:\Desktop\foldder\Code\Claude\ydy\PCAS_App_逆向分析报告.md`。

代码部分采用 MIT 许可。逆向得到的 RSA 密钥、接口、字段名等知识产权归属
中国移动通信有限公司 / H3C，本程序仅在用户对自己账号的合理使用范围内调用。
