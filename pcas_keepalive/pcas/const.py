"""PCAS / 移动云电脑 真实接口常量。

依据 D:\\CloudComputer\\keep-alive 的 Node.js 参考实现（已实测可用）回填。
关键修正：
  - baseUrl: ecloud.10086.cn （不带 cloudpc.）
  - apiPath: /api/cem/gateway/outer/cem-webapi （endpoint 不再含此前缀）
  - 硬编码 AccessKey/SecretKey（PCAS_App 客户端内嵌的应用级凭据）
  - SignatureVersion: V2.0
  - HMAC key 前缀: 'BC_SIGNATURE&'
  - RSA 信封字段: 'params' （不是 'encryptedData'）
"""
from __future__ import annotations

# ---------- 网关 ----------

DEFAULT_BASE_URL = "https://ecloud.10086.cn"
API_PATH = "/api/cem/gateway/outer/cem-webapi"

# ---------- 客户端应用凭据（PCAS_App 内嵌，全局共用） ----------

ECLOUD_ACCESS_KEY = "53bb79015a3f47c4be166d9371f68f14"
ECLOUD_SECRET_KEY = "6b0d3b93f3aa4c7ea076c841bead1ddd"

# ---------- 客户端版本伪装 ----------

APP_VERSION_NAME = "3.8.0"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Ecloud-Cloud-Computer-Application/" + APP_VERSION_NAME + " "
    "Chrome/108.0.5359.215 Electron/22.3.27 Safari/537.36"
)
DEFAULT_CLIENT_TYPE = "pc_windows"
DEFAULT_COMPANY_CODE = "ECloud"
PACKAGE_NAME = "com.cmss.cloudcomputer"


# ---------- 业务 endpoints（不含 apiPath 前缀） ----------

class EP:
    # ===== 登录两阶段：verify → verifyAccessTicket =====
    LOGIN_VERIFY = "/login/verify"
    LOGIN_VERIFY_SMS = "/login/verifySms"
    LOGIN_SEND_SMS = "/login/sendVerifySms"
    LOGIN_BY_CODE = "/login/loginByCode"
    LOGIN_TRUST_DEVICE = "/login/trustDevice"
    LOGIN_TRUST_OR_TEMP = "/login/trustOrTemporaryDevice"
    LOGIN_VERIFY_ACCESS_TICKET = "/login/verifyAccessTicket"
    LOGIN_RECORD_DEVICE = "/login/recordDeviceInfo"
    LOGIN_LOGOUT = "/login/logout"

    # ===== 用户/机器 =====
    USER_GET_DEVICE_INFO = "/user/getDeviceInfo"
    USER_GET_DESKTOP_STATUS = "/user/getDesktopStatus"
    USER_CHANGE_MACHINE_NAME = "/user/changeMachineName"
    USER_SET_SHUTDOWN_TIME = "/user/setShutDownTime"
    USER_GET_USER_DEVICE_POLICY = "/user/getUserDevicePolicy/v2"

    # ===== 资源操作 =====
    RESOURCE_OPERATE = "/resource/operate"

    # ===== 会话/保活 =====
    SESSION_MACHINE_CONNECT = "/session/machineConnect"
    SESSION_UPDATE_STATUS = "/session/updateSessionStatus"
    MACHINE_PERF_BATCH = "/machine/performance/batch"
    DEVICE_PERF_BATCH = "/device/performance/batch"
    MACHINE_PUSH_CONNECT_EVENT = "/machine/pushConnectEventData"

    # ===== 客户端配置（cem stream host/port 来源） =====
    CLIENT_GET_SYS_CONFIG = "/client/getSysConfig"


# ---------- 操作枚举 ----------

class OpType:
    START = "start"
    SHUTDOWN = "shutdown"
    RESTART = "restart"
    RESET = "reset"
    PAUSE = "pause"
    RESUME = "resume"
    STOP = "stop"
    RELOAD = "reload"


OP_TYPES: tuple[str, ...] = (
    OpType.START, OpType.SHUTDOWN, OpType.RESTART, OpType.RESET,
    OpType.PAUSE, OpType.RESUME, OpType.STOP, OpType.RELOAD,
)


class MachineStatus:
    RUNNING = "running"
    AVAILABLE = "available"
    STOPPED = "stopped"
    POWER_OFF = "PowerOff"
    ACTIVE = "active"
    INACTIVE = "inactive"


# ---------- 加密信封 ----------

# 请求体 / 响应体里的密文字段名（确认：参考实现用的就是 'params'）
RSA_ENVELOPE_KEY = "params"


# ---------- RSA 密钥（PCAS_App 客户端内嵌） ----------

PCAS_RSA_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqisJL7YvdPC/gJA7fLrr1G+t6
J0arJr0sVfieVJTXTclm/2afP/fjNYY/CFcg1MUx8KPmPC2CqsUHRMZq6Ev1/UNX
E74I1TfJC/2b8aexcdZ+Lokj7AwzrM9yPy2qfV6vXtxyRrTs+JcFHVXtV6phNkor
NyIahyfy46+iNB+FSQIDAQAB
-----END PUBLIC KEY-----"""

PCAS_RSA_PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKqKwkvti908L+Ak
Dt8uuvUb63onRqsmvSxV+J5UlNdNyWb/Zp8/9+M1hj8IVyDUxTHwo+Y8LYKqxQdE
xmroS/X9Q1cTvgjVN8kL/Zvxp7Fx1n4uiSPsDDOsz3I/Lap9Xq9e3HJGtOz4lwUd
Ve1XqmE2Sis3IhqHJ/Ljr6I0H4VJAgMBAAECgYBD6lx0BlajtRtPxKxTfvWfNQ4y
qD+BWz0M0fPfgcmAcI7bQKyqkLv0NNWQdo7UGUeqmq16u85X8g/i1CW8X2QYHOSY
NBUWsK3k5gFT1wdk+bwuIMZqgjEc48TXzM4pidcplJLyD1tnNiubzcXIsZCIIuQ/
GmWcuxn7ULHnXDsQMQJBANMl4V97be6fkd1beGqYZWIx3XNnL96AQsapBrEbbORT
u/JnwTCRbsRWRBHU11FZuK85dBDXrH8reoAsgepmsF0CQQDOxL99OFjozj8g1weF
GwI/otMKcPhkaslU2tj3QF44zT1TZiOZ710I8GQLPlKeu1yGWvVUwgH4bCY0M8M1
/gndAkB9sU4RTeOqKjllwT7UjbXEl5SRTzrSxB18L0B5i67t2N7INXVumRSMMiJB
TyeCGNv1C0mJgSoBZft9c4E+7TRNAkB+7Azza7Q/6+KaYQRPs32U3HkZbrE6ysYd
XV1ToOJ1kZ60Y/00j9cXFqECudXzc+Ve39S6m4CkIpbs8l1A9ljNAkBy6Rp19R5w
WMr/3feIMZ18akWXT5mgRvZpkT5MgmrjVu1lRv8bHsEsAzRYvdPSjzp0nCkUbOWU
ITxWp7d//Fwc
-----END PRIVATE KEY-----"""


# ---------- 设备指纹（按账号 SHA256 派生稳定值） ----------

CPU_MODELS = (
    "Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz",
    "Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz",
    "Intel(R) Core(TM) i5-12400 CPU @ 2.50GHz",
    "Intel(R) Core(TM) i7-12700 CPU @ 2.10GHz",
    "Intel(R) Core(TM) i5-13400 CPU @ 2.50GHz",
    "AMD Ryzen 5 5600X 6-Core Processor",
    "AMD Ryzen 7 5800X 8-Core Processor",
    "Intel(R) Core(TM) i5-11400 CPU @ 2.60GHz",
)
