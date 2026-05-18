"""CMSS / ZTE 桌面会话协议常量。

来源：
- macOS app.asar `public/electron/config/privateSetting.js`（SDKSecretKey）
- macOS app.asar `public/electron/service/vdconnect/cmss.wc.js` 内嵌 pubkey
- macOS app.asar `public/electron/service/vdconnect/zte.wc.js` 内嵌 pubkey
- 真实抓包 `2.pcapng` 字节级验证 ZTEC 帧布局
"""
from __future__ import annotations

# ---------- ZTEC 协议常量 ----------

# 5 字节 magic 标识（实际是 4 字节 "ZTEC" + 1 字节 0x2c 长度字段，但 magic 字符串只是 ZTEC）
ZTEC_MAGIC = b"ZTEC"
ZTEC_MAGIC_HEX = "5a544543"  # "ZTEC" 4 字节


# ---------- 厂商 RSA 公钥（SDK 级，从 privateSetting.js 提取） ----------

# ZTE 厂商（即纯 ZTE 桌面）
ZTE_PUBKEY_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5dwvTHYehc3BMwFBcZXBzr"
    "EKcEacBeOw7k1BcGy9fv+UhFgL92ENpEqz5dLUEmqpGleGn3fH6VAdWUOS9/8"
    "u9kdS3xlu4DSpAyN7cGNG8LThZST7g8rsNdsmPv7CrT5I4M93Jtl2psTqRYV6"
    "4CbroCOVy2z4QdKrmokSv3SNu+wIDAQAB"
)

# CMSSZTE（移动云电脑用的 ZTE 桌面变体）— 与 ZTE 公钥完全相同
CMSSZTE_PUBKEY_B64 = ZTE_PUBKEY_B64

# H3C 厂商（与 cem-webapi 公钥相同）
H3C_PUBKEY_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqisJL7YvdPC/gJA7fLrr1G"
    "+t6J0arJr0sVfieVJTXTclm/2afP/fjNYY/CFcg1MUx8KPmPC2CqsUHRMZq6E"
    "v1/UNXE74I1TfJC/2b8aexcdZ+Lokj7AwzrM9yPy2qfV6vXtxyRrTs+JcFHVX"
    "tV6phNkorNyIahyfy46+iNB+FSQIDAQAB"
)


def get_vendor_pubkey_b64(company_code: str) -> str:
    """按 companyCode 返回对应厂商的 RSA 公钥 base64。

    Args:
        company_code: machine 字典里的 companyCode 字段
                      （ZTE/CMSSZTE/CMSS/H3C，大小写敏感）
    """
    code = (company_code or "").upper()
    if code in ("ZTE", "CMSSZTE", "CMSS"):
        return ZTE_PUBKEY_B64
    if code == "H3C":
        return H3C_PUBKEY_B64
    # 默认走 ZTE（公众版主流）
    return ZTE_PUBKEY_B64


def get_vendor_pubkey_pem(company_code: str) -> bytes:
    b64 = get_vendor_pubkey_b64(company_code)
    return b"-----BEGIN PUBLIC KEY-----\n" + b64.encode() + b"\n-----END PUBLIC KEY-----\n"


# ---------- SDK 全局 AES key/IV（用于 cs_suOperDesktop.action param 字段） ----------

# 来自 privateSetting.js SDKSecretKey.aesSetting，全局共用（所有厂商）
SDK_AES_KEY = b"56Acf4c3498fD4c5a0B1fb26947e2daB"  # 32 ASCII chars = AES-256 key
SDK_AES_IV = b"3498fD4c5a0B1fbA"                    # 16 ASCII chars = AES-CBC IV


# ---------- /cs/cs_*.action 接口名（共 39 个，来自 libvdconn.dylib） ----------

class CsEndpoint:
    """中兴 SmartView 桌面服务接口（POST 到桌面服务器 8899 端口的同一 TCP，TLS 升级后）。"""

    # 桌面操作（关键）
    SU_OPER_DESKTOP = "/cs/cs_suOperDesktop.action"             # 用户主动连接桌面
    SU_OPER_DESKTOP_ASYNC = "/cs/cs_suOperDesktop_async_query.action"  # 异步查状态
    OP_DESKTOP = "/cs/cs_opDesktop.action"                     # 一般桌面操作
    OP_DESKTOP_ASYNC = "/cs/cs_opDesktop_async_query"
    START_DESKTOP = "/cs/cs_startDesktop.action"
    START_DESKTOP_ASYNC = "/cs/cs_startDesktop_async_query.action"
    RESTART_DESKTOP = "/cs/cs_restartDesktop.action"
    RESET_VD = "/cs/cs_resetVD.action"

    # 登录
    LOGIN_BY_TOKEN = "/cs/cs_loginbytoken.action"
    GET_TOKEN = "/cs/cs_getToken.action"
    GET_TOKEN_EX = "/cs/cs_getToken_ex.action"
    GET_TOKEN_ZJ4A = "/cs/cs_getToken_zj4a.action"
    CHECK_TOKEN = "/cs/cs_check_token.action"
    LOGIN_ONCODE = "/cs/cs_loginOncode.action"
    LOGIN_QUICK_ONCODE = "/cs/cs_loginQuickOncode.action"

    # 查询
    GET_DESKTOP_LIST = "/cs/cs_getDesktopList.action"
    GET_LOGIN_STATUS = "/cs/cs_getLoginStatus.action"
    GET_USER_INFO = "/cs/cs_getUserInfo.action"
    GET_TEMPLATE_LIST = "/cs/cs_getTemplateList.action"
    SYS_CONFIG = "/cs/cs_sysConfig.action"

    # 其他
    CAG_TOKEN = "/cs/cs_getCagToken.action"
    MODIFY_PASSWORD = "/cs/cs_modifyPassword.action"


# ---------- HTTP 请求加密版本 ----------

# encrypt 字段取值（从抓包 + dylib 字符串）
# 数字含义需要进一步反编确认；当前抓包用 encrypt=7
ENCRYPT_VERSIONS = {
    0: "无加密（明文）",
    1: "加密版本 1（早期 RSA + AES）",
    4: "加密版本 4",
    5: "加密版本 5",
    7: "加密版本 7（当前 macOS V3.6.5 使用）",
}

DEFAULT_ENCRYPT_VERSION = 7
