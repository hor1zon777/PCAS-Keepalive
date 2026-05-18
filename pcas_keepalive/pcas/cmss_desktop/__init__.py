"""CMSS / ZTE 桌面会话模块 — 公众版云电脑桌面层模拟。

基于 IDA 反编 `libcag.dll` + `libvdconn.dll` 还原的字节级协议实现。

## 协议栈层次

```
应用层:   cs_suOperDesktop.action HTTP POST (cs_action.py)
TLS:      TLS 1.2 + ZTE 自签证书
CAG 网关: HTTP CONNECT 隧道 + ZTEC 5 帧握手 (ztec_protocol.py)
TCP:      8899 端口
```

## 详细协议文档

`docs/CMSS_DESKTOP_PROTOCOL.md` — pcap 字节级抓包分析
`docs/VDP_GRPC_PROTOCOL.md` — H3C VDP gRPC 控制面

## 当前实现状态

- ✅ ZTEC 5 帧字节级布局（与 IDA 反编一致）
- ✅ cs_suOperDesktop.action HTTP body（8 字段，IDA 反编对齐）
- ✅ AES-256-CBC SDK key/IV
- ⏳ AES 会话 key 派生（sub_100026C0 + sub_10002C00 待完整还原）
- ⏳ cag_param.username / password 实际内容来源
"""
from .client import CmssDesktopClient, CmssDesktopResult
from .const import (
    CMSSZTE_PUBKEY_B64,
    H3C_PUBKEY_B64,
    SDK_AES_IV,
    SDK_AES_KEY,
    ZTE_PUBKEY_B64,
    CsEndpoint,
    get_vendor_pubkey_b64,
    get_vendor_pubkey_pem,
)
from .cs_action import (
    CsActionClient,
    CsRequest,
    CsResponse,
    decode_cs_response_body,
    encode_cs_request_body,
    encode_su_oper_inner_payload,
)
from .ztec_protocol import (
    AUTH_TYPE_RADIUS,
    AUTH_TYPE_UAC,
    CagParam,
    ZtecPongInfo,
    derive_session_key_and_iv,
    encode_ztec_auth_packet,
    encode_ztec_hello,
    rsa_encrypt_with_vendor_pubkey,
    ztec_aes256_cbc_decrypt,
    ztec_aes256_cbc_encrypt,
)

__all__ = [
    # 高层客户端（实验性）
    "CmssDesktopClient",
    "CmssDesktopResult",
    # ZTEC 协议
    "AUTH_TYPE_RADIUS",
    "AUTH_TYPE_UAC",
    "CagParam",
    "ZtecPongInfo",
    "encode_ztec_hello",
    "decode_ztec_pong",
    "encode_ztec_auth_packet",
    "decode_ztec_ack",
    "derive_aes_key_material",
    "build_http_connect_request",
    # HTTP 层
    "CsActionClient",
    "CsRequest",
    "CsResponse",
    "CsEndpoint",
    "encode_su_oper_inner_payload",
    "encode_cs_request_body",
    "decode_cs_response_body",
    # crypto
    "rsa_encrypt_with_vendor_pubkey",
    "aes_encrypt_sdk",
    "aes_decrypt_sdk",
    "aes_encrypt_sdk_base64",
    "aes_decrypt_sdk_base64",
    # 厂商密钥
    "ZTE_PUBKEY_B64",
    "CMSSZTE_PUBKEY_B64",
    "H3C_PUBKEY_B64",
    "SDK_AES_KEY",
    "SDK_AES_IV",
    "get_vendor_pubkey_b64",
    "get_vendor_pubkey_pem",
]
