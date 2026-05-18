"""中兴 SmartView VDI `/cs/cs_*.action` HTTP 客户端。

抓包验证（`2.pcapng` frame 137 / 339）+ IDA 反编 vdconn.dll `DoGetSuOperConnectStr @ 0x19d3c0`
还原的字节级实现：

- POST /cs/cs_suOperDesktop.action HTTP/1.1
- Host: [服务器 IPv6]:8899
- Content-Type: application/xml （客户端 header 写的是 xml，但实际 body 是 JSON）
- X-Ap-sHost: <server>:<vmcport>  （opType==1 时用）/ X-Ap-Host: <server>:<vmcport> （其他时用）

## 完整 body 构造（IDA 反编实证，不再是推测）

```
Step 1: 内层 JSON（AES 加密前）— 仅 3 个字段
  {
    "vmid": "<UUID>",
    "timestamp": "<13-digit ms>",
    "opType": 3   // 固定 3 = suOper 类型
  }

Step 2: AES_EncodeForCsap(innerJson) → base64

Step 3: 外层 JSON（HTTP body，明文）
  {
    "language": "zh",
    "param": "<base64-of-aes-ciphertext>",
    "timestamp": "<同内层>",
    "opType": <connectParams.opType, 用户操作类型>,
    "encrypt": 7,
    "allowExtUSBPolicy": 1,
    "prover": 1,
    "allowSwitchRap": 1
  }
```

## 响应（不加密，明文 JSON）

```
{
    "result": "0",            // "0" 成功
    "connectStr": "<256-byte hex>",  // AES 加密的 SPICE 连接票据
    "success": true,
    "mesg": "Success",
    "encryption": "0"
}
```
"""
from __future__ import annotations

import json
import logging
import ssl
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx

from .const import (
    DEFAULT_ENCRYPT_VERSION,
    CsEndpoint,
)
from .ztec_protocol import aes_decrypt_sdk_base64, aes_encrypt_sdk_base64

log = logging.getLogger("pcas.cmss_desktop.cs_action")


# ---------- 请求/响应模型 ----------

@dataclass
class CsRequest:
    """cs_*.action 请求模型。"""

    endpoint: str                          # 如 "/cs/cs_suOperDesktop.action"
    plaintext_payload: dict[str, Any]      # 内层 JSON（AES 加密前的业务字段）
    server_ipv6: str                       # 桌面服务器 IPv6 地址
    server_port: int = 8899
    x_ap_shost: str = ""                   # X-Ap-sHost header 值（路由用）
    use_x_ap_shost: bool = True            # True=用 X-Ap-sHost, False=用 X-Ap-Host
    encrypt_version: int = DEFAULT_ENCRYPT_VERSION
    language: str = "zh"
    # 外层 JSON 用户操作类型字段（与内层 opType=3 不同；这是 connectParams 里的 opType）
    op_type_outer: int = 0
    # 外层 JSON 附加常量字段（IDA 反编实测）
    allow_ext_usb_policy: int = 1
    prover: int = 1
    allow_switch_rap: int = 1


@dataclass
class CsResponse:
    """cs_*.action 响应模型。"""

    result: str                            # "0" = 成功
    success: bool
    mesg: str                              # 状态消息
    connect_str: str = ""                  # 仅 cs_suOperDesktop 等接口返回
    encryption: str = ""                   # 是否加密
    raw_body: str = ""                     # 原始响应 body（调试用）
    extra_fields: dict[str, Any] | None = None


# ---------- 编码/解码 ----------

def encode_su_oper_inner_payload(vm_id: str, timestamp_ms: int) -> dict[str, Any]:
    """构造 cs_suOperDesktop.action 内层 JSON（AES 加密前）。

    IDA 反编 DoGetSuOperConnectStr @ 0x19d3c0 实证：内层 JSON 只有 3 个字段。
    """
    return {
        "vmid": vm_id,
        "timestamp": str(timestamp_ms),
        "opType": 3,        # 固定 3，suOper 类型
    }


def encode_cs_request_body(
    plaintext: dict[str, Any],
    *,
    encrypt_version: int = DEFAULT_ENCRYPT_VERSION,
    timestamp_ms: int | None = None,
    op_type_outer: int = 0,
    allow_ext_usb_policy: int = 1,
    prover: int = 1,
    allow_switch_rap: int = 1,
) -> bytes:
    """构造 cs_*.action 的完整 HTTP 请求 body（外层 JSON）。

    IDA 反编实证：外层 8 个字段（不是抓包看到的 4 个 — 抓包可能是别的 opType 路径）。

    Args:
        plaintext: 内层业务参数 dict（会序列化为 JSON 然后 AES 加密成 param）
        encrypt_version: encrypt 字段（默认 7，macOS V3.6.5 用的版本）
        timestamp_ms: 13 位毫秒时间戳，默认用 now()
        op_type_outer: 外层 opType（来自 connectParams 里的用户操作类型，不是内层固定 3）
        allow_ext_usb_policy / prover / allow_switch_rap: IDA 反编实测的固定字段
    """
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)

    plain_json = json.dumps(plaintext, ensure_ascii=False, separators=(",", ":"))
    enc_b64 = aes_encrypt_sdk_base64(plain_json)

    # 外层 JSON 字段顺序与真实客户端一致
    body = {
        "language": "zh",
        "param": enc_b64,
        "timestamp": str(timestamp_ms),
        "opType": op_type_outer,
        "encrypt": encrypt_version,
        "allowExtUSBPolicy": allow_ext_usb_policy,
        "prover": prover,
        "allowSwitchRap": allow_switch_rap,
    }
    # 真实客户端用 Json::Value::toStyledString() 输出多行格式，但服务端应该不挑剔
    # 这里用紧凑格式更省字节
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def decode_cs_response_body(body: bytes) -> CsResponse:
    """解 cs_*.action 响应 body（明文 JSON，无加密）。"""
    text = body.decode("utf-8", errors="replace")
    try:
        data = json.loads(text)
    except Exception as e:
        raise ValueError(f"cs response 不是合法 JSON: {e}; body={text[:200]!r}")

    return CsResponse(
        result=str(data.get("result", "")),
        success=bool(data.get("success", False)),
        mesg=str(data.get("mesg", "")),
        connect_str=str(data.get("connectStr", "")),
        encryption=str(data.get("encryption", "")),
        raw_body=text,
        extra_fields={k: v for k, v in data.items()
                      if k not in ("result", "success", "mesg", "connectStr", "encryption")},
    )


# ---------- HTTP 客户端 ----------

class CsActionClient:
    """对桌面服务器 8899 端口的 HTTP/1.1 + TLS 请求客户端。

    注意：真实 macOS 客户端是在 ZTEC 握手 + TLS 升级**后的同一 TCP**上发 HTTP 请求。
    本类提供两种使用方式：
      1. 独立新建 TLS 连接（适合脱离 ZTEC 握手的"半连接"测试）
      2. 复用已有 TLS socket（适合完整 ZTEC + TLS + cs_action 流程）
    """

    def __init__(self, server_ipv6: str, server_port: int = 8899, *, verify_tls: bool = False):
        self.server_ipv6 = server_ipv6
        self.server_port = server_port
        self.verify_tls = verify_tls
        # 桌面服务器自签证书（CN=DC, O=ZTE）不能用公共 CA 验证；
        # 默认 verify=False — 服务端身份通过 ZTEC AuthPacket RSA 校验。
        self._ssl_ctx = ssl.create_default_context()
        if not verify_tls:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE
        self._http: httpx.AsyncClient | None = None

    @property
    def base_url(self) -> str:
        # IPv6 地址要用方括号包起来
        if ":" in self.server_ipv6 and not self.server_ipv6.startswith("["):
            host = f"[{self.server_ipv6}]"
        else:
            host = self.server_ipv6
        return f"https://{host}:{self.server_port}"

    async def __aenter__(self) -> "CsActionClient":
        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            verify=self.verify_tls,
            timeout=30.0,
        )
        return self

    async def __aexit__(self, *_a) -> None:
        if self._http:
            await self._http.aclose()
            self._http = None

    async def post(self, req: CsRequest) -> CsResponse:
        """发起一次 cs_*.action 请求（外层 8 字段完整版）。"""
        if not self._http:
            raise RuntimeError("must use async with CsActionClient(...) as client:")

        body = encode_cs_request_body(
            req.plaintext_payload,
            encrypt_version=req.encrypt_version,
            op_type_outer=req.op_type_outer,
            allow_ext_usb_policy=req.allow_ext_usb_policy,
            prover=req.prover,
            allow_switch_rap=req.allow_switch_rap,
        )
        host_header = (f"[{self.server_ipv6}]:{self.server_port}"
                       if ":" in self.server_ipv6 else f"{self.server_ipv6}:{self.server_port}")
        headers = {
            "Host": host_header,
            "Accept": "*/*",
            "Content-Type": "application/xml",   # 真实抓包就是 xml（即使 body 是 JSON）
            "Content-Length": str(len(body)),
        }
        if req.x_ap_shost:
            key = "X-Ap-sHost" if req.use_x_ap_shost else "X-Ap-Host"
            headers[key] = req.x_ap_shost

        log.info("→ POST %s%s body_len=%d", self.base_url, req.endpoint, len(body))
        resp = await self._http.post(req.endpoint, content=body, headers=headers)
        log.info("← HTTP %d body_len=%d", resp.status_code, len(resp.content))

        if resp.status_code != 200:
            raise RuntimeError(f"cs_action HTTP {resp.status_code}: {resp.text[:200]!r}")
        return decode_cs_response_body(resp.content)

    async def su_oper_desktop(
        self,
        *,
        vm_id: str,
        x_ap_shost: str = "",
        op_type_outer: int = 0,
        timestamp_ms: int | None = None,
    ) -> CsResponse:
        """便捷方法：调 /cs/cs_suOperDesktop.action 拿 connectStr。

        IDA 反编 DoGetSuOperConnectStr @ 0x19d3c0 实证字段：内层只有 vmid/timestamp/opType=3。
        外层 opType 来自连接参数，可能是 0/1/2/3 等。
        """
        if timestamp_ms is None:
            timestamp_ms = int(time.time() * 1000)
        payload = encode_su_oper_inner_payload(vm_id, timestamp_ms)
        req = CsRequest(
            endpoint=CsEndpoint.SU_OPER_DESKTOP,
            plaintext_payload=payload,
            server_ipv6=self.server_ipv6,
            server_port=self.server_port,
            x_ap_shost=x_ap_shost,
            use_x_ap_shost=True,
            op_type_outer=op_type_outer,
        )
        return await self.post(req)


__all__ = [
    "CsRequest",
    "CsResponse",
    "encode_su_oper_inner_payload",
    "encode_cs_request_body",
    "decode_cs_response_body",
    "CsActionClient",
]

