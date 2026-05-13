"""eCloud OpenAPI V2.0 签名 — 精确移植自 D:\\CloudComputer\\keep-alive Node 实现。

签名算法（实证可用）：
    signParams = {
        AccessKey: <硬编码 AK>,
        SignatureMethod: 'HmacSHA1',
        SignatureNonce: <32 hex chars>,
        SignatureVersion: 'V2.0',
        Timestamp: '<北京时间 ISO 字符串>Z',
    }
    qs = querystring.stringify(signParams)               # 按 insertion order，不排序
    stringToSign = 'POST\\n'
        + urlEncode(API_PATH + endpoint) + '\\n'         # urlEncode("/api/cem/gateway/outer/cem-webapi/login/verify")
        + sha256_hex(qs)
    Signature = hmacSha1(stringToSign, 'BC_SIGNATURE&' + secretKey)
              # 注意 HMAC key 是固定前缀 + SK；最终签名也是 hex 字符串

    finalUrl = baseUrl + apiPath + endpoint + '?' + qs + '&Signature=' + Signature

Timestamp 关键细节：
    Node 端是 toISOString() 在 UTC+8 偏移后的时刻 + 'Z'
    即生成的字符串表面是 UTC，但其实是北京时间数字（这是中国移动 OpenAPI 的"约定"）。
"""
from __future__ import annotations

import hashlib
import hmac
import time
import urllib.parse

from .const import API_PATH, ECLOUD_ACCESS_KEY, ECLOUD_SECRET_KEY
from .crypto import gen_nonce

# eCloud HMAC 固定盐前缀（参考实现中硬编码）
_HMAC_KEY_PREFIX = "BC_SIGNATURE&"


def _beijing_timestamp() -> str:
    """北京时间（UTC+8）的 ISO8601 字符串 + 'Z' 后缀。

    与 Node 实现完全一致：
        new Date(now.getTime() + 8*3600*1000).toISOString().slice(0,19) + 'Z'
    """
    bj = time.gmtime(time.time() + 8 * 3600)
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", bj)


def _percent_encode(s: str) -> str:
    """querystring.stringify 风格：单值 URL 编码（保留 -, _, ., ~）。"""
    return urllib.parse.quote(s, safe="-_.~")


def _querystring_stringify(params: list[tuple[str, str]]) -> str:
    """对应 Node querystring.stringify：按插入顺序，键值都 urlEncode，用 = 连接，& 分隔。"""
    return "&".join(f"{_percent_encode(k)}={_percent_encode(v)}" for k, v in params)


def build_signed_url(
    endpoint: str,
    base_url: str,
    access_key: str = ECLOUD_ACCESS_KEY,
    secret_key: str = ECLOUD_SECRET_KEY,
) -> str:
    """生成已签名的完整 URL。

    Args:
        endpoint: 业务路径，如 '/login/verify'（不带 apiPath 前缀）
        base_url: 'https://ecloud.10086.cn'

    Returns:
        完整 URL，可直接 POST
    """
    sign_params: list[tuple[str, str]] = [
        ("AccessKey", access_key),
        ("SignatureMethod", "HmacSHA1"),
        ("SignatureNonce", gen_nonce()),
        ("SignatureVersion", "V2.0"),
        ("Timestamp", _beijing_timestamp()),
    ]
    qs = _querystring_stringify(sign_params)

    full_api_path = API_PATH + endpoint
    string_to_sign = (
        "POST\n"
        + urllib.parse.quote(full_api_path, safe="")     # 全部转义
        + "\n"
        + hashlib.sha256(qs.encode("utf-8")).hexdigest()
    )

    signature = hmac.new(
        (_HMAC_KEY_PREFIX + secret_key).encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha1,
    ).hexdigest()                                       # hex 字符串

    final_qs = qs + "&Signature=" + _percent_encode(signature)
    return f"{base_url.rstrip('/')}{full_api_path}?{final_qs}"
