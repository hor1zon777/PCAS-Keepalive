"""PCAS / 移动云电脑 API 客户端 — 精确实现版（对照 D:\\CloudComputer\\keep-alive）。

每个 POST 请求的完整流程：
  1. 业务参数 + 设备指纹 → JSON
  2. RSA 公钥加密 JSON → base64
  3. 包成 { "params": "<base64>" }
  4. URL 走 buildSignedUrl(endpoint)（含 AK/SK 签名）
  5. POST
  6. 响应 { "params": "<base64>" } → RSA 私钥解密 → JSON
  7. 业务 envelope: { errorCode, errorMessage, body }
     errorCode == '200' 时 body 为成功载荷
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

import httpx

from .const import (
    APP_VERSION_NAME,
    DEFAULT_BASE_URL,
    DEFAULT_USER_AGENT,
    ECLOUD_ACCESS_KEY,
    ECLOUD_SECRET_KEY,
    EP,
    OP_OPERATE_MAP,
    OP_TYPES,
    RSA_ENVELOPE_KEY,
    OpType,
)
from .crypto import decrypt_to_json, encrypt_json, get_device_info
from .sign import build_signed_url

log = logging.getLogger("pcas.client")


def _iso_utc_now() -> str:
    """RFC3339/ISO8601 UTC 时间戳（毫秒精度），对齐 Node 端 new Date().toISOString() 格式。"""
    now = datetime.now(timezone.utc)
    return f"{now.strftime('%Y-%m-%dT%H:%M:%S')}.{now.microsecond // 1000:03d}Z"


@dataclass
class SessionContext:
    """账号级会话上下文 — 对齐 Node 项目 commonParams。

    每个账号一份。machineId 在 connectList 里区分多桌面（同 Node 项目模型）。
    """
    login_uuid: str = ""           # 客户端生成（UUID v4）— pcas_app loginUuid
    session_id: str = ""           # 客户端生成（种子扰动）— pcas_app sessionId
    client_login_uid: str = ""     # 同 login_uuid（Node 项目重复字段，保持对齐）
    client_connect_id: str = ""    # 同 session_id（Node 项目重复字段，保持对齐）
    login_uid: str = ""            # /login/recordDeviceInfo 返回的服务端 loginUid
    session_started_at: str = ""   # ISO 时间戳，cem stream 握手或 connect.result 上报时记录
    session_connect_ok: bool = False
    session_connect_error: str = ""


class PCASError(Exception):
    def __init__(self, code: str | int, msg: str, raw: Any = None):
        super().__init__(f"[{code}] {msg}")
        self.code = str(code)
        self.msg = msg
        self.raw = raw


def _gen_login_uuid() -> str:
    return str(uuid.uuid4())


def _gen_session_id(seed: str) -> str:
    """对应 Node generateSessionId：种子扰动的 UUID v4-like。"""
    base = 0
    for ch in seed:
        base = ord(ch) + ((base << 5) - base)
    base = (0x0FFFFFFF & base) % 16

    import random
    out = []
    template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    for c in template:
        if c in ("x", "y"):
            v = (base + 16 * random.random()) % 16
            v = int(v)
            if c == "y":
                v = (3 & v) | 8
            out.append(format(v, "x"))
        else:
            out.append(c)
    return "".join(out)


def create_official_session_context(machine_id: str) -> dict[str, str]:
    """对应 Node createOfficialSessionContext。"""
    login_uuid = _gen_login_uuid()
    session_id = _gen_session_id(f"{machine_id or ''}{int(time.time() * 1000)}")
    return {
        "loginUuid": login_uuid,
        "sessionId": session_id,
        "clientLoginUid": login_uuid,
        "clientConnectId": session_id,
    }


def make_session_context(seed: str = "") -> SessionContext:
    """构造一个 SessionContext（loginUuid / sessionId / clientLoginUid / clientConnectId）。

    Args:
        seed: 用作 sessionId 生成种子；通常传 machineId（多机器场景）或空字符串。
    """
    raw = create_official_session_context(seed)
    return SessionContext(
        login_uuid=raw["loginUuid"],
        session_id=raw["sessionId"],
        client_login_uid=raw["clientLoginUid"],
        client_connect_id=raw["clientConnectId"],
    )


def pick_connect_target(machines: list[dict]) -> dict | None:
    for m in machines:
        s = str(m.get("status", "")).lower()
        if "available" in s or "running" in s:
            return m
    return None


def is_running(machines: list[dict]) -> bool:
    if not machines:
        return False
    for m in machines:
        s = str(m.get("status", "")).lower()
        if any(k in s for k in ("running", "active", "connected", "on", "available")):
            return True
    return False


async def call_with_auto_refresh(
    client: "PCASClient",
    op: "Callable[[], Awaitable[Any]]",
    *,
    on_refresh: "Callable[[], Awaitable[None] | None] | None" = None,
) -> Any:
    """跑一次 op；如果是 token 失效错误，自动 refresh 一次后再跑一次。

    用于把"业务调用 → PCASError → is_auth_failure → refresh_token → 重试"
    的几处复制粘贴收敛到一处。注意：

    - 只重试一次。第二次仍失败的异常向上抛。
    - 非 auth 失败的 PCASError 不重试，直接 raise（语义保持原样）。
    - on_refresh 在 refresh 成功后、retry 前调用，用于把新 token 持久化到 db。
      可以同步或异步。

    更复杂的"ticket 失败→密码降级"语义不在本 helper 范围（见
    keepalive._refresh_account_token）。
    """
    try:
        return await op()
    except PCASError as e:
        if not PCASClient.is_auth_failure(e):
            raise
    # 走到这里说明捕获了一次 auth failure → refresh + retry
    await client.refresh_token()
    if on_refresh is not None:
        rv = on_refresh()
        if rv is not None and hasattr(rv, "__await__"):
            await rv
    return await op()


class PCASClient:
    """单个移动云账号的 API 会话。"""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        debug_dump: bool = False,
        access_key: str = ECLOUD_ACCESS_KEY,
        secret_key: str = ECLOUD_SECRET_KEY,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.debug_dump = debug_dump
        self.access_key = access_key
        self.secret_key = secret_key
        self.http = httpx.AsyncClient(
            timeout=timeout,
            headers={
                "User-Agent": DEFAULT_USER_AGENT,
                "Content-Type": "application/json",
            },
            follow_redirects=False,
            verify=True,
        )
        # 会话状态
        self.account_name: str = ""        # 登录用的用户名（手机号或别名）
        self.access_ticket: str = ""
        self.access_token: str = ""
        self.user_name: str = ""

    async def close(self) -> None:
        await self.http.aclose()

    async def __aenter__(self) -> "PCASClient":
        return self

    async def __aexit__(self, *_a) -> None:
        await self.close()

    # ---------------- 低层 POST ----------------

    async def _post(self, endpoint: str, params: dict[str, Any]) -> dict[str, Any]:
        """发起一次完整加密签名 POST。

        Args:
            endpoint: '/login/verify' etc.
            params: 业务参数（会自动 merge 设备指纹）
        Returns:
            解密后的 envelope dict: { errorCode, errorMessage, body, ... }
        """
        # 1. 注入设备指纹
        device = get_device_info(self.account_name or "")
        full_params = {**device, **params}

        # 2. 加密 + 签名 URL
        url = build_signed_url(
            endpoint, self.base_url, self.access_key, self.secret_key
        )
        cipher = encrypt_json(full_params)
        body = json.dumps({RSA_ENVELOPE_KEY: cipher}, separators=(",", ":"))

        if self.debug_dump:
            log.info("→ POST %s plain=%s",
                     endpoint, json.dumps(params, ensure_ascii=False)[:300])

        # 3. 发送
        try:
            resp = await self.http.post(url, content=body)
        except httpx.HTTPError as e:
            raise PCASError("net", f"transport error: {type(e).__name__}: {e!r}")

        if resp.status_code != 200:
            raise PCASError(
                resp.status_code,
                f"HTTP {resp.status_code}: {resp.text[:200]!r}",
            )

        # 4. 解密响应
        try:
            outer = resp.json()
        except Exception:
            raise PCASError(
                resp.status_code,
                f"non-json response: {resp.text[:200]!r}",
            )

        if not isinstance(outer, dict) or RSA_ENVELOPE_KEY not in outer:
            raise PCASError(
                resp.status_code,
                f"envelope missing '{RSA_ENVELOPE_KEY}': {resp.text[:200]!r}",
            )

        try:
            decrypted = decrypt_to_json(outer[RSA_ENVELOPE_KEY])
        except Exception as e:
            raise PCASError(resp.status_code, f"decrypt failed: {e}")

        if self.debug_dump:
            log.info("← %s envelope=%s",
                     endpoint, json.dumps(decrypted, ensure_ascii=False)[:400])

        return decrypted

    async def _post_ok(self, endpoint: str, params: dict[str, Any]) -> dict[str, Any]:
        """_post 的便捷版本：errorCode != '200' 时抛 PCASError。"""
        resp = await self._post(endpoint, params)
        code = str(resp.get("errorCode", ""))
        if code != "200":
            raise PCASError(
                code,
                resp.get("errorMessage", "unknown"),
                raw=resp,
            )
        return resp

    # ---------------- 登录 ----------------

    async def login_by_password(
        self, username: str, password: str
    ) -> dict[str, Any]:
        """密码登录两步：verify → verifyAccessTicket。

        Returns:
            { 'accessTicket', 'accessToken', 'userName', 'machines' (list) }
        """
        self.account_name = username
        verify = await self._post(EP.LOGIN_VERIFY, {
            "username": username,
            "password": password,
            "clientNeedTwoFactor": True,
        })

        code = str(verify.get("errorCode", ""))
        err_msg = str(verify.get("errorMessage", ""))
        if code == "UntrustedDevice" or "可信认证" in err_msg or "可信设备" in err_msg:
            return {
                "status": "challenge_required",
                "challengeType": "device",
                "errorCode": code,
                "errorMessage": err_msg,
                "mobile": (verify.get("body") or {}).get("mobile", ""),
                "loginUserName": username,
            }
        if code != "200" or not verify.get("body"):
            raise PCASError(code, err_msg or "账号或密码错误", raw=verify)

        access_ticket = verify["body"].get("accessTicket", "")
        self.access_ticket = access_ticket
        login_state = await self._complete_login(access_ticket)
        return {
            "status": "success",
            "accessTicket": access_ticket,
            **login_state,
        }

    async def send_sms(self, mobile: str, code_type: str = "login") -> dict[str, Any]:
        """发送短信验证码。codeType 可选值常见有 'login' / 'trustDevice'。"""
        if not self.account_name:
            self.account_name = mobile
        return await self._post_ok(EP.LOGIN_SEND_SMS, {
            "mobile": mobile,
            "codeType": code_type,
        })

    async def login_by_sms(self, mobile: str, code: str) -> dict[str, Any]:
        self.account_name = mobile
        verify = await self._post_ok(EP.LOGIN_VERIFY_SMS, {
            "mobile": mobile,
            "verificationCode": code,
            "isNeedTemporaryDeviceSelection": True,
        })
        body = verify.get("body") or {}
        access_ticket = body.get("accessTicket", "")
        if not access_ticket:
            raise PCASError("200", "未拿到 accessTicket", raw=verify)

        # 设备未受信 — 让上层决定 trust 还是 temporary
        if body.get("isCurrentDeviceTrustBeforeLogin") is False:
            return {
                "status": "challenge_required",
                "challengeType": "chooseDeviceType",
                "accessTicket": access_ticket,
                "mobile": mobile,
            }
        self.access_ticket = access_ticket
        login_state = await self._complete_login(access_ticket)
        return {
            "status": "success",
            "accessTicket": access_ticket,
            **login_state,
        }

    async def trust_or_temporary_device(
        self, access_ticket: str, is_temporary: bool
    ) -> dict[str, Any]:
        """完成「短信登录 → 选择设备类型」challenge。

        Args:
            access_ticket: login_by_sms 返回的 challenge accessTicket
            is_temporary: True=临时使用（不信任设备）; False=信任此设备（永久）
        """
        await self._post_ok(EP.LOGIN_TRUST_OR_TEMP, {
            "accessTicket": access_ticket,
            "isTemporary": 1 if is_temporary else 0,
        })
        self.access_ticket = access_ticket
        login_state = await self._complete_login(access_ticket)
        return {
            "status": "success",
            "accessTicket": access_ticket,
            **login_state,
        }

    async def _complete_login(self, access_ticket: str) -> dict[str, Any]:
        """用 accessTicket 换 accessToken 并拉机器列表。"""
        ticket_resp = await self._post_ok(EP.LOGIN_VERIFY_ACCESS_TICKET, {
            "accessTicket": access_ticket,
        })
        body = ticket_resp.get("body") or {}
        access_token = body.get("accessToken", "")
        if not access_token:
            raise PCASError("200", "未拿到 accessToken", raw=ticket_resp)
        self.access_token = access_token
        self.access_ticket = access_ticket
        self.user_name = body.get("userName", self.account_name)

        # 拉机器列表
        machines = await self.get_device_info_list()
        return {
            "accessToken": access_token,
            "userName": self.user_name,
            "machines": machines,
        }

    async def refresh_token(self) -> dict[str, Any]:
        """被动 token 刷新：用已保存的 accessTicket 换新 accessToken。"""
        if not self.access_ticket:
            raise PCASError("no_ticket", "缺少 accessTicket，需要重新登录")
        return await self._complete_login(self.access_ticket)

    # ---------------- 机器查询 ----------------

    async def get_device_info_list(self) -> list[dict[str, Any]]:
        """获取所有机器（带状态）。"""
        resp = await self._post_ok(EP.USER_GET_DEVICE_INFO, {
            "accessToken": self.access_token,
            "companyCode": "H3C",
            "allCompany": True,
            "version": "1.0.0",
        })
        body = resp.get("body") or {}
        raw_list = (
            body.get("machineList")
            or body.get("desktopList")
            or body.get("list")
            or []
        )
        machines = [_map_remote_machine(m) for m in raw_list]
        # 富化状态
        if machines:
            await self._enrich_status(machines)
        return machines

    async def _enrich_status(self, machines: list[dict[str, Any]]) -> None:
        instance_ids = [m.get("instanceId") for m in machines if m.get("instanceId")]
        if not instance_ids:
            return
        try:
            resp = await self._post(EP.USER_GET_DESKTOP_STATUS, {
                "accessToken": self.access_token,
                "instanceIdList": instance_ids,
            })
            if str(resp.get("errorCode")) != "200":
                return
            body = resp.get("body") or {}
            status_list = (
                body.get("statusList")
                or body.get("desktopStatusList")
                or body.get("machineStatusList")
                or []
            )
            for st in status_list:
                for m in machines:
                    if m.get("instanceId") == st.get("instanceId") or m.get("machineId") == st.get("machineId"):
                        m["status"] = st.get("status") or st.get("machineStatus") or st.get("resourceStatus") or m["status"]
                        m["connectStatus"] = st.get("connectStatus") or st.get("loginStatus") or m.get("connectStatus", "")
                        m["resourcePoolUid"] = st.get("resourcePoolUid") or m.get("resourcePoolUid", "")
        except PCASError as e:
            log.warning("get_desktop_status enrich 失败: %s", e)

    async def get_desktop_status(self, instance_ids: list[str]) -> Any:
        return await self._post(EP.USER_GET_DESKTOP_STATUS, {
            "accessToken": self.access_token,
            "instanceIdList": instance_ids,
        })

    # ---------------- 资源操作 ----------------

    async def operate_machine(
        self,
        machine_id: str,
        op: str,
        *,
        machine_name: str = "",
        resource_pool_uid: str = "",
    ) -> Any:
        """电源操作。

        ⚠️ 服务端真实契约（来自 HAR 解密 + Node 参考实现）：
          - 字段名是 `operate`（不是 `operType`）。
          - 字段值要走映射：start → available, stop → shutdown, restart → restart。
          - 必填：`machineId` / `machineName` / `operate` / `accessToken`。
          - `resourcePoolUid` 在成功请求里**不传**，服务端响应中是 null。
            （只在 Node 实现的多桌面 pool mapping 场景需要，本工具单桌面默认不传）

        Args:
            machine_id: 机器 id（UUID 风格 = mapped machineId = instanceId）
            op: OP_TYPES 中的前端术语（start / shutdown / restart ...）
            machine_name: 机器显示名
            resource_pool_uid: 可选；非空才下发
        """
        if op not in OP_TYPES:
            raise ValueError(f"unknown op {op}; allowed: {list(OP_TYPES)}")
        body: dict[str, Any] = {
            "accessToken": self.access_token,
            "machineId": machine_id,
            "machineName": machine_name,
            "operate": OP_OPERATE_MAP.get(op, op),
        }
        if resource_pool_uid:
            body["resourcePoolUid"] = resource_pool_uid
        return await self._post_ok(EP.RESOURCE_OPERATE, body)

    async def start_machine(
        self,
        machine_id: str,
        *,
        machine_name: str = "",
        resource_pool_uid: str = "",
    ) -> Any:
        return await self.operate_machine(
            machine_id, OpType.START,
            machine_name=machine_name, resource_pool_uid=resource_pool_uid,
        )

    async def shutdown_machine(
        self,
        machine_id: str,
        *,
        machine_name: str = "",
        resource_pool_uid: str = "",
    ) -> Any:
        return await self.operate_machine(
            machine_id, OpType.SHUTDOWN,
            machine_name=machine_name, resource_pool_uid=resource_pool_uid,
        )

    async def restart_machine(
        self,
        machine_id: str,
        *,
        machine_name: str = "",
        resource_pool_uid: str = "",
    ) -> Any:
        return await self.operate_machine(
            machine_id, OpType.RESTART,
            machine_name=machine_name, resource_pool_uid=resource_pool_uid,
        )

    async def change_machine_name(self, machine_id: str, name: str) -> Any:
        return await self._post_ok(EP.USER_CHANGE_MACHINE_NAME, {
            "accessToken": self.access_token,
            "machineId": machine_id,
            "machineName": name,
        })

    # ---------------- 会话建立（保活前置） ----------------

    async def record_device_info(self, client_login_uid: str) -> dict[str, Any]:
        """会话开始前登记设备。"""
        return await self._post_ok(EP.LOGIN_RECORD_DEVICE, {
            "accessToken": self.access_token,
            "clientLoginUid": client_login_uid,
        })

    async def machine_connect(
        self,
        machine_id: str,
        machine_name: str,
        client_login_uid: str,
        client_connect_id: str,
    ) -> dict[str, Any]:
        return await self._post_ok(EP.SESSION_MACHINE_CONNECT, {
            "ticket": self.access_ticket,
            "accessToken": self.access_token,
            "machineId": machine_id,
            "machineName": machine_name,
            "status": "success",
            "flag": True,
            "clientConnectId": client_connect_id,
            "clientLoginUid": client_login_uid,
        })

    async def push_connect_event_data(
        self,
        machine_id: str,
        client_connect_id: str,
        client_login_uid: str,
        event_type: str = "desktop_connect",
        success: bool = True,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """上报"连接事件"。配合 machine_connect 使用，告诉服务端"用户尝试/完成桌面连接"。

        event_type 取值参考 PCAS_App 真实上报：
          - "desktop_connect"：建立桌面连接
          - "desktop_disconnect"：断开
          - "tunnel_open" / "tunnel_close"：USB/SPICE 隧道事件
        """
        body: dict[str, Any] = {
            "accessToken": self.access_token,
            "machineId": machine_id,
            "clientConnectId": client_connect_id,
            "clientLoginUid": client_login_uid,
            "eventType": event_type,
            "eventTime": int(time.time() * 1000),
            "success": success,
        }
        if extra:
            body.update(extra)
        return await self._post(EP.MACHINE_PUSH_CONNECT_EVENT, body)

    async def push_connect_event_cloud(
        self,
        machine: dict[str, Any],
        session_ctx: "SessionContext",
        event_type: str = "connect.result",
        *,
        connect_method: str = "manual",
        disconnect_method: str = "",
        error_code: str = "",
        error_msg: str = "",
    ) -> dict[str, Any]:
        """CloudEvents 1.0 格式的 pushConnectEventData 上报（对齐 Node 项目 buildConnectEventParams）。

        服务端把这个事件当成"H3C 桌面客户端"真实建连/断开的上报。Node 项目实测：
        machineConnect 拿到 connectId 后，每个 keepalive 周期再发一次 connect.result，
        服务端就把后续 REST 心跳视为"用户已建立桌面会话"。

        Args:
            machine: 机器字典（至少含 machineId/machineName/companyCode）
            session_ctx: 账号级会话上下文（含 loginUuid/sessionId/clientConnectId 等）
            event_type: "connect.result" / "connect.failure"
            connect_method: 默认 "manual"（手动点击连接）
            disconnect_method: connect.failure 时的断开方式（"error"/"user"）
            error_code: connect.failure 时的错误码
            error_msg: connect.failure 时的错误信息

        Returns:
            服务端响应 envelope（errorCode != '200' 时由 _post 返回但不抛异常）
        """
        device = get_device_info(self.account_name or "")
        machine_id = (
            machine.get("connectMachineId")
            or machine.get("instanceId")
            or machine.get("machineId")
            or ""
        )
        connect_id = machine.get("connectId") or ""
        company_code = machine.get("companyCode") or machine.get("originCompanyCode") or ""
        resource_pool_uid = machine.get("resourcePoolUid") or ""

        # connect.result 必须有真实 connectId（Node 项目硬约束）
        if event_type == "connect.result" and not connect_id:
            raise PCASError("no_connect_id",
                            "connect.result 需要 connectId，但 machineConnect 未成功")

        default_disconnect = "" if event_type == "connect.result" else (disconnect_method or "")
        default_err_code = "" if event_type == "connect.failure" else "0"

        payload = {
            "accessToken": self.access_token,
            "id": session_ctx.client_connect_id or str(uuid.uuid4()),
            "source": "common",
            "specversion": "1.0",
            "type": event_type,
            "datacontenttype": "application/json",
            "time": _iso_utc_now(),
            "data": {
                "machineId": machine_id,
                "sessionId": session_ctx.session_id,
                "loginId": session_ctx.login_uuid,
                "clientConnectId": session_ctx.client_connect_id,
                "connectId": connect_id,
                "companyCode": company_code,
                "resourcePoolUid": resource_pool_uid,
                "startTime": session_ctx.session_started_at or _iso_utc_now(),
                "connectMethod": connect_method,
                "disconnectMethod": default_disconnect,
                "errorCode": error_code or default_err_code,
                "errorMsg": error_msg,
                "clientType": device.get("clientType", "pc_windows"),
                "clientVersion": device.get("clientVersion", APP_VERSION_NAME),
                "clientIp": device.get("ipAddress", ""),
                "clientIpLocation": "",
                "clientNetworkType": "",
                "deviceId": device.get("deviceUid", ""),
                "deviceType": device.get("deviceType", "pc"),
                "deviceSource": "common",
                "deviceOSType": device.get("clientType", "pc_windows"),
                "deviceOSVersion": (
                    device.get("operatingVersion")
                    or device.get("deviceSystem")
                    or "Windows 10"
                ),
                "sdkVersion": device.get("clientVersion", APP_VERSION_NAME),
            },
        }
        return await self._post(EP.MACHINE_PUSH_CONNECT_EVENT, payload)

    async def establish_session(
        self,
        machine: dict[str, Any],
        session_ctx: "SessionContext",
    ) -> dict[str, Any]:
        """对齐 Node 项目 establishSessionConnection：recordDeviceInfo + machineConnect。

        成功后会把 connectId 写入 machine 字典（in-place 更新），并填充 session_ctx
        的 login_uid 字段。

        Args:
            machine: 一台 running 机器的字典（必须含 machineId/machineName）
            session_ctx: 账号级会话上下文（会被 in-place 更新 login_uid 字段）

        Returns:
            { "loginUid": str, "connectId": str, "ok": bool, "error": str }
            ok=False 时 connectId 为空但 loginUid 可能仍有效
        """
        machine_id = (
            machine.get("connectMachineId")
            or machine.get("instanceId")
            or machine.get("machineId")
            or ""
        )
        machine_name = machine.get("machineName") or ""

        # Step 1: recordDeviceInfo 拿服务端确认的 loginUid
        try:
            rec = await self._post_ok(EP.LOGIN_RECORD_DEVICE, {
                "accessToken": self.access_token,
                "clientLoginUid": session_ctx.client_login_uid,
            })
            login_uid = (rec.get("body") or {}).get("loginUid", "")
            if not login_uid:
                return {
                    "loginUid": "",
                    "connectId": "",
                    "ok": False,
                    "error": "recordDeviceInfo 未返回 loginUid",
                }
            session_ctx.login_uid = login_uid
        except PCASError as e:
            return {
                "loginUid": "",
                "connectId": "",
                "ok": False,
                "error": f"recordDeviceInfo 失败: {e.msg}",
            }

        # Step 2: machineConnect 拿 connectId（关键！）
        try:
            conn = await self._post_ok(EP.SESSION_MACHINE_CONNECT, {
                "ticket": self.access_ticket,
                "accessToken": self.access_token,
                "machineId": machine_id,
                "machineName": machine_name,
                "status": "success",
                "flag": True,
                "clientConnectId": session_ctx.client_connect_id,
                "clientLoginUid": session_ctx.client_login_uid,
            })
            connect_id = (conn.get("body") or {}).get("connectId", "")
            if not connect_id:
                return {
                    "loginUid": login_uid,
                    "connectId": "",
                    "ok": False,
                    "error": "machineConnect 未返回 connectId",
                }
            machine["connectId"] = connect_id
            return {
                "loginUid": login_uid,
                "connectId": connect_id,
                "ok": True,
                "error": "",
            }
        except PCASError as e:
            return {
                "loginUid": login_uid,
                "connectId": "",
                "ok": False,
                "error": f"machineConnect 失败: {e.msg}",
            }

    async def get_sys_config(self, config_type: str) -> dict[str, Any]:
        """按 key 拉单个系统配置项（如 DEVICE_PERFORMANCE_PERIOD）。

        ⚠️ 注意：这个接口**不返回** cem stream host/port。
        服务端必填 `type` 字段（配置项 key 名），缺失会报 `9999100 type 不能为空`。

        已知 config_type 取值（来自 blutter 反编）：
          - "DEVICE_PERFORMANCE_PERIOD"
          - "DEVICE_PERFORMANCE_BATCH_PERIOD"
          - "DEVICE_PERFORMANCE_BATCH_INTERVAL"
        """
        return await self._post_ok(EP.CLIENT_GET_SYS_CONFIG, {
            "accessToken": self.access_token,
            "type": config_type,
        })

    # ---------------- 保活 4 路任务 ----------------

    async def task_get_desktop_status(self, instance_ids: list[str]) -> Any:
        """保活任务 1：5 分钟一次。"""
        return await self._post(EP.USER_GET_DESKTOP_STATUS, {
            "accessToken": self.access_token,
            "instanceIdList": instance_ids,
        })

    async def task_machine_performance_batch(self, machine_id: str) -> Any:
        """保活任务 2：5 分钟一次。"""
        now_ms = int(time.time() * 1000)
        params = []
        for i in range(9):
            sample_time = now_ms - (9 - i) * 30000
            params.append({
                "loss": {"time": sample_time, "value": 20 + (i % 5) * 2},
                "netDelay": {"time": sample_time, "value": 22 + (i % 3)},
                "netSpeed": {"time": sample_time + 1200, "value": 0},
                "shake": {"time": sample_time, "value": i % 4},
                "connAddrInfo": {"localAddr": "", "remoteAddr": ""},
            })
        return await self._post(EP.MACHINE_PERF_BATCH, {
            "accessToken": self.access_token,
            "machineId": machine_id,
            "params": params,
        })

    async def task_session_heartbeat(
        self,
        login_uid: str,
        connect_list: list[dict[str, Any]],
        login_status: str = "0",
    ) -> Any:
        """保活任务 3（核心心跳）：5 分钟一次 /session/updateSessionStatus。"""
        return await self._post(EP.SESSION_UPDATE_STATUS, {
            "loginUid": login_uid,
            "loginStatus": login_status,
            "connectList": connect_list,
        })

    async def task_device_performance(
        self,
        screen_resolution: str = "1024x768",
        net_card_base: int = 167200,
    ) -> Any:
        """保活任务 4：30 分钟一次 /device/performance/batch。"""
        device = get_device_info(self.account_name or "")
        device_uid = str(device.get("deviceUid", "")).lower()
        device_model = device.get("deviceModel", "Standard PC (i440FX + PIIX, 1996)")
        now_ms = int(time.time() * 1000)
        dtos = []
        for i in range(6):
            dtos.append({
                "accessToken": self.access_token,
                "deviceUid": device_uid,
                "deviceModel": device_model,
                "countTime": now_ms - (6 - i) * 300000,
                "deviceParams": {
                    "cpuUsage": {"value": f"{20 + i * 1.1:.2f}"},
                    "memUsage": {"value": f"{22 + i * 0.7:.2f}"},
                    "diskUsage": {"value": f"{device.get('diskUsed', 22):.2f}"},
                    "screenResolution": {"value": screen_resolution},
                    "timedelay": {"value": str(15 if i == 0 else max(0, 8 - i))},
                    "shake": {"value": str(15 if i == 0 else max(0, 6 - i))},
                    "netCard": {"value": str(net_card_base + i * 13)},
                },
            })
        return await self._post(EP.DEVICE_PERF_BATCH, {
            "accessToken": self.access_token,
            "devicePerformReqDtoList": dtos,
        })

    # ---------------- 工具 ----------------

    @staticmethod
    def is_auth_failure(err: Exception) -> bool:
        """判断异常是否表示 token 失效，需要刷新。"""
        if not isinstance(err, PCASError):
            return False
        code = err.code.lower()
        msg = err.msg.lower()
        if code == "401" or "http 401" in msg:
            return True
        keywords = (
            "token", "ticket", "accesstoken", "accessticket", "令牌",
            "unauthorized", "not login", "login expired",
            "invalid token", "invalid ticket", "expired token",
            "登录失效", "登录过期", "未登录", "认证失败", "鉴权失败",
            "token失效", "ticket失效",
        )
        return any(kw in msg for kw in keywords)


def _map_remote_machine(m: dict) -> dict[str, Any]:
    """把服务端 raw 机器数据规范化（参考 mapRemoteMachine）。"""
    cp = m.get("customParams") or {}
    machine_id = m.get("machineId") or m.get("instanceId") or ""
    instance_id = m.get("instanceId") or m.get("machineId") or ""
    return {
        "machineId": machine_id,
        "instanceId": instance_id,
        "connectMachineId": instance_id or machine_id,
        "machineName": m.get("machineName") or m.get("name") or "",
        "status": m.get("status") or m.get("machineStatus") or m.get("resourceStatus") or "",
        "region": m.get("poolName") or m.get("region") or m.get("regionName") or "",
        "productType": m.get("resourceVersion") or m.get("productType") or m.get("productName") or "",
        "expireTime": m.get("expireTime") or m.get("endTime") or "",
        "cpu": cp.get("vcpu") or cp.get("cpu") or m.get("cpu") or "",
        "memory": cp.get("mem") or cp.get("memory") or m.get("memory") or "",
        "systemDisk": cp.get("sysDiskSize") or m.get("systemDisk") or "",
        "dataDisk": cp.get("extraDataDiskSize") or m.get("dataDisk") or "",
        "os": cp.get("osVersion") or m.get("os") or m.get("operateSystem") or "",
        "ip": m.get("machineAddress") or m.get("ip") or m.get("privateIp") or "",
        "resourcePoolUid": m.get("resourcePoolUid") or "",
        "companyCode": m.get("companyCode") or m.get("originCompanyCode") or "ZTE",
        "originCompanyCode": m.get("originCompanyCode") or m.get("companyCode") or "",
        # CMSS 桌面层需要的字段（ZTEC 握手用）
        "adUser": m.get("adUser") or "",
        "adPassword": m.get("adPassword") or "",
        "customLoginParams": m.get("customLoginParams") or "",
        "customParams": m.get("customParams") if isinstance(m.get("customParams"), (str, dict)) else cp,
        "customPrivateLoginParams": m.get("customPrivateLoginParams") or "",
    }


def build_connect_list_for_keepalive(machines: list[dict]) -> list[dict[str, Any]]:
    """从 machines 列表构造保活用的 connectList。"""
    result = []
    for m in machines:
        if not m.get("connectId"):
            continue
        result.append({
            "connectId": m["connectId"],
            "connectStatus": True,
            "machineId": m.get("connectMachineId") or m.get("machineId"),
            "companyCode": m.get("companyCode") or "ZTE",
        })
    return result
