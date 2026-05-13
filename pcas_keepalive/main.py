"""FastAPI 入口 — 平台鉴权 + 移动云账号管理 + 24h 保活。

鉴权设计（两层）：
  L1: 平台管理员（admin_users） — 进入 Web 程序的密码门
      首次访问强制 /setup 设置；之后每次访问 /admin/login
  L2: 移动云账号（accounts）   — 管理员登录后添加，由平台账号自己管理
"""
from __future__ import annotations

import contextlib
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

import db
from config import get_settings
from keepalive import get_scheduler
from pcas import OP_TYPES, PCASClient, PCASError
from pcas.crypto import aes_open, aes_seal

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
)
log = logging.getLogger("pcas.main")


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    db.init(settings.db_path)
    sched = get_scheduler()
    await sched.start()
    log.info("PCAS Keepalive ready — http://%s:%d", settings.host, settings.port)
    yield
    await sched.shutdown()


settings = get_settings()
app = FastAPI(title="PCAS Keepalive", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    https_only=False,
    same_site="lax",
)

BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


def _ts_filter(v):
    if not v:
        return "-"
    try:
        return time.strftime("%m-%d %H:%M:%S", time.localtime(int(v)))
    except Exception:
        return str(v)


templates.env.filters["timestamp"] = _ts_filter


# ---------- 鉴权依赖 ----------

def require_admin(request: Request) -> int:
    """所有受保护路由必须经过这个依赖。

    - admin_users 为空 → 401 + "未设置管理员"（前端引导跳 /setup）
    - 未登录 → 401（前端引导跳 /admin/login）
    - 已登录 → 返回 admin_user_id
    """
    if not db.has_admin():
        raise HTTPException(401, "尚未设置管理员，请先访问 /setup")
    aid = request.session.get("admin_user_id")
    if not aid:
        raise HTTPException(401, "请先登录管理员账号")
    if not db.get_admin(aid):
        request.session.clear()
        raise HTTPException(401, "管理员账号已失效")
    return aid


def current_account_id(request: Request) -> int:
    """当前选中的移动云账号 id（需要先过 require_admin 守卫）。"""
    cid = request.session.get("account_id")
    if not cid:
        raise HTTPException(400, "还未选择移动云账号")
    return cid


def _make_client_for(acct: dict) -> PCASClient:
    c = PCASClient(
        base_url=settings.pcas_base_url,
        timeout=settings.http_timeout,
        debug_dump=settings.debug_dump_payload,
    )
    c.account_name = acct["mobile"]
    c.access_token = acct.get("cem_token") or ""
    c.access_ticket = acct.get("access_ticket") or ""
    return c


# ---------- 单页（含 setup / admin_login / dashboard 三态路由） ----------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # 未设置管理员 → 跳 setup
    if not db.has_admin():
        return RedirectResponse("/setup", status_code=303)
    # 未登录管理员 → 跳登录页
    aid = request.session.get("admin_user_id")
    if not aid or not db.get_admin(aid):
        request.session.clear()
        return RedirectResponse("/admin/login", status_code=303)
    admin = db.get_admin(aid)

    accounts = db.list_accounts()
    # 没账号 → 添加账号页
    if not accounts:
        return templates.TemplateResponse(
            request, "login.html",
            {"admin": admin, "accounts": accounts},
        )

    # 默认总览页
    return RedirectResponse("/overview", status_code=303)


@app.get("/overview", response_class=HTMLResponse)
async def overview_page(request: Request):
    if not db.has_admin():
        return RedirectResponse("/setup", status_code=303)
    aid = request.session.get("admin_user_id")
    if not aid or not db.get_admin(aid):
        return RedirectResponse("/admin/login", status_code=303)
    admin = db.get_admin(aid)
    accounts = db.list_accounts()
    if not accounts:
        return RedirectResponse("/accounts", status_code=303)

    # 汇总信息
    sched = get_scheduler()
    rows = []
    total_machines = 0
    total_running = 0
    total_ka_running = 0
    total_ka_success = 0
    total_ka_fail = 0
    for a in accounts:
        machines = db.list_machines(a["id"])
        ka = await sched.status_for(a["id"])
        running_count = sum(
            1 for m in machines if (m.get("status") or "").lower() in
            ("running", "active", "available", "on")
        )
        total_machines += len(machines)
        total_running += running_count
        if ka.get("running"):
            total_ka_running += 1
            for s in ka.get("tasks", {}).values():
                total_ka_success += s.get("success", 0)
                total_ka_fail += s.get("fail", 0)
        rows.append({
            "account": a,
            "machine_count": len(machines),
            "running_count": running_count,
            "ka_running": ka.get("running", False),
            "ka_started_at": ka.get("started_at"),
        })

    return templates.TemplateResponse(
        request, "overview.html",
        {
            "admin": admin,
            "rows": rows,
            "totals": {
                "accounts": len(accounts),
                "machines": total_machines,
                "running": total_running,
                "ka_running": total_ka_running,
                "ka_success": total_ka_success,
                "ka_fail": total_ka_fail,
            },
            "recent_logs": db.list_logs(None, 10),
        },
    )


@app.get("/accounts", response_class=HTMLResponse)
async def accounts_page(request: Request):
    """添加 / 切换移动云账号。"""
    if not db.has_admin():
        return RedirectResponse("/setup", status_code=303)
    aid = request.session.get("admin_user_id")
    if not aid or not db.get_admin(aid):
        return RedirectResponse("/admin/login", status_code=303)
    return templates.TemplateResponse(
        request, "login.html",
        {"admin": db.get_admin(aid), "accounts": db.list_accounts()},
    )


@app.get("/account/{account_id}", response_class=HTMLResponse)
async def account_detail(request: Request, account_id: int):
    """指定账号的控制台。"""
    if not db.has_admin():
        return RedirectResponse("/setup", status_code=303)
    aid = request.session.get("admin_user_id")
    if not aid or not db.get_admin(aid):
        return RedirectResponse("/admin/login", status_code=303)
    acct = db.get_account(account_id)
    if not acct:
        return RedirectResponse("/overview", status_code=303)
    request.session["account_id"] = account_id
    sched = get_scheduler()
    ka_status = await sched.status_for(account_id)
    return templates.TemplateResponse(
        request, "dashboard.html",
        {
            "admin": db.get_admin(aid),
            "account": acct,
            "all_accounts": db.list_accounts(),
            "machines": db.list_machines(account_id),
            "logs": db.list_logs(account_id, 30),
            "ka_status": ka_status,
            "settings": settings,
        },
    )


# ---------- 管理员设置 / 登录 / 登出 ----------

@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    if db.has_admin():
        # 已设置过，禁止再次访问
        return RedirectResponse("/admin/login", status_code=303)
    return templates.TemplateResponse(request, "setup.html")


@app.post("/setup")
async def setup_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
):
    if db.has_admin():
        return JSONResponse({"ok": False, "msg": "管理员已存在，无法重复设置"}, status_code=400)
    if password != password_confirm:
        return JSONResponse({"ok": False, "msg": "两次密码输入不一致"}, status_code=400)
    try:
        admin_id = db.create_admin(username, password)
    except ValueError as e:
        return JSONResponse({"ok": False, "msg": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"ok": False, "msg": f"设置失败：{e}"}, status_code=400)
    # 自动登录
    request.session["admin_user_id"] = admin_id
    log.info("admin created: id=%d username=%s", admin_id, username)
    return {"ok": True}


@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    if not db.has_admin():
        return RedirectResponse("/setup", status_code=303)
    if request.session.get("admin_user_id"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "admin_login.html")


@app.post("/admin/login")
async def admin_login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if not db.has_admin():
        return JSONResponse({"ok": False, "msg": "尚未设置管理员"}, status_code=400)
    admin_id = db.verify_admin(username, password)
    if not admin_id:
        return JSONResponse({"ok": False, "msg": "用户名或密码错误"}, status_code=401)
    request.session["admin_user_id"] = admin_id
    return {"ok": True}


@app.post("/admin/logout")
async def admin_logout(request: Request):
    request.session.clear()
    return {"ok": True}


@app.post("/admin/change-password")
async def admin_change_password(
    request: Request,
    old_password: str = Form(...),
    new_password: str = Form(...),
    admin_id: int = Depends(require_admin),
):
    try:
        ok = db.change_admin_password(admin_id, old_password, new_password)
    except ValueError as e:
        return JSONResponse({"ok": False, "msg": str(e)}, status_code=400)
    if not ok:
        return JSONResponse({"ok": False, "msg": "旧密码错误"}, status_code=400)
    return {"ok": True}


@app.get("/api/admin/me")
async def admin_me(admin_id: int = Depends(require_admin)):
    return db.get_admin(admin_id)


@app.post("/api/accounts/select")
async def select_account(
    request: Request,
    account_id: int = Form(...),
    admin_id: int = Depends(require_admin),
):
    """切换当前操作的移动云账号。"""
    if not db.get_account(account_id):
        return JSONResponse({"ok": False, "msg": "账号不存在"}, status_code=404)
    request.session["account_id"] = account_id
    return {"ok": True}


@app.post("/api/accounts/{account_id}/delete")
async def delete_account(
    request: Request,
    account_id: int,
    admin_id: int = Depends(require_admin),
):
    sched = get_scheduler()
    with contextlib.suppress(Exception):
        await sched.stop_for(account_id)
    db.delete_account(account_id)
    if request.session.get("account_id") == account_id:
        request.session.pop("account_id", None)
    return {"ok": True}


# ---------- 移动云账号 登录 / 切换 / 登出 ----------

@app.post("/api/login")
async def api_login(
    request: Request,
    mobile: str = Form(...),
    password: str = Form(...),
    admin_id: int = Depends(require_admin),
):
    # 密码登录支持手机号 / 渠道账号，仅去空白
    mobile = mobile.strip()
    if not mobile:
        raise HTTPException(400, "账号不能为空")

    existing = db.get_account_by_mobile(mobile)
    device_id = existing["device_id"] if existing else str(uuid.uuid4())
    pwd_blob = aes_seal(password, settings.local_key_hex)
    acct_id = db.upsert_account(mobile, pwd_blob, device_id)

    client = PCASClient(
        base_url=settings.pcas_base_url,
        timeout=settings.http_timeout,
        debug_dump=settings.debug_dump_payload,
    )
    client.account_name = mobile
    try:
        try:
            result = await client.login_by_password(mobile, password)
        except PCASError as e:
            db.update_account_session(acct_id, None, None, None, e.msg)
            db.add_log(acct_id, None, "login", False, e.msg)
            return JSONResponse(
                {"ok": False, "code": str(e.code), "msg": e.msg}, status_code=400
            )

        if result.get("status") != "success":
            # 设备未受信任 / 二次验证 — 提示需要短信码
            db.add_log(acct_id, None, "login", False,
                       f"challenge: {result.get('challengeType')}")
            return JSONResponse({
                "ok": False,
                "challenge": True,
                "msg": result.get("errorMessage", "需要可信设备验证"),
                "challengeType": result.get("challengeType"),
                "mobile": result.get("mobile"),
            }, status_code=400)

        db.update_account_session(
            acct_id,
            result["accessToken"],
            result["accessTicket"],
            result.get("userName", ""),
            None,
        )
        # 缓存机器列表
        for m in result["machines"]:
            db.upsert_machine(
                acct_id, m["machineId"],
                m.get("machineName"), m.get("status"),
                extras={
                    "instanceId": m.get("instanceId"),
                    "resourceId": m.get("resourcePoolUid"),
                    "vmId": m.get("instanceId"),
                },
                raw_json=json.dumps(m, ensure_ascii=False),
            )
        request.session["account_id"] = acct_id
        db.add_log(acct_id, None, "login", True,
                   f"{len(result['machines'])} machines")
        return {"ok": True, "machines": result["machines"]}
    finally:
        await client.close()


@app.post("/api/sms")
async def api_sms(
    mobile: str = Form(...),
    admin_id: int = Depends(require_admin),
):
    if len(mobile) != 11:
        raise HTTPException(400, "手机号格式不对")
    client = PCASClient(
        base_url=settings.pcas_base_url,
        timeout=settings.http_timeout,
        debug_dump=settings.debug_dump_payload,
    )
    client.account_name = mobile
    try:
        data = await client.send_sms(mobile, code_type="login")
        return {"ok": True, "data": data}
    except PCASError as e:
        return JSONResponse({"ok": False, "code": str(e.code), "msg": e.msg}, status_code=400)
    finally:
        await client.close()


@app.post("/api/login-sms")
async def api_login_sms(
    request: Request,
    mobile: str = Form(...),
    code: str = Form(...),
    admin_id: int = Depends(require_admin),
):
    existing = db.get_account_by_mobile(mobile)
    device_id = existing["device_id"] if existing else str(uuid.uuid4())
    pwd_blob = (
        existing["password_blob"] if existing else aes_seal("", settings.local_key_hex)
    )
    acct_id = db.upsert_account(mobile, pwd_blob, device_id)

    client = PCASClient(
        base_url=settings.pcas_base_url,
        timeout=settings.http_timeout,
        debug_dump=settings.debug_dump_payload,
    )
    client.account_name = mobile
    try:
        try:
            result = await client.login_by_sms(mobile, code)
        except PCASError as e:
            db.update_account_session(acct_id, None, None, None, e.msg)
            db.add_log(acct_id, None, "login_sms", False, e.msg)
            return JSONResponse(
                {"ok": False, "code": str(e.code), "msg": e.msg}, status_code=400
            )
        if result.get("status") != "success":
            # 短信登录的 challenge：把 accessTicket 暂存到 session，让前端 UI 选「信任/临时」
            request.session["pending_trust"] = {
                "mobile": mobile,
                "accessTicket": result.get("accessTicket", ""),
                "acct_id": acct_id,
            }
            return JSONResponse({
                "ok": False,
                "challenge": True,
                "msg": "新设备：请选择「信任此设备」或「仅临时使用」",
                "challengeType": result.get("challengeType"),
                "accessTicket": result.get("accessTicket"),
            }, status_code=400)
        db.update_account_session(
            acct_id, result["accessToken"], result["accessTicket"],
            result.get("userName", ""), None,
        )
        for m in result["machines"]:
            db.upsert_machine(
                acct_id, m["machineId"],
                m.get("machineName"), m.get("status"),
                extras={
                    "instanceId": m.get("instanceId"),
                    "resourceId": m.get("resourcePoolUid"),
                    "vmId": m.get("instanceId"),
                },
                raw_json=json.dumps(m, ensure_ascii=False),
            )
        request.session["account_id"] = acct_id
        db.add_log(acct_id, None, "login_sms", True, "ok")
        return {"ok": True}
    finally:
        await client.close()


@app.post("/api/login-sms/trust")
async def api_login_sms_trust(
    request: Request,
    is_temporary: bool = Form(...),
    admin_id: int = Depends(require_admin),
):
    """完成短信登录的「选择设备类型」challenge：永久信任 or 仅本次临时。

    必须先调用 /api/login-sms 拿到 accessTicket 并把它放到 session.pending_trust。
    """
    pending = request.session.get("pending_trust")
    if not pending:
        return JSONResponse({"ok": False, "msg": "没有等待处理的设备验证"}, status_code=400)

    mobile = pending.get("mobile", "")
    ticket = pending.get("accessTicket", "")
    acct_id = pending.get("acct_id")
    if not ticket or not mobile or not acct_id:
        request.session.pop("pending_trust", None)
        return JSONResponse({"ok": False, "msg": "challenge 数据不完整，请重新登录"}, status_code=400)

    client = PCASClient(
        base_url=settings.pcas_base_url,
        timeout=settings.http_timeout,
        debug_dump=settings.debug_dump_payload,
    )
    client.account_name = mobile
    try:
        try:
            result = await client.trust_or_temporary_device(ticket, is_temporary)
        except PCASError as e:
            db.add_log(acct_id, None, "trust_device", False, e.msg)
            return JSONResponse(
                {"ok": False, "code": str(e.code), "msg": e.msg}, status_code=400
            )

        if result.get("status") != "success":
            return JSONResponse({"ok": False, "msg": "设备验证未完成"}, status_code=400)

        db.update_account_session(
            acct_id, result["accessToken"], result["accessTicket"],
            result.get("userName", ""), None,
        )
        for m in result["machines"]:
            db.upsert_machine(
                acct_id, m["machineId"],
                m.get("machineName"), m.get("status"),
                extras={
                    "instanceId": m.get("instanceId"),
                    "resourceId": m.get("resourcePoolUid"),
                    "vmId": m.get("instanceId"),
                },
                raw_json=json.dumps(m, ensure_ascii=False),
            )

        request.session.pop("pending_trust", None)
        request.session["account_id"] = acct_id
        db.add_log(acct_id, None, "trust_device", True,
                   "temporary" if is_temporary else "trusted")
        return {"ok": True}
    finally:
        await client.close()


@app.post("/api/logout")
async def api_logout(request: Request, admin_id: int = Depends(require_admin)):
    """退出当前选中的移动云账号（保留管理员登录态）。"""
    aid = request.session.get("account_id")
    request.session.pop("account_id", None)
    if aid:
        sched = get_scheduler()
        with contextlib.suppress(Exception):
            await sched.stop_for(aid)
        db.update_account_session(aid, None, None, None, None)
        db.add_log(aid, None, "logout", True, "")
    return {"ok": True}


@app.get("/api/me")
async def api_me(request: Request, admin_id: int = Depends(require_admin)):
    aid = current_account_id(request)
    acct = db.get_account(aid)
    if not acct:
        request.session.pop("account_id", None)
        raise HTTPException(400, "账号已失效")
    return {
        "id": acct["id"],
        "mobile": acct["mobile"],
        "user_name": acct.get("login_uid"),
        "last_login_at": acct["last_login_at"],
        "last_error": acct["last_error"],
        "has_token": bool(acct["cem_token"]),
    }


# ---------- 机器 ----------

@app.get("/api/machines")
async def api_machines(request: Request, admin_id: int = Depends(require_admin)):
    aid = current_account_id(request)
    return {"ok": True, "machines": db.list_machines(aid)}


@app.post("/api/refresh")
async def api_refresh(request: Request, admin_id: int = Depends(require_admin)):
    """主动重拉机器列表（用已有 accessTicket 刷新一次 token + getDeviceInfo）。"""
    aid = current_account_id(request)
    acct = db.get_account(aid)
    client = _make_client_for(acct)
    try:
        try:
            result = await client.refresh_token()
        except PCASError as e:
            db.add_log(aid, None, "refresh", False, e.msg)
            return JSONResponse({"ok": False, "msg": e.msg}, status_code=400)

        db.update_account_session(
            aid, result["accessToken"], client.access_ticket,
            result.get("userName", ""), None,
        )
        for m in result["machines"]:
            db.upsert_machine(
                aid, m["machineId"], m.get("machineName"), m.get("status"),
                extras={
                    "instanceId": m.get("instanceId"),
                    "resourceId": m.get("resourcePoolUid"),
                    "vmId": m.get("instanceId"),
                },
                raw_json=json.dumps(m, ensure_ascii=False),
            )
        db.add_log(aid, None, "refresh", True, f"{len(result['machines'])} machines")
        return {"ok": True, "machines": db.list_machines(aid)}
    finally:
        await client.close()


# ---------- 开关机 ----------

def _resolve_op_target(account_id: int, machine_id: str) -> tuple[str, str, str]:
    """从 db 里查机器，解析出真正下发给 /resource/operate 的 (machineId, machineName, resourcePoolUid)。

    ⚠️ 服务端期望的 machineId 是 **display 的 UUID 风格 machineId**，不是
    `connectMachineId` / `instance_id`（后者一般是 `CCA-xxxx`，Node 实现
    `server.js:1480` 明确把 CCA- 开头标记为 "suspicious"）。
    对照 Node `resolveMachineConnectMachineId`：当 `connect_machine_id ==
    instance_id` 时判 fallback，无 poolMappings 时最终回到 `displayMachineId`。

    `resourcePoolUid` 仅在 db 已记录时透传；服务端成功请求里通常不传。
    """
    m = db.get_machine(account_id, machine_id)
    if not m:
        raise HTTPException(404, f"未找到机器 {machine_id}")
    raw = {}
    if m.get("raw_json"):
        try:
            raw = json.loads(m["raw_json"]) or {}
        except Exception:
            raw = {}
    # 优先取 raw_json 里 mapped 后的 display machineId（与前端展示一致），
    # 兜底用 db.machine_id（== 前端传过来的）。
    display_id = (
        raw.get("machineId")
        or m.get("machine_id")
        or machine_id
    )
    # 如果上一行结果意外是 CCA- 前缀（不该出现），再退到前端原值
    if str(display_id).startswith("CCA-"):
        display_id = m.get("machine_id") or machine_id
    machine_name = raw.get("machineName") or m.get("machine_name") or ""
    resource_pool_uid = raw.get("resourcePoolUid") or ""
    return str(display_id), str(machine_name), str(resource_pool_uid)


@app.post("/api/op")
async def api_op(
    request: Request,
    machine_id: str = Form(...),
    op: str = Form(...),
    admin_id: int = Depends(require_admin),
):
    aid = current_account_id(request)
    if op not in OP_TYPES:
        raise HTTPException(400, f"未知 op={op}")
    connect_id, machine_name, resource_pool_uid = _resolve_op_target(aid, machine_id)
    acct = db.get_account(aid)
    client = _make_client_for(acct)
    try:
        try:
            data = await client.operate_machine(
                connect_id, op,
                machine_name=machine_name,
                resource_pool_uid=resource_pool_uid,
            )
        except PCASError as e:
            # token 失效时尝试一次刷新
            if PCASClient.is_auth_failure(e):
                try:
                    await client.refresh_token()
                    db.update_account_session(
                        aid, client.access_token, client.access_ticket,
                        acct.get("login_uid"), None,
                    )
                    data = await client.operate_machine(
                        connect_id, op,
                        machine_name=machine_name,
                        resource_pool_uid=resource_pool_uid,
                    )
                except PCASError as e2:
                    db.add_log(aid, machine_id, f"op:{op}", False, e2.msg)
                    return JSONResponse({"ok": False, "msg": e2.msg}, status_code=400)
            else:
                db.add_log(aid, machine_id, f"op:{op}", False, e.msg)
                return JSONResponse({"ok": False, "msg": e.msg}, status_code=400)
        db.add_log(aid, machine_id, f"op:{op}", True, "")
        return {"ok": True, "data": data}
    finally:
        await client.close()


# ---------- 24h 保活 ----------

@app.post("/api/keepalive/start")
async def api_ka_start(request: Request, admin_id: int = Depends(require_admin)):
    aid = current_account_id(request)
    sched = get_scheduler()
    try:
        result = await sched.start_for(aid)
        return result
    except Exception as e:
        db.add_log(aid, None, "keepalive_start", False, repr(e))
        return JSONResponse({"ok": False, "msg": repr(e)}, status_code=400)


@app.post("/api/keepalive/stop")
async def api_ka_stop(request: Request, admin_id: int = Depends(require_admin)):
    aid = current_account_id(request)
    sched = get_scheduler()
    return await sched.stop_for(aid)


@app.get("/api/keepalive/status")
async def api_ka_status(request: Request, admin_id: int = Depends(require_admin)):
    aid = current_account_id(request)
    sched = get_scheduler()
    return await sched.status_for(aid)


@app.post("/api/keepalive/trigger")
async def api_ka_trigger(request: Request, admin_id: int = Depends(require_admin)):
    """手动触发一次桌面会话模拟（不等 23h 周期）。"""
    aid = current_account_id(request)
    sched = get_scheduler()
    try:
        result = await sched.trigger_now(aid)
        return result
    except Exception as e:
        db.add_log(aid, None, "manual_trigger", False, repr(e))
        return JSONResponse({"ok": False, "msg": repr(e)}, status_code=400)


# ---------- 健康检查（无需鉴权，供 docker / 反向代理探活） ----------

@app.get("/healthz")
async def healthz():
    return {"ok": True}


# ---------- logs ----------

@app.get("/api/logs")
async def api_logs(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    admin_id: int = Depends(require_admin),
):
    aid = current_account_id(request)
    return {"ok": True, "logs": db.list_logs(aid, limit)}


if __name__ == "__main__":
    import uvicorn

    s = get_settings()
    uvicorn.run("main:app", host=s.host, port=s.port, reload=False, log_level="info")
