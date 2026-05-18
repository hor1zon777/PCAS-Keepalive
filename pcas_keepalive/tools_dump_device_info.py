"""dump 一次 cem-webapi getDeviceInfo 完整响应 — 找出 customParams/adUser/adPassword 等桌面连接字段。

用法：
    cd pcas_keepalive
    python -m tools_dump_device_info

会用 DB 里已有的 account 凭据调 getDeviceInfo，打印每台机器的全部字段。
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import db
from config import get_settings
from pcas.client import PCASClient
from pcas.crypto import aes_open


async def main() -> None:
    settings = get_settings()
    db.init(str(Path(settings.base_dir) / settings.db_path))
    accounts = db.list_accounts()
    if not accounts:
        print("没有账号，请先在 Web UI 登录一个")
        return

    settings = get_settings()
    for acct_summary in accounts:
        acct = db.get_account(acct_summary['id'])
        print(f"\n{'='*60}")
        print(f"账号: {acct['mobile']} (id={acct['id']})")

        client = PCASClient(
            base_url=settings.pcas_base_url,
            timeout=settings.http_timeout,
            debug_dump=True,  # 打印原始 payload
        )
        client.account_name = acct["mobile"]
        client.access_token = acct.get("cem_token") or ""
        client.access_ticket = acct.get("access_ticket") or ""

        if not client.access_ticket:
            print("  skip: no access_ticket")
            await client.close()
            continue

        # 先刷新 token
        try:
            refreshed = await client.refresh_token()
            client.access_token = refreshed["accessToken"]
            print(f"  token refreshed: {client.access_token[:30]}...")
        except Exception as e:
            print(f"  token refresh failed: {e}, trying password login...")
            try:
                pwd = aes_open(acct["password_blob"], settings.local_key_hex)
                result = await client.login_by_password(acct["mobile"], pwd)
                if result.get("status") != "success":
                    print(f"  login incomplete: {result.get('challengeType')}")
                    await client.close()
                    continue
                client.access_token = result["accessToken"]
                client.access_ticket = result["accessTicket"]
                db.update_account_session(acct["id"], client.access_token, client.access_ticket, "", None)
                print(f"  password login ok: {client.access_token[:30]}...")
            except Exception as e2:
                print(f"  password login failed: {e2}")
                await client.close()
                continue

        try:
            # 调 getDeviceInfo 拿完整机器列表（原始 body）
            raw = await client._post_ok("/user/getDeviceInfo", {
                "accessToken": client.access_token,
                "companyCode": "ECloud",
                "allCompany": True,
                "version": "1.0.0",
            })
            body = raw.get("body") or {}
            machine_list = body.get("machineList") or body.get("desktopList") or []

            print(f"  机器数: {len(machine_list)}")

            for i, m in enumerate(machine_list):
                print(f"\n  --- 机器 #{i} ---")
                # 打印所有字段（重点看 customParams / adUser / adPassword / customLoginParams）
                for key in sorted(m.keys()):
                    val = m[key]
                    val_str = json.dumps(val, ensure_ascii=False) if isinstance(val, (dict, list)) else str(val)
                    # 高亮关键字段
                    marker = ""
                    if key.lower() in (
                        "customparams", "customloginparams", "customprivateloginparams",
                        "aduser", "adpassword", "companycode", "origincompanycode",
                        "machineid", "instanceid", "machinename", "resourcepooluid",
                        "connectmachineid", "status", "ip",
                    ):
                        marker = " ⭐"
                    print(f"    {key}: {val_str[:500]}{marker}")

        except Exception as e:
            print(f"  错误: {e}")
        finally:
            await client.close()


if __name__ == "__main__":
    asyncio.run(main())
