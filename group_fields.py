"""Extract field-name candidates from libapp.so and group by business domain.

Heuristic: Dart JSON field names are camelCase, length 3-30, start with lowercase,
typically appear as standalone strings in .rodata. We classify them by keyword
roots that match business domains.
"""
import re

path = r'E:\Desktop\foldder\Code\Claude\ydy\pcas_out\apktool_out\lib\arm64-v8a\libapp.so'
data = open(path, 'rb').read()

# extract printable ascii runs >= 3 chars
pattern = re.compile(rb'[\x20-\x7E]{3,40}')
all_strings = set(pattern.findall(data))
print(f"Total unique printable strings: {len(all_strings)}")

# filter to "camelCase identifier" shape
def is_field_like(s: bytes):
    try:
        st = s.decode('ascii')
    except UnicodeDecodeError:
        return False
    if not re.fullmatch(r'[a-z][a-zA-Z0-9]{2,29}', st):
        return False
    # filter common english words & noise
    blacklist = {'true', 'false', 'null', 'this', 'that', 'self', 'true', 'true2', 'value', 'class', 'list', 'string', 'object'}
    if st.lower() in blacklist:
        return False
    return True

fields = sorted({s.decode('ascii') for s in all_strings if is_field_like(s)})
print(f"Filtered identifier-shape strings: {len(fields)}")

# Group by business root (case-insensitive substring match)
groups = {
    'login/auth': r'login|auth|password|pwd|verif|captch|sms|token|ticket|loginType|access|umc|sso|qrcode',
    'mobile/phone': r'mobile|phone|countryCode|smsTemplate',
    'device/client': r'device|client|terminal|deviceUid|deviceUuid|deviceId|clientType|appVersion|clientVersion|sdkVersion|osType|platform|brand|model|imei|imsi',
    'machine/desktop': r'machine|desktop|instance|^pc|^vm|^vd|cloudPc|resource(?!Pool)|machineId|desktopId',
    'operation': r'^op[A-Z]|operate|operation|action|command|cmd|startUp|shutDown|reboot|restart|poweron|poweroff|wake|hibernate|sleep',
    'status': r'status|state|active|inactive|online|offline|idle|busy|running|shutdown|stopped|booting',
    'session': r'session|heartBeat|heartbeat|keepAlive|lastActive|sessionId',
    'connect/network': r'connect|disconnect|reconnect|^ip$|^mac$|publicIp|privateIp|^port$|rdpPort|spice|network|wifi',
    'time/billing': r'time|expire|duration|interval|timeout|charge|fee|price|hour|package|billing|^remain|^left',
    'tenant/org': r'tenant|company|enterprise|org|group',
    'sec/policy': r'policy|trust|blacklist|whitelist|peripheral|watermark|forbid|allow',
    'shutdown timer': r'shutDownTime|autoShutDown|idleTimeout|autoLogout',
    'response wrap': r'^data$|^code$|^msg$|^message$|^success|^retCode|^result',
}

# Compile regex for each group
compiled = {k: re.compile(v, re.I) for k, v in groups.items()}

results = {k: [] for k in groups}
unclassified = []

for f in fields:
    matched = False
    for k, regex in compiled.items():
        if regex.search(f):
            results[k].append(f)
            matched = True
            break  # first match wins for clarity
    if not matched:
        unclassified.append(f)

# Print each group
import sys
for k, items in results.items():
    items = sorted(set(items))
    print(f"\n=== {k} ({len(items)}) ===")
    # Print in column form
    for i in range(0, len(items), 4):
        row = items[i:i+4]
        print("  " + "  ".join(f"{x:<30}" for x in row))

print(f"\n=== Unclassified sample (total {len(unclassified)}) ===")
# print first 50 unclassified for inspection
for s in unclassified[:50]:
    print(" ", s)
