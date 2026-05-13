"""Locate each endpoint's nearby identifier strings via .rodata proximity heuristic.

Dart AOT compilers tend to place string constants of the same module nearby.
This script scans ±4 KB around each URL string and lists camelCase identifiers
that look like JSON keys (lowercase first char, 3-30 chars, no underscores).
"""
import re

path = r'E:\Desktop\foldder\Code\Claude\ydy\pcas_out\apktool_out\lib\arm64-v8a\libapp.so'
data = open(path, 'rb').read()

TARGETS = [
    ('/api/cem/gateway/outer/cem-webapi/login/verify', 'login.verify'),
    ('/api/cem/gateway/outer/cem-webapi/login/checkMobile', 'login.checkMobile'),
    ('/api/cem/gateway/outer/cem-webapi/login/sendVerifySms', 'login.sendVerifySms'),
    ('/api/cem/gateway/outer/cem-webapi/login/loginByCode', 'login.loginByCode'),
    ('/api/cem/gateway/outer/cem-webapi/login/verifySms', 'login.verifySms'),
    ('/api/cem/gateway/outer/cem-webapi/login/verifyAccessTicket', 'login.verifyAccessTicket'),
    ('/api/cem/gateway/outer/cem-webapi/login/trustDevice', 'login.trustDevice'),
    ('/api/cem/gateway/outer/cem-webapi/login/recordDeviceInfo', 'login.recordDeviceInfo'),
    ('/api/cem/gateway/outer/cem-webapi/user/getLoginUserInfo', 'user.getLoginUserInfo'),
    ('/api/cem/gateway/outer/cem-webapi/user/getDeviceInfo', 'user.getDeviceInfo'),
    ('/api/cem/gateway/outer/cem-webapi/user/getDesktopStatus', 'user.getDesktopStatus'),
    ('/api/cem/gateway/outer/cem-webapi/user/setShutDownTime', 'user.setShutDownTime'),
    ('/api/cem/gateway/outer/cem-webapi/resource/operate', 'resource.operate'),
    ('/api/cem/gateway/outer/cem-webapi/session/machineConnect', 'session.machineConnect'),
    ('/api/cem/gateway/outer/cem-webapi/session/updateSessionStatus', 'session.updateSessionStatus'),
    ('/api/cem/gateway/outer/cem-webapi/machine/pushConnectEventData', 'machine.pushConnectEventData'),
    ('/api/cem/gateway/outer/cem-webapi/machine/performance/batch', 'machine.performance.batch'),
]

WINDOW = 4096

# Pattern: camelCase or lower start, 3-30 chars, alnum+underscore allowed
ID_RE = re.compile(rb'(?<![A-Za-z0-9_])([a-z][a-zA-Z0-9_]{2,29})(?![A-Za-z0-9_])')

# Pattern: standalone printable ascii run
RUN_RE = re.compile(rb'[\x20-\x7E]{3,40}')

# Common Flutter/Dart/general English noise words to filter out
NOISE = set("""value class object string list false true null this that self type
key data result code msg message success error info name path uri url width height size
left right top bottom center start end of for and or not new old get set is to from
add remove update fetch handle on by with without none default has count length
package import library main args fn cb tmp temp obj item index pos point area
prefix suffix begin finish init final return loop while if else do try catch throw
""".split())

def scan(off):
    lo = max(0, off - WINDOW)
    hi = min(len(data), off + WINDOW)
    region = data[lo:hi]
    cand = set()
    for m in ID_RE.finditer(region):
        s = m.group(1).decode('ascii')
        if s.lower() in NOISE:
            continue
        if len(s) < 4 or len(s) > 24:
            continue
        # camelCase quality check
        if not any(c.isupper() for c in s) and len(s) < 5:
            continue
        cand.add(s)
    return cand

print("# PCAS Endpoint Field Discovery (proximity heuristic)\n")
for url, label in TARGETS:
    off = data.find(url.encode())
    if off < 0:
        print(f"## {label}\n  URL NOT FOUND\n")
        continue
    cand = scan(off)
    # rank by relevance: prefer short and obviously JSON-key-ish
    ranked = sorted(cand, key=lambda s: (len(s), s))
    print(f"## {label}  (url offset 0x{off:x})")
    print(f"  URL: {url}")
    print(f"  Nearby identifiers (sample):")
    for s in ranked[:40]:
        print(f"    - {s}")
    print()
