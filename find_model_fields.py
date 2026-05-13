import os, re, sys

path = r'E:\Desktop\foldder\Code\Claude\ydy\pcas_out\apktool_out\lib\arm64-v8a\libapp.so'
data = open(path, 'rb').read()
print(f"Size: {len(data)} bytes")

def find_all(needle):
    out = []
    needle = needle.encode()
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out

# Extract printable ascii strings in a window
def extract_ascii_strings(off, before=512, after=2048, minlen=3, maxlen=40):
    lo = max(0, off - before)
    hi = min(len(data), off + len(needle_main) + after)
    region = data[lo:hi]
    strings = []
    cur = bytearray()
    cur_start = 0
    for i, b in enumerate(region):
        if 0x20 <= b < 0x7F:
            if not cur:
                cur_start = i
            cur.append(b)
        else:
            if minlen <= len(cur) <= maxlen:
                # filter: identifier-ish
                s = cur.decode('ascii', 'ignore')
                if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', s):
                    strings.append((lo + cur_start, s))
            cur = bytearray()
    return strings

for name in ['CemLoginModel', 'VerifyLoginModel', 'CheckMobileModel',
             'SendVerifySmsModel', 'MachineOperateInfo', 'DesktopStatusModel',
             'HeartBeatServerModel', 'SessionStatusConnectInfoModel',
             'HardwareInfoModel', 'LoginUserInfo', 'CloudPcConnectInfoModel',
             'MachineConnectInfoModel', 'MachineInfoModel']:
    needle_main = name
    offsets = find_all(name)
    print(f"\n[{name}] offsets={offsets[:5]} (total={len(offsets)})")
    for off in offsets[:2]:
        ss = extract_ascii_strings(off, before=128, after=512)
        # filter likely field names (camelCase, length 4-30, lower start)
        candidates = [s for _, s in ss if s[0].islower() and 3 <= len(s) <= 28]
        print(f"  context near {hex(off)}: {candidates[:30]}")
