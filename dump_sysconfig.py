"""Find SysConfigModel field names by scanning .rodata around its function symbols."""
import re
data = open(r'E:\Desktop\foldder\Code\Claude\ydy\pcas_out\apktool_out\lib\arm64-v8a\libapp.so', 'rb').read()

for needle in [b'_$SysConfigModelFromJson', b'_$SysConfigModelToJson', b'SysConfigModel']:
    i = data.find(needle)
    print(f'\n=== {needle.decode()} @ 0x{i:x} ===')
    if i < 0:
        continue
    # 扫前后 3KB
    lo, hi = max(0, i-1500), min(len(data), i+1500)
    region = data[lo:hi]
    runs = re.findall(rb'[\x20-\x7E]{4,50}', region)
    seen = set()
    candidates = []
    for r in runs:
        s = r.decode('ascii','ignore')
        # 像字段名：lowerCamelCase 起手，3-30 字符，无下划线
        if re.fullmatch(r'[a-z][a-zA-Z0-9]{3,29}', s) and s not in seen:
            seen.add(s)
            candidates.append(s)
    for c in candidates[:70]:
        print(' ', c)
