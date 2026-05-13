"""Dump ascii surroundings of DoubleStream-related symbols in libapp.so."""
import re
data = open(r'E:\Desktop\foldder\Code\Claude\ydy\pcas_out\apktool_out\lib\arm64-v8a\libapp.so', 'rb').read()

needles = [
    b'DoubleStreamEncoder',
    b'DoubleStreamDecoder',
    b'HeartBeatClientCommand',
    b'ConnectionRequestClientCommand',
    b'_doubleStreamIsConnected',
    b'cemDoubleStreamPort',
    b'DoubleStreamUID',
    b'doubleStreamListener',
]

for needle in needles:
    occs = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        occs.append(i)
        start = i + 1
    print(f'\n=== [{needle.decode()}] {len(occs)} occurrences ===')
    for off in occs[:2]:
        lo = max(0, off - 80)
        hi = min(len(data), off + len(needle) + 350)
        region = data[lo:hi]
        runs = re.findall(rb'[\x20-\x7E]{4,40}', region)
        ascii_runs = [r.decode('ascii','ignore') for r in runs]
        print(f'  @ 0x{off:x}: {ascii_runs[:20]}')
