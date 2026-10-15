#!/usr/bin/env python3
"""验证 antiformat.ko 的 __versions CRC 是否匹配 6.1 符号表"""
import subprocess, sys

ko = sys.argv[1] if len(sys.argv) > 1 else 'antiformat.ko'
symvers = sys.argv[2] if len(sys.argv) > 2 else '/tmp/ko61/Module.symvers.full'

# 提取 __versions 段
out = subprocess.run(['readelf', '-SW', ko], capture_output=True, text=True).stdout
off = sz = None
for line in out.splitlines():
    if '__versions' in line:
        parts = line.split()
        for i, p in enumerate(parts):
            if p == 'PROGBITS':
                off = int(parts[i+2], 16)
                sz = int(parts[i+3], 16)
                break
        break
if off is None:
    print('FAIL: no __versions section')
    sys.exit(1)

with open(ko, 'rb') as f:
    f.seek(off)
    data = f.read(sz)

ko_syms = {}
for i in range(0, len(data) - 63, 64):
    rec = data[i:i+64]
    crc = int.from_bytes(rec[:4], 'little')
    name = rec[8:64].split(b'\x00')[0].decode('utf-8', 'replace').strip()
    if name:
        ko_syms[name] = crc
print('__versions records: %d' % len(ko_syms))

# 读符号表
ref = {}
with open(symvers) as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) >= 2:
            ref[parts[1]] = int(parts[0], 16)

miss = [s for s in ko_syms if s not in ref]
mismatch = [(s, hex(ref[s]), hex(ko_syms[s])) for s in ko_syms if s in ref and ref[s] != ko_syms[s]]
print('missing in symvers: %d' % len(miss))
for s in miss:
    print('  MISS:', s)
print('CRC mismatch: %d' % len(mismatch))
for s, a, b in mismatch:
    print('  MISMATCH %s: ref=%s ko=%s' % (s, a, b))
print('RESULT: %s' % ('OK' if not miss and not mismatch else 'FAIL'))
