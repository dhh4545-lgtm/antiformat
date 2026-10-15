#!/usr/bin/env python3
import re
d = open('/tmp/gj_v13.bin', 'rb').read()
tail = d[0x22c9ca:]
print('尾部长度:', len(tail))
for m in re.finditer(rb'[\x20-\x7e]{6,}', tail):
    print('  %#x: %r' % (m.start(), m.group().decode('latin1')))
print('尾部 hex:')
for i in range(0, len(tail), 16):
    print('%08x: %s' % (0x22c9ca + i, tail[i:i+16].hex()))
