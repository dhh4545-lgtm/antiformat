#!/usr/bin/env python3
# lzfull.py - 从 0x22c1e8 连续 LZ 解压，完整还原格机V13.2 载荷
import struct, re, sys

d = open('/tmp/gj_v13.bin', 'rb').read()

def decompress(data, start):
    pos = start
    out = bytearray()
    bitbuf = 0x80000000

    def getbit():
        nonlocal bitbuf, pos
        bitbuf = (bitbuf << 1) & 0xffffffff
        if bitbuf == 0:
            if pos + 4 > len(data):
                return 0
            bitbuf = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            bitbuf = (bitbuf << 1) & 0xffffffff
        return (bitbuf >> 31) & 1

    w5_val = 0xffffffff
    while pos < len(data) and len(out) < 0x400000:
        c = getbit()
        if c == 1:
            out.append(data[pos]); pos += 1
            continue
        w1 = 1
        while True:
            w1 = (w1 - 1) & 0xffffffff
            c = getbit(); w1 = (w1 + w1 + c) & 0xffffffff
            c = getbit(); w1 = (w1 + w1 + c) & 0xffffffff
            c = getbit()
            if c == 1:
                break
        w3 = (w1 - 3) & 0xffffffff
        if w3 >= 0x80000000:
            # 短模式
            c = getbit()
            if c == 1:
                w1 = 0
            else:
                w1 = 1
                c = getbit()
                if c == 1:
                    pass
                else:
                    while True:
                        c = getbit(); w1 = (w1 + w1 + c) & 0xffffffff
                        c = getbit()
                        if c == 1:
                            break
                    w1 = (w1 + 4) & 0xffffffff
            c = getbit(); w1 = (w1 + w1 + c) & 0xffffffff
            w1 = (w1 + 2) & 0xffffffff
            dist = (-w5_val) & 0xffffffff
        else:
            b0 = data[pos]; pos += 1
            w5_val = (b0 | ((w3 << 8) & 0xffff)) & 0xffffffff
            w5_val = (~w5_val) & 0xffffffff
            if w5_val == 0:
                break
            low = w5_val & 1
            w5_val = (w5_val >> 1) & 0x7fffffff
            if low == 1:
                c = getbit(); w1 = (w1 + w1 + c) & 0xffffffff
                w1 = (w1 + 2) & 0xffffffff
            else:
                w1 = 1
                c = getbit()
                if c == 1:
                    c = getbit(); w1 = (w1 + w1 + c) & 0xffffffff
                    w1 = (w1 + 2) & 0xffffffff
                else:
                    while True:
                        c = getbit(); w1 = (w1 + w1 + c) & 0xffffffff
                        c = getbit()
                        if c == 1:
                            break
                    w1 = (w1 + 4) & 0xffffffff
                    c = getbit(); w1 = (w1 + w1 + c) & 0xffffffff
                    w1 = (w1 + 2) & 0xffffffff
            dist = (-w5_val) & 0xffffffff
        if (w5_val + 0x500) < 0x100000000:
            w1 = (w1 + 1) & 0xffffffff
        for _ in range(w1 & 0xffffff):
            if len(out) - dist < 0:
                break
            out.append(out[len(out) - dist])
    return bytes(out), pos

out, endpos = decompress(d, 0x22c1e8)
print(f'解压输出 {len(out)} 字节, 输入消耗到 {endpos:#x} (文件尾 {len(d):#x})')
open('/tmp/gj_full_dec.bin', 'wb').write(out)
print('头部 64B:', out[:64].hex())
print('--- 字符串 (前 0x20000) ---')
for m in re.finditer(rb'[\x20-\x7e]{5,}', out[:0x20000]):
    print(f'  {m.start():#x}: {m.group().decode("latin1")!r}')
print('--- 分区关键词 ---')
for kw in [b'boot', b'init_boot', b'recovery', b'persist', b'userdata', b'system',
           b'vendor', b'by-name', b'mmcblk', b'sde', b'BLKZERO', b'BLKDISCARD',
           b'/dev/block', b'wipe', b'format', b'erase', b'1277', b'127f',
           b'BLKFLSBUF', b'BLKSECDISCARD', b'0xc0185875', b'0x1277', b'0x127f']:
    idx = out.find(kw)
    if idx >= 0:
        print(f'  HIT {kw!r} @ {idx:#x}: {out[max(0,idx-24):idx+48]!r}')