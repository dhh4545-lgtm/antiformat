#!/usr/bin/env python3
# lzsim.py - AntiFormat 静态复现工具
# 精确模拟「格机V13.2.sh」解密器主循环 (0x77be88 -> 0x77bea0 收尾)
# 纯静态：不执行任何样本代码，只按反汇编还原的寄存器语义解压加密区
import struct, sys

data = open(sys.argv[1] if len(sys.argv) > 1 else '/tmp/gj_v13.bin', 'rb').read()

# ---- 常量（从 readelf + 反汇编还原） ----
VMA_BASE   = 0x550000
IN_START   = 0x77c1e8          # x0 初始 (VMA) = 文件偏移 0x22c1e8
IN_END     = 0x77c9ca          # x7 (VMA) = 文件偏移 0x22c9ca
OUT_SIZE   = 0xaa4             # mmap 缓冲 2724B

in_off  = IN_START - VMA_BASE
in_end  = IN_END  - VMA_BASE
in_data = data[in_off:in_end]
print(f'输入: 文件[{in_off:#x}:{in_end:#x}] {len(in_data)} 字节')

# ---- AArch64 标志模拟 ----
NZCV = {'N':0,'Z':0,'C':0,'V':0}
def set_flags_add(w, a, b, carry=0):
    r = (a + b + carry) & 0xffffffff
    NZCV['N'] = (r >> 31) & 1
    NZCV['Z'] = 1 if r == 0 else 0
    NZCV['C'] = 1 if (a + b + carry) > 0xffffffff else 0
    NZCV['V'] = 1 if (((a ^ r) & (b ^ r) & 0x80000000) != 0) else 0
    return r
def set_flags_sub(w, a, b, borrow=0):
    r = (a - b - borrow) & 0xffffffff
    NZCV['N'] = (r >> 31) & 1
    NZCV['Z'] = 1 if r == 0 else 0
    NZCV['C'] = 1 if a >= (b + borrow) else 0
    NZCV['V'] = 1 if (((a ^ r) & (a ^ b) & 0x80000000) != 0) else 0
    return r

def cond(name):
    N,Z,C,V = NZCV['N'],NZCV['Z'],NZCV['C'],NZCV['V']
    return {
        'eq': Z==1, 'ne': Z==0, 'hs': C==1, 'lo': C==0,
        'mi': N==1, 'pl': N==0, 'vs': V==1, 'vc': V==0,
        'hi': C==1 and Z==0, 'ls': C==0 or Z==1,
        'ge': N==V, 'lt': N!=V, 'gt': Z==0 and N==V, 'le': Z==1 or N!=V,
    }[name]

# ---- 寄存器 ----
X = [0]*32   # x0-x30, x31=sp 用独立变量
# 初始状态（0x77be88 处）
X[0] = IN_START          # x0 = 输入指针 (VMA)
out_buf = bytearray(OUT_SIZE)
X[2] = 0                 # x2 = 输出指针 → 用 out_buf 索引
X[7] = IN_END            # x7 = 输入结束
X[5] = 0xffffffff        # w5 = -1 (0x77be94 mov w5,#-1)
X[4] = 0x80000000        # w4 = -0x80000000 (位缓冲)
# x3 = sp 相关（0x77be8c stp x2,x3 保存；结束才用）
sp_saved_x3 = 0
sp = 0x400000            # 虚拟栈

def mem_rd_u32(vma):
    off = vma - VMA_BASE
    if off < 0 or off+4 > len(data):
        return 0
    return struct.unpack('<I', data[off:off+4])[0]
def mem_rd_u8(vma):
    off = vma - VMA_BASE
    if off < 0 or off >= len(data):
        return 0
    return data[off]

def readbit():
    global X
    # 77bf30: adds w4,w4,w4
    X[4] = set_flags_add(None, X[4], X[4])
    if X[4] == 0:
        # 77bf3c: ldr w4,[x0],#4
        X[4] = mem_rd_u32(X[0]); X[0] += 4
        # 77bf40: adcs w4,w4,w4  (加 C，C 是 adds 设的=0)
        X[4] = set_flags_add(None, X[4], X[4], NZCV['C'])
    # 返回时 C = 读到的位
    return NZCV['C']

out_len = 0
def put_byte(b):
    global out_len
    out_buf[out_len] = b & 0xff
    out_len += 1

# ---- 主循环模拟 (从 0x77be9c b 0x77bf50 进入) ----
max_iter = len(in_data) * 16
it = 0
while it < max_iter:
    it += 1
    # 0x77bf50: bl 0x77bf30 (readbit) → C
    c = readbit()
    # 0x77bf54: b.hs 0x77bf48 → C==1 字面复制
    if c == 1:
        # 0x77bf48: ldrb w3,[x0],#1; strb w3,[x2],#1
        b = mem_rd_u8(X[0]); X[0] += 1
        put_byte(b)
        continue
    # C==0 → 匹配
    # 0x77bf58: mov w1,#1; 0x77bf5c: b 0x77bf6c
    w1 = 1
    while True:
        # 0x77bf60: sub w1,w1,#1
        w1 = (w1 - 1) & 0xffffffff
        # 0x77bf64: bl readbit; 0x77bf68: adc w1,w1,w1
        c = readbit(); w1 = (w1 + w1 + c) & 0xffffffff
        # 0x77bf6c: bl readbit; 0x77bf70: adc w1,w1,w1
        c = readbit(); w1 = (w1 + w1 + c) & 0xffffffff
        # 0x77bf74: bl readbit
        c = readbit()
        # 0x77bf78: b.lo 0x77bf60  (C==0 继续)
        if c == 0:
            continue
        break
    # 0x77bf7c: subs w3,w1,#3
    w3 = set_flags_sub(None, w1, 3)
    # 0x77bf80: mov w1,#0
    w1 = 0
    # 0x77bf84: b.lo 0x77bfa8  (w1<3 → 短模式)
    if cond('lo'):
        # 短模式 0x77bfa8
        c = readbit()
        if c == 1:
            # b.hs 0x77bfd4 (w1=0)
            pass
        else:
            # 0x77bfb0: mov w1,#1
            w1 = 1
            c = readbit()
            if c == 1:
                # b.hs 0x77bfd4 (w1=1)
                pass
            else:
                # 0x77bfbc 循环
                while True:
                    c = readbit(); w1 = (w1 + w1 + c) & 0xffffffff
                    c = readbit()
                    if c == 1:
                        break
                # 0x77bfcc: add w1,w1,#4
                w1 = (w1 + 4) & 0xffffffff
                # 0x77bfd0: b 0x77bfe0
                # 0x77bfd4 也要执行: readbit; adc w1; +2
                c = readbit(); w1 = (w1 + w1 + c) & 0xffffffff
                w1 = (w1 + 2) & 0xffffffff
                # 0x77bfe0
                # cmn w5,#0x500 → lo → w1+=1
                cmn_c = 1 if (X[5] + 0x500) > 0xffffffff else 0
                if cmn_c == 0:
                    w1 = (w1 + 1) & 0xffffffff
                # 复制 w1 字节, 距离 = |w5|
                dist = (-X[5]) & 0xffffffff
                for _ in range(w1):
                    src = out_len - dist
                    if src < 0: break
                    put_byte(out_buf[src])
                continue
    else:
        # 长模式 0x77bf88
        w5 = mem_rd_u8(X[0]); X[0] += 1
        # 0x77bf8c: orr w5,w5,w3,lsl#8
        w5 = (w5 | ((w3 << 8) & 0xffff)) & 0xffffffff
        # 0x77bf90: mvn w5,w5
        w5 = (~w5) & 0xffffffff
        # 0x77bf94: cbz w5 → 结束
        if w5 == 0:
            break
        # 0x77bf98: tst w5,#1; 0x77bf9c: asr w5,w5,#1
        low_bit = w5 & 1
        w5 = (w5 >> 1) | (0x80000000 if (w5 & 0x80000000) else 0)  # 算术右移32位
        # 0x77bfa0: b.ne 0x77bfd4 (low_bit==1)
        if low_bit == 1:
            # 0x77bfd4: bl readbit; adc w1,w1,w1 (w1=0); add w1,#2
            c = readbit(); w1 = (w1 + w1 + c) & 0xffffffff
            w1 = (w1 + 2) & 0xffffffff
        else:
            # 0x77bfa4: b 0x77bfb0 → 短长度解码 (w1=0)
            # 0x77bfb0: mov w1,#1; 0x77bfb4: bl readbit; 0x77bfb8: b.hs 0x77bfd4
            w1 = 1
            c = readbit()
            if c == 1:
                # 0x77bfd4: readbit; adc; +2
                c = readbit(); w1 = (w1 + w1 + c) & 0xffffffff
                w1 = (w1 + 2) & 0xffffffff
            else:
                # 0x77bfbc 循环
                while True:
                    c = readbit(); w1 = (w1 + w1 + c) & 0xffffffff
                    c = readbit()
                    if c == 1:
                        break
                # 0x77bfcc: add w1,#4
                w1 = (w1 + 4) & 0xffffffff
                # 0x77bfd0: b 0x77bfe0 → 但 0x77bfd4 也要跑
                c = readbit(); w1 = (w1 + w1 + c) & 0xffffffff
                w1 = (w1 + 2) & 0xffffffff
        # 0x77bfe0: cmn w5,#0x500 → lo → +1
        cmn_c = 1 if (X[5] + 0x500) > 0xffffffff else 0
        if cmn_c == 0:
            w1 = (w1 + 1) & 0xffffffff
        # 复制 w1 字节, 距离 = |w5|
        dist = (-X[5]) & 0xffffffff
        for _ in range(w1):
            src = out_len - dist
            if src < 0: break
            put_byte(out_buf[src])
    if out_len > OUT_SIZE + 0x100000:
        break

print(f'解压完成: 输出 {out_len} 字节 (上限 {OUT_SIZE:#x})')
out = bytes(out_buf[:out_len])
# 保存
open('/tmp/gj_v13_dec.bin', 'wb').write(out)
print('已保存 /tmp/gj_v13_dec.bin')
print('头部:', out[:32].hex())
print('尾部:', out[-32:].hex() if out_len > 32 else '')
# 搜分区/关键词
for kw in [b'boot', b'init_boot', b'recovery', b'persist', b'userdata', b'system',
           b'vendor', b'by-name', b'mmcblk', b'sde', b'BLKZERO', b'BLKDISCARD',
           b'0x127f', b'wipe', b'format', b'erase', b'/dev/block', b'super',
           b'dtbo', b'vbmeta', b'cache', b'modem', b'efs', b'oem']:
    idx = out.find(kw)
    if idx >= 0:
        print(f'  HIT {kw!r} @ {idx:#x}: {out[max(0,idx-16):idx+32]!r}')
