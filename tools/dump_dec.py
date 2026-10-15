#!/usr/bin/env python3
# dump_dec.py - 从 unicorn 模拟器输出 dump 解密后代码并分析
# 复用 unicorn_sim 的执行逻辑，但把 MMAP_RET 内容完整写盘
import struct, sys, re
from unicorn import *
from unicorn.arm64_const import *

BIN = '/tmp/gj_v13.bin'
BASE = 0x550000
LOAD2_SZ   = 0x22c9ca
STACK_TOP  = 0x40000000
MMAP_OUT   = 0x20000000
MMAP_SELF  = 0x21000000
MMAP_RET   = 0x22000000

data = open(BIN, 'rb').read()
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

mu.mem_map(BASE, 0x400000)
mu.mem_write(BASE, data[:LOAD2_SZ])
mu.mem_map(0, 0x1000)
mu.mem_write(0, data[:0x1000])
mu.mem_map(STACK_TOP - 0x100000, 0x100000)
mu.mem_map(MMAP_OUT, 0x100000)
mu.mem_map(MMAP_RET, 0x100000)
mu.mem_map(MMAP_SELF, 0x400000)
mu.mem_write(MMAP_SELF, data)

sp = STACK_TOP - 0x8000
mu.reg_write(UC_ARM64_REG_SP, sp)

argv_str = b'/proc/self/exe\x00'
argv_addr = sp + 0x1000
mu.mem_write(argv_addr, argv_str)
argv_arr = sp + 0x1100
mu.mem_write(argv_arr, struct.pack('<Q', argv_addr) + b'\x00'*8)
envp_arr = sp + 0x1200
mu.mem_write(envp_arr, b'\x00'*8)
auxv = sp + 0x1300
auxv_data = struct.pack('<QQ', 3, 0x550000)
auxv_data += struct.pack('<QQ', 4, 56)
auxv_data += struct.pack('<QQ', 5, 3)
auxv_data += struct.pack('<QQ', 9, 0x77be7c)
auxv_data += struct.pack('<QQ', 0, 0)
mu.mem_write(auxv, auxv_data)

def hook_svc(uc, intno, user_data):
    w8 = uc.reg_read(UC_ARM64_REG_W8)
    if w8 == 56:
        uc.reg_write(UC_ARM64_REG_X0, 3)
    elif w8 == 222:
        uc.reg_write(UC_ARM64_REG_X0, MMAP_RET)
    elif w8 == 226:
        uc.reg_write(UC_ARM64_REG_X0, 0)
    elif w8 == 93:
        uc.emu_stop()
    elif w8 == 64:
        uc.reg_write(UC_ARM64_REG_X0, uc.reg_read(UC_ARM64_REG_X2))
    else:
        uc.reg_write(UC_ARM64_REG_X0, 0)

mu.hook_add(UC_HOOK_INTR, hook_svc)
mu.reg_write(UC_ARM64_REG_X0, 1)
mu.reg_write(UC_ARM64_REG_X1, argv_arr)
mu.reg_write(UC_ARM64_REG_X2, envp_arr)
mu.reg_write(UC_ARM64_REG_X3, auxv)

try:
    mu.emu_start(0x77be7c, 0, count=20000000, timeout=30000)
except UcError as e:
    pc = mu.reg_read(UC_ARM64_REG_PC)
    print(f'UcError: {e} pc={pc:#x}')

pc = mu.reg_read(UC_ARM64_REG_PC)
x0 = mu.reg_read(UC_ARM64_REG_X0)
print(f'结束 pc={pc:#x} x0={x0:#x}')

# 完整 dump MMAP_RET (解密输出)
out = bytes(mu.mem_read(MMAP_RET, 0x10000))
open('/tmp/gj_v13_dec.bin', 'wb').write(out)
print(f'解密输出已保存 /tmp/gj_v13_dec.bin ({len(out)} 字节)')
print('头部 128B:', out[:128].hex())

# 全量搜字符串（可打印 + 中文）
def extract_strings(buf, min_len=4):
    results = []
    cur = b''
    for i, b in enumerate(buf):
        if 0x20 <= b < 0x7f:
            cur += bytes([b])
        else:
            if len(cur) >= min_len:
                results.append((i - len(cur), cur))
            cur = b''
    if len(cur) >= min_len:
        results.append((len(buf) - len(cur), cur))
    return results

print('\n=== 可打印字符串 ===')
for off, s in extract_strings(out, 4):
    t = s.decode('latin1')
    print(f'  {off:#08x}: {t!r}')

print('\n=== 中文串 ===')
for m in re.finditer(rb'[\xe4-\xe9][\x80-\xbf][\x80-\xbf](?:[\xe4-\xe9][\x80-\xbf][\x80-\xbf])+', out):
    print(f'  {m.start():#08x}: {m.group().decode("utf-8","ignore")!r}')

# 搜关键词
print('\n=== 关键词命中 ===')
for kw in [b'boot', b'init_boot', b'recovery', b'persist', b'userdata', b'system',
           b'vendor', b'product', b'odm', b'by-name', b'mmcblk', b'sde', b'sdf',
           b'BLKZERO', b'BLKDISCARD', b'BLKFLSBUF', b'BLKSECDISCARD',
           b'0x1277', b'0x127d', b'0x127f', b'0x127c', b'0xc0185875',
           b'/dev/block', b'wipe', b'format', b'erase', b'factory',
           b'super', b'dtbo', b'vbmeta', b'cache', b'modem', b'efs', b'oem',
           b'cust', b'preloader', b'proinfo', b'nvram', b'protect', b'frp',
           b'misc', b'logo', b'xbl', b'tz', b'rpm', b'aboot', b'sbl1', b'cmnlib']:
    idx = out.find(kw)
    if idx >= 0:
        print(f'  HIT {kw!r} @ {idx:#x}: {out[max(0,idx-24):idx+48]!r}')

# 用 capstone 反汇编解密输出（假设从偏移 0 开始是指令）
try:
    from capstone import *
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    print('\n=== 解密输出反汇编（前 200 条）===')
    code = out[:0x4000]
    for ins in md.disasm(code, 0x22000000):
        print(f'  {ins.address:#x}: {ins.mnemonic}\t{ins.op_str}')
        if ins.address - 0x22000000 > 0x4000:
            break
except ImportError:
    print('capstone 不可用')