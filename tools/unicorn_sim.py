#!/usr/bin/env python3
# unicorn_sim.py - 用 unicorn 指令级模拟「格机V13.2.sh」解密器
# 拦截所有 svc，不执行真实 syscall。纯静态复现解密过程。
import struct
from unicorn import *
from unicorn.arm64_const import *

BIN = '/tmp/gj_v13.bin'
BASE = 0x550000          # ELF VMA 基址
LOAD1_OFF = 0            # 第一个 LOAD 段文件偏移
LOAD1_VMA  = 0           # VMA 0 (RW)
LOAD1_SZ   = 0x54c680
LOAD2_OFF  = 0           # 第二个 LOAD 段
LOAD2_VMA  = 0x550000
LOAD2_SZ   = 0x22c9ca
STACK_TOP  = 0x40000000  # 虚拟栈
MMAP_OUT   = 0x20000000  # 模拟 mmap 输出缓冲（解密器 x2 指向）
MMAP_SELF  = 0x21000000  # 模拟 /proc/self/exe 映射（把 ELF 内容放这）
MMAP_RET   = 0x22000000  # mmap syscall 实际返回（解密输出写这里，独立于源数据）

data = open(BIN, 'rb').read()

mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# 映射：ELF 镜像（LOAD2 段）
mu.mem_map(BASE, 0x400000)   # 4MB 足够覆盖 0x550000-0x77c9ca
mu.mem_write(BASE, data[:LOAD2_SZ])
# 映射第一个 LOAD 段 (VMA 0, RW) - 0x1000
mu.mem_map(0, 0x1000)
mu.mem_write(0, data[:0x1000])
# 栈
mu.mem_map(STACK_TOP - 0x100000, 0x100000)
# 模拟 mmap 输出缓冲
mu.mem_map(MMAP_OUT, 0x100000)
mu.mem_map(MMAP_RET, 0x100000)
mu.mem_map(MMAP_SELF, 0x400000)
mu.mem_write(MMAP_SELF, data)   # 模拟 /proc/self/exe 内容

# 栈指针
sp = STACK_TOP - 0x8000
mu.reg_write(UC_ARM64_REG_SP, sp)

# 模拟 argv/auxv（入口 0x77c190 扫描 auxv 找 AT_PHDR type=6）
# 在栈上构造 argv[0]=/proc/self/exe 和 auxv
argv_str = b'/proc/self/exe\x00'
argv_addr = sp + 0x1000
mu.mem_write(argv_addr, argv_str)
# argv 数组
argv_arr = sp + 0x1100
mu.mem_write(argv_arr, struct.pack('<Q', argv_addr) + b'\x00'*8)
# envp 空
envp_arr = sp + 0x1200
mu.mem_write(envp_arr, b'\x00'*8)
# auxv: AT_PHDR(3)=? AT_PHENT(4)=56 AT_PHNUM(5)=3 AT_ENTRY(9)=0x77be7c AT_NULL(0)
# 实际扫描器找 type==6 (AT_PHDR=3? 不对，AT_PHDR=3, AT_PHENT=4, AT_PHNUM=5, AT_ENTRY=9)
# 0x77c1a8: cmp w1,#6 → 找 type==6? 反汇编 0x77c1a8 cmp w1,#0x6 / b.eq → 是找 auxv type==6
# 但 AT_PHDR=3。扫描的是 [x0] 的指针数组：先跳过 NULL 指针，然后读 auxv 对
# 0x77c184: 扫描 NULL 终止的指针数组（argv+envp），0x77c1a4 读 auxv 对 [type,val]
auxv = sp + 0x1300
auxv_data = struct.pack('<QQ', 3, 0x550000)   # AT_PHDR=3 → 值 0x550000 (PHDR 在文件偏移64, VMA 0x550000+0x40? 实际 PHDR VMA = 0x550040)
auxv_data += struct.pack('<QQ', 4, 56)          # AT_PHENT
auxv_data += struct.pack('<QQ', 5, 3)           # AT_PHNUM
auxv_data += struct.pack('<QQ', 9, 0x77be7c)    # AT_ENTRY
auxv_data += struct.pack('<QQ', 0, 0)           # AT_NULL
mu.mem_write(auxv, auxv_data)
# argv 数组尾部放 NULL 然后 envp 指针（0），然后 auxv
# 简化：把 auxv 放在 argv 数组后面

# 写入口参数：x0=argc=1, x1=argv 数组, x2=envp, x3=auxv
# 但入口 0x77be7c 先 stp x0,x1 保存 → 从栈取 x1 扫描? 
# 0x77be7c: stp x0,x1,[sp,#-0x10]! → 保存 argc/argv
# 0x77be84: bl 0x77c190 → 扫描 argv/envp/auxv

def hook_svc(uc, intno, user_data):
    w8 = uc.reg_read(UC_ARM64_REG_W8)
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    x1 = uc.reg_read(UC_ARM64_REG_X1)
    x2 = uc.reg_read(UC_ARM64_REG_X2)
    x3 = uc.reg_read(UC_ARM64_REG_X3)
    x4 = uc.reg_read(UC_ARM64_REG_X4)
    x5 = uc.reg_read(UC_ARM64_REG_X5)
    pc = uc.reg_read(UC_ARM64_REG_PC)
    # print(f'  svc pc={pc:#x} w8={w8} x0={x0:#x} x1={x1:#x} x2={x2:#x} x3={x3:#x} x4={x4:#x}')
    if w8 == 56:      # openat → 返回 fd=3
        uc.reg_write(UC_ARM64_REG_X0, 3)
    elif w8 == 222:   # mmap → 返回 MMAP_RET（独立输出缓冲，RWX）
        # 真实调用: mmap(0, 0xaa4, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
        # 返回解密输出缓冲
        uc.reg_write(UC_ARM64_REG_X0, MMAP_RET)
    elif w8 == 226:   # mprotect → 0
        uc.reg_write(UC_ARM64_REG_X0, 0)
    elif w8 == 93:    # exit → 停
        uc.emu_stop()
    elif w8 == 64:    # write → 模拟输出? 返回 len
        uc.reg_write(UC_ARM64_REG_X0, x2)
    elif w8 == 222+1:
        pass
    else:
        # 其他 syscall 一律返回 0（静态分析不需要真实结果）
        uc.reg_write(UC_ARM64_REG_X0, 0)

mu.hook_add(UC_HOOK_INTR, hook_svc)

# 设置入口寄存器
mu.reg_write(UC_ARM64_REG_X0, 1)               # argc
mu.reg_write(UC_ARM64_REG_X1, argv_arr)        # argv
mu.reg_write(UC_ARM64_REG_X2, envp_arr)        # envp
mu.reg_write(UC_ARM64_REG_X3, auxv)            # auxv

# 执行入口 0x77be7c，最多跑 2000 万指令
try:
    mu.emu_start(0x77be7c, 0, count=20000000, timeout=30000)
except UcError as e:
    pc = mu.reg_read(UC_ARM64_REG_PC)
    print(f'UcError: {e} pc={pc:#x}')

pc = mu.reg_read(UC_ARM64_REG_PC)
x0 = mu.reg_read(UC_ARM64_REG_X0)
print(f'结束 pc={pc:#x} x0={x0:#x}')

# dump 可能的解密输出（br x0 目标附近）
for base in [MMAP_OUT, MMAP_SELF, MMAP_RET, x0 & ~0xfff]:
    try:
        buf = mu.mem_read(base, 0x10000)
        print(f'--- dump {base:#x}: 头部 {buf[:64].hex()}')
        # 搜字符串
        for kw in [b'boot', b'init_boot', b'recovery', b'persist', b'userdata', b'system',
                   b'vendor', b'by-name', b'mmcblk', b'sde', b'BLKZERO', b'BLKDISCARD',
                   b'/dev/block', b'wipe', b'format', b'erase']:
            idx = buf.find(kw)
            if idx >= 0:
                print(f'    HIT {kw!r} @ {idx:#x}: {buf[max(0,idx-20):idx+40]!r}')
    except UcError:
        pass