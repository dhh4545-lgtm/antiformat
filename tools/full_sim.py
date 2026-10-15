#!/usr/bin/env python3
# full_sim.py - 完整模拟格机V13.2 执行链，记录所有 openat 路径 + syscall
# 静态分析：所有可能破坏分区的系统调用参数全记录，但不真实执行
import struct, sys
from unicorn import *
from unicorn.arm64_const import *

BIN = '/tmp/gj_v13.bin'
BASE = 0x550000
LOAD2_SZ = 0x22c9ca
STACK_TOP = 0x40000000
MMAP_RET  = 0x22000000   # 解密输出缓冲（RWX）
MMAP_SELF = 0x21000000

data = open(BIN, 'rb').read()
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

mu.mem_map(BASE, 0x400000)
mu.mem_write(BASE, data[:LOAD2_SZ])
mu.mem_map(0, 0x1000)
mu.mem_write(0, data[:0x1000])
mu.mem_map(STACK_TOP - 0x100000, 0x100000)
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

syscall_log = []
fd_offset = {3: 0}   # 模拟 fd=3 → /proc/self/exe 的读偏移
next_fd = 4          # 后续 openat 分配的 fd 从 4 开始

def hook_svc(uc, intno, user_data):
    global fd_offset
    w8 = uc.reg_read(UC_ARM64_REG_W8)
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    x1 = uc.reg_read(UC_ARM64_REG_X1)
    x2 = uc.reg_read(UC_ARM64_REG_X2)
    x3 = uc.reg_read(UC_ARM64_REG_X3)
    x4 = uc.reg_read(UC_ARM64_REG_X4)
    pc = uc.reg_read(UC_ARM64_REG_PC)
    # 读路径字符串 (openat 的 x1)
    path_str = b''
    if w8 == 56:  # openat
        try:
            path_str = bytes(mu.mem_read(x1, 256)).split(b'\x00')[0]
        except Exception:
            path_str = b'?'
        syscall_log.append(('openat', pc, x0, path_str, x2))
        print(f'  [openat] pc={pc:#x} dirfd={x0:#x} path={path_str!r} flags={x2:#x}')
        # 记录 fd 分配
        global next_fd
        fd = next_fd
        next_fd += 1
        fd_offset[fd] = 0
        uc.reg_write(UC_ARM64_REG_X0, fd)
    elif w8 == 222:  # mmap
        uc.reg_write(UC_ARM64_REG_X0, MMAP_RET)
    elif w8 == 226:  # mprotect
        uc.reg_write(UC_ARM64_REG_X0, 0)
    elif w8 == 29:   # ioctl
        syscall_log.append(('ioctl', pc, x0, x1, x2))
        uc.reg_write(UC_ARM64_REG_X0, 0)
    elif w8 == 64:   # write
        syscall_log.append(('write', pc, x0, x1, x2))
        uc.reg_write(UC_ARM64_REG_X0, x2)
    elif w8 == 78:   # readlink → 返回假路径
        # x0=path, x1=buf, x2=size
        fake = b'/system/bin/app_process64'
        try:
            mu.mem_write(x1, fake)
        except Exception:
            pass
        uc.reg_write(UC_ARM64_REG_X0, len(fake))
    elif w8 == 93:   # exit → 不退出，继续执行（跳过自校验）
        syscall_log.append(('exit', pc, x0, 0, 0))
        # 不 emu_stop，直接返回 0
        uc.reg_write(UC_ARM64_REG_X0, 0)
    elif w8 == 63:   # read → 从 fd 模拟读
        # x0=fd, x1=buf, x2=count
        fd = x0
        if fd in fd_offset:
            try:
                off = fd_offset.get(fd, 0)
                avail = len(data) - off
                if avail <= 0:
                    uc.reg_write(UC_ARM64_REG_X0, 0)
                    return
                chunk = bytes(mu.mem_read(MMAP_SELF + off, min(x2, avail)))
                mu.mem_write(x1, chunk)
                fd_offset[fd] = off + len(chunk)
                uc.reg_write(UC_ARM64_REG_X0, len(chunk))
                # print(f'  [read] fd={fd} off={off:#x} n={len(chunk)} pc={pc:#x}')
            except Exception:
                uc.reg_write(UC_ARM64_REG_X0, 0)
        else:
            uc.reg_write(UC_ARM64_REG_X0, 0)
    elif w8 == 62:   # lseek → 模拟设置偏移
        # x0=fd, x1=offset, x2=whence
        fd = x0
        if fd == 3:
            if x2 == 0:
                fd_offset[fd] = x1
            elif x2 == 1:
                fd_offset[fd] = fd_offset.get(fd, 0) + x1
            elif x2 == 2:
                fd_offset[fd] = len(data) + x1
            uc.reg_write(UC_ARM64_REG_X0, fd_offset.get(fd, 0))
        else:
            uc.reg_write(UC_ARM64_REG_X0, 0)
    else:
        syscall_log.append((f'sys_{w8}', pc, x0, x1, x2))
        uc.reg_write(UC_ARM64_REG_X0, 0)
        # 打印所有 syscall（限制频率防刷屏）
        if len(syscall_log) < 2000:
            print(f'  sys_{w8} pc={pc:#x} a={x0:#x} b={x1:#x} c={x2:#x}')

mu.hook_add(UC_HOOK_INTR, hook_svc)
mu.reg_write(UC_ARM64_REG_X0, 1)
mu.reg_write(UC_ARM64_REG_X1, argv_arr)
mu.reg_write(UC_ARM64_REG_X2, envp_arr)
mu.reg_write(UC_ARM64_REG_X3, auxv)

try:
    mu.emu_start(0x77be7c, 0, count=50000000, timeout=60000)
except UcError as e:
    pc = mu.reg_read(UC_ARM64_REG_PC)
    print(f'UcError: {e} pc={pc:#x}')

pc = mu.reg_read(UC_ARM64_REG_PC)
print(f'结束 pc={pc:#x} x0={mu.reg_read(UC_ARM64_REG_X0):#x}')

print(f'\n=== syscall 日志 ({len(syscall_log)}) ===')
openat_count = 0
ioctl_count = 0
write_count = 0
for name, pc, a, b, c in syscall_log:
    if name == 'openat':
        openat_count += 1
        print(f'  openat pc={pc:#x} dirfd={a:#x} path={b!r} flags={c:#x}')
    elif name == 'ioctl':
        ioctl_count += 1
        print(f'  ioctl pc={pc:#x} fd={a:#x} cmd={b:#x} arg={c:#x}')
    elif name == 'write':
        write_count += 1
        print(f'  write pc={pc:#x} fd={a:#x} buf={b:#x} len={c:#x}')
print(f'\n统计: openat={openat_count} ioctl={ioctl_count} write={write_count} 其他={len(syscall_log)-openat_count-ioctl_count-write_count}')

# 保存解密输出
out = bytes(mu.mem_read(MMAP_RET, 0x10000))
open('/tmp/gj_v13_dec.bin', 'wb').write(out)
print(f'\n解密输出保存 /tmp/gj_v13_dec.bin')