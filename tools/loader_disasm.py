#!/usr/bin/env python3
# loader_disasm.py - 反汇编第一层解密器输出的 loader (2724B)，找第二层解密循环
from capstone import *
import re

d = open('/tmp/gj_dec_clean.bin', 'rb').read()
print('loader 大小:', len(d))

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

# 反汇编 0x14 起全部
print('=== loader 全量反汇编 ===')
insns = []
for ins in md.disasm(d[0x14:0xaa4], 0x22000014):
    insns.append(ins)
    print('%#x: %s\t%s' % (ins.address, ins.mnemonic, ins.op_str))

# 找所有分支目标（函数边界线索）
print('\n=== 分支目标统计 ===')
targets = {}
for ins in insns:
    if ins.mnemonic in ('bl', 'b', 'b.eq', 'b.ne', 'b.hs', 'b.lo', 'b.hi', 'b.ls', 'b.ge', 'b.lt', 'b.gt', 'b.le', 'br', 'blr'):
        if '#' in ins.op_str:
            t = int(ins.op_str.split('#')[1].split()[0] if ' ' in ins.op_str.split('#')[1] else ins.op_str.split('#')[1], 16)
            targets.setdefault(t, []).append((ins.address, ins.mnemonic))
for t, calls in sorted(targets.items()):
    print('  %#x <- %s' % (t, ', '.join('%#x:%s' % (a, m) for a, m in calls)))

# 找可疑常量 (ioctl 命令值)
print('\n=== 常量搜索 (BLK ioctl 命令) ===')
for val in [0x1277, 0x127D, 0x127F, 0x127C, 0xC0185875, 0x1261, 0x1260, 0x40081271]:
    pat = val.to_bytes(4, 'little')
    idx = d.find(pat)
    if idx >= 0:
        print('  %#x @ loader 偏移 %#x' % (val, idx))

# 字符串
print('\n=== loader 字符串 ===')
for m in re.finditer(rb'[\x20-\x7e]{4,}', d):
    print('  %#x: %r' % (m.start(), m.group().decode('latin1')))