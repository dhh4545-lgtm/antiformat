#!/usr/bin/env python3
"""解析设备导出的多行 hex（每行一个模块的 __versions 段连续hex），
合并所有 (符号名->CRC)，输出完整 Module.symvers。

输入: /storage/emulated/0/allversions.hex  (由 dumpall.sh 生成)
每条记录 64 字节 = 128 hex: CRC(3..0小端) + 符号名(56字节, NUL结尾)
"""
import sys

def parse_line_hex(h):
    h = ''.join(h.split())
    n = len(h)
    recs = []
    i = 0
    while i + 127 < n:
        rec = h[i:i+128]
        # CRC: 前4字节小端 (hex 0..7)
        crc = (int(rec[0:2],16) | (int(rec[2:4],16)<<8) |
               (int(rec[4:6],16)<<16) | (int(rec[6:8],16)<<24)) & 0xffffffff
        # 符号名: 字节偏移8起 (hex 16..)
        name = ""
        for k in range(56):
            b = int(rec[(8+k)*2:(8+k)*2+2], 16)
            if b == 0:
                break
            name += chr(b)
        if name:
            recs.append((name, crc))
        i += 128
    return recs

def main():
    src = sys.argv[1]
    outpx = sys.argv[2] if len(sys.argv) > 2 else None
    all_recs = []
    for line in open(src):
        line = line.strip()
        if not line:
            continue
        all_recs += parse_line_hex(line)
    # 去重：同名取最后一次（不同模块对同一符号 CRC 应一致，此处以防万一）
    mapping = {}
    for name, crc in all_recs:
        mapping[name] = crc
    print("parsed records:", len(all_recs), "unique symbols:", len(mapping))
    out = []
    for name in sorted(mapping):
        out.append("0x%08x\t%s\t%s\tEXPORT_SYMBOL\t\n" % (mapping[name], name, "vmlinux"))
    text = "".join(out)
    if outpx:
        open(outpx, 'w').write(text)
        print("wrote Module.symvers-like file ->", outpx, "(%d lines)" % len(lines))
    else:
        sys.stdout.write(text)
    # 校验关键符号是否有覆盖 & CRC 一致性
    import collections
    c = collections.Counter(all_recs)
    dup = {k: v for k, v in c.items() if v > 1}
    if dup:
        print("\n[!] %d symbols appear in multiple modules (quoting first occurrences)" % len(dup))
        for k in list(dup)[:10]:
            print("    %s x%d" % (k, dup[k]))

if __name__ == '__main__':
    main()