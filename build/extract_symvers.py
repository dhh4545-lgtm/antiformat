#!/usr/bin/env python3
"""
从设备内核模块的 __versions 段提取 (符号名 -> CRC) 映射，并输出 Module.symvers 格式。
设备模块由设备内核同一套 Module.symvers 构建，因此其 __versions 中记录的
导出符号 CRC 与设备运行内核保持一致 —— 可直接用于构造匹配的 Module.symvers。

__versions 每条记录 = struct modversion_info {
    unsigned long crc;      // 8 字节，实际有效为低 4 字节（kbuild genksyms 产生 32 位 CRC）
    char name[MODULE_NAME_LEN]; // 56 字节
};                             // 合计 64 字节
"""
import sys, os

def parse_hex_file(hexpath):
    """hex 文件由 `od -v -An -tx1 xxx | tr -d ' \\n'` 生成，每字节2hex连续。"""
    h = open(hexpath).read().strip()
    # 去掉可能的空格/回车残留
    h = ''.join(h.split())
    recs = []
    for i in range(0, len(h) - 127, 128):
        rec = h[i:i+128]
        # CRC: 前 4 字节小端
        crc_bytes = [int(rec[j*2:j*2+2], 16) for j in range(4)]
        crc = (crc_bytes[0] | (crc_bytes[1]<<8) | (crc_bytes[2]<<16) | (crc_bytes[3]<<24)) & 0xffffffff
        # 符号名: 字节偏移8起，最56字节
        name_bytes = bytes(int(rec[(8+k)*2:(8+k)*2+2], 16) or 0x00 for k in range(56))
        name = name_bytes.split(b'\x00')[0].decode('utf-8', 'replace').strip()
        if name:
            recs.append((name, crc))
    return recs

def main():
    inhex = sys.argv[1]
    outpath = sys.argv[2] if len(sys.argv) > 2 else None
    recs = parse_hex_file(inhex)
    # 去重（同名取最后一次）
    mapping = {}
    for name, crc in recs:
        mapping[name] = crc
    lines = []
    for name in sorted(mapping):
        lines.append("0x%08x\t%s\tvmlinux\tEXPORT_SYMBOL" % (mapping[name], name))
    text = "\n".join(lines) + "\n"
    if outpath:
        open(outpath, 'w').write(text)
        print("wrote %d symbols -> %s" % (len(mapping), outpath))
    else:
        sys.stdout.write(text)
    # 额外打印特殊关心的符号，方便人工核对
    print("--- key symbols ---", file=sys.stderr)
    for want in ("_printk","kfree","kmalloc_caches","kmalloc_trace",
                 "strncpy_from_user","proc_create","proc_mkdir",
                 "remove_proc_entry","_raw_spin_lock_irqsave",
                 "_raw_spin_unlock_irqrestore","_debug_locks_off",
                 "__might_fault","__counted_by","__flush_icache_range",
                 "set_memory_ro","set_memory_rw","set_memory_x","set_memory_nx"):
        print("%-28s %s" % (want, ("0x%08x"%mapping[want]) if want in mapping else "(missing)"), file=sys.stderr)

if __name__ == '__main__':
    main()