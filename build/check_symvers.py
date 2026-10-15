#!/usr/bin/env python3
"""合并多个 .symvers，对照需要的符号清单，输出仍缺失的符号。"""
import sys

NEED = {
    "__arch_copy_from_user",
    "__check_object_size",
    "__stack_chk_fail",
    "_printk",
    "_raw_spin_lock_irqsave",
    "_raw_spin_unlock_irqrestore",
    "alt_cb_patch_nops",
    "d_path",
    "fget",
    "fput",
    "kfree",
    "kmalloc_caches",
    "kmalloc_trace",
    "kstrdup",
    "memstart_addr",
    "memset",
    "param_ops_bool",
    "proc_create",
    "proc_mkdir",
    "register_kprobe",
    "remove_proc_entry",
    "seq_lseek",
    "seq_printf",
    "seq_read",
    "single_open",
    "single_release",
    "strcmp",
    "strlen",
    "strncmp",
    "strncpy_from_user",
    "system_cpucaps",
    "unregister_kprobe",
    "memcpy",
    "strscpy",
    "strncpy",
    "sprintf",
    "snprintf",
}

def read_map(path):
    m = {}
    try:
        for line in open(path):
            line = line.strip()
            if "\t" not in line:
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            m[parts[1]] = parts[0]
    except FileNotFoundError:
        pass
    return m

if __name__ == "__main__":
    all_map = {}
    for p in sys.argv[1:]:
        all_map.update(read_map(p))
    print("total collected symbols:", len(all_map))
    missing = [s for s in sorted(NEED) if s not in all_map]
    print("=== MISSING (%d) ===" % len(missing))
    for s in missing:
        print("  ", s)
    print("=== HELD ===")
    for s in sorted(NEED):
        if s in all_map:
            print("  0x%-10s %s" % (all_map[s], s))