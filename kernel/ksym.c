/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 AntiFormat contributors
 *
 * ksym.c — 内核符号解析
 *
 * 通过 kprobe 注册 "kallsyms_lookup_name" 获取其真实地址后调用之，
 * 以绕过 GKI 6.6 未导出符号的限制。
 *
 * 参考: https://github.com/fuqiuluo/kernel-hook-syscalls (Arm64 6.6)
 *
 * License: GPL-3.0-or-later (见项目根 LICENSE)
 */
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t lookup_name = NULL;

/* 解析任意内核符号地址（0 表示失败） */
unsigned long my_kallsyms_lookup_name(const char *symbol_name)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name"
	};

	if (lookup_name == NULL) {
		if (register_kprobe(&kp) < 0)
			return 0;
		lookup_name = (kallsyms_lookup_name_t)kp.addr;
		unregister_kprobe(&kp);
	}
	if (!lookup_name)
		return 0;
	return lookup_name(symbol_name);
#else
	extern unsigned long kallsyms_lookup_name(const char *name);
	return kallsyms_lookup_name(symbol_name);
#endif
}

/* 解析 sys_call_table 地址 */
static void **syscall_table_ptr = NULL;

void **find_syscall_table(void)
{
	if (!syscall_table_ptr)
		syscall_table_ptr = (void **)my_kallsyms_lookup_name("sys_call_table");
	return syscall_table_ptr;
}