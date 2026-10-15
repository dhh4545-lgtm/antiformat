/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 AntiFormat contributors
 *
 * mmuhack.c — 内核只读内存写权限切换 (aarch64, PTE hack)
 *
 * sys_call_table 位于只读 rodata 段。要改写它，需临时将对应页面的
 * 页表项改为可写，写入后再恢复只读并刷新 TLB。
 *
 * PRD_MODE_V3: 直接 hack PTE（适用于 CONFIG_STRICT_KERNEL_RWX）
 *
 * 参考: https://github.com/3intermute/arm64_silent_syscall_hook
 *       https://github.com/fuqiuluo/kernel-hook-syscalls
 *
 * License: GPL-3.0-or-later (见项目根 LICENSE)
 */
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/sched/mm.h>

#include "ksym.h"

#define PAGE_ALIGN_BOTTOM(addr) (PAGE_ALIGN(addr) - PAGE_SIZE)

/* update_mapping_prot 用于 V2 模式，这里不启用 */
static struct mm_struct *init_mm_ptr = NULL;

extern unsigned long my_kallsyms_lookup_name(const char *name);

/*
 * 通过 init_mm 页表遍历，取得虚拟地址对应的 pte 表项
 */
static pte_t *page_from_virt(uintptr_t addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;

	if ((unsigned long)addr & (PAGE_SIZE - 1))
		addr = (addr + PAGE_SIZE) & ~(PAGE_SIZE - 1);

	if (!init_mm_ptr) {
		init_mm_ptr = (struct mm_struct *)my_kallsyms_lookup_name("init_mm");
		if (!init_mm_ptr)
			return NULL;
	}

	pgd = pgd_offset(init_mm_ptr, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return NULL;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return NULL;
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		return NULL;
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return NULL;
	ptep = pte_offset_kernel(pmd, addr);
	return ptep;
}

/*
 * 自定义 set_pte_at（结合 icache/dcache 同步与 MTE 处理，
 * 兼容带 PAC/MTE 的 arm64 内核）
 */
static void my_set_pte_at(struct mm_struct *mm, unsigned long addr,
			  pte_t *ptep, pte_t pte)
{
	typedef void (*sync_icache_dcache_t)(pte_t pteval);
	typedef void (*mte_sync_tags_t)(pte_t pte, unsigned int nr_pages);
	static sync_icache_dcache_t sync_icache_dcache;
	static mte_sync_tags_t mte_sync_tags;

	if (!sync_icache_dcache)
		sync_icache_dcache = (sync_icache_dcache_t)
			my_kallsyms_lookup_name("__sync_icache_dcache");
	if (!mte_sync_tags)
		mte_sync_tags = (mte_sync_tags_t)
			my_kallsyms_lookup_name("mte_sync_tags");

	if (pte_present(pte) && pte_user_exec(pte) && !pte_special(pte))
		sync_icache_dcache(pte);

	if (system_supports_mte() && pte_access_permitted(pte, false) &&
	    !pte_special(pte) && pte_tagged(pte))
		mte_sync_tags(pte, 1);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	__check_safe_pte_update(mm, ptep, pte);
	__set_pte(ptep, pte);
#else
	/* 6.1: 使用 set_pte（内含 barrier） + __check_racy_pte_update */
	__check_racy_pte_update(mm, ptep, pte);
	set_pte(ptep, pte);
#endif
}

/*
 * 保护: 使 sys_call_table 对应页只读
 */
int protect_rodata_memory(unsigned long syscall_addr)
{
	unsigned long addr = (unsigned long)syscall_addr & PAGE_MASK;
	pte_t *ptep = page_from_virt(addr);
	pte_t pte;

	if (!ptep || !pte_valid(READ_ONCE(*ptep)))
		return -2;

	pte = READ_ONCE(*ptep);
	pte = pte_wrprotect(pte);
	my_set_pte_at(init_mm_ptr, addr, ptep, pte);
	__flush_tlb_kernel_pgtable(addr);
	return 0;
}

/*
 * 解锁: 使 sys_call_table 对应页可写
 */
int unprotect_rodata_memory(unsigned long syscall_addr)
{
	unsigned long addr = (unsigned long)syscall_addr & PAGE_MASK;
	pte_t *ptep = page_from_virt(addr);
	pte_t pte;

	if (!ptep || !pte_valid(READ_ONCE(*ptep)))
		return -2;

	pte = READ_ONCE(*ptep);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	pte = pte_mkwrite_novma(pte);
#else
	/* 6.1: pte_mkwrite 单参数版本 */
	pte = pte_mkwrite(pte);
#endif
	my_set_pte_at(init_mm_ptr, addr, ptep, pte);
	__flush_tlb_kernel_pgtable(addr);
	return 0;
}