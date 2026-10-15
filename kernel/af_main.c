/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 AntiFormat contributors
 *
 * antiformat.c — Android 防格机内核模块 (第一阶段)
 *
 * 防止对受保护目录/分区执行格式化、删除、覆盖、截断等破坏性操作。
 *
 * 平台: GKI 6.6 aarch64 / KernelSU
 * 技术: sys_call_table hook via pt_regs (arm64),
 *       kprobe 符号解析, PTE hack 切换 rodata 读写
 *
 * 参考 syscall-hook 项目: https://github.com/fuqiuluo/kernel-hook-syscalls
 *
 * License: GPL-3.0-or-later (见项目根 LICENSE)
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/spinlock.h>
#include <linux/ptrace.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>
#include <linux/stop_machine.h>
#include <linux/rcupdate.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/kstrtox.h>
#include <asm/unistd.h>

#include "ksym.h"

/* GKI 未导出的符号, 通过 kallsyms 运行时解析 */
static int (*kern_path_p)(const char *, unsigned int, struct path *) = NULL;
static void (*path_put_p)(const struct path *) = NULL;

static void resolve_vfs_symbols(void)
{
	if (!kern_path_p)
		kern_path_p = (int (*)(const char *, unsigned int, struct path *))
			my_kallsyms_lookup_name("kern_path");
	if (!path_put_p)
		path_put_p = (void (*)(const struct path *))
			my_kallsyms_lookup_name("path_put");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("operit");
MODULE_DESCRIPTION("AntiFormat - device destructive-operation protection (phase 1)");
MODULE_VERSION("0.1.0");
/* 导入空命名空间: 兼容 GKI 符号命名空间检查 (vmlinux EXPORT_SYMBOL 无 ns) */
MODULE_IMPORT_NS("");

/* ================================================================ */
/* syscall 编号 (arm64 / asm-generic)                                */
/* ================================================================ */
#define __NR_AF_IOCTL     29
#define __NR_AF_UNLINKAT  35
#define __NR_AF_TRUNCATE  45
#define __NR_AF_FTRUNCATE 46
#define __NR_AF_FALLOCATE 47
#define __NR_AF_RENAMEAT  38
#define __NR_AF_UMOUNT2   39
#define __NR_AF_MOUNT     40
#define __NR_AF_OPENAT    56
#define __NR_AF_WRITE     64
#define __NR_AF_PWRITE64  68
#define __NR_AF_SWAPON    224
#define __NR_AF_SWAPOFF   225
#define __NR_AF_RENAMEAT2 276
#define __NR_AF_PTRACE    117
#define __NR_AF_KILL      129
#define __NR_AF_TKILL     130
#define __NR_AF_TGKILL    131

#define AT_REMOVEDIR    0x200

/* ================================================================ */
/* 受保护路径配置                                                     */
/* ================================================================ */
#define MAX_PROTECT      256
#define PATHLEN          256

static char *protect_paths[MAX_PROTECT];
static dev_t protect_devs[MAX_PROTECT]; /* 保护路径解析出的块设备号 (0=未解析) */
static int nr_protected;
static DEFINE_SPINLOCK(protect_lock);

/* 默认保护开关 */
static bool block_unlink  = true; /* 删除/重命名 */
static bool block_open_w  = true; /* 以写方式打开 */
static bool block_ioctl   = true; /* 格式化相关 ioctl */
static bool block_write   = true; /* 直接写块设备 */
static bool block_mount   = true; /* 挂载/卸载（防重新挂载绕过） */

module_param(block_unlink, bool, 0644);
module_param(block_open_w, bool, 0644);
module_param(block_ioctl,  bool, 0644);
module_param(block_write,  bool, 0644);
module_param(block_mount,  bool, 0644);

/* ================================================================ */
/* 极端模式: 任何进程(含 root)不能打开 /dev/block/ 下设备, 白名单例外  */
/* 白名单编译期内定, 无任何运行时修改接口(恶意程序无法篡改)            */
/* ================================================================ */
static bool extreme_mode = true;
module_param(extreme_mode, bool, 0644);

/* 判断路径是否 /dev/block 或 /dev/ 下裸块设备 */
static bool path_is_block_dev(const char *path)
{
	if (!path)
		return false;
	/* /dev/block 前缀 */
	if (strncmp(path, "/dev/block", 10) == 0 &&
	    (path[10] == '\0' || path[10] == '/'))
		return true;
	/* /dev/ 下裸块设备节点 (mmcblk0, sda, sdX, nvme, dm- 等) */
	if (strncmp(path, "/dev/", 5) == 0) {
		const char *b = path + 5;
		if (strncmp(b, "mmcblk", 6) == 0 ||
		    strncmp(b, "sda", 3) == 0 ||
		    strncmp(b, "sdb", 3) == 0 ||
		    strncmp(b, "sdc", 3) == 0 ||
		    strncmp(b, "sdd", 3) == 0 ||
		    strncmp(b, "sd", 2) == 0 ||
		    strncmp(b, "nvme", 4) == 0 ||
		    strncmp(b, "dm-", 3) == 0)
			return true;
	}
	return false;
}

/* 编译期内定白名单 (comm 精确匹配; 不可运行时修改) */
#define WL_MAX  96
#define WL_LEN  32
static char wl_comm[WL_MAX][WL_LEN];
static int  wl_count;
static DEFINE_SPINLOCK(wl_lock);

/* 系统进程白名单: 仅保留"必须访问块设备"的系统组件 + 守护 afd */
static const char *const wl_default[] = {
	"afd",           /* 守护进程: 管理加载/卸载/验证 */
	"vold",          /* 卷管理守护: 挂载/分区/加密 */
	"qseecomd",      /* 高通 secure world 通信 */
	"keystore2",     /* keystore 服务 */
	"fsck",          /* 文件系统检查 */
	"e2fsck",        /* ext4 fsck */
	"init",          /* init 进程 (早期挂载) */
	"ueventd",       /* 设备节点管理 (mknod /dev/block) */
	"zygote",        /* 应用孵化 */
	"system_server", /* 系统核心服务 */
	"servicemanager",/* 服务管理 */
	"surfaceflinger",/* 显示服务 */
	"audioserver",   /* 音频服务 */
	"cameraserver",  /* 相机服务 */
	"media",         /* media 服务 */
	"mediaextractor",/* 媒体提取 */
	"mediaserver",   /* 媒体服务 */
	"logd",          /* 日志守护 */
	"lmkd",          /* 内存管理 */
	"healthd",       /* 电池健康 */
	"installd",      /* 安装服务 */
	"dex2oat",       /* dex 编译 */
	"apexd",         /* apex 管理 */
	"statsd",        /* 统计 */
	"netd",          /* 网络守护 (可能读 block) */
	"mdnsd",         /* mDNS */
	"wificond",      /* WiFi 控制 */
	"wpa_supplicant",/* WiFi */
	"bluetooth",     /* 蓝牙 */
	"gatekeeperd",   /* gatekeeper */
	"thermalservice",/* 温控 */
	"vendor.thermal",/* 厂商温控 */
	"vibrator",      /* 振动 */
	"sensorservice", /* 传感器 */
	"powerservice",  /* 电源 */
	"batteryservice",/* 电池 */
	"dumpsys",       /* 系统 dump */
	"tombstoned",    /* tombstone */
	"crash_dump32",  /* crash dump */
	"crash_dump64",
	"perfprofd",     /* perf */
	"traced",        /* tracing */
	"traced_probes",
	"lldb-server",   /* 调试 (只读) */
	"app_process",   /* app 进程 */
	"sh",            /* shell (受限, 但需允许基本操作) */
	"toolbox",       /* toolbox 工具 */
	"toybox",        /* toybox 工具 */
};

static void load_default_whitelist(void)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(wl_default); i++) {
		if (wl_count >= WL_MAX)
			break;
		strscpy(wl_comm[wl_count], wl_default[i], WL_LEN);
		wl_count++;
	}
	pr_info("[antiformat] whitelist loaded: %d entries\n", wl_count);
}

/* 当前进程是否在白名单 (comm 匹配) */
static bool proc_is_whitelisted(void)
{
	struct task_struct *task = current;
	char comm[TASK_COMM_LEN];
	int i;
	unsigned long flags;
	bool hit = false;

	/* 内核线程直接放行 (非用户态打开路径) */
	if (task->flags & PF_KTHREAD)
		return true;

	get_task_comm(comm, task);

	spin_lock_irqsave(&wl_lock, flags);
	for (i = 0; i < wl_count; i++) {
		if (strcmp(comm, wl_comm[i]) == 0) {
			hit = true;
			break;
		}
	}
	spin_unlock_irqrestore(&wl_lock, flags);
	return hit;
}

/* ================================================================ */
/* 路径匹配                                                           */
/* ================================================================ */
static bool path_protected(const char *path)
{
	int i;
	bool hit = false;
	unsigned long flags;

	if (!path || !path[0])
		return false;

	spin_lock_irqsave(&protect_lock, flags);
	for (i = 0; i < nr_protected; i++) {
		const char *p = protect_paths[i];
		size_t len = p ? strlen(p) : 0;
		if (!len)
			continue;
		/* 前缀匹配：完全相等 或 以 p/ 开头 */
		if (strncmp(path, p, len) == 0 &&
		    (path[len] == '\0' || path[len] == '/')) {
			hit = true;
			break;
		}
	}
	spin_unlock_irqrestore(&protect_lock, flags);
	return hit;
}

/* 从用户态指针读路径 */
static bool user_path_is_protected(const char __user *user_path)
{
	char *kbuf;
	bool hit = false;

	if (!user_path)
		return false;

	kbuf = kmalloc(PATHLEN, GFP_KERNEL);
	if (!kbuf)
		return false;

	if (copy_from_user(kbuf, user_path, PATHLEN - 1) == 0) {
		kbuf[PATHLEN - 1] = '\0';
		hit = path_protected(kbuf);
	}
	kfree(kbuf);
	return hit;
}

/* 根据 fd 解析实际路径并判断是否受保护 */
static bool fd_is_protected(unsigned int fd)
{
	struct file *filp;
	bool hit = false;
	char *buf;
	char *p;

	filp = fget(fd);
	if (!filp)
		return false;

	buf = kmalloc(PATHLEN, GFP_KERNEL);
	if (!buf) {
		fput(filp);
		return false;
	}

	p = d_path(&filp->f_path, buf, PATHLEN);
	if (!IS_ERR(p))
		hit = path_protected(p);

	kfree(buf);
	fput(filp);
	return hit;
}

/* dev_t 是否在保护列表 (按设备号匹配, 解决别名问题) */
static bool dev_is_protected(dev_t d)
{
	int i;
	unsigned long flags;
	bool hit = false;

	if (!d)
		return false;

	spin_lock_irqsave(&protect_lock, flags);
	for (i = 0; i < nr_protected; i++) {
		if (protect_devs[i] && protect_devs[i] == d) {
			hit = true;
			break;
		}
	}
	spin_unlock_irqrestore(&protect_lock, flags);
	return hit;
}

/* 根据 fd 解析 dev_t 并判断是否受保护 (块设备) */
static bool fd_is_protected_dev(unsigned int fd)
{
	struct file *filp;
	bool ret = false;

	filp = fget(fd);
	if (!filp)
		return false;
	if (filp->f_path.dentry) {
		struct inode *in = d_inode(filp->f_path.dentry);
		if (in && S_ISBLK(in->i_mode))
			ret = dev_is_protected(in->i_rdev);
	}
	fput(filp);
	return ret;
}

/* 根据 fd 判断是否块设备 (极端模式: 拦一切块设备 fd 操作) */
static bool fd_is_block_dev(unsigned int fd)
{
	struct file *filp;
	bool ret = false;

	filp = fget(fd);
	if (!filp)
		return false;
	if (filp->f_path.dentry) {
		struct inode *in = d_inode(filp->f_path.dentry);
		if (in && S_ISBLK(in->i_mode))
			ret = true;
	}
	fput(filp);
	return ret;
}

/* 根据用户路径字符串解析 dev_t 并判断是否受保护 (块设备) */
static bool user_path_is_protected_dev(const char __user *user_path)
{
	char *kbuf;
	bool hit = false;
	struct path pp;

	if (!user_path)
		return false;

	kbuf = kmalloc(PATHLEN, GFP_KERNEL);
	if (!kbuf)
		return false;

	if (copy_from_user(kbuf, user_path, PATHLEN - 1) != 0) {
		kfree(kbuf);
		return false;
	}
	kbuf[PATHLEN - 1] = '\0';

	if (kern_path_p && kern_path_p(kbuf, LOOKUP_FOLLOW, &pp) == 0) {
		struct inode *in = d_backing_inode(pp.dentry);
		if (in && S_ISBLK(in->i_mode))
			hit = dev_is_protected(in->i_rdev);
		if (path_put_p)
			path_put_p(&pp);
	}
	kfree(kbuf);
	return hit;
}

/* ================================================================ */
/* afd 守护进程保护: 注册 pid, 阻止对其 kill/tgkill/tkill/ptrace      */
/* ================================================================ */
static int afd_pid = -1;
static DEFINE_SPINLOCK(afd_lock);
static bool afd_registered = false;

/* 守护进程受保护: 返回 true 表示被保护 */
static bool pid_is_afd(int pid)
{
	bool hit = false;
	unsigned long flags;

	spin_lock_irqsave(&afd_lock, flags);
	if (afd_registered && pid == afd_pid)
		hit = true;
	spin_unlock_irqrestore(&afd_lock, flags);
	return hit;
}

/* 根据用户路径字符串判断是否块设备路径 (极端模式)
 * 注意: 目录也必须拦! 因为 openat(dirfd, "相对路径") 可绕过前缀检查:
 *   先 open("/dev/block/by-name", O_DIRECTORY) 拿 dirfd,
 *   再 openat(dirfd, "userdata", O_RDWR) -> 相对路径不匹配 /dev/block 前缀.
 * 所以: 只要字符串命中设备模式(含目录路径本身)就拦, 防止拿 dirfd. */
static bool user_path_is_block_dev(const char __user *user_path)
{
	char *kbuf;
	bool hit = false;

	if (!user_path)
		return false;

	kbuf = kmalloc(PATHLEN, GFP_KERNEL);
	if (!kbuf)
		return false;

	if (copy_from_user(kbuf, user_path, PATHLEN - 1) == 0) {
		kbuf[PATHLEN - 1] = '\0';
		hit = path_is_block_dev(kbuf);
	}
	kfree(kbuf);
	return hit;
}

/* 判断路径是否 /proc/<afd_pid>/mem|maps|environ|auxv|syscall 等敏感文件 */
static bool path_is_afd_proc(const char *path)
{
	char buf[64];
	const char *rest;
	int n;
	int pid;
	unsigned long flags;

	if (!path || strncmp(path, "/proc/", 6) != 0)
		return false;

	spin_lock_irqsave(&afd_lock, flags);
	if (!afd_registered) {
		spin_unlock_irqrestore(&afd_lock, flags);
		return false;
	}
	pid = afd_pid;
	spin_unlock_irqrestore(&afd_lock, flags);

	n = snprintf(buf, sizeof(buf), "/proc/%d/", pid);
	if (strncmp(path, buf, n) != 0)
		return false;

	rest = path + n;
	if (strcmp(rest, "mem") == 0 ||
	    strcmp(rest, "maps") == 0 ||
	    strcmp(rest, "environ") == 0 ||
	    strcmp(rest, "auxv") == 0 ||
	    strcmp(rest, "syscall") == 0 ||
	    strcmp(rest, "cmdline") == 0 ||
	    strcmp(rest, "stat") == 0)
		return true;
	return false;
}

static bool user_path_is_afd_proc(const char __user *user_path)
{
	char *kbuf;
	bool hit = false;

	if (!user_path)
		return false;

	kbuf = kmalloc(PATHLEN, GFP_KERNEL);
	if (!kbuf)
		return false;

	if (copy_from_user(kbuf, user_path, PATHLEN - 1) == 0) {
		kbuf[PATHLEN - 1] = '\0';
		hit = path_is_afd_proc(kbuf);
	}
	kfree(kbuf);
	return hit;
}

/* 根据 dirfd 解析实际路径, 判断是否在 /dev/block 下 (防 openat 相对路径绕过) */
static bool dirfd_is_block_dir(unsigned int dirfd)
{
	struct file *filp;
	bool hit = false;
	char *buf;
	char *p;

	if (dirfd == AT_FDCWD)
		return false;

	filp = fget(dirfd);
	if (!filp)
		return false;

	buf = kmalloc(PATHLEN, GFP_KERNEL);
	if (!buf) {
		fput(filp);
		return false;
	}

	p = d_path(&filp->f_path, buf, PATHLEN);
	if (!IS_ERR(p)) {
		/* dirfd 指向 /dev/block 或 /dev/ 下任意节点 (含目录) */
		hit = path_is_block_dev(p);
	}
	kfree(buf);
	fput(filp);
	return hit;
}

/* ================================================================ */
/* syscall hook 定义 (arm64: long fn(const struct pt_regs*))         */
/* ================================================================ */
typedef long (*syscall_fn_t)(const struct pt_regs *regs);

/*
 * 卸载竞态终极修复: hook 执行引用计数
 *
 * 背景: rmmod 时即使 stop_machine 原子还原了 sys_call_table,
 * 其他 CPU 上正在执行 hook 的线程只是被"暂停"而非"退出";
 * 模块内存释放后, 这些线程恢复执行 -> 跳到已释放内存 -> panic.
 * synchronize_rcu() 无效, 因为 syscall hook 路径不持有 RCU 读锁.
 *
 * 方案: 每个 hook 入口 atomic_inc, 出口 atomic_dec.
 * 卸载时 stop_machine 还原表后, 自旋等待 hook_active 归零
 * (所有执行者已真正退出模块代码), 才允许释放模块内存.
 */
static atomic_t hook_active = ATOMIC_INIT(0);

/*
 * disabled: 逻辑卸载标志.
 * key 解锁后置 1, 所有 hook 入口直接放行 orig, 防护逻辑失效.
 * 模块内存永不释放 (refcount 钉死), 因此正在执行的 hook 永远
 * 能安全跑完, 不存在"跳转到已释放内存"的死机竞态.
 */
static bool af_disabled = false;

/* 每个 hook 入口调用: 若已逻辑卸载则直接放行 (由调用方负责 return orig) */
#define HOOK_ENTER() atomic_inc(&hook_active)
#define HOOK_EXIT()  atomic_dec(&hook_active)

/* 逻辑卸载快速通道: 返回 true 表示应直接放行 orig */
#define HOOK_DISABLED() (unlikely(READ_ONCE(af_disabled)))

/* 原始函数指针（存放在 sys_call_table 中） */
static syscall_fn_t orig_unlinkat;
static syscall_fn_t orig_truncate;
static syscall_fn_t orig_ftruncate;
static syscall_fn_t orig_fallocate;
static syscall_fn_t orig_renameat;
static syscall_fn_t orig_renameat2;
static syscall_fn_t orig_openat;
static syscall_fn_t orig_ioctl;
static syscall_fn_t orig_write;
static syscall_fn_t orig_pwrite64;
static syscall_fn_t orig_mount;
static syscall_fn_t orig_umount2;
static syscall_fn_t orig_kill;
static syscall_fn_t orig_tkill;
static syscall_fn_t orig_tgkill;
static syscall_fn_t orig_ptrace;

/* ---- 记录路径（仅调试日志用） ---- */
static char *get_user_str(const char __user *p)
{
	char *buf;

	if (!p)
		return NULL;
	buf = kmalloc(PATHLEN, GFP_KERNEL);
	if (!buf)
		return NULL;
	if (copy_from_user(buf, p, PATHLEN - 1) != 0) {
		kfree(buf);
		return NULL;
	}
	buf[PATHLEN - 1] = '\0';
	return buf;
}

/* ---- truncate: 按路径截断清空 ---- */
static long hook_truncate(const struct pt_regs *regs)
{
	const char __user *path = (const char __user *)regs->regs[0];

	if (HOOK_DISABLED())
		return orig_truncate(regs);
	HOOK_ENTER();
	if (block_unlink && user_path_is_protected(path)) {
		char *s = get_user_str(path);
		pr_warn("[antiformat] BLOCK truncate: %s\n", s ? s : "?");
		kfree(s);
		HOOK_EXIT();
		return -EPERM;
	}
	HOOK_EXIT();
	return orig_truncate(regs);
}

/* ---- ftruncate: 按 fd 截断清空 ---- */
static long hook_ftruncate(const struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];

	if (HOOK_DISABLED())
		return orig_ftruncate(regs);
	HOOK_ENTER();
	if (block_write && fd_is_protected(fd)) {
		HOOK_EXIT();
		return -EPERM;
	}
	HOOK_EXIT();
	return orig_ftruncate(regs);
}

/* ---- fallocate: 预分配/覆盖 文件块 ---- */
static long hook_fallocate(const struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];

	if (HOOK_DISABLED())
		return orig_fallocate(regs);
	HOOK_ENTER();
	if (block_write && fd_is_protected(fd)) {
		HOOK_EXIT();
		return -EPERM;
	}
	HOOK_EXIT();
	return orig_fallocate(regs);
}

/* ---- unlinkat: rm 文件 / rmdir (AT_REMOVEDIR) ---- */
static long hook_unlinkat(const struct pt_regs *regs)
{
	const char __user *pathname = (const char __user *)regs->regs[1];

	if (HOOK_DISABLED())
		return orig_unlinkat(regs);
	HOOK_ENTER();
	if (block_unlink && user_path_is_protected(pathname)) {
		char *s = get_user_str(pathname);
		pr_warn("[antiformat] BLOCK unlinkat: %s\n",
			s ? s : "?");
		kfree(s);
		HOOK_EXIT();
		return -EPERM;
	}
	HOOK_EXIT();
	return orig_unlinkat(regs);
}

/* ---- renameat / renameat2: mv 覆盖 ---- */
static long hook_renameat(const struct pt_regs *regs)
{
	const char __user *old = (const char __user *)regs->regs[1];
	const char __user *new_ = (const char __user *)regs->regs[3];

	if (HOOK_DISABLED())
		return orig_renameat(regs);
	HOOK_ENTER();
	if (block_unlink &&
	    (user_path_is_protected(old) || user_path_is_protected(new_))) {
		HOOK_EXIT();
		return -EPERM;
	}
	HOOK_EXIT();
	return orig_renameat(regs);
}

static long hook_renameat2(const struct pt_regs *regs)
{
	const char __user *old = (const char __user *)regs->regs[1];
	const char __user *new_ = (const char __user *)regs->regs[3];

	if (HOOK_DISABLED())
		return orig_renameat2(regs);
	HOOK_ENTER();
	if (block_unlink &&
	    (user_path_is_protected(old) || user_path_is_protected(new_))) {
		HOOK_EXIT();
		return -EPERM;
	}
	HOOK_EXIT();
	return orig_renameat2(regs);
}

/* ---- openat: 极端模式 -> 任何进程(含 root)不能打开 /dev/block 下设备 ----
 * 白名单进程 (编译期内定) 除外。格机工具用 root 打开块设备,
 * 即使以 O_RDONLY 打开也会被拦 (因为 ioctl BLKZEROOUT 可只读打开后擦除)。
 * 防 openat(dirfd, 相对路径) 绕过: dirfd 指向 /dev/block 时也拦。 */
static long hook_openat(const struct pt_regs *regs)
{
	unsigned int dirfd = (unsigned int)regs->regs[0];
	const char __user *filename = (const char __user *)regs->regs[1];
	int flags = (int)regs->regs[2];
	int acc = flags & O_ACCMODE;

	if (HOOK_DISABLED())
		return orig_openat(regs);
	HOOK_ENTER();

	/* 极端模式: 拦所有对块设备路径的 open (含只读) */
	if (extreme_mode) {
		/* 任何进程都不能读 afd 敏感 proc (防偷 key) */
		if (user_path_is_afd_proc(filename)) {
			char *s = get_user_str(filename);
			pr_warn("[antiformat] BLOCK afd proc access: %s (comm=%s)\n",
				s ? s : "?", current->comm);
			kfree(s);
			HOOK_EXIT();
			return -EPERM;
		}
		/* 白名单进程放行块设备 */
		if (!proc_is_whitelisted()) {
			if (user_path_is_block_dev(filename) ||
			    dirfd_is_block_dir(dirfd)) {
				char *s = get_user_str(filename);
				pr_warn("[antiformat] EXTREME BLOCK open: %s (comm=%s dirfd=%u)\n",
					s ? s : "?", current->comm, dirfd);
				kfree(s);
				HOOK_EXIT();
				return -EPERM;
			}
		}
		HOOK_EXIT();
		return orig_openat(regs);
	}

	/* 非极端模式: 保持原有写/截断打开保护 */
	if (block_open_w &&
	    (acc != O_RDONLY || (flags & (O_TRUNC | O_APPEND | O_CREAT)))) {
		/* 1) 受保护路径 (前缀匹配) */
		if (user_path_is_protected(filename)) {
			HOOK_EXIT();
			return -EPERM;
		}

		/* 2) 受保护块设备 (dev_t 匹配, 识别所有别名) */
		if (user_path_is_protected_dev(filename)) {
			HOOK_EXIT();
			return -EPERM;
		}
	}
	HOOK_EXIT();
	return orig_openat(regs);
}

/* ---- ioctl: 拦截格式化相关命令 ---- */
#define A_BLKDISCARD       0x1277
#define A_BLKSECDISCARD    0x127D
#define A_BLKZEROOUT       0x127F
#define A_BLKDISCARDZEROES 0x127C
#define A_BLKFLSBUF        0x1261
#define A_FITRIM           0xC0185875
#define A_BLKRASET         0x1253
#define A_BLKSSZGET        0x1268

static long hook_ioctl(const struct pt_regs *regs)
{
	unsigned int fd  = (unsigned int)regs->regs[0];
	unsigned int cmd = (unsigned int)regs->regs[1];
	bool prot_dev = fd_is_protected_dev(fd);

	if (HOOK_DISABLED())
		return orig_ioctl(regs);
	HOOK_ENTER();

	/* 极端模式: 对块设备 fd 的一切 ioctl 全部拦截 (含 BLK 擦除/清零),
	 * 即使 fd 由白名单进程打开 (防止借 fd 绕过)。 */
	if (extreme_mode) {
		if (fd_is_block_dev(fd)) {
			pr_warn("[antiformat] EXTREME BLOCK ioctl(0x%x) fd=%u (comm=%s)\n",
				cmd, fd, current->comm);
			HOOK_EXIT();
			return -EPERM;
		}
		HOOK_EXIT();
		return orig_ioctl(regs);
	}

	if (block_ioctl) {
		/* 标准 BLK 擦除/清零命令 */
		switch (cmd) {
		case A_BLKDISCARD:
		case A_BLKSECDISCARD:
		case A_BLKZEROOUT:
		case A_BLKDISCARDZEROES:
		case A_FITRIM:
		case A_BLKFLSBUF:
			if (fd_is_protected(fd) || prot_dev) {
				pr_warn("[antiformat] BLOCK ioctl(0x%x) on fd=%u\n",
					cmd, fd);
				HOOK_EXIT();
				return -EPERM;
			}
			break;
		/* 私有擦除命令家族: 0x8018_0000 ~ 0x8018_FFFF
		 * (格机工具如"张豪全防"用 _IOW(0x12, 0x40-0x47, 结构体) 的自定义命令,
		 *  高位 0x8018 = 写方向 + 8字节参数, 对受保护块设备 fd 拦) */
		default:
			if ((cmd & 0xFFFF0000) == 0x80180000 && prot_dev) {
				pr_warn("[antiformat] BLOCK wipe ioctl(0x%x) fd=%u\n",
					cmd, fd);
				HOOK_EXIT();
				return -EPERM;
			}
			break;
		}
	}
	HOOK_EXIT();
	return orig_ioctl(regs);
}

/* ---- write / pwrite64: 直接写受保护块设备/文件 (dd) ---- */
static long hook_write(const struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];

	if (HOOK_DISABLED())
		return orig_write(regs);
	HOOK_ENTER();
	/* 极端模式: 任何进程(含白名单)不能写块设备 fd */
	if (extreme_mode) {
		if (fd_is_block_dev(fd)) {
			pr_warn("[antiformat] EXTREME BLOCK write fd=%u (comm=%s)\n",
				fd, current->comm);
			HOOK_EXIT();
			return -EPERM;
		}
		HOOK_EXIT();
		return orig_write(regs);
	}
	if (block_write &&
	    (fd_is_protected(fd) || fd_is_protected_dev(fd))) {
		HOOK_EXIT();
		return -EPERM;
	}
	HOOK_EXIT();
	return orig_write(regs);
}

static long hook_pwrite64(const struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];

	if (HOOK_DISABLED())
		return orig_pwrite64(regs);
	HOOK_ENTER();
	/* 极端模式: 任何进程(含白名单)不能写块设备 fd */
	if (extreme_mode) {
		if (fd_is_block_dev(fd)) {
			pr_warn("[antiformat] EXTREME BLOCK pwrite64 fd=%u (comm=%s)\n",
				fd, current->comm);
			HOOK_EXIT();
			return -EPERM;
		}
		HOOK_EXIT();
		return orig_pwrite64(regs);
	}
	if (block_write &&
	    (fd_is_protected(fd) || fd_is_protected_dev(fd))) {
		HOOK_EXIT();
		return -EPERM;
	}
	HOOK_EXIT();
	return orig_pwrite64(regs);
}

/* ---- mount / umount2: 防止通过重挂载/卸载绕过保护 ---- */
static long hook_mount(const struct pt_regs *regs)
{
	const char __user *src = (const char __user *)regs->regs[0];
	const char __user *dir = (const char __user *)regs->regs[1];

	if (HOOK_DISABLED())
		return orig_mount(regs);
	HOOK_ENTER();
	if (block_mount &&
	    (user_path_is_protected(src) || user_path_is_protected(dir))) {
		HOOK_EXIT();
		return -EPERM;
	}
	HOOK_EXIT();
	return orig_mount(regs);
}

static long hook_umount2(const struct pt_regs *regs)
{
	const char __user *name = (const char __user *)regs->regs[0];

	if (HOOK_DISABLED())
		return orig_umount2(regs);
	HOOK_ENTER();
	if (block_mount && user_path_is_protected(name)) {
		HOOK_EXIT();
		return -EPERM;
	}
	HOOK_EXIT();
	return orig_umount2(regs);
}

/* ---- kill / tgkill / tkill: 保护 afd 守护进程 ---- */
static long hook_kill(const struct pt_regs *regs)
{
	int pid = (int)regs->regs[0];

	if (HOOK_DISABLED())
		return orig_kill(regs);
	HOOK_ENTER();
	if (pid_is_afd(pid)) {
		pr_warn("[antiformat] BLOCK kill(%d) on afd (comm=%s)\n",
			pid, current->comm);
		HOOK_EXIT();
		return -EPERM;
	}
	HOOK_EXIT();
	return orig_kill(regs);
}

static long hook_tkill(const struct pt_regs *regs)
{
	int pid = (int)regs->regs[0];

	if (HOOK_DISABLED())
		return orig_tkill(regs);
	HOOK_ENTER();
	if (pid_is_afd(pid)) {
		pr_warn("[antiformat] BLOCK tkill(%d) on afd (comm=%s)\n",
			pid, current->comm);
		HOOK_EXIT();
		return -EPERM;
	}
	HOOK_EXIT();
	return orig_tkill(regs);
}

static long hook_tgkill(const struct pt_regs *regs)
{
	int pid = (int)regs->regs[0];
	int tgid = (int)regs->regs[1];

	if (HOOK_DISABLED())
		return orig_tgkill(regs);
	HOOK_ENTER();
	if (pid_is_afd(pid) || pid_is_afd(tgid)) {
		pr_warn("[antiformat] BLOCK tgkill(%d,%d) on afd (comm=%s)\n",
			pid, tgid, current->comm);
		HOOK_EXIT();
		return -EPERM;
	}
	HOOK_EXIT();
	return orig_tgkill(regs);
}

/* hook_ptrace: 阻止 ptrace 附加 afd (调试器偷 key) */
static long hook_ptrace(const struct pt_regs *regs)
{
	int pid = (int)regs->regs[1];

	if (HOOK_DISABLED())
		return orig_ptrace(regs);
	HOOK_ENTER();
	if (pid_is_afd(pid)) {
		pr_warn("[antiformat] BLOCK ptrace on afd pid=%d (comm=%s)\n",
			pid, current->comm);
		HOOK_EXIT();
		return -EPERM;
	}
	HOOK_EXIT();
	return orig_ptrace(regs);
}

/* ================================================================ */
/* hook 安装 / 卸载                                                    */
/* ================================================================ */
static void **sct = NULL;

static int install_hook(unsigned int nr, syscall_fn_t hook, syscall_fn_t *save)
{
	void **tab = sct;
	unsigned long addr;
	int ret;

	if (!tab)
		return -1;

	addr = (unsigned long)&tab[nr];

	*save = (syscall_fn_t)tab[nr];

	ret = unprotect_rodata_memory(addr);
	if (ret != 0) {
		pr_err("[antiformat] unprotect rodata failed for nr=%u ret=%d\n",
		       nr, ret);
		return -2;
	}
	WRITE_ONCE(tab[nr], hook);
	ret = protect_rodata_memory(addr);
	if (ret != 0)
		pr_err("[antiformat] protect rodata failed for nr=%u ret=%d\n",
		       nr, ret);
	return 0;
}

static void uninstall_hook(unsigned int nr, syscall_fn_t orig)
{
	void **tab = sct;
	unsigned long addr;

	if (!tab || !orig)
		return;
	addr = (unsigned long)&tab[nr];
	unprotect_rodata_memory(addr);
	WRITE_ONCE(tab[nr], orig);
	protect_rodata_memory(addr);
}

/* ================================================================ */
/* 配置管理                                                           */
/* ================================================================ */
static int add_protect_path(const char *path)
{
	int i;
	unsigned long flags;
	struct path pp;
	dev_t d = 0;

	if (!path || !path[0] || strlen(path) >= PATHLEN)
		return -EINVAL;

	/* 尝试解析为块设备节点 -> 记录 dev_t (解决 mmcblk0pX/by-name/sdX 别名)
	 * 注意: by-name 下是符号链接, 必须 LOOKUP_FOLLOW 跟随到真实块设备,
	 *       否则解析到 symlink inode (S_ISLNK) dev_t=0, 设备号匹配失效. */
	if (kern_path_p && kern_path_p(path, LOOKUP_FOLLOW, &pp) == 0) {
		struct inode *in = d_backing_inode(pp.dentry);
		if (in && S_ISBLK(in->i_mode))
			d = in->i_rdev;
		if (path_put_p)
			path_put_p(&pp);
	}

	spin_lock_irqsave(&protect_lock, flags);
	for (i = 0; i < nr_protected; i++)
		if (protect_paths[i] &&
		    strcmp(protect_paths[i], path) == 0) {
			spin_unlock_irqrestore(&protect_lock, flags);
			return 0;
		}
	if (nr_protected >= MAX_PROTECT) {
		spin_unlock_irqrestore(&protect_lock, flags);
		return -ENOSPC;
	}
	protect_paths[nr_protected] = kstrdup(path, GFP_KERNEL);
	if (!protect_paths[nr_protected]) {
		spin_unlock_irqrestore(&protect_lock, flags);
		return -ENOMEM;
	}
	protect_devs[nr_protected] = d;
	nr_protected++;
	spin_unlock_irqrestore(&protect_lock, flags);

	pr_info("[antiformat] protect +%s (dev=%u:%u)\n",
		path, MAJOR(d), MINOR(d));
	return 0;
}

static void clear_protect_paths(void)
{
	int i;
	unsigned long flags;

	spin_lock_irqsave(&protect_lock, flags);
	for (i = 0; i < nr_protected; i++) {
		kfree(protect_paths[i]);
		protect_paths[i] = NULL;
		protect_devs[i] = 0;
	}
	nr_protected = 0;
	spin_unlock_irqrestore(&protect_lock, flags);
}

/* 移除一个保护路径 */
static int remove_protect_path(const char *path)
{
	int i;
	int ret = -ENOENT;
	unsigned long flags;

	if (!path || !path[0])
		return -EINVAL;

	spin_lock_irqsave(&protect_lock, flags);
	for (i = 0; i < nr_protected; i++) {
		if (protect_paths[i] && strcmp(protect_paths[i], path) == 0) {
			kfree(protect_paths[i]);
			/* 紧凑数组 */
			nr_protected--;
			protect_paths[i] = protect_paths[nr_protected];
			protect_paths[nr_protected] = NULL;
			protect_devs[i] = protect_devs[nr_protected];
			protect_devs[nr_protected] = 0;
			ret = 0;
			break;
		}
	}
	spin_unlock_irqrestore(&protect_lock, flags);

	if (ret == 0)
		pr_info("[antiformat] unprotect -%s\n", path);
	return ret;
}

/* ------------------------------------------------------------------ */
/* proc 接口                                                           */
/* ------------------------------------------------------------------ */
static struct proc_dir_entry *af_proc_root;

/* 前向声明 (af_unload_write 调用) */
static int uninstall_all_hooks(void *unused);
static void clear_protect_paths(void);

/* ================================================================ */
/* 卸载认证: 64 进制 key (加载时随机生成, 写对 key 才允许逻辑卸载)     */
/* key 不打印 dmesg, 只通过 /proc/antiformat/key 一次性读取 (afd 用)   */
/* 内核只存 SHA-256(key) 哈希, 明文交付 afd 后立即清零                 */
/* ================================================================ */

/* ---- SHA-256 (纯 C 实现, 避免依赖未导出的 crypto 符号) ---- */
typedef struct {
	u32 state[8];
	u64 bitlen;
	u8 buffer[64];
	size_t buflen;
} af_sha256_ctx;

static const u32 af_sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static u32 af_ror(u32 x, int n)
{
	return (x >> n) | (x << (32 - n));
}

static void af_sha256_transform(af_sha256_ctx *ctx, const u8 *data)
{
	u32 m[64];
	u32 a, b, c, d, e, f, g, h;
	int i;

	for (i = 0; i < 16; i++)
		m[i] = ((u32)data[i * 4] << 24) | ((u32)data[i * 4 + 1] << 16) |
		       ((u32)data[i * 4 + 2] << 8) | (u32)data[i * 4 + 3];
	for (i = 16; i < 64; i++) {
		u32 s0 = af_ror(m[i - 15], 7) ^ af_ror(m[i - 15], 18) ^
			 (m[i - 15] >> 3);
		u32 s1 = af_ror(m[i - 2], 17) ^ af_ror(m[i - 2], 19) ^
			 (m[i - 2] >> 10);
		m[i] = m[i - 16] + s0 + m[i - 7] + s1;
	}
	a = ctx->state[0]; b = ctx->state[1];
	c = ctx->state[2]; d = ctx->state[3];
	e = ctx->state[4]; f = ctx->state[5];
	g = ctx->state[6]; h = ctx->state[7];
	for (i = 0; i < 64; i++) {
		u32 S1 = af_ror(e, 6) ^ af_ror(e, 11) ^ af_ror(e, 25);
		u32 ch = (e & f) ^ (~e & g);
		u32 temp1 = h + S1 + ch + af_sha256_k[i] + m[i];
		u32 S0 = af_ror(a, 2) ^ af_ror(a, 13) ^ af_ror(a, 22);
		u32 maj = (a & b) ^ (a & c) ^ (b & c);
		u32 temp2 = S0 + maj;
		h = g; g = f; f = e; e = d + temp1;
		d = c; c = b; b = a; a = temp1 + temp2;
	}
	ctx->state[0] += a; ctx->state[1] += b;
	ctx->state[2] += c; ctx->state[3] += d;
	ctx->state[4] += e; ctx->state[5] += f;
	ctx->state[6] += g; ctx->state[7] += h;
}

static void af_sha256_init(af_sha256_ctx *ctx)
{
	ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
	ctx->bitlen = 0; ctx->buflen = 0;
}

static void af_sha256_update(af_sha256_ctx *ctx, const u8 *data, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		ctx->buffer[ctx->buflen++] = data[i];
		if (ctx->buflen == 64) {
			af_sha256_transform(ctx, ctx->buffer);
			ctx->bitlen += 512;
			ctx->buflen = 0;
		}
	}
}

static void af_sha256_final(af_sha256_ctx *ctx, u8 *out)
{
	size_t i = ctx->buflen;
	u64 bits = ctx->bitlen + (u64)ctx->buflen * 8;

	ctx->buffer[i++] = 0x80;
	if (i > 56) {
		while (i < 64)
			ctx->buffer[i++] = 0;
		af_sha256_transform(ctx, ctx->buffer);
		ctx->bitlen += 512;
		i = 0;
	}
	while (i < 56)
		ctx->buffer[i++] = 0;
	ctx->buffer[56] = (u8)(bits >> 56); ctx->buffer[57] = (u8)(bits >> 48);
	ctx->buffer[58] = (u8)(bits >> 40); ctx->buffer[59] = (u8)(bits >> 32);
	ctx->buffer[60] = (u8)(bits >> 24); ctx->buffer[61] = (u8)(bits >> 16);
	ctx->buffer[62] = (u8)(bits >> 8);  ctx->buffer[63] = (u8)bits;
	af_sha256_transform(ctx, ctx->buffer);
	for (i = 0; i < 8; i++) {
		out[i * 4]     = (u8)(ctx->state[i] >> 24);
		out[i * 4 + 1] = (u8)(ctx->state[i] >> 16);
		out[i * 4 + 2] = (u8)(ctx->state[i] >> 8);
		out[i * 4 + 3] = (u8)ctx->state[i];
	}
}

static void af_sha256(const u8 *data, size_t len, u8 *out)
{
	af_sha256_ctx ctx;

	af_sha256_init(&ctx);
	af_sha256_update(&ctx, data, len);
	af_sha256_final(&ctx, out);
}
#define KEY_LEN 8

static char unload_key[KEY_LEN + 1]; /* 当前卸载 key (ASCII, 64进制) */
static u8 unload_key_hash[32];       /* SHA-256(key), 明文交付后仅存哈希 */
static bool unload_unlocked = false; /* 是否已通过 key 认证 */
static bool key_delivered = false;   /* key 是否已被 afd 读取(一次性) */

/* 64 进制字符表: 0-9, A-Z, a-z, -, _ */
static const char key_chars[] =
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";

/* 生成 8 位 64 进制随机 key (每加载一次都不同) */
static void gen_unload_key(void)
{
	unsigned int seed[KEY_LEN];
	int i;

	get_random_bytes(seed, sizeof(seed));
	for (i = 0; i < KEY_LEN; i++) {
		unsigned int v = seed[i];
		v ^= (unsigned int)(jiffies + (unsigned long)&unload_key);
		unload_key[i] = key_chars[v % 64];
	}
	unload_key[KEY_LEN] = '\0';
	/* 保存 SHA-256 哈希 (卸载校验用), 明文在交付 afd 后清零 */
	af_sha256((const u8 *)unload_key, KEY_LEN, unload_key_hash);
	unload_unlocked = false;
	key_delivered = false;
	/* 不再打印 key 到 dmesg (防止 dmesg_restrict 关闭时泄露) */
	pr_info("[antiformat] unload key generated (afd will read via /proc/antiformat/key)\n");
}

/* 校验 key: 计算输入 SHA-256 与存储哈希比对 (明文不在内核内存) */
static bool check_unload_key(const char *buf, size_t len)
{
	u8 h[32];

	if (key_delivered == false || len != KEY_LEN)
		return false;
	af_sha256((const u8 *)buf, len, h);
	return memcmp(h, unload_key_hash, 32) == 0;
}

/* /proc/antiformat/key (read once -> 一次性交付 key 给 afd) */
static ssize_t af_key_read(struct file *file, char __user *ubuf,
			   size_t count, loff_t *ppos)
{
	unsigned long flags;
	int len;

	spin_lock_irqsave(&afd_lock, flags);
	if (!afd_registered || key_delivered) {
		/* 守护未注册或 key 已被取走: 拒绝泄露 */
		spin_unlock_irqrestore(&afd_lock, flags);
		return -EPERM;
	}
	/* 仅 afd 本人可读 (pid 匹配 + 白名单) */
	if (task_tgid_nr(current) != afd_pid || !proc_is_whitelisted()) {
		spin_unlock_irqrestore(&afd_lock, flags);
		return -EPERM;
	}
	if (!unload_key[0]) {
		spin_unlock_irqrestore(&afd_lock, flags);
		return -EIO;
	}
	len = strlen(unload_key);
	if (copy_to_user(ubuf, unload_key, len) != 0) {
		spin_unlock_irqrestore(&afd_lock, flags);
		return -EFAULT;
	}
	/* 交付即毁: 清空明文 key (哈希保留在 unload_key_hash 用于校验) */
	memset(unload_key, 0, sizeof(unload_key));
	key_delivered = true;
	spin_unlock_irqrestore(&afd_lock, flags);
	return len;
}

static const struct proc_ops af_key_fops = {
	.proc_read = af_key_read,
};

/* /proc/antiformat/guard (write 任意内容 -> 注册调用者自身为 afd 守护 pid)
 * 强制 pid = 调用者 tgid, 攻击者无法把自己注册成 afd (防冒充读 key) */
static ssize_t af_guard_write(struct file *file, const char __user *ubuf,
			      size_t count, loff_t *ppos)
{
	int pid;
	unsigned long flags;

	/* 仅白名单进程(afd)可注册 */
	if (!proc_is_whitelisted())
		return -EACCES;

	/* 强制注册调用者自身 tgid, 忽略用户传入内容 */
	pid = task_tgid_nr(current);
	if (pid <= 0)
		return -EINVAL;

	spin_lock_irqsave(&afd_lock, flags);
	afd_pid = pid;
	afd_registered = true;
	/* key 已被交付过(旧 afd 曾读取) -> 不允许重新生成:
	 * 必须重启设备重新加载模块才能获得新 key (防攻击者冒充拿 key) */
	spin_unlock_irqrestore(&afd_lock, flags);

	pr_info("[antiformat] guard registered pid=%d\n", pid);
	return count;
}

static const struct proc_ops af_guard_fops = {
	.proc_write = af_guard_write,
};

/* /proc/antiformat/unload (write key -> 逻辑卸载: 还原表 + 置 disabled) */
static ssize_t af_unload_write(struct file *file, const char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	char buf[KEY_LEN + 2];
	size_t len = count;

	if (len > KEY_LEN + 1)
		len = KEY_LEN + 1;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = '\0';
	while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
		buf[--len] = '\0';

	if (len != KEY_LEN || !check_unload_key(buf, len)) {
		pr_warn("[antiformat] unload key mismatch\n");
		return -EACCES;
	}

	/* 认证通过: 逻辑卸载 */
	if (READ_ONCE(af_disabled)) {
		/* 已卸载过: 幂等返回 */
		pr_info("[antiformat] already disabled\n");
		return count;
	}
	pr_info("[antiformat] unload key OK, disabling protection...\n");

	/* 1) 原子还原全部 syscall (全核停摆, 消除窗口) */
	stop_machine(uninstall_all_hooks, NULL, NULL);

	/* 2) 等待所有正在执行的 hook 退出 (引用计数归零) */
	{
		int waited = 0;
		while (atomic_read(&hook_active) != 0 && waited < 5000) {
			msleep(1);
			waited++;
		}
	}

	/* 3) 置 disabled: 后续任何残余 hook 调用直接放行 orig */
	WRITE_ONCE(af_disabled, true);

	/* 4) 清空保护配置 (保留 proc 节点, 供查看状态) */
	clear_protect_paths();

	pr_info("[antiformat] protection disabled (module resident, safe)\n");
	return count;
}

static const struct proc_ops af_unload_fops = {
	.proc_write = af_unload_write,
};

/* /proc/antiformat/status */
static int af_status_show(struct seq_file *m, void *v)
{
	int i;
	unsigned long flags;

	seq_printf(m, "antiformat status\n");
	seq_printf(m, "block_unlink=%d block_open_w=%d block_ioctl=%d "
		   "block_write=%d block_mount=%d\n",
		   block_unlink, block_open_w, block_ioctl,
		   block_write, block_mount);
	seq_printf(m, "disabled=%d (1=逻辑卸载)\n", READ_ONCE(af_disabled));
	seq_printf(m, "protected paths (%d):\n", nr_protected);

	spin_lock_irqsave(&protect_lock, flags);
	for (i = 0; i < nr_protected; i++)
		if (protect_paths[i])
			seq_printf(m, "  %s\n", protect_paths[i]);
	spin_unlock_irqrestore(&protect_lock, flags);
	return 0;
}

static int af_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, af_status_show, NULL);
}

static const struct proc_ops af_status_fops = {
	.proc_open = af_status_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/* /proc/antiformat/protect (write to add) */
static ssize_t af_protect_write(struct file *file, const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	char buf[PATHLEN];
	size_t len = count;

	if (len >= PATHLEN)
		len = PATHLEN - 1;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = '\0';
	/* 去掉末尾换行/空白 */
	while (len > 0 &&
	       (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
		buf[len - 1] == ' '))
		buf[--len] = '\0';
	if (len == 0)
		return count;

	add_protect_path(buf);
	return count;
}

static const struct proc_ops af_protect_fops = {
	.proc_write = af_protect_write,
};

/* /proc/antiformat/unprotect (write to remove) */
static ssize_t af_unprotect_write(struct file *file, const char __user *ubuf,
				  size_t count, loff_t *ppos)
{
	char buf[PATHLEN];
	size_t len = count;

	if (len >= PATHLEN)
		len = PATHLEN - 1;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = '\0';
	while (len > 0 &&
	       (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
		buf[len - 1] == ' '))
		buf[--len] = '\0';
	if (len == 0)
		return count;

	remove_protect_path(buf);
	return count;
}

static const struct proc_ops af_unprotect_fops = {
	.proc_write = af_unprotect_write,
};

static int af_proc_init(void)
{
	af_proc_root = proc_mkdir("antiformat", NULL);
	if (!af_proc_root)
		return -ENOMEM;

	proc_create("status", 0444, af_proc_root, &af_status_fops);
	proc_create("protect", 0222, af_proc_root, &af_protect_fops);
	proc_create("unprotect", 0222, af_proc_root, &af_unprotect_fops);
	proc_create("unload", 0222, af_proc_root, &af_unload_fops);
	proc_create("key", 0400, af_proc_root, &af_key_fops);
	proc_create("guard", 0222, af_proc_root, &af_guard_fops);
	return 0;
}

static void af_proc_exit(void)
{
	remove_proc_entry("status", af_proc_root);
	remove_proc_entry("protect", af_proc_root);
	remove_proc_entry("unprotect", af_proc_root);
	remove_proc_entry("unload", af_proc_root);
	remove_proc_entry("key", af_proc_root);
	remove_proc_entry("guard", af_proc_root);
	remove_proc_entry("antiformat", NULL);
}

/* 默认保护路径（编译期内定, 无配置文件） */
static void load_default_paths(void)
{
	add_protect_path("/data/media/0/DCIM");
	add_protect_path("/data/media/0/Pictures");
	add_protect_path("/data/media/0/Movies");
	/* /data/adb 直接保护: 防止攻击者删模块文件/降级 */
	add_protect_path("/data/adb");
	add_protect_path("/sdcard/Download");
}

/* ================================================================ */
/* 模块生命周期                                                       */
/* ================================================================ */
static int __init antiformat_init(void)
{
	void *sct_addr;

	pr_info("[antiformat] init (kernel %s)\n", utsname()->release);

	sct_addr = find_syscall_table();
	if (!sct_addr) {
		pr_err("[antiformat] cannot find sys_call_table\n");
		return -EINVAL;
	}
	sct = (void **)sct_addr;
	pr_info("[antiformat] sys_call_table @ 0x%px\n", sct);

	resolve_vfs_symbols();
	pr_info("[antiformat] vfs symbols: kern_path=%px path_put=%px\n",
		kern_path_p, path_put_p);

	load_default_whitelist();
	load_default_paths();

	/* 生成卸载认证 key (每次加载都不同, afd 通过 /proc/antiformat/key 一次性读取) */
	gen_unload_key();

	/* 创建 /proc/antiformat 控制接口 */
	af_proc_init();

	/* 安装 hooks */
	install_hook(__NR_AF_UNLINKAT,  hook_unlinkat,  &orig_unlinkat);
	install_hook(__NR_AF_TRUNCATE,  hook_truncate,  &orig_truncate);
	install_hook(__NR_AF_FTRUNCATE, hook_ftruncate, &orig_ftruncate);
	install_hook(__NR_AF_FALLOCATE, hook_fallocate, &orig_fallocate);
	install_hook(__NR_AF_RENAMEAT,  hook_renameat,  &orig_renameat);
	install_hook(__NR_AF_RENAMEAT2, hook_renameat2, &orig_renameat2);
	install_hook(__NR_AF_OPENAT,    hook_openat,    &orig_openat);
	install_hook(__NR_AF_IOCTL,     hook_ioctl,     &orig_ioctl);
	install_hook(__NR_AF_WRITE,     hook_write,     &orig_write);
	install_hook(__NR_AF_PWRITE64,  hook_pwrite64,  &orig_pwrite64);
	install_hook(__NR_AF_MOUNT,     hook_mount,     &orig_mount);
	install_hook(__NR_AF_UMOUNT2,   hook_umount2,   &orig_umount2);
	install_hook(__NR_AF_KILL,      hook_kill,      &orig_kill);
	install_hook(__NR_AF_TKILL,     hook_tkill,     &orig_tkill);
	install_hook(__NR_AF_TGKILL,    hook_tgkill,    &orig_tgkill);
	install_hook(__NR_AF_PTRACE,    hook_ptrace,    &orig_ptrace);

	/*
	 * 自引用钉死: 使模块 refcount 恒 >= 1, rmmod 返回 EBUSY 拒绝.
	 * 这是防格机防护的核心属性: 恶意样本无法直接卸载防护.
	 * 卸载必须通过 /proc/antiformat/unload 写 key (逻辑卸载).
	 */
	if (!try_module_get(THIS_MODULE)) {
		pr_err("[antiformat] try_module_get failed\n");
		return -EINVAL;
	}
	pr_info("[antiformat] module pinned (rmmod will be rejected; "
		"use /proc/antiformat/unload with key)\n");

	pr_info("[antiformat] hooks installed (%d paths protected)\n",
		nr_protected);
	return 0;
}

/*
 * 原子还原全部 hooks —— 在 stop_machine 上下文中执行,
 * 全核停摆, 不存在"一部分已还原、另一部分还是 hook"的窗口。
 * 注意: 此时仍在使用模块代码 (本函数), 所以真正的内存释放
 * 必须等 synchronize_rcu() 之后由 module 框架完成。
 */
static int uninstall_all_hooks(void *unused)
{
	uninstall_hook(__NR_AF_UNLINKAT,  orig_unlinkat);
	uninstall_hook(__NR_AF_TRUNCATE,  orig_truncate);
	uninstall_hook(__NR_AF_FTRUNCATE, orig_ftruncate);
	uninstall_hook(__NR_AF_FALLOCATE, orig_fallocate);
	uninstall_hook(__NR_AF_RENAMEAT,  orig_renameat);
	uninstall_hook(__NR_AF_RENAMEAT2, orig_renameat2);
	uninstall_hook(__NR_AF_OPENAT,    orig_openat);
	uninstall_hook(__NR_AF_IOCTL,     orig_ioctl);
	uninstall_hook(__NR_AF_WRITE,     orig_write);
	uninstall_hook(__NR_AF_PWRITE64,  orig_pwrite64);
	uninstall_hook(__NR_AF_MOUNT,     orig_mount);
	uninstall_hook(__NR_AF_UMOUNT2,   orig_umount2);
	uninstall_hook(__NR_AF_KILL,      orig_kill);
	uninstall_hook(__NR_AF_TKILL,     orig_tkill);
	uninstall_hook(__NR_AF_TGKILL,    orig_tgkill);
	uninstall_hook(__NR_AF_PTRACE,    orig_ptrace);
	return 0;
}

static void __exit antiformat_exit(void)
{
	/*
	 * 注意: 本函数实际不会被调用 —— antiformat_init 里 try_module_get
	 * 自引用钉死了 refcount, rmmod 会返回 EBUSY (模块永不真正卸载).
	 *
	 * 卸载/停用防护的唯一途径: 向 /proc/antiformat/unload 写入
	 * 本次加载生成的 64 进制 key, 触发 af_unload_write 逻辑卸载:
	 *   - stop_machine 原子还原全部 syscall
	 *   - 等 hook 引用计数归零
	 *   - 置 af_disabled=true, 残余 hook 调用直接放行 orig
	 *   - 清空保护路径 / proc 接口
	 *
	 * 为什么必须"永不真正卸载": 实测 stop_machine 还原表时, 正在
	 * syscall 路径执行 hook 的线程只是被暂停而非退出; 模块内存一旦
	 * 释放, 恢复执行的线程跳到已释放内存 -> IABT panic (binder 线程
	 * 三次实证). 只有让模块内存永不释放 (驻留 + 逻辑禁用) 才能
	 * 从根上消除这个竞态.
	 *
	 * 本函数作为理论兜底: 若未来放宽策略允许真正 rmmod, 需要
	 * 先 unlock (af_unload_write) 再释放 refcount, 且必须保证
	 * hook_active==0. 当前实现永不走到这里.
	 */
	pr_info("[antiformat] exit called (should not happen; module is pinned)\n");

	/* 仅清理资源; 不还原 sys_call_table (若走到这里说明已逻辑卸载) */
	af_proc_exit();
	clear_protect_paths();
}

module_init(antiformat_init);
module_exit(antiformat_exit);