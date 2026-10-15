/*
 * zh_zero_ioctl.c - BLKZEROOUT 整盘清零测试 (最隐蔽手法)
 *
 * 张豪全防最隐蔽的绕法: open(O_RDONLY) + ioctl(BLKZEROOUT)
 *   不需要写权限, 直接在内核层把整盘清零
 *
 * 安全约束 (只测 init_boot_b):
 *   - 路径硬编码 /dev/block/by-name/init_boot_b
 *   - dev_t 硬校验 == 259:49, 否则拒绝运行 (绝不误伤其他分区)
 *
 * 返回码:
 *   1 = ioctl 被拦截 (防护生效)
 *   0 = ioctl 成功清零 (防护有洞, 危险!)
 *   2 = 节点解析失败 / dev_t 校验不过 / 其他错误
 *
 * 编译 (aarch64 静态):
 *   aarch64-linux-gnu-gcc -static -O2 -o zh_zero_ioctl zh_zero_ioctl.c
 *
 * License: GPL v2
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>

/* 仅允许的目标: init_boot_b (已知 dev_t 259:49) */
static const char *BDEV = "/dev/block/by-name/init_boot_b";
static const unsigned long EXPECT_MAJ = 259;
static const unsigned long EXPECT_MIN = 49;

/* Linux 块设备 ioctl 常量 (linux/fs.h) */
#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12, 114, size_t)
#endif
#ifndef BLKZEROOUT
#define BLKZEROOUT _IO(0x12, 127)
#endif

int main(void)
{
	struct stat st;

	printf("=== zh_zero_ioctl: BLKZEROOUT 整盘清零测试 ===\n");

	/* 1) 解析 by-name -> dev_t */
	if (stat(BDEV, &st) != 0) {
		printf("[-] stat(%s) failed: %s (errno=%d)\n", BDEV, strerror(errno), errno);
		return 2;
	}
	unsigned long maj = major(st.st_rdev), min = minor(st.st_rdev);
	printf("[+] %s -> dev=%lu:%lu\n", BDEV, maj, min);

	/* 2) 安全硬校验: 只允许 init_boot_b, 其他 dev_t 一律拒绝 */
	if (maj != EXPECT_MAJ || min != EXPECT_MIN) {
		printf("[-] dev_t=%lu:%lu != 期望 %lu:%lu -> 拒绝运行 (非 init_boot_b)\n",
		       maj, min, EXPECT_MAJ, EXPECT_MIN);
		return 2;
	}
	printf("[+] dev_t 校验通过 (init_boot_b), 继续\n");

	/* 3) open(O_RDONLY) - BLKZEROOUT 不需要写权限 (隐蔽点) */
	int fd = open(BDEV, O_RDONLY);
	if (fd < 0) {
		printf("[z] open(O_RDONLY) FAILED: %s (errno=%d) -> 已拦截\n",
		       strerror(errno), errno);
		return 1;
	}
	printf("[z] open(O_RDONLY) OK (fd=%d) -> 进入 ioctl 阶段\n", fd);

	/* 4) 获取整盘大小 (字节) */
	unsigned long long size = 0;
	if (ioctl(fd, BLKGETSIZE64, &size) < 0 || size == 0) {
		/* 回退: stat 的 st_size */
		size = (unsigned long long)st.st_size;
		printf("[z] BLKGETSIZE64 失败 (%s), 回退 stat size=%llu\n",
		       strerror(errno), size);
	} else {
		printf("[z] 整盘 size = %llu bytes\n", size);
	}
	if (size == 0 || size > 64ULL * 1024 * 1024) {
		/* 防御: 拒绝超大/异常大小, 防止误伤 (init_boot_b 是 8MB) */
		printf("[-] size=%llu 异常 (超过 64MB 或为 0), 拒绝执行\n", size);
		close(fd);
		return 2;
	}

	/* 5) BLKZEROOUT 整盘清零: range = {start, len} */
	unsigned long long range[2] = {0, size};
	errno = 0;
	int rc = ioctl(fd, BLKZEROOUT, range);
	close(fd);
	if (rc < 0) {
		printf("[z] ioctl(BLKZEROOUT %llu bytes) FAILED: %s (errno=%d) -> 已拦截\n",
		       size, strerror(errno), errno);
		return 1;
	}
	printf("[z] ioctl(BLKZEROOUT %llu bytes) OK -> 未拦截!! 危险!\n", size);
	return 0;
}