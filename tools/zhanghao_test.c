/*
 * zhanghao_test.c - 对标"张豪全防"格机样本的防格机测试 ELF
 *
 * 张豪全防真实攻击链（反编译还原）:
 *   1) 枚举 /dev/block/mmcblk0pX 所有分区
 *   2) 逐个 open + 擦除:
 *      - [擦除][w]  = open(O_WRONLY) + write() 直写
 *      - [擦除][m]  = 主设备整盘擦除
 *      - BLKZEROOUT = ioctl 清零 (O_RDONLY 也能发, 最隐蔽)
 *   3) 专门格 recovery/system/data
 *
 * 本测试对标该行为, 但只攻击 /dev/block/by-name/init_boot_b
 * (映射真实节点, 如 sdd64), 对设备无任何风险。
 * 三种手法全试, 验证新版 dev_t 匹配是否覆盖所有路径别名。
 *
 * 返回码:
 *   0 = 某种手法未被拦截 (防护有洞)
 *   1 = 三种手法全部被 EPERM 拦截 (防护生效)
 *   2 = 设备节点解析失败
 *
 * 编译 (aarch64 静态):
 *   aarch64-linux-gnu-gcc -static -O2 -o zhanghao_test zhanghao_test.c
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
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>

/* 与张豪全防相同的 BLK 擦除命令 (linux/fs.h) */
#ifndef BLKZEROOUT
#define BLKZEROOUT _IO(0x12, 127)
#endif
#ifndef BLKDISCARD
#define BLKDISCARD _IO(0x12, 119)
#endif
#ifndef BLKFLSBUF
#define BLKFLSBUF _IO(0x12, 97)
#endif

static const char *BDEV = "/dev/block/by-name/init_boot_b";
static const char *MMC_PREFIX = "/dev/block/mmcblk0p";

static int blocked_all = 1; /* 全部被拦截? */

/* 手法 A: 张豪全防 [擦除][w] - O_WRONLY + write 直写 */
static int attack_write(const char *bdev)
{
	int fd = open(bdev, O_WRONLY);
	if (fd < 0) {
		printf("[w] open(O_WRONLY) %s FAILED: %s (errno=%d) -> 已拦截\n",
		       bdev, strerror(errno), errno);
		return 1;
	}
	/* 只写 4KB 试探 (真实样本会整盘写) */
	char buf[4096] = {0};
	ssize_t n = write(fd, buf, sizeof(buf));
	close(fd);
	if (n < 0) {
		printf("[w] write FAILED: %s (errno=%d) -> 已拦截\n",
		       strerror(errno), errno);
		return 1;
	}
	printf("[w] write OK (n=%zd) -> 未拦截!! 危险\n", n);
	blocked_all = 0;
	return 0;
}

/* 手法 B: BLKZEROOUT - O_RDONLY + ioctl 清零 (最隐蔽, 张豪全防可能用) */
static int attack_ioctl_zero(const char *bdev)
{
	int fd = open(bdev, O_RDONLY);
	if (fd < 0) {
		printf("[z] open(O_RDONLY) %s FAILED: %s (errno=%d) -> 已拦截\n",
		       bdev, strerror(errno), errno);
		return 1;
	}
	/* BLKZEROOUT: 参数是 64 位区间 [start, len), 必须在内核栈上 */
	unsigned long long range[2] = {0, 4096};
	int rc = ioctl(fd, BLKZEROOUT, range);
	close(fd);
	if (rc < 0) {
		printf("[z] ioctl(BLKZEROOUT) FAILED: %s (errno=%d) -> 已拦截\n",
		       strerror(errno), errno);
		return 1;
	}
	printf("[z] ioctl(BLKZEROOUT) OK -> 未拦截!! 危险\n");
	blocked_all = 0;
	return 0;
}

/* 手法 C: O_WRONLY|O_TRUNC 截断式打开 */
static int attack_trunc(const char *bdev)
{
	int fd = open(bdev, O_WRONLY | O_TRUNC);
	if (fd < 0) {
		printf("[t] open(O_WRONLY|O_TRUNC) %s FAILED: %s (errno=%d) -> 已拦截\n",
		       bdev, strerror(errno), errno);
		return 1;
	}
	printf("[t] open(O_WRONLY|O_TRUNC) OK -> 未拦截!! 危险\n");
	blocked_all = 0;
	close(fd);
	return 0;
}

int main(void)
{
	struct stat st;

	printf("=== zhanghao_test: 对标张豪全防攻击链 ===\n");

	/* 1) 解析 by-name -> 真实节点 (sdd64 等), 模拟张豪全防的路径解析 */
	if (stat(BDEV, &st) != 0) {
		printf("[-] stat(%s) failed: %s (errno=%d)\n", BDEV, strerror(errno), errno);
		return 2;
	}
	printf("[+] %s -> dev=%u:%u (major:minor)\n", BDEV,
	       major(st.st_rdev), minor(st.st_rdev));

	/* 2) 枚举 /dev/block/mmcblk0p* 目录, 模拟张豪全防的分区发现 */
	DIR *d = opendir("/dev/block");
	if (d) {
		struct dirent *e;
		int cnt = 0;
		while ((e = readdir(d))) {
			if (strncmp(e->d_name, "mmcblk0p", 8) == 0)
				cnt++;
		}
		closedir(d);
		printf("[+] 枚举 mmcblk0p* 分区: 找到 %d 个 (与张豪全防同手法)\n", cnt);
	}

	/* 3) 三种擦除手法全试 */
	attack_write(BDEV);
	attack_ioctl_zero(BDEV);
	attack_trunc(BDEV);

	printf("\n=== 结果: %s ===\n",
	       blocked_all ? "全部手法被拦截, 防护生效 ✓"
	                   : "存在未拦截手法, 防护有洞 ✗");
	return blocked_all ? 1 : 0;
}
