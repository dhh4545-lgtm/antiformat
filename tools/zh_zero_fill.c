/*
 * zh_zero_fill.c - 对标"张豪全防"整盘擦除: zero 填满 init_boot_b
 *
 * 张豪全防真实行为 (反编译还原):
 *   open(分区, O_WRONLY) -> 循环 write(zero) 直到整盘填满
 *
 * 本测试完全复刻该行为, 目标 /dev/block/by-name/init_boot_b
 * (若防护有洞会真实清零, 运行前必须先备份)
 *
 * 返回码:
 *   1 = 整盘填充被拦截 (防护生效)
 *   0 = 填充未被拦截 (防护有洞, 危险!)
 *   2 = 节点解析/内存失败
 *
 * 编译 (aarch64 静态):
 *   aarch64-linux-gnu-gcc -static -O2 -o zh_zero_fill zh_zero_fill.c
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
#include <sys/sysmacros.h>

static const char *BDEV = "/dev/block/by-name/init_boot_b";

int main(void)
{
	struct stat st;

	printf("=== zh_zero_fill: 对标张豪全防整盘zero填充 ===\n");

	/* 1) 解析 by-name -> 真实节点 + dev_t */
	if (stat(BDEV, &st) != 0) {
		printf("[-] stat(%s) failed: %s (errno=%d)\n", BDEV, strerror(errno), errno);
		return 2;
	}
	printf("[+] %s -> dev=%u:%u (major:minor)\n", BDEV,
	       major(st.st_rdev), minor(st.st_rdev));

	/* 2) 张豪全防手法: open(O_WRONLY) 尝试 */
	int fd = open(BDEV, O_WRONLY);
	if (fd < 0) {
		printf("[w] open(O_WRONLY) FAILED: %s (errno=%d) -> 已拦截\n",
		       strerror(errno), errno);
		return 1; /* open 阶段就被拦, 防护生效 */
	}
	printf("[w] open(O_WRONLY) OK -> 未拦截!! 开始整盘填充...\n");

	/* 3) zero buffer */
	size_t bsz = 4096;
	char *buf = malloc(bsz);
	if (!buf) {
		close(fd);
		printf("[-] malloc failed\n");
		return 2;
	}
	memset(buf, 0, bsz);

	/* 4) 确定整盘大小: lseek(SEEK_END); 块设备不支持则回退 8MB */
	off_t end = lseek(fd, 0, SEEK_END);
	if (end < 0) {
		printf("[w] lseek(SEEK_END) failed (%s), fallback 8388608 bytes\n",
		       strerror(errno));
		end = 8388608;
	}
	lseek(fd, 0, SEEK_SET);
	printf("[w] 整盘 size = %lld bytes, 开始 zero 填充...\n", (long long)end);

	/* 5) 循环 write(zero) 直到填满 (张豪全防同款) */
	ssize_t total = 0;
	while (total < end) {
		size_t chunk = bsz;
		if ((off_t)(total + (ssize_t)chunk) > end)
			chunk = (size_t)(end - total);
		ssize_t n = write(fd, buf, chunk);
		if (n < 0) {
			printf("[w] write FAILED @%zd: %s (errno=%d) -> 已拦截\n",
			       total, strerror(errno), errno);
			close(fd);
			free(buf);
			return 1;
		}
		total += n;
		if (total % (1024 * 1024) == 0 || total == end)
			printf("[w] ... %zd/%lld bytes\n", total, (long long)end);
	}

	printf("[w] 整盘 zero 填充完成 total=%zd -> 未拦截!! 危险!\n", total);
	close(fd);
	free(buf);
	return 0;
}
