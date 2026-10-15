/*
 * flash_initboot.c - 模拟"恶意刷机 ELF"把 img 写入 init_boot 分区
 *
 * 用于测试 antiformat 模块的拦截能力（真实破坏性测试）。
 * 行为完全模拟真实刷机工具（dd/odin 类）:
 *   1) 打开 img 文件读取内容
 *   2) open("/dev/block/by-name/init_boot_b", O_WRONLY)
 *   3) write() 整盘写入 img 内容
 *
 * 如果 antiformat 拦截 openat(O_WRONLY)/write，程序会得到 EPERM 并返回非 0。
 * 返回码:
 *   0  = 全程未被拦截, 写入完成 (测试失败: 防护没拦住)
 *   2  = open(块设备) 被拦截 (block_open_w 生效)
 *   3  = img 读取失败
 *   4  = write 被拦截 (block_write 生效)
 *
 * 编译 (aarch64 静态):
 *   aarch64-linux-gnu-gcc -static -O2 -o flash_initboot flash_initboot.c
 *
 * 注意: 本工具仅用于授权环境下的防护功能测试。
 * 刷入后 init_boot 可随时用备份恢复: dd if=init_boot_b.bak of=/dev/block/by-name/init_boot_b
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

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s <img_file> <bdev>\n"
		"  <img_file> 要刷入的镜像, 如 /storage/emulated/0/Download/kernelsu_patched_20261008_180910.img\n"
		"  <bdev>     目标块设备, 如 /dev/block/by-name/init_boot_b\n",
		prog);
	exit(1);
}

int main(int argc, char **argv)
{
	const char *img_path;
	const char *bdev;
	int img_fd, fd;
	ssize_t n;
	struct stat st;
	unsigned char buf[65536];
	size_t total = 0, fsz;

	if (argc < 3)
		usage(argv[0]);

	img_path = argv[1];
	bdev = argv[2];

	/* 1) 打开 img 文件 */
	img_fd = open(img_path, O_RDONLY);
	if (img_fd < 0) {
		fprintf(stderr, "[flash] open(img=%s) failed: %s (errno=%d)\n",
			img_path, strerror(errno), errno);
		return 3;
	}
	if (fstat(img_fd, &st) < 0) {
		fprintf(stderr, "[flash] fstat failed: %s\n", strerror(errno));
		close(img_fd);
		return 3;
	}
	fsz = (size_t)st.st_size;
	fprintf(stderr, "[flash] img %s size=%zu bytes, sha256 见外部校验\n",
		img_path, fsz);

	/* 2) 打开目标块设备 (写模式) */
	fd = open(bdev, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "[flash] open(%s, O_WRONLY) FAILED: %s (errno=%d)\n",
			bdev, strerror(errno), errno);
		close(img_fd);
		return 2; /* openat 被拦截 => block_open_w 生效 */
	}
	fprintf(stderr, "[flash] open(%s, O_WRONLY) OK, fd=%d\n", bdev, fd);

	/* 3) 整盘写入 img 内容 */
	while (total < fsz) {
		n = read(img_fd, buf, sizeof(buf));
		if (n <= 0) {
			fprintf(stderr, "[flash] read(img) failed at %zu: %s\n",
				total, strerror(errno));
			close(fd); close(img_fd);
			return 3;
		}
		{
			size_t off = 0;
			while (off < (size_t)n) {
				ssize_t w = write(fd, buf + off, (size_t)n - off);
				if (w < 0) {
					fprintf(stderr,
						"[flash] write(%s) FAILED at offset %zu: %s (errno=%d)\n",
						bdev, total + off, strerror(errno), errno);
					close(fd); close(img_fd);
					return 4; /* write 被拦截 => block_write 生效 */
				}
				off += (size_t)w;
			}
		}
		total += (size_t)n;
	}

	fprintf(stderr, "[flash] 写入完成: %zu bytes (未被拦截!)\n", total);
	close(fd);
	close(img_fd);
	return 0; /* 未被拦截, 破坏成功 */
}
