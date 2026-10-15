/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 AntiFormat contributors
 *
 * afd.c - AntiFormat 守护进程
 *
 * 架构:
 *   - 守护模式 (afd): 开机常驻, 注册 pid 到内核(受 kill 保护),
 *     一次性读 key 入内存(内核清零), 监听 unix socket 等待卸载请求
 *   - 验证模式 (afd verify): uninstall.sh 调用, 连接守护进程 socket,
 *     转发"错别字人机验证"题目/答案 (验证与卸载都在守护进程内完成,
 *     key 永远不出守护进程内存)
 *
 * 安全性:
 *   - key 只在守护进程内存 (不落盘/不打印/socket 不传输)
 *   - 卸载必须通过 60 段错别字题人机验证 (恶意程序无人操作过不了)
 *   - 守护进程被内核 kill/tgkill/ptrace 保护, 无法被杀死/调试
 *
 * 编译: aarch64-linux-gnu-gcc -static -O2 -s -o afd afd.c
 *
 * License: GPL-3.0-or-later (见项目根 LICENSE)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define KEY_PATH     "/proc/antiformat/key"
#define GUARD_PATH   "/proc/antiformat/guard"
#define UNLOAD_PATH  "/proc/antiformat/unload"
#define SOCK_PATH    "/data/local/tmp/afd.sock"
#define KEY_LEN      8
#define BUF_SZ       512

/* 60 段错别字题目: {错句, 正确答案1, 正确答案2(可空)}
 * 每题支持多个合理修正 (中文口语语气词存在合理变体, 如 拉->啦/了) */
static const char *const quiz[][3] = {
	{"你再干什么", "你在干什么", NULL},
	{"你吗吃饭了", "你妈吃饭了", NULL},
	{"今天天气真号", "今天天气真好", NULL},
	{"我要去上班拉", "我要去上班啦", "我要去上班了"},
	{"他还没回来那", "他还没回来哪", "他还没回来呢"},
	{"你快点走把", "你快点走吧", NULL},
	{"这个题太难拉", "这个题太难啦", "这个题太难了"},
	{"你吃了马", "你吃了嘛", "你吃了吗"},
	{"他做的很号", "他做的很好", "他做得很好"},
	{"我回佳了", "我回家啦", "我回家了"},
	{"你走把", "你走吧", NULL},
	{"别忘拉带钥匙", "别忘了带钥匙", "别忘啦带钥匙"},
	{"别在那站着", "别在那儿站着", "别在哪儿站着"},
	{"你吃饭了把", "你吃饭了吧", NULL},
	{"作业写玩了吗", "作业写完了吗", NULL},
	{"他去那了", "他去哪了", "他去哪儿了"},
	{"你去那了", "你去哪了", "你去哪儿了"},
	{"你到那了", "你到哪了", "你到哪儿了"},
	{"你在那", "你在哪", "你在哪儿"},
	{"快点来把", "快点来吧", NULL},
	{"别等了把", "别等了吧", NULL},
	{"走了把", "走了吧", NULL},
	{"知道了把", "知道了吧", NULL},
	{"饭吃了把", "饭吃了吧", NULL},
	{"水喝了把", "水喝了吧", NULL},
	{"明天去那玩", "明天去哪玩", "明天去哪儿玩"},
	{"你在干什么那", "你在干什么呢", NULL},
	{"我找不到你拉", "我找不到你了", "我找不到你啦"},
	{"我想你拉", "我想你了", "我想你啦"},
	{"我在这那", "我在这呢", NULL},
	{"你睡拉吗", "你睡了吗", NULL},
	{"你吃饭拉吗", "你吃饭了吗", NULL},
	{"好酒不见", "好久不见", NULL},
	{"一切安号", "一切安好", NULL},
	{"祝你好运阿", "祝你好运啊", "祝你好运呀"},
	{"明天见把", "明天见吧", NULL},
	{"晚安把", "晚安吧", NULL},
	{"好的没问题拉", "好的没问题啦", "好的没问题了"},
	{"我马上就到拉", "我马上就到啦", "我马上就到了"},
	{"你到佳了没", "你到家了没", NULL},
	{"路上小心阿", "路上小心啊", "路上小心呀"},
	{"记得吃饭阿", "记得吃饭啊", NULL},
	{"早点休息把", "早点休息吧", NULL},
	{"你吃饭拉没", "你吃饭了没", NULL},
	{"别太累了阿", "别太累了啊", "别太累了呀"},
	{"加油把", "加油吧", NULL},
	{"注意安全阿", "注意安全啊", "注意安全呀"},
	{"你做的真号", "你做得真好", "你做的真好"},
	{"快回来把", "快回来吧", NULL},
	{"睡觉拉", "睡觉啦", "睡觉了"},
	{"起床拉", "起床啦", "起床了"},
	{"上班拉", "上班啦", "上班了"},
	{"下班拉", "下班啦", "下班了"},
	{"吃饭拉", "吃饭啦", "吃饭了"},
	{"洗澡拉", "洗澡啦", "洗澡了"},
	{"出去完", "出去玩", NULL},
	{"回家把", "回家吧", NULL},
	{"慢走阿", "慢走啊", "慢走呀"},
	{"你等我一下拉", "你等我一下啦", "你等我一下"},
	{"谢谢你阿", "谢谢你啊", "谢谢你呀"},
};

#define QUIZ_COUNT (sizeof(quiz) / sizeof(quiz[0]))

static char key[KEY_LEN + 1];
static int  have_key = 0;
static int  sock_fd = -1;

/* 一次性读取 key */
static int read_key(void)
{
	int fd;
	int n;

	fd = open(KEY_PATH, O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, key, KEY_LEN);
	close(fd);
	if (n != KEY_LEN)
		return -1;
	key[KEY_LEN] = '\0';
	have_key = 1;
	return 0;
}

/* 注册守护 pid */
static int register_guard(void)
{
	int fd;
	char c = '1';

	fd = open(GUARD_PATH, O_WRONLY);
	if (fd < 0)
		return -1;
	write(fd, &c, 1);
	close(fd);
	return 0;
}

/* 触发逻辑卸载 (守护进程内, key 在内存) */
static int do_unload(void)
{
	int fd;
	int n;

	if (!have_key) {
		fprintf(stderr, "afd: 无 key, 无法卸载\n");
		return -1;
	}
	fd = open(UNLOAD_PATH, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "afd: 无法打开卸载接口: %s\n", strerror(errno));
		return -1;
	}
	n = write(fd, key, KEY_LEN);
	close(fd);
	if (n != KEY_LEN) {
		fprintf(stderr, "afd: 卸载接口拒绝 (key 错误或已交付)\n");
		return -1;
	}
	return 0;
}

/* 错别字验证 (守护进程内): 返回 0=通过
 * answer 匹配正确答案1 或 正确答案2(可空) */
static int verify_answer(const char *wrong, const char *r1, const char *r2,
			 const char *answer)
{
	if (!answer)
		return -1;
	if (strcmp(answer, r1) == 0)
		return 0;
	if (r2 && strcmp(answer, r2) == 0)
		return 0;
	return -1;
}

/* 处理单个客户端连接 (子进程内, 阻塞无碍) */
static void handle_client(int cfd)
{
	char buf[BUF_SZ];
	int n;
	unsigned int idx;

	/* 读命令 */
	n = read(cfd, buf, sizeof(buf) - 1);
	if (n <= 0)
		goto out;
	buf[n] = '\0';
	if (strncmp(buf, "VERIFY", 6) != 0) {
		write(cfd, "BADCMD", 6);
		goto out;
	}

	/* 随机出题 */
	{
		int rfd = open("/dev/urandom", O_RDONLY);
		if (rfd >= 0) {
			read(rfd, &idx, sizeof(idx));
			close(rfd);
		} else {
			idx = (unsigned int)time(NULL);
		}
	}
	idx %= QUIZ_COUNT;

	/* 发送题目: "Q:<错句>" */
	{
		char q[256];
		snprintf(q, sizeof(q), "Q:%s", quiz[idx][0]);
		write(cfd, q, strlen(q));
	}

	/* 等答案 (最多 30 秒, 防卡死) */
	alarm(30);
	n = read(cfd, buf, sizeof(buf) - 1);
	alarm(0);
	if (n <= 0)
		goto out;
	buf[n] = '\0';
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = '\0';

	if (verify_answer(quiz[idx][0], quiz[idx][1], quiz[idx][2], buf) != 0) {
		write(cfd, "FAIL", 4);
		goto out;
	}

	/* 验证通过: 由守护进程自己卸载 (key 不出本进程) */
	if (do_unload() == 0) {
		write(cfd, "OK", 2);
		/* 卸载完成, 通知父进程退出 */
		kill(getppid(), SIGTERM);
		goto out;
	}
	write(cfd, "ERR", 3);
out:
	close(cfd);
	_exit(0);
}

/* 守护进程主循环: fork 处理每个连接, 单连接阻塞不影响 accept */
static int daemon_loop(void)
{
	for (;;) {
		int cfd;
		pid_t pid;

		cfd = accept(sock_fd, NULL, NULL);
		if (cfd < 0)
			continue;

		pid = fork();
		if (pid < 0) {
			close(cfd);
			continue;
		}
		if (pid == 0) {
			/* 子进程: 处理该连接 */
			handle_client(cfd);
		}
		/* 父进程: 关闭子进程的 fd, 继续 accept */
		close(cfd);
	}
}

/* 验证模式: 连接守护进程 socket, 显示题目, 转发答案 */
static int verify_mode(void)
{
	struct sockaddr_un addr;
	int fd;
	char buf[BUF_SZ];
	int n;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "afd: 无法连接守护进程 (afd 未运行?): %s\n",
			strerror(errno));
		return 1;
	}

	/* 发 VERIFY */
	write(fd, "VERIFY", 6);

	/* 收题目 */
	n = read(fd, buf, sizeof(buf) - 1);
	if (n <= 0) {
		fprintf(stderr, "afd: 守护进程无响应\n");
		return 1;
	}
	buf[n] = '\0';
	if (strncmp(buf, "Q:", 2) == 0) {
		const char *q = buf + 2;
		printf("验证: 下面这句话有错别字, 请把修正后的句子完整输入:\n");
		printf("  原句: %s\n> ", q);
		fflush(stdout);
	} else {
		fprintf(stderr, "afd: 协议错误: %s\n", buf);
		return 1;
	}

	/* 读用户输入 */
	if (fgets(buf, sizeof(buf), stdin) == NULL) {
		fprintf(stderr, "afd: 输入读取失败\n");
		return 1;
	}
	buf[strcspn(buf, "\r\n")] = '\0';

	/* 发答案 */
	write(fd, buf, strlen(buf));

	/* 收结果 */
	n = read(fd, buf, sizeof(buf) - 1);
	if (n <= 0) {
		fprintf(stderr, "afd: 守护进程无响应\n");
		return 1;
	}
	buf[n] = '\0';
	if (strncmp(buf, "OK", 2) == 0) {
		printf("验证通过, 防护已停用。\n");
		return 0;
	} else if (strncmp(buf, "FAIL", 4) == 0) {
		printf("修正不正确, 验证失败。\n");
		return 1;
	}
	printf("卸载失败: %s\n", buf);
	return 1;
}

int main(int argc, char **argv)
{
	int mode = 0; /* 0=守护, 1=验证 */

	if (argc >= 2 && strcmp(argv[1], "verify") == 0)
		mode = 1;

	if (mode == 0) {
		/* 守护模式 */
		/* 防止被 OOM 杀掉 */
		{
			int fd = open("/proc/self/oom_score_adj", O_WRONLY);
			if (fd >= 0) {
				write(fd, "-1000", 5);
				close(fd);
			}
		}
		/* 注册 pid (受内核 kill 保护) */
		if (register_guard() != 0)
			fprintf(stderr, "afd: guard register failed: %s\n",
				strerror(errno));
		/* 一次性读 key */
		if (read_key() != 0)
			fprintf(stderr, "afd: key read failed\n");
		else
			fprintf(stderr, "afd: 守护在线 (pid=%d), key 已入内存\n",
				getpid());
		/* 创建 socket */
		if (sock_init() != 0) {
			fprintf(stderr, "afd: socket init failed: %s\n",
				strerror(errno));
			/* 即使 socket 失败也常驻 (防止进程死亡) */
			for (;;) pause();
		}
		daemon_loop();
		return 0;
	}

	/* 验证卸载模式 */
	return verify_mode();
}