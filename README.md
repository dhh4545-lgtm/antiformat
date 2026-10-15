# AntiFormat — Android 防格机内核模块

防止对受保护目录/分区进行格式化、删除、覆盖等破坏性操作。

**开源许可：GPL-3.0-or-later**（见 [LICENSE](LICENSE)）。
本项目为自由软件：你可依据自由软件基金会发布的 GNU 通用公共许可证第 3 版
（或更新版本）条款重新分发和/或修改它。分发时不提供任何担保。

## 架构

| 层级 | 内容 |
|------|------|
| 内核模块 | `antiformat.ko`（LKM，syscall hook） |
| 模块框架 | KernelSU 模块（`/data/adb/modules/antiformat/`） |
| 配置 | 受保护目录列表，支持动态增删 |
| 用户工具 | 可选的命令行配置工具 |

## 构建目标环境

- 内核：`6.6.89-android15-8-gf4dc45704e54-abogki446052083-4k` (GKI, aarch64)
- CONFIG: `CFI_CLANG=y`, `KALLSYMS_ALL=y`, `KPROBES=y`, `MODULES=y`
- Root: KernelSU (`context: u:r:ksu:s0`)

## 阶段规划

### 第一阶段：防止 dd / rm / 格式化 等破坏性操作
拦截以下 syscall（对受保护路径）：
- `unlinkat` / `unlink` — `rm` 删除文件
- `rmdir` — 删除目录
- `renameat` / `renameat2` — 覆盖/移动
- `truncate` / `ftruncate` — 截断文件
- `openat` — 以写/截断方式打开受保护目标
- `ioctl` — 格式化相关 ioctl (BLKDISCARD 等)
- `write` / `pwrite64` — 对受保护块设备/文件的直接写

### 第二阶段：ELF 可执行文件拦截（规划中）
对可执行文件 (exec) 的加载实施白名单/黑名单控制。

### 第三阶段：用户自测
由用户自行安装并测试验证。

## 目录结构

```
antiformat/
├── README.md
├── LICENSE            # GPL-3.0 全文
├── kernel/            # 内核模块源码 (antiformat.ko)
│   ├── af_main.c      # 主体: syscall hook + 极端模式 + 白名单 + SHA-256
│   ├── ksym.c         # 内核符号解析 (kprobe)
│   ├── mmuhack.c      # PTE hack 切换 rodata 读写
│   ├── Makefile
│   └── ...
├── daemon/            # afd 守护进程源码 (人机验证卸载)
│   ├── afd.c
│   └── ...
├── module/            # KernelSU 模块打包内容
│   ├── module.prop
│   ├── service.sh
│   ├── uninstall.sh
│   └── ...
├── build/             # 构建环境与产物
│   ├── kheaders/      # 从设备 /sys/kernel/kheaders.tar.xz 解出的头文件
│   ├── kernel_config  # 从设备 /proc/config.gz 提取的配置
│   └── gki-kernel/    # GKI 6.6 内核源码树（构建基础设施）
└── tools/             # 用户态配置工具
```

## 配置

受保护目录存放在模块目录 `protect.list`，每行一个路径，支持通配符。
示例：
```
/data/media/0/DCIM
/data/media/0/Pictures
/sdcard/Download
/data/adb
```