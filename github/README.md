# ⚠️ AntiFormat 防格机保护模块（测试版）

> **版本：v0.2.0-TEST（测试版 / BETA）**
> **状态：实验性内核模块，仅供技术研究与测试**
> **制作：本工具由 AI 辅助设计、开发与测试**

---

## 🚨 重要免责声明（请务必先阅读）

**本模块为测试版（BETA），并非稳定发布版本。**

1. **风险自负**：本模块直接修改 Linux 内核系统调用表（sys_call_table），属于高风险操作。使用、测试本模块可能导致：**手机死机（panic）、无法开机（变砖）、系统分区损坏、数据丢失、保修失效**等严重后果。
2. **作者不承担任何责任**：因使用、安装、测试本模块（包括但不限于误操作、模块缺陷、与其他软件/固件冲突、设备损坏）造成的任何直接或间接损失，**作者及本项目一律不承担任何责任**。
3. **测试版无保证**：本模块不提供任何形式的明示或暗示担保，包括但不限于适销性、特定用途适用性、稳定性、兼容性保证。
4. **仅限有经验用户**：本模块仅面向**具备 Android 内核刷写、救砖、备份恢复能力的高级用户**。小白用户请勿尝试。
5. **请在测试设备上使用**：强烈建议仅在**专门用于测试的备用设备**上使用，**切勿在主力机/日常使用设备上安装**。
6. **测试范围限制**：作者仅在一台特定机型（Android 16 / 内核 6.6.89 GKI aarch64 / KernelSU）上测试通过，**不代表其他机型、内核版本、ROM 兼容**。
7. **第三方风险**：本模块被第三方（非作者）转发、修改、重新打包后，作者不保证其完整性、安全性，一切后果与作者无关。
8. **卸载依赖 key**：模块设计为永久驻留，卸载需使用加载时生成的 64 进制 key（见下文）。**请务必保存好 key，丢失 key 将无法逻辑卸载**（只能通过重启前移除模块文件等方式处理）。

**继续使用即表示您已阅读、理解并同意以上全部条款。**

---

## 📦 这是什么

**AntiFormat** 是一个 Android 内核级防格机/防破坏性操作保护模块（KernelSU 模块）。

它通过 hook 关键系统调用（open/write/ioctl/truncate/unlink/rename/mount 等），
在内核层拦截对**受保护块设备分区**和**受保护目录**的破坏性操作，
用于对抗"格机工具"（如张豪全防类样本）对手机分区的格式化、清零、覆写攻击。

> 🤖 **本工具由 AI（Operit）辅助完成设计、开发与测试**：从内核模块架构设计、syscall hook 实现、
> dev_t 匹配机制修复、极限攻击测试到 KernelSU 模块打包，均由 AI 协作产出。

### 核心特性
- ✅ **dev_t 设备号匹配**：保护真实分区块（persist/基带/启动链等），不依赖路径字符串，别名（by-name / bootdevice）也能拦截
- ✅ **12 个 syscall hook**：open、write、pwrite64、ioctl（BLKZEROOUT/BLKDISCARD/FITRIM）、truncate、ftruncate、fallocate、unlinkat、renameat、mount、umount2、swapon/off
- ✅ **64 进制 key 卸载认证**：加载时随机生成 8 位 key，无 key 无法卸载（rmmod 返回 EBUSY）
- ✅ **永久驻留 + 逻辑卸载**：模块内存永不释放（根治卸载死机竞态），用 key 写节点可逻辑停用防护
- ✅ **EPERM 指令拦截（不断进程）**：命中保护时仅拒绝该次系统调用（返回 -EPERM），不 kill 进程；格机工具可继续运行，但所有破坏操作被精准弹回
- ✅ **开机自启**：KernelSU service.sh 等待系统完全启动后自动加载

---

## 📦 安装要求

| 项目 | 要求 |
|---|---|
| 设备 | Android 13+（理论），已实测 Android 16 |
| 内核 | 6.6.x GKI aarch64（已实测 6.6.89-android15-8） |
| Root | KernelSU（模块管理器） |
| 架构 | arm64 (aarch64) 仅 |

> ⚠️ **非 GKI 内核 / 非 KernelSU / 其他架构 不保证可用，请勿强行安装**

---

## 📥 下载

**📥 直链下载（v0.2.0-TEST）：**

👉 **https://github.com/dhh4545-lgtm/antiformat/releases/download/v0.2.0-TEST/antiformat-kernelsu.zip**

> 提示：该 Release 为 **Pre-release（预发布/测试版）**，不是正式版。

## 📮 反馈 / 交流群（QQ）

测试中遇到任何问题（死机、重启、防护失效、兼容性问题），请加入反馈群：

| 群 | 群号 |
|---|---|
| 一群 | **863932624** |
| 二群 | **994378564** |
| 三群 | **454087230** |
| 四群 | **1081449657** |

> 反馈请附：设备型号、内核版本（`uname -r`）、模块日志（`/data/adb/modules/antiformat/antiformat.log`）、dmesg 相关输出。

---

## 📥 安装方法

1. 下载 `antiformat-kernelsu.zip`
2. 打开 KernelSU 管理器 → **模块** → **本地安装** → 选择该 zip
3. 安装完成后 **重启手机**
4. 重启后模块自动加载，防护自动生效

### 验证安装
```sh
# 模块是否加载（refcount=1 表示已驻留）
cat /proc/modules | grep -i anti

# 防护状态
cat /proc/antiformat/status
# 期望输出: disabled=0, 保护路径 126 条（含 persist/boot 等分区块，不含 /data/adb）

# 模块加载日志
cat /data/adb/modules/antiformat/antiformat.log
```

---

## 🔑 卸载 / 停用防护（重要！）

模块**永久驻留**，`rmmod` 会被内核拒绝（返回 EBUSY），这是防恶意卸载的设计。

**逻辑卸载（停用防护）必须使用加载时生成的 key：**

```sh
# 1. 查看 key（加载时打印在 dmesg）
dmesg | grep "unload key"
# 例: [antiformat] unload key: oD5wCcbN

# 2. 用 key 逻辑卸载（防护停用, 模块仍驻留但不再拦截）
echo "你的key" > /proc/antiformat/unload

# 3. 确认防护已停用
cat /proc/antiformat/status   # disabled=1
```

> ⚠️ **key 每次加载随机生成，且只打印一次。请保存好，丢失将无法逻辑卸载。**

---

## 🛡️ 受保护对象（v0.2.0 默认保护）

**块设备分区（真实分区块 dev_t 匹配）**，包括但不限于：

- **persist / 校准 / 基带**：persist、fsg、fsc、modemst1/2、oplusdycnvbk、vm-persist、qmcs、spunvm 等
- **安全/密钥**：keystore、connsec、tzsc、storsec、secdata、frp、devinfo、uefivarstore 等
- **启动链**：boot_a/b、init_boot_a/b、dtbo、vendor_boot、recovery、super、vbmeta 全套
- **固件镜像**：modem_a/b、dsp、hyp、tz、bluetooth、keymaster、uefi、xbl 等

**目录（前缀匹配）**：DCIM、Pictures、Movies、/sdcard/Download

> 🔧 **v0.2.0-TEST 修复说明**：`/data/adb` 不再列入默认保护。它是 KernelSU 模块安装/升级目录（`/data/adb/modules/`），保护会导致模块无法安装/升级；且模块已 insmod 驻留内核，攻击者删除该目录不影响防护，故无保护价值。

> 注：userdata（用户数据）、rawdump（崩溃转储）、hybridswap（交换）、metadata（FBE 元数据）默认**不保护**（需系统可写）。

---

## 🧪 已知测试结果（仅限作者测试机）

| 攻击手法 | 结果 |
|---|---|
| open(O_WRONLY)+write 整盘覆写 | ✅ 拦截（EPERM） |
| open(O_RDONLY)+ioctl(BLKZEROOUT) 整盘清零 | ✅ 拦截（EPERM） |
| open(O_WRONLY\|O_TRUNC) 截断 | ✅ 拦截（EPERM） |
| pwrite64 / fallocate / ftruncate | ✅ 拦截（EPERM） |
| open(O_RDWR)+mmap 直接写映射 | ✅ 拦截（open 阶段） |
| /dev/block/bootdevice/ 别名路径 | ✅ 拦截（dev_t 匹配） |
| dd / head / echo 等 shell 工具覆写 | ✅ 拦截 |
| rmmod 直接卸载 | ✅ 拒绝（EBUSY，不死机） |
| key 逻辑卸载 | ✅ 成功（不死机） |

---

## 📁 目录结构

```
antiformat-kernelsu.zip
├── module.prop         模块元数据
├── customize.sh        安装脚本
├── service.sh          开机加载脚本（等 sys.boot_completed）
├── uninstall.sh        卸载脚本（key 逻辑卸载）
├── protect.list        受保护分区/路径列表
└── lib/modules/antiformat.ko  内核模块本体
```

---

## 📜 许可证

本项目采用 **GNU 通用公共许可证第 3 版（或更新版本）** 发布，即 **GPL-3.0-or-later**。
完整条款见项目根目录 [LICENSE](LICENSE)。

- 本程序为自由软件：你可以依据自由软件基金会发布的 GPLv3 条款重新分发和/或修改它。
- 本程序按"AS IS"分发，**不提供任何担保**，亦不保证适销性或特定用途适用性。
- 依据 GPLv3，任何分发本程序（或衍生作品）者，**必须一并提供完整对应源码**。
- 严禁将本项目用于任何非法用途。

## 📮 反馈

- 本仓库为**开源项目**，完整源码见 `kernel/`、`daemon/`、`module/` 等目录。
- 测试问题反馈请附：设备型号、内核版本（`uname -r`）、模块日志（`/data/adb/modules/antiformat/antiformat.log`）、dmesg 相关输出。

---

**再次提醒：这是测试版！使用有风险！请自备救砖工具！作者不承担任何责任！**
