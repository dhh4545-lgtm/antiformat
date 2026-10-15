⚠️【内核级防格机】AntiFormat 防格机保护模块 v0.2.0-TEST（测试版）—— 持久化驻留 · dev_t 分区级拦截 · 极限攻击实测全拦截

一、这是啥
防格机大家都懂吧？就是防止"格机工具"（张豪全防这类样本）一键把你手机分区格式化、清零、覆写，直接变砖。

AntiFormat 是一个 Android 内核级（KernelSU 模块）防格机保护模块：
🔹 直接 hook 内核系统调用（open/write/ioctl/truncate/...）
🔹 在内核层拦截对受保护分区/目录的一切破坏性操作
🔹 不是 APP、不是壳，是真正跑在内核里的保镖

🤖 本工具由 AI（Operit）辅助完成设计、开发与测试。

二、核心特性
✅ dev_t 设备号级匹配：保护真实分区块（persist/基带/启动链等），不看路径字符串——by-name、bootdevice 各种别名全都能拦
✅ 12 个 syscall hook：open、write、pwrite64、ioctl(BLKZEROOUT/BLKDISCARD/FITRIM)、truncate、ftruncate、fallocate、unlinkat、renameat、mount、umount2、swapon/off
✅ 64 进制 key 卸载认证：加载时随机生成 key，没 key 别想卸（rmmod 直接 EBUSY）
✅ 永久驻留 + 逻辑卸载：模块内存永不释放，根治"卸载死机"竞态；用 key 写 /proc 节点可停用防护
✅ 开机自启：等系统完全启动后再加载，不碰 persist 初始化期（防分区坏死）

三、极限攻击实测（作者测试机，全部被拦）
攻击手法矩阵（8 种）：
| open+write 整盘覆写 | ✅ EPERM |
| open(O_RDONLY)+ioctl BLKZEROOUT 整盘清零 | ✅ EPERM |
| O_TRUNC 截断 / pwrite64 / fallocate / ftruncate | ✅ 全拦 |
| open+mmap 直接写映射 | ✅ open 阶段就拦 |
| /dev/block/bootdevice/ 别名路径 | ✅ dev_t 匹配拦 |
| dd / head / echo 覆写 | ✅ 拦 |
| rmmod 直接卸载 | ✅ EBUSY 拒绝，不死机 |
| key 逻辑卸载 | ✅ 成功，不死机 |

四、安装要求
- 内核：6.6.x GKI aarch64（实测 6.6.89）
- Root：KernelSU
- 其他内核/非KSU 别装！不保证兼容！

五、下载
📥 直链：
https://github.com/dhh4545-lgtm/antiformat/releases/download/v0.2.0-TEST/antiformat-kernelsu.zip

KernelSU 管理器 → 模块 → 本地安装 → 重启生效

六、卸载（重要！保存好 key！）
dmesg | grep "unload key"  → 得到 key
echo "你的key" > /proc/antiformat/unload  → 停用防护
key 每次加载随机生成，只打印一次，丢了没法逻辑卸载！

⚠️⚠️ 七、免责声明（务必看完）⚠️⚠️
🚨 这是测试版（Pre-release），不是正式版！
🚨 直接改内核 syscall table，高风险！可能死机、变砖、丢数据！
🚨 作者不承担任何责任！所有风险自负！
🚨 只建议在备用机上测试！主力机别装！
🚨 请自备救砖工具和原厂固件！
🚨 安装即视为同意以上条款！

老规矩：研究测试可以，别拿去做坏事。有任何问题欢迎评论区留言或私信，附上机型 + uname -r + 模块日志。
