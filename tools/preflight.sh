#!/system/bin/sh
# preflight.sh - 测试前预检: 配置保护 + 确认 status + 校验 img
LOG=/data/local/tmp/preflight.log
echo "=== preflight $(date) ===" > $LOG

# 1) 配置保护路径 (by-name 权威, 模块会解析 dev_t)
echo "/dev/block/by-name/init_boot_b" > /proc/antiformat/protect 2>> $LOG
echo "/dev/block/by-name/init_boot" > /proc/antiformat/protect 2>> $LOG
echo "protect rc=$?" >> $LOG

# 2) 打印 status 看 dev_t
echo "=== status ===" >> $LOG
cat /proc/antiformat/status >> $LOG 2>&1

# 3) 备份当前 init_boot_b sha256 (测试前后对比)
echo "=== before sha ===" >> $LOG
sha256sum /dev/block/by-name/init_boot_b >> $LOG 2>&1

# 4) 校验 img 存在
echo "=== img ===" >> $LOG
ls -la /storage/emulated/0/Download/kernelsu_patched_20261008_180910.img >> $LOG 2>&1
sha256sum /storage/emulated/0/Download/kernelsu_patched_20261008_180910.img >> $LOG 2>&1

echo "=== done ===" >> $LOG
