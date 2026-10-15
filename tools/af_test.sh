#!/system/bin/sh
# af_test.sh - 加载 antiformat 模块并测试 "img 刷入 init_boot" 拦截
# 用法: sh /data/local/tmp/af_test.sh
# 模拟恶意刷机 ELF: 把 kernelsu_patched_*.img 写入 init_boot_b 分区

LOG=/data/local/tmp/af_test.log
echo "=== AntiFormat flash-initboot test ===" > $LOG
date >> $LOG

BDEV=/dev/block/by-name/init_boot_b
# 解析 by-name 指向的真实设备节点 (兼容不同内核的映射)
BDEV_REAL=$(readlink -f $BDEV)
echo "bdev_real=$BDEV_REAL" >> $LOG

IMG=/storage/emulated/0/Download/kernelsu_patched_20261008_180910.img
ELF=/sdcard/aftest/flash_initboot

# 1) 卸载旧模块 (忽略错误)
/system/bin/rmmod antiformat 2>>$LOG >>$LOG || true

# 2) 加载新模块
/system/bin/insmod /data/local/tmp/antiformat.ko 2>>$LOG >>$LOG
RC=$?
echo "insmod rc=$RC" >> $LOG
if [ $RC -ne 0 ]; then
  echo "FATAL: insmod failed" >> $LOG
  lsmod | grep anti >> $LOG
  exit 10
fi
echo "module loaded:" >> $LOG
lsmod | grep anti >> $LOG

# 3) 配置保护路径: 真实设备节点 + by-name
echo "$BDEV_REAL" > /proc/antiformat/protect 2>>$LOG
echo "protect +$BDEV_REAL rc=$?" >> $LOG
echo "$BDEV" > /proc/antiformat/protect 2>>$LOG
echo "protect +$BDEV rc=$?" >> $LOG

# 4) 显示保护状态
echo "--- status ---" >> $LOG
cat /proc/antiformat/status >> $LOG 2>&1

# 5) 记录 img 与分区 before 校验
echo "--- before ---" >> $LOG
sha256sum "$IMG" >> $LOG 2>&1
sha256sum "$BDEV_REAL" >> $LOG 2>&1

# 6) 运行刷机 ELF (模拟恶意刷机工具)
echo "--- running flash_initboot ---" >> $LOG
/system/bin/chmod 755 $ELF >> $LOG 2>&1
$ELF "$IMG" "$BDEV_REAL" >> $LOG 2>&1
ELF_RC=$?
echo "flash_initboot rc=$ELF_RC (0=未被拦截/刷入成功, 2=open被拦, 4=write被拦, 3=img读取失败)" >> $LOG

# 7) 校验 init_boot_b 是否被改写
echo "--- after ---" >> $LOG
sha256sum "$BDEV_REAL" >> $LOG 2>&1

# 8) 记录 dmesg
echo "--- dmesg antiformat ---" >> $LOG
dmesg | grep -i anti | tail -30 >> $LOG 2>&1

echo "=== done rc=$ELF_RC ===" >> $LOG
exit 0