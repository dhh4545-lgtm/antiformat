#!/system/bin/sh
# run_zero_fill.sh - 备份 + 整盘 zero 填充测试 + sha256 校验 + 自动恢复
LOG=/data/local/tmp/zero_fill.log
ELF=/data/local/tmp/zh_zero_fill
BDEV=/dev/block/by-name/init_boot_b
BAK=/sdcard/aftest/init_boot_b.bak
GOOD_SHA=338daff69fbfa5456bc2d518f8f8c49e8e244fc05b241f94e6493125f95dbf67

echo "=== zero_fill run $(date) ===" > $LOG

# 0) 确认模块在线
echo "=== module ===" >> $LOG
cat /proc/modules 2>&1 | grep -i anti >> $LOG
cat /proc/antiformat/status 2>&1 | head -20 >> $LOG

# 1) 备份 (必须)
echo "=== backup ===" >> $LOG
dd if=$BDEV of=$BAK bs=4M count=2 status=none 2>> $LOG
sha256sum $BAK >> $LOG 2>&1

# 2) 攻击前基准
echo "=== before ===" >> $LOG
sha256sum $BDEV >> $LOG 2>&1

# 3) 复制 ELF + 执行整盘 zero 填充
cp /sdcard/aftest/zh_zero_fill $ELF 2>> $LOG
chmod 755 $ELF 2>> $LOG
echo "=== attack ===" >> $LOG
$ELF >> $LOG 2>&1
RC=$?
echo "zh_zero_fill rc=$RC (1=拦截/0=未拦截有洞)" >> $LOG

# 4) 攻击后校验
echo "=== after ===" >> $LOG
sha256sum $BDEV >> $LOG 2>&1

# 5) 若有洞 (rc=0) 立即从备份恢复
if [ "$RC" = "0" ]; then
  echo "!!! 防护有洞, 立即恢复备份 !!!" >> $LOG
  dd if=$BAK of=$BDEV bs=4M count=2 status=none 2>> $LOG
  echo "=== after restore ===" >> $LOG
  sha256sum $BDEV >> $LOG 2>&1
fi

echo "=== done rc=$RC ===" >> $LOG
exit 0