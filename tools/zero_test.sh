#!/system/bin/sh
# zero_test.sh - 用 zero 覆写 init_boot_b 整盘, 验证防护
LOG=/data/local/tmp/zero_test.log
BDEV=/dev/block/by-name/init_boot_b
BAK=/sdcard/aftest/init_boot_b.bak

echo "=== zero_test $(date) ===" > $LOG

# 0) 当前防护状态
echo "=== module ===" >> $LOG
cat /proc/modules 2>&1 | grep -i anti >> $LOG
echo "=== status ===" >> $LOG
cat /proc/antiformat/status 2>&1 | head -30 >> $LOG

# 1) 备份当前 init_boot_b (万一防护有洞被清零, 可恢复)
echo "=== backup ===" >> $LOG
dd if=$BDEV of=$BAK bs=4M count=2 status=none 2>> $LOG
ls -la $BAK >> $LOG 2>&1
sha256sum $BDEV >> $LOG 2>&1

# 2) 攻击前 sha256 (基准)
echo "=== before sha256 ===" >> $LOG
sha256sum $BDEV >> $LOG 2>&1

# 3) zero 整盘覆写攻击: 3 种方式
echo "=== attack A: dd zero direct ===" >> $LOG
dd if=/dev/zero of=$BDEV bs=4K count=1 oflag=direct 2>> $LOG
echo "A rc=$? (0=未拦截!! 1=被拦或出错)" >> $LOG

echo "=== attack B: cp zero (受限4KB) ===" >> $LOG
head -c 4096 /dev/zero > $BDEV 2>> $LOG
echo "B rc=$? (0=未拦截!! 1=被拦或出错)" >> $LOG

echo "=== attack C: echo zero ===" >> $LOG
head -c 4096 /dev/zero > $BDEV 2>> $LOG
echo "C rc=$? (0=未拦截!! 1=被拦或出错)" >> $LOG

# 4) 攻击后 sha256 (必须与 before 一致)
echo "=== after sha256 ===" >> $LOG
sha256sum $BDEV >> $LOG 2>&1

echo "=== done ===" >> $LOG