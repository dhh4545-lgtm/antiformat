#!/system/bin/sh
# run_zhanghao.sh - 执行 zhanghao_test 攻击测试 + 前后 sha256 校验
LOG=/data/local/tmp/zhanghao_test.log
ELF=/data/local/tmp/zhanghao_test

echo "=== zhanghao_test run $(date) ===" > $LOG

# 1) 复制 ELF 到可执行位置
cp /sdcard/aftest/zhanghao_test $ELF 2>> $LOG
chmod 755 $ELF 2>> $LOG
ls -la $ELF >> $LOG 2>&1

# 2) 攻击前 sha256
echo "=== before sha256 ===" >> $LOG
sha256sum /dev/block/by-name/init_boot_b >> $LOG 2>&1

# 3) 执行攻击测试
echo "=== attack output ===" >> $LOG
$ELF >> $LOG 2>&1
ELF_RC=$?
echo "zhanghao_test rc=$ELF_RC" >> $LOG

# 4) 攻击后 sha256 (必须不变)
echo "=== after sha256 ===" >> $LOG
sha256sum /dev/block/by-name/init_boot_b >> $LOG 2>&1

echo "=== done rc=$ELF_RC ===" >> $LOG
exit 0