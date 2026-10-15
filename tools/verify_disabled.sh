#!/system/bin/sh
# verify_disabled.sh - 验证逻辑卸载后: 防护失效 + rmmod 仍被拒
LOG=/data/local/tmp/verify_disabled.log
echo "=== verify disabled $(date) ===" > $LOG

echo "=== status ===" >> $LOG
cat /proc/antiformat/status 2>&1 >> $LOG

echo "=== write to Download (should SUCCEED, protection off) ===" >> $LOG
echo "af_test_$(date +%s)" > /sdcard/Download/af_test.txt 2>> $LOG
echo "write rc=$? (0=写成功=防护已失效)" >> $LOG
ls -la /sdcard/Download/af_test.txt 2>&1 >> $LOG

echo "=== rm the test file (should SUCCEED) ===" >> $LOG
rm /sdcard/Download/af_test.txt 2>&1 >> $LOG
echo "rm rc=$? (0=删除成功=防护已失效)" >> $LOG

echo "=== rmmod attempt (should be rejected EBUSY) ===" >> $LOG
/system/bin/rmmod antiformat 2>&1 >> $LOG
echo "rmmod rc=$? (非0=仍被拒, 模块驻留)" >> $LOG

echo "=== module still present ===" >> $LOG
cat /proc/modules 2>&1 | grep -i anti >> $LOG

echo "=== done ===" >> $LOG