#!/system/bin/sh
# verify_pin.sh - 验证: 模块加载 + rmmod 被拒 + status
LOG=/data/local/tmp/verify_pin.log
echo "=== verify $(date) ===" > $LOG

echo "=== module ===" >> $LOG
cat /proc/modules 2>&1 | grep -i anti >> $LOG

echo "=== status ===" >> $LOG
cat /proc/antiformat/status 2>&1 >> $LOG

echo "=== try rmmod (should be EBUSY) ===" >> $LOG
/system/bin/rmmod antiformat 2>&1 >> $LOG
echo "rmmod rc=$? (0=卸载了/非0=被拒)" >> $LOG

echo "=== module after rmmod attempt ===" >> $LOG
cat /proc/modules 2>&1 | grep -i anti >> $LOG

echo "=== done ===" >> $LOG