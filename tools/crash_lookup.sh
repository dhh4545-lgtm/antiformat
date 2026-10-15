#!/system/bin/sh
# crash_lookup.sh - 死机后诊断: 状态 + pstore + bootreason
LOG=/data/local/tmp/crash_lookup.log
echo "=== crash lookup $(date) ===" > $LOG

echo "=== uptime ===" >> $LOG
uptime >> $LOG 2>&1

echo "=== modules ===" >> $LOG
cat /proc/modules 2>&1 | head -20 >> $LOG

echo "=== pstore ===" >> $LOG
ls -la /sys/fs/pstore/ 2>&1 >> $LOG

echo "=== console ramoops size ===" >> $LOG
wc -c /sys/fs/pstore/console-ramoops-0 2>&1 >> $LOG

echo "=== boot reason ===" >> $LOG
getprop ro.boot.bootreason 2>&1 >> $LOG
getprop persist.sys.boot.reason 2>&1 >> $LOG

echo "=== dmesg tail ===" >> $LOG
dmesg 2>&1 | tail -20 >> $LOG

echo "=== done ===" >> $LOG
exit 0