#!/system/bin/sh
# unload_test.sh - 卸载 antiformat 模块, 验证 rmmod 三保险修复
LOG=/data/local/tmp/unload_test.log
echo "=== unload test $(date) ===" > $LOG

# 1) 卸载前状态
echo "=== before ===" >> $LOG
lsmod 2>&1 | grep -i anti >> $LOG

# 2) 卸载 (三保险: stop_machine + synchronize_rcu + 延后清理)
/system/bin/rmmod antiformat 2>> $LOG
echo "rmmod rc=$? (0=卸载成功)" >> $LOG

# 3) 卸载后验证
echo "=== after lsmod ===" >> $LOG
lsmod 2>&1 | grep -i anti >> $LOG
echo "lsmod grep rc=$? (1=模块已移除)" >> $LOG

# 4) proc 清理验证
echo "=== proc node ===" >> $LOG
ls -la /proc/antiformat 2>&1 >> $LOG

echo "=== done ===" >> $LOG
exit 0