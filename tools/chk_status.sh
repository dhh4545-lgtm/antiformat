#!/system/bin/sh
# chk_status.sh - 查看 antiformat 状态
echo "=== module ==="
cat /proc/modules 2>&1 | grep -i anti
echo "=== status ==="
cat /proc/antiformat/status 2>&1
echo "=== persist mount ==="
mount 2>/dev/null | grep -iE 'persist|fsg|fsc|efs|modemst' | head
echo "=== done ==="