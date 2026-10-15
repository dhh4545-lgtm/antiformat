#!/system/bin/sh
echo "=== module ==="
cat /proc/modules 2>&1 | grep -i anti
echo "=== status ==="
cat /proc/antiformat/status 2>&1 | head -5
echo "=== dmesg dev_t sample ==="
dmesg 2>&1 | grep -i "protect +/dev/block/sd" | head -5
echo "=== done ==="