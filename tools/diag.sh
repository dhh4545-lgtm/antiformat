#!/system/bin/sh
# diag.sh - 诊断防护为何失效
echo "=== 1. module ==="
cat /proc/modules 2>&1 | grep -i anti
echo "=== 2. status ==="
cat /proc/antiformat/status 2>&1
echo "=== 3. ksu log ==="
cat /data/adb/modules/antiformat/antiformat.log 2>&1
echo "=== 4. protect paths count ==="
cat /proc/antiformat/status 2>&1 | grep -c "block/by-name"
echo "=== 5. init_boot_b dev ==="
stat -c '%t:%T %n' /dev/block/bootdevice/by-name/init_boot_b 2>&1
stat -c '%t:%T %n' /dev/block/by-name/init_boot_b 2>&1
echo "=== 6. boot_completed ==="
getprop sys.boot_completed 2>&1
echo "=== done ==="