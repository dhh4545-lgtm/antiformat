#!/system/bin/sh
# getkey.sh - 尝试各种途径获取卸载 key
echo "=== 1. dmesg raw ==="
dmesg 2>&1 | grep -a 'nload' | tail -5
echo "=== 2. dmesg full tail ==="
dmesg 2>&1 | tail -30 | grep -aiE 'anti|key|unload'
echo "=== 3. module log ==="
cat /data/adb/modules/antiformat/antiformat.log 2>&1 | tail -20
echo "=== 4. proc unload node ==="
ls -la /proc/antiformat/ 2>&1
echo "--- try read unload ---"
cat /proc/antiformat/unload 2>&1
echo "=== 5. try unprotect node ==="
cat /proc/antiformat/unprotect 2>&1
echo "=== done ==="