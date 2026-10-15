#!/system/bin/sh
# ============================================================
# attackshell.sh — AntiFormat 红队验证（Shell 层攻击）
# 目标: init_boot_b / boot_b (B 分区)
# 方案: 覆盖常见 shell 格机命令，全部应被模块 EPERM 拦截
# 输出约定:
#   [BLOCKED] -> 被 AntiFormat 拦截 (防护生效 ✓)
#   [WRITE OK] -> 写入成功 (模块没拦住 ✗ 漏洞!)
#   [FAIL]    -> 其他失败 (路径不存在/权限等)
# ============================================================
TARGETS="/dev/block/by-name/init_boot_b /dev/block/by-name/boot_b"
TOTAL=0; BLOCKED=0; OK=0; FAIL=0

run_check() {
    # $1=方案名 $2=命令
    local name="$1"; shift
    TOTAL=$((TOTAL+1))
    "$@" >/dev/null 2>&1
    local rc=$?
    case $rc in
        1) BLOCKED=$((BLOCKED+1)); echo "  [BLOCKED] $name -> EPERM (拦截✓)";;
        0) OK=$((OK+1));           echo "  [WRITE OK] $name -> 写入了! 模块未拦截 ✗";;
        *) FAIL=$((FAIL+1));       echo "  [FAIL   ] $name -> rc=$rc";;
    esac
}

echo "=== AntiFormat Shell 层攻击测试 (init_boot_b + boot_b) ==="
for T in $TARGETS; do
    echo "◆ 目标: $T"
    # 1. dd 直接写零
    run_check "dd write zero" dd if=/dev/zero of=$T bs=4096 count=1 conv=notrunc
    # 2. dd 用随机数据覆写
    run_check "dd write rand" dd if=/dev/urandom of=$T bs=4096 count=1 conv=notrunc
    # 3. cp 覆写
    run_check "cp overwrite" cp /dev/zero $T
    # 4. tee 覆写
    run_check "tee overwrite" sh -c "dd if=/dev/zero bs=4096 count=1 | tee $T >/dev/null"
    # 5. echo 重定向
    run_check "echo redirect" sh -c "echo 'AAAA' > $T"
    # 6. truncate 截断
    run_check "truncate -s 0" truncate -s 0 $T
    # 7. fallocate
    run_check "fallocate zero" fallocate -z -l 4096 $T
    # 8. blkdiscard (ioctl BLKDISCARD)
    run_check "blkdiscard" blkdiscard -s -l 4096 $T
    echo ""
done

echo "=== 汇总: 总=$TOTAL 拦截=$BLOCKED 成功=$OK 其他=$FAIL ==="
if [ $OK -eq 0 ] && [ $BLOCKED -gt 0 ]; then
    echo "结论: 全部被模块拦截 ✓"
elif [ $OK -gt 0 ]; then
    echo "结论: 存在绕过路径 ✗ 需要补漏!"
else
    echo "结论: 无成功也无拦截(路径可能不可用)"
fi
exit 0
