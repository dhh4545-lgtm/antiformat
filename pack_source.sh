#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 AntiFormat contributors
#
# pack_source.sh - 打包 antiformat 开源源码 (排除 gki-kernel 内核树/编译产物)
# 用法: bash pack_source.sh
# 产物: dist/antiformat-source.zip

set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="$ROOT_DIR/dist"
STAGE="$ROOT_DIR/build/source_stage"
SRC_ZIP="$DIST_DIR/antiformat-source.zip"

echo "[*] AntiFormat 源码打包开始"

rm -rf "$STAGE"
mkdir -p "$STAGE"

# 复制项目源码 (排除 build/gki-kernel 内核树, build/module_stage 打包产物, dist, .o/.ko/临时)
# 无 rsync, 用 cp -a + find 删除排除项
cp -a "$ROOT_DIR"/kernel "$STAGE/kernel"
cp -a "$ROOT_DIR/module" "$STAGE/module"
cp -a "$ROOT_DIR/daemon" "$STAGE/daemon"
cp -a "$ROOT_DIR/tools" "$STAGE/tools"
cp -a "$ROOT_DIR/github" "$STAGE/github" 2>/dev/null || true
mkdir -p "$STAGE/build"
cp -a "$ROOT_DIR"/build/*.py "$STAGE/build/" 2>/dev/null || true
cp -a "$ROOT_DIR"/build/*.sh "$STAGE/build/" 2>/dev/null || true
cp -a "$ROOT_DIR"/build/*.c "$STAGE/build/" 2>/dev/null || true
cp -a "$ROOT_DIR"/build/*.h "$STAGE/build/" 2>/dev/null || true
cp -a "$ROOT_DIR"/build/*.log "$STAGE/build/" 2>/dev/null || true
cp -a "$ROOT_DIR"/build/kernel_config "$STAGE/build/" 2>/dev/null || true
cp -a "$ROOT_DIR"/build/ref_* "$STAGE/build/" 2>/dev/null || true
cp -a "$ROOT_DIR"/build/check_symvers.py "$STAGE/build/" 2>/dev/null || true
cp -a "$ROOT_DIR"/build/merge_symvers.py "$STAGE/build/" 2>/dev/null || true
cp -a "$ROOT_DIR"/build/extract_symvers.py "$STAGE/build/" 2>/dev/null || true
cp -a "$ROOT_DIR"/build/gk_input.c "$STAGE/build/" 2>/dev/null || true
cp -a "$ROOT_DIR"/build/gki_* "$STAGE/build/" 2>/dev/null || true
cp -a "$ROOT_DIR/README.md" "$STAGE/" 2>/dev/null || true
cp -a "$ROOT_DIR/LICENSE" "$STAGE/" 2>/dev/null || true
cp -a "$ROOT_DIR/build_package.sh" "$STAGE/" 2>/dev/null || true
cp -a "$ROOT_DIR/pack_source.sh" "$STAGE/" 2>/dev/null || true

# 删除编译产物/临时文件
find "$STAGE" -name '.tmp_*' -type d -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" -name '*.o' -delete 2>/dev/null || true
find "$STAGE" -name '*.ko' -delete 2>/dev/null || true
find "$STAGE" -name '.*.cmd' -delete 2>/dev/null || true
find "$STAGE" -name '*.mod*' -delete 2>/dev/null || true
find "$STAGE" -name 'Module.symvers' -delete 2>/dev/null || true
find "$STAGE" -name 'modules.order' -delete 2>/dev/null || true

# 删除编译出的可执行文件 (只保留 .c/.sh 源码), 避免分发二进制
find "$STAGE" -type f -exec sh -c '
  for f do
    case "$f" in
      *.c|*.h|*.sh|*.py|*.md|*.prop|*.txt|*Makefile*|*LICENSE*) ;;
      *) if head -c4 "$f" 2>/dev/null | grep -q "ELF"; then rm -f "$f"; fi ;;
    esac
  done
' sh {} + 2>/dev/null || true

# 打包 zip
mkdir -p "$DIST_DIR"
rm -f "$SRC_ZIP"
python3 - "$STAGE" "$SRC_ZIP" <<'PYEOF'
import sys, os, zipfile
stage, outzip = sys.argv[1], sys.argv[2]
FIXED = (1980, 1, 1, 0, 0, 0)
with zipfile.ZipFile(outzip, 'w', zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk(stage):
        for f in files:
            full = os.path.join(root, f)
            arc = os.path.relpath(full, stage)
            zi = zipfile.ZipInfo(arc, date_time=FIXED)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = (0o644 & 0xFFFF) << 16
            with open(full, 'rb') as fh:
                zf.writestr(zi, fh.read())
print("[*] source zip entries:")
with zipfile.ZipFile(outzip) as zf:
    for i in zf.infolist():
        print(f"    {i.filename}  ({i.file_size}B)")
PYEOF

echo "[*] 源码打包完成: $SRC_ZIP"
echo "    $(stat -c%s "$SRC_ZIP") bytes"