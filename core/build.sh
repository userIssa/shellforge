#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
echo "[*] ShellForge build starting..."
mkdir -p "$BUILD_DIR"

SOURCES="$SCRIPT_DIR/src/shellforge.c \
         $SCRIPT_DIR/src/arch_profiles.c \
         $SCRIPT_DIR/src/arch_x86_32.c \
         $SCRIPT_DIR/src/arch_arm.c \
         $SCRIPT_DIR/src/arch_mips.c \
         $SCRIPT_DIR/src/arch_win64.c"

echo "[*] Compiling libshellforge.so..."
gcc -Wall -Wextra -std=c99 -fPIC -shared \
    -o "$BUILD_DIR/libshellforge.so" \
    $SOURCES \
    -I "$SCRIPT_DIR/include"
echo "[+] libshellforge.so -> $BUILD_DIR/libshellforge.so"

echo "[*] Compiling sf_cli..."
gcc -Wall -Wextra -std=c99 \
    -o "$BUILD_DIR/sf_cli" \
    "$SCRIPT_DIR/src/cli.c" \
    $SOURCES \
    -I "$SCRIPT_DIR/include"
echo "[+] sf_cli -> $BUILD_DIR/sf_cli"

echo ""
echo "── Build complete ───────────────────────────────────"
echo "CLI:          ./build/sf_cli"
echo "Python tests: cd .. && python tests/python/test_phase1.py"
