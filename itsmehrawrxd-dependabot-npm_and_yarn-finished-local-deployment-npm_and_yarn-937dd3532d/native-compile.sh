#!/bin/sh
set -e

# RawrZ Native Compilation Script
# Compiles C/C++ source to native executables entirely in memory

# 1. Read source from stdin (curl pipe or API)
SRC=$(cat)

# 2. Detect source type and set appropriate compiler flags
if echo "$SRC" | grep -q "#include.*<iostream>"; then
    # C++ source
    COMPILER="clang++"
    EXTENSION="cpp"
elif echo "$SRC" | grep -q "#include.*<stdio.h>"; then
    # C source
    COMPILER="clang"
    EXTENSION="c"
else
    # Default to C
    COMPILER="clang"
    EXTENSION="c"
fi

# 3. Set target architecture based on environment
if [ -n "$TARGET_ARCH" ]; then
    case "$TARGET_ARCH" in
        "windows")
            TARGET_FLAGS="-target x86_64-pc-windows-gnu -fuse-ld=lld"
            OUTPUT_EXT=".exe"
            ;;
        "linux")
            TARGET_FLAGS="-target x86_64-linux-gnu -fuse-ld=lld"
            OUTPUT_EXT=""
            ;;
        "macos")
            TARGET_FLAGS="-target x86_64-apple-darwin -fuse-ld=lld"
            OUTPUT_EXT=""
            ;;
        *)
            TARGET_FLAGS=""
            OUTPUT_EXT=""
            ;;
    esac
else
    TARGET_FLAGS=""
    OUTPUT_EXT=""
fi

# 4. Set optimization level
if [ -n "$OPTIMIZATION" ]; then
    case "$OPTIMIZATION" in
        "debug")
            OPT_FLAGS="-g -O0"
            ;;
        "release")
            OPT_FLAGS="-O3 -DNDEBUG"
            ;;
        "size")
            OPT_FLAGS="-Os -DNDEBUG"
            ;;
        *)
            OPT_FLAGS="-O2"
            ;;
    esac
else
    OPT_FLAGS="-O2"
fi

# 5. Set additional flags
STATIC_FLAGS="-static"
SECURITY_FLAGS="-fstack-protector-strong -D_FORTIFY_SOURCE=2"
WARNING_FLAGS="-Wall -Wextra -Werror"

# 6. Compile straight to executable, no intermediate files
#    -x c/c++ => specify language
#    - => read from stdin
#    -o - => write executable to stdout
#    -fuse-ld=lld => use LLD linker for better performance
#    -static => create statically linked executable

echo "$SRC" | $COMPILER \
    -x $EXTENSION \
    - \
    -o - \
    $OPT_FLAGS \
    $TARGET_FLAGS \
    $STATIC_FLAGS \
    $SECURITY_FLAGS \
    $WARNING_FLAGS \
    -fuse-ld=lld \
    2>/dev/null

# 7. If compilation fails, exit with error
if [ $? -ne 0 ]; then
    echo "Compilation failed" >&2
    exit 1
fi
