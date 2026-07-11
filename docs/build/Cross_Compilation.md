# Cross Compilation Guide
## Sovereign IDE Build Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

This guide covers cross-compiling the Sovereign IDE for different target platforms.

### Supported Host/Target Combinations

| Host | Target | Status |
|------|--------|--------|
| Linux x64 | Windows x64 | ✅ Supported |
| Linux x64 | macOS x64 | ✅ Supported |
| Windows x64 | Linux x64 | ✅ Supported |
| macOS x64 | Linux x64 | ✅ Supported |

---

## Linux to Windows

### Prerequisites

```bash
# Install MinGW
sudo apt-get install mingw-w64

# Install cross-compilation tools
sudo apt-get install cmake ninja-build
```

### Build

```bash
# Configure
cmake -B build-windows \
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64-x86_64.cmake \
    -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build-windows --parallel

# Package
cpack -G ZIP -B build-windows
```

---

## Windows to Linux

### Using WSL

```powershell
# In WSL
wsl cmake -B build-linux -DCMAKE_BUILD_TYPE=Release
wsl cmake --build build-linux --parallel
```

### Using Docker

```powershell
# Build in container
docker run -v ${PWD}:/src -w /src \
    gcc:latest \
    bash -c "cmake -B build-linux && cmake --build build-linux"
```

---

## Toolchain Files

### mingw-w64-x86_64.cmake

```cmake
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)

set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)

set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
```

---

## Summary

Cross Compilation provides:

- ✅ **4 host/target combos**
- ✅ **MinGW support**
- ✅ **Docker builds**
- ✅ **WSL integration**
- ✅ **Toolchain files**

**Status:** ✅ Complete
