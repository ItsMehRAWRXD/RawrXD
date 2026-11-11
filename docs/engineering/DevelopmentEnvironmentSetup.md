# Sovereign IDE - Development Environment Setup
## Internal Engineering Guide

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** ✅ Complete

---

## Table of Contents

1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Windows Setup](#windows-setup)
4. [Linux Setup](#linux-setup)
5. [macOS Setup](#macos-setup)
6. [IDE Configuration](#ide-configuration)
7. [Build Tools](#build-tools)
8. [Debugging Setup](#debugging-setup)
9. [Verification](#verification)

---

## Overview

This guide provides step-by-step instructions for setting up a complete Sovereign IDE development environment.

### Supported Platforms

| Platform | Version | Status |
|----------|---------|--------|
| Windows | 10/11 | ✅ Primary |
| Linux | Ubuntu 22.04+ | ✅ Supported |
| macOS | 13+ | ✅ Supported |

---

## System Requirements

### Minimum Requirements

- **CPU:** 8-core x64 processor
- **RAM:** 32 GB
- **Storage:** 100 GB SSD
- **GPU:** NVIDIA GTX 1080 or AMD equivalent

### Recommended Requirements

- **CPU:** 16-core x64 processor (Intel Sapphire Rapids / AMD EPYC)
- **RAM:** 128 GB DDR5
- **Storage:** 500 GB NVMe SSD
- **GPU:** NVIDIA RTX 4090 or AMD RX 7900 XTX

### Development Tools

- Visual Studio 2022 Enterprise (Windows)
- GCC 12+ or Clang 15+ (Linux/macOS)
- CMake 3.25+
- Python 3.11+
- Git 2.40+

---

## Windows Setup

### Step 1: Install Visual Studio 2022

```powershell
# Download from: https://visualstudio.microsoft.com/downloads/
# Required Workloads:
# - Desktop development with C++
# - Linux development with C++

# Required Individual Components:
# - MSVC v143 - VS 2022 C++ x64/x86 build tools
# - Windows 11 SDK (10.0.22621.0)
# - C++ CMake tools for Windows
# - Git for Windows
```

### Step 2: Install CUDA (Optional)

```powershell
# Download from: https://developer.nvidia.com/cuda-downloads
# Recommended: CUDA 12.2+

# Verify installation:
nvcc --version
```

### Step 3: Clone Repository

```powershell
# Create development directory
mkdir D:\dev
cd D:\dev

# Clone Sovereign IDE
git clone https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD

# Initialize submodules
git submodule update --init --recursive
```

### Step 4: Configure Environment

```powershell
# Create environment configuration
$env:SOVEREIGN_ROOT = "D:\dev\RawrXD"
$env:SOVEREIGN_BUILD_DIR = "$env:SOVEREIGN_ROOT\build"
$env:SOVEREIGN_CONFIG = "Release"

# Add to system PATH (run as Administrator)
[Environment]::SetEnvironmentVariable(
    "SOVEREIGN_ROOT", 
    $env:SOVEREIGN_ROOT, 
    "User"
)
```

### Step 5: Build

```powershell
# Run build script
.\scripts\build\build.ps1 -Configuration Release -Clean

# Or manual build
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release --parallel 16
```

---

## Linux Setup

### Step 1: Install Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    git \
    python3 \
    python3-pip \
    ninja-build \
    llvm \
    clang

# Install CUDA (if using NVIDIA GPU)
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.0-1_all.deb
sudo dpkg -i cuda-keyring_1.0-1_all.deb
sudo apt-get update
sudo apt-get install -y cuda-toolkit-12-2
```

### Step 2: Clone Repository

```bash
# Create development directory
mkdir -p ~/dev
cd ~/dev

# Clone Sovereign IDE
git clone https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD

# Initialize submodules
git submodule update --init --recursive
```

### Step 3: Configure Environment

```bash
# Add to ~/.bashrc or ~/.zshrc
export SOVEREIGN_ROOT="$HOME/dev/RawrXD"
export SOVEREIGN_BUILD_DIR="$SOVEREIGN_ROOT/build"
export SOVEREIGN_CONFIG="Release"
export PATH="$SOVEREIGN_ROOT/scripts:$PATH"

# Apply changes
source ~/.bashrc
```

### Step 4: Build

```bash
# Run build script
./scripts/build/build.sh Release $(nproc)

# Or manual build
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja -j$(nproc)
```

---

## macOS Setup

### Step 1: Install Dependencies

```bash
# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install cmake git python@3.11 ninja llvm

# Install Xcode Command Line Tools
xcode-select --install
```

### Step 2: Clone Repository

```bash
# Create development directory
mkdir -p ~/dev
cd ~/dev

# Clone Sovereign IDE
git clone https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD

# Initialize submodules
git submodule update --init --recursive
```

### Step 3: Configure Environment

```bash
# Add to ~/.zshrc
export SOVEREIGN_ROOT="$HOME/dev/RawrXD"
export SOVEREIGN_BUILD_DIR="$SOVEREIGN_ROOT/build"
export SOVEREIGN_CONFIG="Release"
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"

# Apply changes
source ~/.zshrc
```

### Step 4: Build

```bash
# Run build script
./scripts/build/build.sh Release $(sysctl -n hw.ncpu)

# Or manual build
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang \
    -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++
ninja
```

---

## IDE Configuration

### Visual Studio Code

```json
// .vscode/settings.json
{
    "C_Cpp.default.configurationProvider": "ms-vscode.cmake-tools",
    "C_Cpp.default.cppStandard": "c++20",
    "cmake.buildDirectory": "${workspaceFolder}/build",
    "cmake.configureOnOpen": true,
    "files.associations": {
        "*.asm": "asm",
        "*.inc": "asm"
    },
    "editor.formatOnSave": true,
    "C_Cpp.clang_format_style": "file"
}
```

### Visual Studio

```xml
<!-- RawrXD.sln -->
<!-- Open solution and configure: -->
<!-- 1. Set Startup Project to SovereignIDE -->
<!-- 2. Configuration: Release x64 -->
<!-- 3. Enable AddressSanitizer for Debug builds -->
```

### CLion

```
# File → Settings → Build, Execution, Deployment
# - Toolchain: Visual Studio (Windows) or System (Linux/macOS)
# - CMake: build
# - Build options: -j 16
```

---

## Build Tools

### CMake Configuration

```cmake
# CMakeLists.txt (excerpt)
cmake_minimum_required(VERSION 3.25)
project(SovereignIDE VERSION 1.0.0 LANGUAGES CXX ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
option(SOVEREIGN_BUILD_TESTS "Build tests" ON)
option(SOVEREIGN_ENABLE_CUDA "Enable CUDA support" OFF)
option(SOVEREIGN_ENABLE_PROFILING "Enable profiling" OFF)

# Find packages
find_package(Threads REQUIRED)

if(SOVEREIGN_ENABLE_CUDA)
    find_package(CUDA 12.0 REQUIRED)
endif()

# Add subdirectories
add_subdirectory(src/kernel)
add_subdirectory(src/abi)
add_subdirectory(src/seg)
add_subdirectory(src/moe)
add_subdirectory(src/batches)
add_subdirectory(src/gui)
```

### Build Scripts

```powershell
# scripts/build/build.ps1
# See Build_Scripts_Reference.md for full implementation

# Quick build
.\scripts\build\build.ps1 -Configuration Release

# Full build with tests
.\scripts\build\build.ps1 -Configuration Release -Clean -Parallel 16

# Debug build
.\scripts\build\build.ps1 -Configuration Debug
```

---

## Debugging Setup

### Windows Debugging

```powershell
# Install Windows Debugging Tools
# Download from: https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/

# Configure symbols
$env:_NT_SYMBOL_PATH = "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols"

# Launch with debugger
windbg -g build\bin\SovereignIDE.exe
```

### GDB Configuration

```bash
# .gdbinit
set pagination off
set print pretty on
set confirm off

# Load Sovereign IDE pretty printers
source $SOVEREIGN_ROOT/scripts/gdb/sovereign_printers.py

# Set breakpoints
break main
break SEGNode_Execute
break MoERouter_Route
```

### LLDB Configuration

```bash
# .lldbinit
settings set target.x86-disassembly-flavor intel
settings set frame-format "frame #${frame.index}: ${frame.pc}{ ${module.file.basename}{`${function.name-with-args}{${frame.no-debug}${frame.var-error}}}}\n"

# Load Sovereign IDE formatters
command script import ~/dev/RawrXD/scripts/lldb/sovereign_formatters.py
```

---

## Verification

### Build Verification

```powershell
# Windows
.\build\bin\SovereignIDE.exe --version
.\build\bin\SovereignIDE.exe --test-quick

# Expected output:
# Sovereign IDE v1.0.0
# Build: Release
# Architecture: x64
# Quick test: PASSED
```

```bash
# Linux/macOS
./build/bin/SovereignIDE --version
./build/bin/SovereignIDE --test-quick
```

### SDK Verification

```cpp
// test_sdk.cpp
#include <sovereign/sdk.h>

int main() {
    SDKHandle sdk;
    SDKResult result = SDK_Initialize(nullptr, &sdk);
    if (result != SDK_SUCCESS) {
        return 1;
    }
    
    // Test capability discovery
    CapabilityInfo caps[10];
    uint32_t count = 10;
    result = SDK_DiscoverCapabilities(sdk, "test", caps, &count);
    
    SDK_Shutdown(sdk);
    return (result == SDK_SUCCESS) ? 0 : 1;
}
```

### Full Test Suite

```powershell
# Run all tests
.\scripts\utils\test.ps1 -Type All

# Or manual execution
.\build\tests\unit_tests.exe
.\build\tests\integration_tests.exe
.\build\tests\system_tests.exe
```

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| CMake not found | Install CMake 3.25+ and add to PATH |
| CUDA not detected | Set CUDA_HOME environment variable |
| Linker errors | Ensure all submodules initialized |
| Test failures | Check GPU drivers and CUDA installation |

### Getting Help

- Check [Troubleshooting_Build_Issues.md](../build/Troubleshooting_Build_Issues.md)
- Review [Build_Scripts_Reference.md](../build/Build_Scripts_Reference.md)
- Open issue: https://github.com/ItsMehRAWRXD/RawrXD/issues

---

## Summary

Development environment setup includes:

- ✅ **Platform-specific instructions** (Windows/Linux/macOS)
- ✅ **IDE configuration** (VS Code, Visual Studio, CLion)
- ✅ **Build tools** (CMake, scripts)
- ✅ **Debugging setup** (WinDbg, GDB, LLDB)
- ✅ **Verification procedures**

**Status:** ✅ Complete

---

*End of Development Environment Setup*
