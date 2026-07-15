# RawrXD Build Guide

Complete instructions for building RawrXD from source on all supported platforms.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Platform-Specific Instructions](#platform-specific-instructions)
- [Build Options](#build-options)
- [Troubleshooting](#troubleshooting)
- [Advanced Topics](#advanced-topics)

## Prerequisites

### Required Tools

| Tool | Minimum Version | Purpose |
|------|-----------------|---------|
| CMake | 3.16+ | Build system generator |
| C++ Compiler | C++17 compatible | Compilation |
| Python | 3.8+ | Build scripts, tests |
| Git | 2.20+ | Source control |

### Supported Compilers

- **GCC**: 9.0+
- **Clang**: 10.0+
- **MSVC**: 2019+ (Visual Studio 16.0+)
- **Apple Clang**: 12.0+

### Optional Dependencies

| Component | Purpose | Required For |
|-----------|---------|--------------|
| CUDA Toolkit 11.8+ | GPU acceleration | CUDA backend |
| Vulkan SDK 1.3+ | GPU acceleration | Vulkan backend |
| Qt 6.5+ | IDE application | Win32IDE |
| NASM | Assembly optimizations | x86 kernels |

## Quick Start

```bash
# Clone repository
git clone --recursive https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD

# Configure build
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build --parallel

# Run tests
cd build && ctest --parallel

# Install
sudo cmake --install build
```

## Platform-Specific Instructions

### Linux (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    git \
    python3 \
    python3-pip

# Optional: GPU support
# CUDA
sudo apt-get install -y nvidia-cuda-toolkit

# Vulkan
sudo apt-get install -y vulkan-sdk

# Build
cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -GNinja \
    -DRAWRXD_BUILD_TESTS=ON

cmake --build build --parallel

# Install
sudo cmake --install build
```

### macOS

```bash
# Install Homebrew if needed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install cmake ninja python git

# Optional: GPU support (Metal)
# Included with macOS SDK

# Build
cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -GNinja \
    -DRAWRXD_BUILD_TESTS=ON

cmake --build build --parallel

# Install
sudo cmake --install build
```

### Windows

```powershell
# Install Visual Studio 2019 or 2022 with C++ workload
# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install dependencies
choco install cmake ninja git python

# Optional: Install Qt for IDE
pip install aqtinstall
python -m aqt install-qt windows desktop 6.5.2 win64_msvc2019_64

# Open Developer Command Prompt and build
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --parallel
```

## Build Options

Configure the build with CMake options:

```bash
cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DRAWRXD_BUILD_TESTS=ON \
    -DRAWRXD_BUILD_BENCHMARKS=ON \
    -DRAWRXD_BUILD_EXAMPLES=ON \
    -DRAWRXD_BUILD_DOCS=ON \
    -DRAWRXD_ENABLE_CUDA=ON \
    -DRAWRXD_ENABLE_VULKAN=ON \
    -DRAWRXD_ENABLE_METAL=OFF
```

### Available Options

| Option | Default | Description |
|--------|---------|-------------|
| `RAWRXD_BUILD_TESTS` | ON | Build unit tests |
| `RAWRXD_BUILD_BENCHMARKS` | ON | Build performance benchmarks |
| `RAWRXD_BUILD_EXAMPLES` | ON | Build example applications |
| `RAWRXD_BUILD_DOCS` | OFF | Build documentation |
| `RAWRXD_ENABLE_CUDA` | OFF | Enable CUDA backend |
| `RAWRXD_ENABLE_VULKAN` | OFF | Enable Vulkan backend |
| `RAWRXD_ENABLE_METAL` | OFF | Enable Metal backend (macOS) |
| `RAWRXD_ENABLE_QT` | OFF | Build Qt-based IDE |
| `RAWRXD_ENABLE_COVERAGE` | OFF | Enable code coverage |
| `RAWRXD_SANITIZE_ADDRESS` | OFF | Enable AddressSanitizer |
| `RAWRXD_SANITIZE_THREAD` | OFF | Enable ThreadSanitizer |

## Build Configurations

### Debug Build

```bash
cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug --parallel
```

### Release Build

```bash
cmake -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --parallel
```

### RelWithDebInfo (Recommended for profiling)

```bash
cmake -B build-rel -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build-rel --parallel
```

## Troubleshooting

### Common Issues

#### "CMake Error: Could not find a package configuration file"

**Cause**: Missing dependencies

**Solution**:
```bash
# Update submodules
git submodule update --init --recursive

# Or disable optional components
cmake -B build -DRAWRXD_ENABLE_CUDA=OFF
```

#### "fatal error: 'cuda_runtime.h' file not found"

**Cause**: CUDA not in PATH

**Solution**:
```bash
export PATH="/usr/local/cuda/bin:$PATH"
export CPATH="/usr/local/cuda/include:$CPATH"
```

#### "LINK : fatal error LNK1181: cannot open input file"

**Cause**: Missing libraries on Windows

**Solution**: Use Visual Studio Developer Command Prompt

#### "undefined reference to `pthread_create'"

**Cause**: Missing pthread on Linux

**Solution**:
```bash
sudo apt-get install libpthread-stubs0-dev
```

### Clean Build

```bash
rm -rf build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

## Advanced Topics

### Cross-Compilation

#### Linux to Windows (MinGW)

```bash
cmake -B build-mingw \
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64.cmake \
    -DCMAKE_BUILD_TYPE=Release

cmake --build build-mingw --parallel
```

#### macOS Universal Binary

```bash
cmake -B build-universal \
    -DCMAKE_OSX_ARCHITECTURES="x86_64;arm64" \
    -DCMAKE_BUILD_TYPE=Release

cmake --build build-universal --parallel
```

### Static Linking

```bash
cmake -B build-static \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DRAWRXD_STATIC_RUNTIME=ON

cmake --build build-static --parallel
```

### Custom Install Prefix

```bash
cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/opt/rawrxd

cmake --build build --parallel
sudo cmake --install build
```

### Using ccache

```bash
# Install ccache
sudo apt-get install ccache  # Linux
brew install ccache        # macOS

# Configure CMake
cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
```

## IDE Integration

### Visual Studio Code

Install extensions:
- CMake Tools
- C/C++
- CMake

Open folder, CMake Tools will auto-configure.

### CLion

Open project root, CLion auto-detects CMake.

### Visual Studio

```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
```

Open `build/RawrXD.sln`.

## Next Steps

- [Quick Start Guide](QuickStart.md) - Get running in 5 minutes
- [Architecture Overview](Architecture.md) - Understand the design
- [API Reference](../include/rawrxd/) - Complete API documentation
- [Contributing](../CONTRIBUTING.md) - How to contribute
