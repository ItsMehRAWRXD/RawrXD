# MinGW Compilation Guide - Quantum MASM System 2035

## 🔧 MinGW-Compatible Build System

This directory contains a complete **Quantum MASM System 2035** that has been recovered and enhanced with MinGW compatibility. All C++ components are now fully compatible with MinGW-w64, MSYS2, and TDM-GCC compilers.

## 📁 Recovered Files

### Core Documentation
- `FINAL_QUANTUM_SYSTEM_README.md` - Complete system documentation

### Build Scripts
- `master_build_system.bat` - Complete build system (requires MASM + MinGW)
- `build_compact_stub_generator.bat` - Stub generator build script
- `build_mingw.bat` - **MinGW-only build script** (recommended for MinGW users)
- `Makefile` - Cross-platform Makefile for MinGW/Linux

### C++ Source Files (MinGW Compatible)
- `data_converter.cpp` - Multi-format data converter utility
- `shellcode_generator.cpp` - Test payload generator

## 🚀 Quick Start with MinGW

### Option 1: Use the MinGW Build Script (Recommended)
```bash
# Windows Command Prompt or PowerShell
build_mingw.bat
```

### Option 2: Use Make
```bash
# MinGW/MSYS2 Terminal
make clean
make all
```

### Option 3: Manual Compilation
```bash
# Compile individual components
g++ -O3 -std=c++11 -Wall -Wextra -static-libgcc -static-libstdc++ -o shellcode_generator.exe shellcode_generator.cpp
g++ -O3 -std=c++11 -Wall -Wextra -static-libgcc -static-libstdc++ -o data_converter.exe data_converter.cpp
```

## 🔧 MinGW Installation Options

### Windows Users
1. **MSYS2** (Recommended): https://www.msys2.org/
   ```bash
   pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-make
   ```

2. **MinGW-w64**: https://www.mingw-w64.org/
3. **TDM-GCC**: https://jmeubank.github.io/tdm-gcc/

### Verify Installation
```bash
g++ --version
make --version  # Optional, for Makefile support
```

## 🧪 Testing the Build

After building, test the components:

```bash
# Generate test shellcode
./shellcode_generator.exe

# Test data converter
./data_converter.exe

# Verify test payload was created
ls -la test_shellcode.bin
```

## 📋 What Was Fixed for MinGW Compatibility

### 1. **C++11 Standard Compliance**
- Replaced C++17 features with C++11 equivalents
- Changed `std::stoi()` to `std::strtol()` for better compatibility
- Replaced range-based for loops with traditional loops
- Replaced `std::to_string()` with stringstream operations

### 2. **Static Linking**
- Added `-static-libgcc -static-libstdc++` flags
- Ensures no external DLL dependencies

### 3. **Cross-Platform Headers**
- Added `#include <cstdint>` and `#include <cstring>`
- Ensured all standard library includes are present

### 4. **Build System Enhancements**
- Created MinGW-specific build script (`build_mingw.bat`)
- Added comprehensive Makefile with multiple targets
- Included error checking and environment validation

## 🎯 Current Status

✅ **FULLY RECOVERED** - All commit files have been restored  
✅ **MinGW COMPATIBLE** - C++ components compile without errors  
✅ **TESTED** - Build system validated and working  
✅ **DOCUMENTED** - Complete usage instructions provided  

## 🔗 Original GitHub Commit

The complete system has been recovered from:
**https://github.com/ItsMehRAWRXD/RawrXD/commit/599dfa920a22909238d74eca5621639a5849f41e**

## 📞 Build Support

If you encounter MinGW compilation issues:

1. **Check Compiler Version**: Ensure you have MinGW-w64 or newer
2. **Verify PATH**: Make sure `g++` is in your system PATH
3. **Use C++11**: The code is designed for C++11 standard compliance
4. **Static Linking**: The build uses static linking to avoid DLL dependencies

## 🌟 Features Confirmed Working

- ✅ Data format conversion (hex, decimal, base64, C arrays, ASM format)
- ✅ Test shellcode generation 
- ✅ Cross-platform compatibility (Windows/Linux)
- ✅ Static compilation (no external dependencies)
- ✅ Optimized builds (-O3 optimization)
- ✅ Error handling and validation

---

*Successfully recovered and enhanced for MinGW compatibility by Cursor Agent*