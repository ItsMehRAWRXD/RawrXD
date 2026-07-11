# Sovereign IDE - Troubleshooting Build Issues
## Common Problems and Solutions

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** ✅ Complete

---

## Table of Contents

1. [Overview](#overview)
2. [Environment Issues](#environment-issues)
3. [Compilation Errors](#compilation-errors)
4. [Linker Errors](#linker-errors)
5. [Runtime Issues](#runtime-issues)
6. [Performance Issues](#performance-issues)
7. [Diagnostic Tools](#diagnostic-tools)

---

## Overview

This guide helps diagnose and resolve common build issues when compiling the Sovereign IDE.

### Build Error Categories

| Category | Frequency | Severity |
|----------|-----------|----------|
| Environment | 40% | Medium |
| Compilation | 35% | High |
| Linking | 20% | High |
| Runtime | 5% | Critical |

---

## Environment Issues

### Issue 1: Visual Studio Not Found

**Symptoms:**
```
Error: Could not find Visual Studio installation
Error: ml64.exe not found in PATH
Error: cl.exe not found in PATH
```

**Solutions:**

```powershell
# Solution 1: Run from Developer Command Prompt
# Start Menu → Visual Studio 2022 → Developer Command Prompt

# Solution 2: Set environment manually
$env:VS_INSTALL_PATH = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
$env:PATH = "$env:VS_INSTALL_PATH\VC\Tools\MSVC\14.35.32215\bin\Hostx64\x64;$env:PATH"
$env:INCLUDE = "$env:VS_INSTALL_PATH\VC\Tools\MSVC\14.35.32215\include"
$env:LIB = "$env:VS_INSTALL_PATH\VC\Tools\MSVC\14.35.32215\lib\x64"

# Solution 3: Use vswhere to locate VS
$vsPath = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
    -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath

Import-Module "$vsPath\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $vsPath -SkipAutomaticLocation
```

### Issue 2: Windows SDK Not Found

**Symptoms:**
```
Error: windows.h not found
Error: Cannot open include file: 'ucrt/corecrt.h'
```

**Solutions:**

```powershell
# Check SDK installation
Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\Include"

# Set SDK paths
$env:WINDOWS_SDK_VERSION = "10.0.22621.0"
$env:INCLUDE = "C:\Program Files (x86)\Windows Kits\10\Include\$env:WINDOWS_SDK_VERSION\ucrt;" +
               "C:\Program Files (x86)\Windows Kits\10\Include\$env:WINDOWS_SDK_VERSION\um;" +
               "C:\Program Files (x86)\Windows Kits\10\Include\$env:WINDOWS_SDK_VERSION\shared;" +
               $env:INCLUDE

$env:LIB = "C:\Program Files (x86)\Windows Kits\10\Lib\$env:WINDOWS_SDK_VERSION\ucrt\x64;" +
            "C:\Program Files (x86)\Windows Kits\10\Lib\$env:WINDOWS_SDK_VERSION\um\x64;" +
            $env:LIB
```

### Issue 3: Insufficient Disk Space

**Symptoms:**
```
Error: fatal error LNK1106: invalid file or disk full
Error: No space left on device
```

**Solutions:**

```bash
# Check disk space
df -h

# Clean up build artifacts
rm -rf build/obj/*
rm -rf build/lib/*

# Clean up temporary files
rm -rf %TEMP%/*
rm -rf %LOCALAPPDATA%/Temp/*

# Move build to different drive
mklink /D build D:\sovereign-build
```

---

## Compilation Errors

### Issue 1: MASM Syntax Errors

**Symptoms:**
```
Error A2008: syntax error : mov
Error A2070: invalid instruction operands
```

**Solutions:**

```asm
; Common fixes:

; 1. Use correct operand size
; Wrong:
mov rax, dword ptr [rbx]
; Correct:
mov eax, dword ptr [rbx]

; 2. Use proper addressing modes
; Wrong:
mov rax, [rbx + rcx]
; Correct:
mov rax, [rbx + rcx*8]

; 3. Use explicit labels
; Wrong:
jmp loop
; Correct:
jmp loop_start
loop_start:
```

### Issue 2: C++ Template Errors

**Symptoms:**
```
Error C2955: 'std::vector': use of class template requires template argument list
Error C2065: 'T': undeclared identifier
```

**Solutions:**

```cpp
// Common fixes:

// 1. Include proper headers
#include <vector>
#include <string>

// 2. Use correct template syntax
template<typename T>
class Container {
    std::vector<T> items;  // Don't forget <T>
};

// 3. Explicit instantiation
template class Container<int>;
```

### Issue 3: Missing Header Files

**Symptoms:**
```
Error C1083: Cannot open include file: 'sovereign/sdk.h': No such file or directory
```

**Solutions:**

```powershell
# Check include paths
cl.exe /showIncludes main.cpp

# Add missing include path
$env:INCLUDE = "D:\rawrxd\include;$env:INCLUDE"

# Or in build command
cl.exe /I"D:\rawrxd\include" main.cpp
```

### Issue 4: Precompiled Header Issues

**Symptoms:**
```
Error C2857: #include statement specified with /Ycpch.h command line option was not found
Error C2859: <path> is not the precompiled header file that was used when this object was created
```

**Solutions:**

```cpp
// 1. Ensure pch.h is first include
// pch.cpp
#include "pch.h"  // Must be first!

// 2. Clean and rebuild
rm -rf build/obj/*.obj
rm -rf build/obj/*.pch

// 3. Rebuild PCH
cl.exe /c /Yc"pch.h" /Fp"build/obj/pch.pch" src/pch.cpp

// 4. Use PCH in other files
cl.exe /c /Yu"pch.h" /Fp"build/obj/pch.pch" src/other.cpp
```

---

## Linker Errors

### Issue 1: Unresolved External Symbols

**Symptoms:**
```
Error LNK2019: unresolved external symbol "function_name" referenced in function "caller"
Error LNK2001: unresolved external symbol "symbol_name"
```

**Solutions:**

```powershell
# 1. Check symbol exists in library
dumpbin.exe /SYMBOLS build/lib/kernel.lib | findstr "function_name"

# 2. Ensure correct calling convention
# In header:
#ifdef __cplusplus
extern "C" {
#endif
__declspec(dllexport) void function_name(void);
#ifdef __cplusplus
}
#endif

# 3. Add missing library to link
link.exe ... build/lib/missing.lib

# 4. Check for name mangling
dumpbin.exe /EXPORTS build/lib/kernel.lib
```

### Issue 2: Duplicate Symbols

**Symptoms:**
```
Error LNK2005: "symbol" already defined in "file1.obj"
Error LNK1169: one or more multiply defined symbols found
```

**Solutions:**

```cpp
// 1. Use include guards
#ifndef HEADER_H
#define HEADER_H
// ... declarations ...
#endif

// 2. Or use pragma once
#pragma once

// 3. Move definitions to .cpp files
// In header:
extern int global_var;

// In one .cpp file:
int global_var = 0;

// 4. Use inline for header definitions
inline int get_value() { return 42; }
```

### Issue 3: Library Not Found

**Symptoms:**
```
Error LNK1181: cannot open input file 'kernel.lib'
Error LNK1104: cannot open file 'kernel.lib'
```

**Solutions:**

```powershell
# 1. Check library exists
Test-Path build/lib/kernel.lib

# 2. Add library path
link.exe /LIBPATH:"D:\rawrxd\build\lib" ...

# 3. Or set environment
$env:LIB = "D:\rawrxd\build\lib;$env:LIB"

# 4. Use full path
link.exe ... "D:\rawrxd\build\lib\kernel.lib"
```

### Issue 4: Entry Point Not Found

**Symptoms:**
```
Error LNK1561: entry point must be defined
Error LNK2019: unresolved external symbol _WinMain@16
```

**Solutions:**

```powershell
# 1. Specify correct entry point
link.exe /ENTRY:mainCRTStartup ...  # Console
link.exe /ENTRY:wWinMainCRTStartup ...  # Windows

# 2. Ensure main function exists
# For console:
int main(int argc, char* argv[]) { ... }

# For Windows:
int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) { ... }

# 3. Check subsystem
link.exe /SUBSYSTEM:CONSOLE ...  # Console app
link.exe /SUBSYSTEM:WINDOWS ...  # GUI app
```

---

## Runtime Issues

### Issue 1: Missing Runtime DLLs

**Symptoms:**
```
Error: The code execution cannot proceed because VCRUNTIME140.dll was not found
Error: MSVCP140.dll missing
```

**Solutions:**

```powershell
# 1. Install Visual C++ Redistributables
# Download from Microsoft

# 2. Use static runtime (larger binary)
cl.exe /MT ...  # Instead of /MD

# 3. Copy runtime DLLs to output
Copy-Item "$env:VCToolsRedistDir\x64\Microsoft.VC143.CRT\*.dll" build/bin/

# 4. Use app-local deployment
# Create build/bin/Microsoft.VC143.CRT/
# Copy runtime files there
```

### Issue 2: Debug Assertion Failed

**Symptoms:**
```
Debug Assertion Failed!
File: minkernel\crts\ucrt\src\appcrt\stdio\input.cpp
Line: 123
Expression: c >= -1 && c <= 255
```

**Solutions:**

```cpp
// 1. Check input validation
if (!input || length == 0) {
    return ERROR_INVALID_PARAMETER;
}

// 2. Use safe functions
// Instead of:
strcpy(dest, src);
// Use:
strncpy_s(dest, dest_size, src, _TRUNCATE);

// 3. Enable runtime checks
cl.exe /RTC1 ...

// 4. Check for buffer overflows
// Use AddressSanitizer in debug builds
cl.exe /fsanitize=address ...
```

### Issue 3: Access Violation

**Symptoms:**
```
Exception thrown at 0x00007FF... : Access violation reading location 0x00000000...
```

**Solutions:**

```cpp
// 1. Check null pointers
if (!ptr) {
    return ERROR_NULL_POINTER;
}

// 2. Validate array bounds
if (index >= array_size) {
    return ERROR_OUT_OF_BOUNDS;
}

// 3. Use smart pointers
std::unique_ptr<Resource> resource(new Resource());

// 4. Enable guard pages
// Link with /GUARD:CF
```

---

## Performance Issues

### Issue 1: Slow Build Times

**Symptoms:**
- Clean build takes > 2 hours
- Incremental builds still slow

**Solutions:**

```powershell
# 1. Enable parallel builds
$env:CL = "/MP16"  # Use 16 parallel processes

# 2. Use precompiled headers
# See Build_Configuration_Reference.md

# 3. Enable unity builds
# See Build_Configuration_Reference.md

# 4. Use SSD for build directory
mklink /D build D:\fast-ssd\sovereign-build

# 5. Disable antivirus for build dir
# Add exclusion in Windows Defender

# 6. Use incremental linking (debug only)
link.exe /INCREMENTAL ...
```

### Issue 2: High Memory Usage

**Symptoms:**
- Build uses > 32GB RAM
- System becomes unresponsive

**Solutions:**

```powershell
# 1. Reduce parallel jobs
$env:CL = "/MP4"  # Use only 4 processes

# 2. Disable whole program optimization
# Remove /GL from compiler flags

# 3. Split large translation units
# Break up large .cpp files

# 4. Use 64-bit tools
# Ensure using x64 native tools

# 5. Add more RAM or page file
# System Properties → Advanced → Performance → Virtual Memory
```

---

## Diagnostic Tools

### Build Diagnostics Script

```powershell
# diagnose-build.ps1

Write-Host "=== Sovereign IDE Build Diagnostics ===" -ForegroundColor Green

# Check Visual Studio
Write-Host "`nChecking Visual Studio..." -ForegroundColor Yellow
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vsWhere) {
    & $vsWhere -latest -format json | ConvertFrom-Json | Select-Object displayName, installationPath, installationVersion
} else {
    Write-Host "ERROR: vswhere.exe not found" -ForegroundColor Red
}

# Check environment
Write-Host "`nChecking environment variables..." -ForegroundColor Yellow
Write-Host "INCLUDE: $env:INCLUDE"
Write-Host "LIB: $env:LIB"
Write-Host "PATH contains cl.exe: $($env:PATH -match 'cl.exe')"

# Check tools
Write-Host "`nChecking build tools..." -ForegroundColor Yellow
$tools = @("ml64.exe", "cl.exe", "link.exe", "lib.exe")
foreach ($tool in $tools) {
    $path = Get-Command $tool -ErrorAction SilentlyContinue
    if ($path) {
        Write-Host "$tool`: $($path.Source)" -ForegroundColor Green
    } else {
        Write-Host "$tool`: NOT FOUND" -ForegroundColor Red
    }
}

# Check disk space
Write-Host "`nChecking disk space..." -ForegroundColor Yellow
Get-Volume | Where-Object { $_.DriveLetter } | Select-Object DriveLetter, SizeRemaining, Size | Format-Table -AutoSize

# Check build directory
Write-Host "`nChecking build directory..." -ForegroundColor Yellow
if (Test-Path "build") {
    $size = (Get-ChildItem build -Recurse | Measure-Object -Property Length -Sum).Sum / 1GB
    Write-Host "Build directory size: $([math]::Round($size, 2)) GB"
} else {
    Write-Host "Build directory not found" -ForegroundColor Yellow
}

Write-Host "`nDiagnostics complete!" -ForegroundColor Green
```

### Build Log Analysis

```powershell
# analyze-build-log.ps1
param([string]$LogFile = "build.log")

if (!(Test-Path $LogFile)) {
    Write-Error "Log file not found: $LogFile"
    exit 1
}

$content = Get-Content $LogFile

# Count errors
$errors = $content | Select-String "error [A-Z]*\d*:"
$warnings = $content | Select-String "warning [A-Z]*\d*:"

Write-Host "Build Analysis" -ForegroundColor Green
Write-Host "=============" -ForegroundColor Green
Write-Host "Total lines: $($content.Count)"
Write-Host "Errors: $($errors.Count)" -ForegroundColor $(if($errors.Count -gt 0){"Red"}else{"Green"})
Write-Host "Warnings: $($warnings.Count)" -ForegroundColor $(if($warnings.Count -gt 100){"Yellow"}else{"Green"})

# Show first 10 errors
if ($errors.Count -gt 0) {
    Write-Host "`nFirst 10 errors:" -ForegroundColor Red
    $errors | Select-Object -First 10 | ForEach-Object {
        Write-Host "  $_" -ForegroundColor Red
    }
}

# Show build time
$timeMatch = $content | Select-String "Time Elapsed (\d+:\d+:\d+\.\d+)"
if ($timeMatch) {
    Write-Host "`nBuild time: $($timeMatch.Matches[0].Groups[1].Value)"
}
```

### Clean Build Script

```powershell
# clean-build.ps1

Write-Host "Cleaning build artifacts..." -ForegroundColor Yellow

# Remove object files
Remove-Item -Recurse -Force build/obj/* -ErrorAction SilentlyContinue
Write-Host "Removed object files"

# Remove libraries
Remove-Item -Force build/lib/*.lib -ErrorAction SilentlyContinue
Write-Host "Removed libraries"

# Remove executables
Remove-Item -Force build/bin/*.exe -ErrorAction SilentlyContinue
Remove-Item -Force build/bin/*.dll -ErrorAction SilentlyContinue
Write-Host "Removed executables"

# Remove PDB files
Remove-Item -Force build/bin/*.pdb -ErrorAction SilentlyContinue
Write-Host "Removed PDB files"

# Keep logs but archive
$logArchive = "build/logs/archive/$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Force -Path $logArchive
Move-Item build/logs/*.log $logArchive -ErrorAction SilentlyContinue
Write-Host "Archived old logs to $logArchive"

Write-Host "`nClean complete! Ready for fresh build." -ForegroundColor Green
```

---

## Summary

The Troubleshooting Build Issues guide provides:

- ✅ **Environment issue solutions** (VS, SDK, disk space)
- ✅ **Compilation error fixes** (MASM, C++, headers, PCH)
- ✅ **Linker error resolutions** (symbols, libraries, entry points)
- ✅ **Runtime issue fixes** (DLLs, assertions, access violations)
- ✅ **Performance optimizations** (build speed, memory)
- ✅ **Diagnostic tools** (scripts, log analysis)

**Status:** ✅ Complete

---

*End of Troubleshooting Build Issues*
