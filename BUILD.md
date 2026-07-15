# RawrXD Aperture Kernels - Build Documentation

## Overview

This document describes how to build the Aperture AVX-512 optimized kernels for RawrXD. These kernels provide hardware-accelerated quantization/dequantization for GGUF model loading.

## Prerequisites

### Required Tools

| Tool | Version | Purpose |
|------|---------|---------|
| Visual Studio 2022 | 17.8+ | C++ compiler and build tools |
| MSVC | 14.50+ | C++ compiler (cl.exe) |
| MASM (ml64.exe) | 14.50+ | x64 assembler |
| Windows SDK | 10.0.22621.0+ | Windows headers and libraries |

### Required Visual Studio Components

- **Desktop development with C++** workload
- **MSVC v143 - VS 2022 C++ x64/x86 build tools**
- **Windows 11 SDK (10.0.22621.0)**
- **C++ AddressSanitizer** (optional, for debugging)

## Build Instructions

### Method 1: Manual Build (Recommended for Development)

Use this method when CMake/Ninja is failing or for rapid iteration.

#### Step 1: Open VS Developer Command Prompt

```powershell
# Option A: From Start Menu
# "Developer Command Prompt for VS 2022" → "x64 Native Tools"

# Option B: From PowerShell (adjust path to your VS installation)
& "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
```

#### Step 2: Navigate to Source Directory

```powershell
cd d:\rawrxd\src\core
```

#### Step 3: Assemble AVX-512 Kernel

```powershell
ml64.exe /c /Foaperture_q4_0_avx512_v2.obj aperture_q4_0_avx512_v2.asm
```

**Expected output:**
```
Microsoft (R) Macro Assembler (x64) Version 14.50.35717.0
Copyright (C) Microsoft Corporation.  All rights reserved.

 Assembling: aperture_q4_0_avx512_v2.asm
```

#### Step 4: Compile C++ Sources

**CPU Feature Detection:**
```powershell
cl /c /O2 /arch:AVX512 /EHsc /W3 /D_CRT_SECURE_NO_WARNINGS `
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" `
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" `
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" `
   /Foaperture_cpu_features.obj aperture_cpu_features.cpp
```

**Reference Implementation:**
```powershell
cl /c /O2 /arch:AVX512 /EHsc /W3 /D_CRT_SECURE_NO_WARNINGS `
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" `
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" `
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" `
   /Foaperture_q4_0_reference.obj aperture_q4_0_reference.cpp
```

**GGUF Bridge:**
```powershell
cl /c /O2 /arch:AVX512 /EHsc /W3 /D_CRT_SECURE_NO_WARNINGS `
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" `
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" `
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" `
   /Foaperture_gguf_bridge.obj aperture_gguf_bridge.cpp
```

#### Step 5: Link Static Library

```powershell
lib /OUT:ApertureKernels.lib `
    aperture_q4_0_avx512_v2.obj `
    aperture_cpu_features.obj `
    aperture_q4_0_reference.obj `
    aperture_gguf_bridge.obj
```

#### Step 6: Build Test Executable (Optional)

**Compile test:**
```powershell
cl /c /O2 /arch:AVX512 /EHsc /W3 /D_CRT_SECURE_NO_WARNINGS `
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" `
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" `
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" `
   /Fotest_gguf_bridge.obj test_gguf_bridge.cpp
```

**Link test executable:**
```powershell
link /OUT:Aperture_GGUF_Test.exe /SUBSYSTEM:CONSOLE /LARGEADDRESSAWARE:NO /NOLOGO `
    test_gguf_bridge.obj aperture_gguf_bridge.obj aperture_cpu_features.obj `
    aperture_q4_0_avx512_v2.obj aperture_q4_0_reference.obj `
    /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" `
    /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" `
    kernel32.lib user32.lib
```

#### Step 7: Run Tests

```powershell
.\Aperture_GGUF_Test.exe
```

**Expected output:**
```
========================================
Aperture GGUF Bridge Integration Test
========================================
[INFO] Initializing Aperture dispatch...
[Aperture] Initialization complete: Using AVX-512 Kernel (Ready for inference)
[INFO] AVX-512 Available: YES
[INFO] Active Kernel: AVX-512
[TEST] Q4_0 Dequantization...
[PASS] Q4_0 dequantization successful
...
All GGUF Bridge Tests PASSED
```

### Method 2: CMake Build (Production)

For full RawrXD builds, use CMake with the ApertureKernels target:

```powershell
# From project root
cd d:\rawrxd
mkdir build && cd build

# Configure
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release

# Build Aperture kernels specifically
ninja ApertureKernels

# Or build everything
ninja
```

**Note:** CMake configuration automatically handles:
- MASM compilation (`.asm` → `.obj`)
- Include paths
- Library linking
- Compiler flags (`/arch:AVX512`, `/O2`)

## File Dependencies

```
aperture_q4_0_avx512_v2.asm
    ↓ (assembles to)
aperture_q4_0_avx512_v2.obj
    ↓ (linked with)
aperture_cpu_features.cpp → aperture_cpu_features.obj
aperture_q4_0_reference.cpp → aperture_q4_0_reference.obj
aperture_gguf_bridge.cpp → aperture_gguf_bridge.obj
    ↓ (creates)
ApertureKernels.lib
    ↓ (linked into)
RawrEngine.exe (via GGUF loader)
```

## Troubleshooting

### "cl.exe is not recognized"

**Cause:** Not in VS Developer Command Prompt

**Fix:** Run `vcvars64.bat` or use "x64 Native Tools Command Prompt"

### "Cannot open include file: 'stdio.h'"

**Cause:** Windows SDK include paths not specified

**Fix:** Add `/I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt"`

### "unresolved external symbol Aperture_Q4_0_Dequant_AVX512"

**Cause:** ASM object not linked

**Fix:** Ensure `aperture_q4_0_avx512_v2.obj` is in the link command

### "Access violation" when running tests

**Cause:** AVX-512 kernel not ABI-compliant

**Fix:** Check that ASM file:
- Uses `vzeroupper` before ret
- Preserves non-volatile registers (R12-R15, RSI, RDI, RBX, RBP)
- Uses proper FRAME directives

### CMake can't find MASM

**Cause:** CMake not detecting ASM_MASM compiler

**Fix:** In `CMakeLists.txt`, ensure:
```cmake
enable_language(ASM_MASM)
set(CMAKE_ASM_MASM_COMPILER "C:/VS2022Enterprise/VC/Tools/MSVC/14.50.35717/bin/Hostx64/x64/ml64.exe")
```

## Performance Verification

After building, verify performance with:

```powershell
.\Aperture_GGUF_Test.exe
```

Expected performance (AMD Ryzen 7 7800X3D):
- **Reference:** ~1.26M weights/sec
- **AVX-512:** ~5.73M weights/sec (4.5x speedup)

## Integration with RawrXD

The Aperture kernels integrate automatically with RawrXD's GGUF loader:

1. **At startup:** `Aperture_InitDispatch()` detects CPU features
2. **On model load:** GGUF loader calls `asm_dml_dequant_q4_0_to_fp32()`
3. **Dispatch:** Bridge automatically selects AVX-512 or reference
4. **Logging:** Heartbeat message confirms active kernel

No code changes required in `gguf_dml_bridge.cpp` - the bridge provides the expected symbol.

## Build Output Files

| File | Description |
|------|-------------|
| `ApertureKernels.lib` | Static library for linking |
| `Aperture_GGUF_Test.exe` | Integration test executable |
| `*.obj` | Intermediate object files |

## See Also

- `README.md` - Project overview and features
- `aperture_register_map.md` - ASM register usage documentation
- `src/core/gguf_dml_bridge.cpp` - GGUF loader integration point

## Changelog

| Date | Change |
|------|--------|
| 2026-06-28 | Initial AVX-512 Q4_0 kernel integration |
| 2026-06-28 | Added production heartbeat logging |
