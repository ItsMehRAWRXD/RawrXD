# Sovereign IDE Build Guide
## Complete Compilation Instructions

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** ✅ Build System Ready

---

## Quick Start

### Option 1: Automated Build (Recommended)

```batch
cd d:\rawrxd\build
build_sovereign.bat
```

This executes all 15 build phases automatically.

### Option 2: Manual Build

```batch
:: Phase 1: Clean
rmdir /S /Q d:\rawrxd\obj 2>nul
mkdir d:\rawrxd\obj

:: Phase 2: Build MASM Kernel
ml64.exe /c /W3 /nologo /Zi /Fo d:\rawrxd\obj\SOVEREIGN_MOE.obj d:\rawrxd\src\asm\SOVEREIGN_MOE.asm

:: Phase 3: Compile C ABI
cl.exe /c /W3 /nologo /O2 /Fo d:\rawrxd\obj\MoEBackend_ABI.obj d:\rawrxd\src\inference\MoEBackend_ABI.c

:: Phase 4: Compile Backend Glue
cl.exe /c /W3 /nologo /O2 /EHsc /Fo d:\rawrxd\obj\MoEBackend.obj d:\rawrxd\src\inference\MoEBackend.cpp

:: Phase 5: Build SEG Engine
cl.exe /c /W3 /nologo /O2 /EHsc /Fo d:\rawrxd\obj\SEGNode_MoE.obj d:\rawrxd\src\seg\SEGNode_MoE.cpp
cl.exe /c /W3 /nologo /O2 /EHsc /Fo d:\rawrxd\obj\SEGExec_MoE.obj d:\rawrxd\src\seg\SEGExec_MoE.cpp
cl.exe /c /W3 /nologo /O2 /EHsc /Fo d:\rawrxd\obj\SEGRegistry.obj d:\rawrxd\src\seg\SEGRegistry.cpp

:: Phase 6-9: Build Batches 1-40
:: (See batch-specific build scripts)

:: Phase 10: Build GUI
cl.exe /c /W3 /nologo /O2 /EHsc /Fo d:\rawrxd\obj\MoEPanel.obj d:\rawrxd\src\gui\MoEPanel.cpp
:: ... (other GUI files)

:: Phase 11: Link
link.exe /SUBSYSTEM:WINDOWS /OUT:d:\rawrxd\bin\SovereignIDE.exe d:\rawrxd\obj\*.obj kernel32.lib user32.lib gdi32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib ws2_32.lib

:: Phase 12: Validate
:: Check binary exists and is valid

:: Phase 13: Package
copy d:\rawrxd\bin\SovereignIDE.exe d:\rawrxd\dist\
```

---

## Build Phases

| Phase | Name | Description | Duration |
|-------|------|-------------|----------|
| 0 | INIT | Initialize build system | <1s |
| 1 | CLEAN | Clean previous builds | 1-2s |
| 2 | MASM KERNEL | Build MASM MoE kernel | 5-10s |
| 3 | C ABI | Compile C ABI layer | 3-5s |
| 4 | BACKEND GLUE | Compile backend glue | 5-10s |
| 5 | SEG ENGINE | Build SEG engine | 10-15s |
| 6 | BATCHES 1-10 | Build batches 1-10 | 30-60s |
| 7 | BATCHES 11-20 | Build batches 11-20 | 30-60s |
| 8 | BATCHES 21-30 | Build batches 21-30 | 30-60s |
| 9 | BATCHES 31-40 | Build batches 31-40 | 30-60s |
| 10 | GUI LAYER | Build GUI layer | 20-30s |
| 11 | LINKING | Link all objects | 10-20s |
| 12 | VALIDATION | Validate binary | 2-5s |
| 13 | PACKAGE | Create distribution | 5-10s |
| 14 | COMPLETE | Build complete | <1s |

**Total Build Time:** ~3-5 minutes

---

## Build Configuration

### Compiler Options

#### MSVC (Recommended)
```
/W3          - Warning level 3
/nologo      - Suppress copyright message
/O2          - Optimize for speed
/EHsc        - Enable C++ exceptions
/Zi          - Debug information
```

#### MinGW (Alternative)
```
-Wall        - All warnings
-O2          - Optimize for speed
-std=c++17   - C++17 standard
```

### Linker Options

```
/SUBSYSTEM:WINDOWS  - Windows GUI application
/OUT:path           - Output path
/LARGEADDRESSAWARE  - Support >2GB memory
```

### Libraries Required

- `kernel32.lib` - Windows base API
- `user32.lib` - User interface
- `gdi32.lib` - Graphics device interface
- `comdlg32.lib` - Common dialogs
- `advapi32.lib` - Advanced API
- `shell32.lib` - Shell API
- `ole32.lib` - COM
- `oleaut32.lib` - Automation
- `uuid.lib` - UUIDs
- `ws2_32.lib` - Winsock

---

## Directory Structure

```
d:\rawrxd\
├── build\                    # Build scripts
│   ├── build_sovereign.bat   # Main build script
│   ├── SovereignBuildMaster.h
│   └── SovereignBuildMaster.cpp
├── src\                      # Source code
│   ├── asm\                  # MASM sources
│   ├── inference\            # MoE backend
│   ├── seg\                 # SEG engine
│   ├── core\                # Core subsystems (batches)
│   └── gui\                 # GUI layer
├── obj\                     # Object files (created)
├── bin\                     # Binaries (created)
├── lib\                     # Libraries (created)
├── dist\                   # Distribution (created)
└── docs\                    # Documentation
```

---

## Build Outputs

### Primary Output
- **File:** `d:\rawrxd\bin\SovereignIDE.exe`
- **Type:** Windows GUI application
- **Estimated Size:** ~2-5 MB

### Secondary Outputs
- `d:\rawrxd\obj\*.obj` - Object files
- `d:\rawrxd\lib\*.lib` - Static libraries (if any)
- `d:\rawrxd\dist\*` - Distribution package

---

## Troubleshooting

### Issue: "ml64.exe not found"
**Solution:** Install Visual Studio 2022 with C++ build tools, or use MinGW build path.

### Issue: "Cannot open include file"
**Solution:** Check include paths in compiler configuration. Ensure Windows SDK is installed.

### Issue: "Unresolved external symbol"
**Solution:** Check that all source files are compiled and linked. Verify library paths.

### Issue: "Out of memory"
**Solution:** Close other applications. Ensure 64-bit build tools are used.

---

## Build Verification

After successful build, verify:

1. **Binary exists:**
   ```batch
   dir d:\rawrxd\bin\SovereignIDE.exe
   ```

2. **Binary is valid PE:**
   ```batch
   dumpbin /headers d:\rawrxd\bin\SovereignIDE.exe
   ```

3. **Binary runs:**
   ```batch
   d:\rawrxd\bin\SovereignIDE.exe
   ```

---

## Next Steps After Build

1. **Run the IDE:**
   ```batch
   d:\rawrxd\bin\SovereignIDE.exe
   ```

2. **Test integration:**
   - Load a binary file
   - Run MoE inference
   - Check all panels render

3. **Begin testing:**
   - Run smoke tests
   - Validate subsystems
   - Check cross-subsystem calls

---

## Build System Files

| File | Purpose |
|------|---------|
| `build_sovereign.bat` | Main build script |
| `SovereignBuildMaster.h` | Build orchestrator header |
| `SovereignBuildMaster.cpp` | Build orchestrator implementation |
| `SOVEREIGN_BUILD_GUIDE.md` | This guide |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-07-11 | Initial build system |

---

**Status:** ✅ Build System Complete and Ready

*End of Build Guide*
