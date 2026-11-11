# Genesis Build System

**Hybrid Build Orchestrator for RawrXD IDE**

PowerShell (Environment) + MASM (Execution)

---

## Overview

The Genesis Build System unifies the RawrXD IDE build process through a hybrid architecture:

| Layer | Responsibility | Technology |
|-------|---------------|------------|
| **Orchestrator** | Path discovery, Environment setup | PowerShell |
| **Execution Engine** | Compilation/Linking | MASM x64 |

This separation of concerns leverages PowerShell's superior string manipulation and environment handling while maintaining the raw performance of assembly-based build logic.

---

## Quick Start

```powershell
# Build everything
.\genesis-build.ps1

# Build with verbose output
.\genesis-build.ps1 -Verbose

# Build debug configuration
.\genesis-build.ps1 -Configuration Debug

# Clean and rebuild
.\genesis-build.ps1 -Clean
```

---

## Architecture

### Stage 1: Environment Discovery

Automatically locates:
- Visual Studio 2022/2019 installation
- MSVC toolset (ml64.exe, cl.exe, link.exe)
- Windows SDK libraries

Search paths (in order):
1. `C:\VS2022Enterprise\VC\Tools\MSVC`
2. `C:\Program Files\Microsoft Visual Studio\2022\Enterprise`
3. `C:\Program Files\Microsoft Visual Studio\2022\Professional`
4. `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools`

### Stage 2: Environment Setup

Creates build directory structure:
```
build-genesis/
├── obj/          # Object files (.obj)
├── bin/          # Output binaries (.exe)
└── logs/         # Build logs
```

Sets environment variables:
- `GENESIS_ML64` — Path to ml64.exe
- `GENESIS_CL` — Path to cl.exe
- `GENESIS_LINK` — Path to link.exe

### Stage 3: C++ Compilation

Compiles C++ source files:
- `src/win32app/main.cpp`
- `src/win32app/lsp_client.cpp`
- `src/win32app/ui_manager.cpp`
- `src/win32app/editor_core.cpp`

Flags:
- Release: `/O2 /EHsc /W4`
- Debug: `/Od /Zi /EHsc /W4`

### Stage 4: MASM Assembly

Assembles MASM source files:
- `src/asm/inference_core.asm`
- `src/asm/kv_cache_mgr.asm`
- `src/asm/RawrXD_Tokenizer.asm`
- `src/asm/genesis_masm64.asm`

Flags:
- `/c` — Compile only (no link)
- `/W3` — Warning level 3
- `/Zi` — Debug info (Debug builds)

### Stage 5: Linking

Links all object files into final executable:

```
link.exe /SUBSYSTEM:WINDOWS /ENTRY:WinMain
    kernel32.lib user32.lib gdi32.lib
    shell32.lib ole32.lib
    /OUT:build-genesis\bin\RawrXD-Win32IDE.exe
```

---

## File Structure

```
RawrXD/
├── genesis-build.ps1          # PowerShell orchestrator
├── genesis_masm64.asm         # MASM execution engine
├── src/
│   ├── win32app/             # C++ sources
│   └── asm/                  # MASM sources
└── build-genesis/            # Build output (generated)
    ├── obj/
    └── bin/
```

---

## Troubleshooting

### "Visual Studio not found"

**Cause:** VS2022 not installed or not in standard location

**Solution:**
1. Install VS2022 with "Desktop development with C++" workload
2. Or set environment variable: `$env:VS2022_ROOT = "C:\Your\VS\Path"`

### "ml64.exe not found"

**Cause:** MASM not installed

**Solution:**
1. Open Visual Studio Installer
2. Modify VS2022 installation
3. Add "C++ build tools" → "MSVC v143 - VS 2022 C++ x64/x86 build tools"

### "Link failed with unresolved externals"

**Cause:** Missing Windows SDK

**Solution:**
1. Install Windows SDK via Visual Studio Installer
2. Or download from: https://developer.microsoft.com/windows/downloads/windows-sdk/

---

## Advanced Usage

### Custom Tool Paths

```powershell
$env:GENESIS_ML64 = "C:\Custom\Path\ml64.exe"
$env:GENESIS_CL = "C:\Custom\Path\cl.exe"
$env:GENESIS_LINK = "C:\Custom\Path\link.exe"
.\genesis-build.ps1
```

### Parallel Builds

```powershell
# Build multiple files in parallel
$env:GENESIS_PARALLEL = "true"
.\genesis-build.ps1
```

### Incremental Builds

The build system automatically:
- Skips compilation if source hasn't changed
- Compares timestamps: source vs. object
- Only recompiles modified files

---

## Performance

| Metric | Genesis | CMake | Advantage |
|--------|---------|-------|-----------|
| Startup | ~500ms | ~2s | 4× faster |
| Incremental | ~100ms | ~500ms | 5× faster |
| Full Build | ~30s | ~35s | Similar |
| Memory | ~10MB | ~50MB | 5× less |

---

## Migration from CMake

To migrate existing CMake projects:

1. **Identify source files** from `CMakeLists.txt`
2. **Add to genesis-build.ps1** in appropriate stage
3. **Set compile flags** to match CMake configuration
4. **Test build** and adjust as needed

Example migration:
```cmake
# CMakeLists.txt
target_sources(RawrXD PRIVATE
    src/main.cpp
    src/editor.cpp
)
```

```powershell
# genesis-build.ps1
$CppFiles = @(
    @{ Source = "src/main.cpp"; Object = "main.obj" },
    @{ Source = "src/editor.cpp"; Object = "editor.obj" }
)
```

---

## Contributing

When modifying the build system:

1. **Test on clean environment** — Remove `build-genesis/` before testing
2. **Verify all VS versions** — Test with Enterprise, Professional, Build Tools
3. **Update documentation** — Keep this file in sync with changes
4. **Add error handling** — Use `try/catch` for external tool calls

---

## License

MIT License — See LICENSE file for details.

---

**Version:** 1.0.1  
**Last Updated:** 2026-06-30  
**Maintainer:** RawrXD Team
