# OMEGA-1 Self-Mutating Engine - CMake Integration Complete

## Overview

The OMEGA-1 self-mutating engine and PowerShell bridge have been successfully integrated into the RawrXD CMake build system. This integration provides:

- **Static Library Target**: `Omega1Engine` - Contains the PowerShell bridge and IAT export functions
- **IAT Export Alignment**: Slots 64-75 reserved for OMEGA-1 functions
- **Post-Build Manifest Generation**: Automatic manifest generation for both `RawrEngine` and `RawrXD_Gold`
- **Test Harness**: `test_omega1_bridge` executable for validating IAT slots 64-75

## Files Created/Modified

### New Files

1. **`src/omega1_modules/OmegaPowerShellBridge.h`**
   - Complete header with IAT export declarations (slots 64-75)
   - `PowerShellExecutor` class declaration
   - `Omega1Engine` C++ class interface
   - C API for external binding
   - Manifest constants and status codes

2. **`tests/test_omega1_bridge.cpp`**
   - Comprehensive test harness for all 12 IAT slots
   - C API validation tests
   - C++ class integration tests
   - Test result reporting

### Modified Files

1. **`src/omega1_modules/OmegaPowerShellBridge.cpp`**
   - Added `#include "OmegaPowerShellBridge.h"`
   - Implemented all IAT export functions (slots 64-75)
   - Added `Omega1Engine` class implementation
   - Added `Omega1Utils` namespace with helper functions
   - Added C API implementations

2. **`CMakeLists.txt`** (Root)
   - Added OMEGA-1 Engine static library target
   - Added `Omega1Engine` to `RawrEngine` link dependencies
   - Added `Omega1Engine` to `RawrXD_Gold` link dependencies
   - Added post-build manifest generation for both targets
   - Added `test_omega1_bridge` test executable
   - Added `RAWRXD_OMEGA1_ENABLED=1` compile definition
   - Added `src/omega1_modules` to include directories

## IAT Export Slots (64-75)

| Slot | Function | Description |
|------|----------|-------------|
| 64 | `Omega1_Initialize` | Initialize OMEGA-1 context |
| 65 | `Omega1_Shutdown` | Shutdown and cleanup context |
| 66 | `Omega1_GetModuleCount` | Get count of loaded PowerShell modules |
| 67 | `Omega1_IsMutant` | Check if current instance is a mutant |
| 68 | `Omega1_GetMutationCount` | Get number of mutations performed |
| 69 | `Omega1_ExecuteReflective` | Execute reflective payload |
| 70 | `Omega1_ValidateIntegrity` | Validate binary integrity |
| 71 | `Omega1_TriggerMutation` | Trigger mutation event |
| 72 | `Omega1_GetManifestJson` | Get JSON manifest of modules |
| 73 | `Omega1_ExecutePowerShell` | Execute PowerShell command |
| 74 | `Omega1_LoadModule` | Load PowerShell module |
| 75 | `Omega1_InvokeModule` | Invoke function from loaded module |

## Build Instructions

### Configure
```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
```

### Build OMEGA-1 Engine
```bash
cmake --build build --target Omega1Engine --config Release
```

### Build RawrEngine with OMEGA-1
```bash
cmake --build build --target RawrEngine --config Release
```

### Build Test Harness
```bash
cmake --build build --target test_omega1_bridge --config Release
```

### Run Tests
```bash
.\build\tests\Release\test_omega1_bridge.exe
```

## CMake Targets

| Target | Type | Description |
|--------|------|-------------|
| `Omega1Engine` | Static Library | OMEGA-1 PowerShell bridge and IAT exports |
| `RawrEngine` | Executable | Headless engine with OMEGA-1 linked |
| `RawrXD_Gold` | Executable | Gold build with OMEGA-1 linked |
| `test_omega1_bridge` | Executable | Test harness for IAT validation |

## Post-Build Manifest Generation

After building `RawrEngine` or `RawrXD_Gold`, the following manifests are generated:

- `${CMAKE_BINARY_DIR}/omega1_manifest.json` (for RawrEngine)
- `${CMAKE_BINARY_DIR}/gold/omega1_manifest.json` (for RawrXD_Gold)

These manifests contain:
- OMEGA-1 version information
- Loaded PowerShell modules
- Module count
- Binary metadata

## Integration Points

### RawrEngine
- Links against `Omega1Engine` static library
- Includes `src/omega1_modules` in search path
- Defines `RAWRXD_OMEGA1_ENABLED=1`
- Post-build manifest generation

### RawrXD_Gold
- Links against `Omega1Engine` static library
- Includes `src/omega1_modules` in search path
- Defines `RAWRXD_OMEGA1_ENABLED=1`
- Post-build manifest generation

## Usage Example

```cpp
#include "omega1_modules/OmegaPowerShellBridge.h"

// C++ API
RawrXD::Bridge::Omega1Engine engine;
if (engine.Initialize(OMEGA1_FLAG_NONE)) {
    uint32_t count = engine.GetModuleCount();
    std::string manifest = engine.GetManifestJson();
    
    // Execute PowerShell
    char output[4096];
    engine.ExecutePowerShell("Get-Date", output, sizeof(output));
    
    engine.Shutdown();
}

// C API
void* ctx = Omega1_CreateContext();
uint32_t count = Omega1_GetModuleCount(ctx);
Omega1_DestroyContext(ctx);
```

## Verification

Run the test harness to verify all IAT slots are properly exported:

```bash
.\build\tests\Release\test_omega1_bridge.exe
```

Expected output:
```
═════════════════════════════════════════════════════════════════════════════
  OMEGA-1 Bridge Test Harness
  Validating IAT Slots 64-75 for Self-Mutating Engine Integration
═════════════════════════════════════════════════════════════════════════════

[TEST] Slot 64: Omega1_Initialize
  [PASS] Initialize returns TRUE
  [PASS] Context is allocated

[TEST] Slot 65: Omega1_Shutdown
  [PASS] Shutdown completes without crash
  [PASS] Shutdown with null handles gracefully

...

═════════════════════════════════════════════════════════════════════════════
  TEST SUMMARY
═════════════════════════════════════════════════════════════════════════════
  Total Tests:  XX
  Passed:       XX
  Failed:       0
═════════════════════════════════════════════════════════════════════════════

[✓] All tests passed!
```

## Notes

- The OMEGA-1 Engine requires Windows (uses Win32 APIs for PowerShell execution)
- PowerShell modules must be in `src/omega1_modules/` directory
- The `genesis.ps1` script is used for mutation type 3 (GENESIS)
- All IAT exports use `__declspec(dllexport)` for proper symbol visibility
- Static CRT linking is enforced for both `Omega1Engine` and dependent targets

## Linker Symbol Preservation

To prevent MSVC linker optimizations (`/OPT:REF`) from stripping IAT symbols that are only referenced dynamically, the following mechanisms are in place:

### 1. Header-Level `#pragma comment(linker, "/INCLUDE:...")`
Located in `OmegaPowerShellBridge.h`, these pragmas force the linker to include all 12 IAT entry points plus C API exports.

### 2. CMake `/INCLUDE:` Linker Options
Both `RawrEngine` and `RawrXD_Gold` targets explicitly specify `/INCLUDE:` flags for all IAT symbols in their `target_link_options()`.

### 3. Module Definition File (`Omega1Engine.def`)
An explicit `.def` file lists all exports, providing an additional layer of symbol preservation for potential DLL builds.

### 4. Static Library Linker Flags
`Omega1Engine` is compiled with `/OPT:NOREF /OPT:NOICF` to prevent symbol stripping at the static library level.

These redundant mechanisms ensure that even if one method fails or is bypassed, the IAT slots 64-75 will remain available in the final binary for reflective execution.
