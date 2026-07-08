# RawrXD-CoreRuntime: Immediate Next Steps

## What Was Just Created

You now have a **symbol governance layer** that prevents the linker oscillation you've been fighting.

### Files Created

| File | Purpose | Status |
|------|---------|--------|
| `cmake/CoreRuntime.cmake` | Target definition with isolation rules | ✅ Ready |
| `include/core_runtime/inference_engine.h` | Public API (no UI deps) | ✅ Ready |
| `include/core_runtime/symbol_ownership.h` | Compile-time guards | ✅ Ready |
| `src/inference/inference_engine.cpp` | Real implementation | ✅ Ready |
| `tests/core_runtime/test_inference_loop.cpp` | Truth baseline test | ✅ Ready |
| `docs/CoreRuntime_Architecture.md` | Architecture documentation | ✅ Ready |
| `docs/SymbolGovernance_Manifesto.md` | Problem/solution explanation | ✅ Ready |

## Immediate Action Required

### Step 1: Build CoreRuntime

```powershell
cd d:\rawrxd\build-ninja

# Clean configure (picks up new CoreRuntime.cmake)
cmake .. -G Ninja

# Build CoreRuntime (should be < 2 minutes)
ninja RawrXD-CoreRuntime

# Build and run tests
ninja RawrXD-CoreRuntime-Test
.\tests\core_runtime\RawrXD-CoreRuntime-Test.exe
```

### Expected Outcomes

**Success:**
- CoreRuntime builds without errors
- Tests pass (5/5 tests)
- No UI dependencies in link
- Build time < 2 minutes

**Failure (Expected Issues):**
- Missing source files (need to create stubs for other modules)
- Include path issues
- Missing dependencies

## If Build Fails

### Common Issues and Fixes

#### Issue: "Cannot find source file"
```
CMake Error: Cannot find source file:
  src/gguf/gguf_loader.cpp
```

**Fix:** Create minimal stub files for missing modules:

```cpp
// src/gguf/gguf_loader.cpp
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"

namespace RawrXD {
namespace Core {

// Minimal implementation - real logic in Phase 2
class GGUFLoader::Impl {};

GGUFLoader::GGUFLoader() = default;
GGUFLoader::~GGUFLoader() = default;

bool GGUFLoader::Load(const char* path) {
    (void)path;
    return true;  // Placeholder
}

} // namespace Core
} // namespace RawrXD
```

#### Issue: "Include path not found"
```
fatal error: 'core_runtime/inference_engine.h' file not found
```

**Fix:** Add include directory to CMakeLists.txt:

```cmake
target_include_directories(RawrXD-CoreRuntime
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/include/core_runtime
)
```

#### Issue: "Undefined reference to..."
```
undefined reference to `RawrXD::Core::CreateInferenceEngine()`
```

**Fix:** Ensure source file is in CORE_RUNTIME_SOURCES list in CoreRuntime.cmake

## Phase 2: Integration

### Link Win32IDE to CoreRuntime

Once CoreRuntime builds, modify Win32IDE to link against it:

```cmake
# In CMakeLists.txt where Win32IDE is defined
target_link_libraries(RawrXD-Win32IDE
    PRIVATE
        RawrXD-CoreRuntime  # Add this
        # ... other deps
)
```

### Remove Duplicate Symbols

Delete or exclude these files (they duplicate CoreRuntime symbols):

- `src/core/link_closure_stubs.cpp` (already deleted ✅)
- `src/asm/unresolved_stubs_production.asm` (already deleted ✅)
- Any other stub files that define Core symbols

## Phase 3: Validation

### Test Matrix

| Test | Command | Expected Result |
|------|---------|-----------------|
| CoreRuntime builds | `ninja RawrXD-CoreRuntime` | Success |
| CoreRuntime tests | `ninja RawrXD-CoreRuntime-Test` | 5/5 pass |
| Win32IDE builds | `ninja RawrXD-Win32IDE` | Success |
| Gold builds | `ninja RawrXD_Gold` | Success |
| No duplicates | Linker output | No LNK2005 |

### Symbol Ownership Verification

Run this script to check for violations:

```powershell
# tools/verify_symbol_ownership.ps1
$forbiddenPatterns = @(
    "Win32IDE",
    "UI_",
    "QuickJS",
    "QObject",
    "CreateWindow"
)

$coreSources = Get-ChildItem src/inference, src/gguf, src/memory -Filter "*.cpp"

foreach ($file in $coreSources) {
    $content = Get-Content $file -Raw
    foreach ($pattern in $forbiddenPatterns) {
        if ($content -match $pattern) {
            Write-Error "SYMBOL VIOLATION: $file contains $pattern"
        }
    }
}
```

## Success Metrics

### Build Time
- CoreRuntime: < 2 minutes
- Full build: < 10 minutes (was 30+)

### Test Results
- CoreRuntime-Test: 5/5 pass
- No test failures in Core domain

### Linker Health
- Zero LNK2005 errors
- Zero LNK2019 errors in Core
- Clean dependency graph

### Architectural
- Core builds without UI headers
- UI depends on Core (verified)
- No circular dependencies

## Troubleshooting

### "LNK2005: already defined"

**Cause:** Duplicate symbol definitions

**Fix:**
1. Identify which files define the symbol
2. Keep the definition in CoreRuntime
3. Remove from other locations
4. Link other targets against CoreRuntime

### "LNK2019: unresolved external"

**Cause:** Missing implementation or not linked

**Fix:**
1. Check if symbol should be in CoreRuntime
2. Add to appropriate source file
3. Ensure file is in CORE_RUNTIME_SOURCES
4. Rebuild

### "C1083: Cannot open include file"

**Cause:** Missing include path

**Fix:**
```cmake
target_include_directories(RawrXD-CoreRuntime
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
```

## The Real Win

Once CoreRuntime builds and tests pass:

1. **You have a truth baseline** - Core works = system works
2. **Fast iteration** - 2 min builds vs 30 min
3. **Clean boundaries** - No more linker oscillation
4. **Governed system** - Symbol ownership is enforced

## Contact

If build fails and you can't resolve:

1. Check `docs/CoreRuntime_Architecture.md` for design
2. Check `docs/SymbolGovernance_Manifesto.md` for philosophy
3. Review error messages against "Troubleshooting" section
4. Iterate on minimal stub implementations

## Final Note

> The goal is not to add features. The goal is to establish governance.

CoreRuntime is the foundation. Everything else builds on top of it.

Build CoreRuntime first. Everything else follows.
