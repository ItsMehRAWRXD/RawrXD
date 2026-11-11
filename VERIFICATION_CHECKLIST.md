# Build Verification Checklist

## Manual Verification Steps

Since the build environment requires MSVC which isn't available in this terminal, follow these steps to verify the build:

### Step 1: Open Developer Command Prompt

```
Start Menu → Visual Studio 2022 → x64 Native Tools Command Prompt
```

### Step 2: Navigate to Project

```cmd
cd d:\RawrXD
```

### Step 3: Run Verification Script

```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify_build.ps1 -Verbose
```

Or manually:

### Step 3a: Configure with CMake

```cmd
cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
```

Expected output:
```
-- Configuring done
-- Generating done
-- Build files have been written to: D:/RawrXD/build
```

### Step 3b: Build

```cmd
ninja RawrEngine
```

Expected output:
```
[1/50] Building CXX object CMakeFiles/RawrEngine.dir/src/intent/intent_config.cpp.obj
[2/50] Building CXX object CMakeFiles/RawrEngine.dir/src/intent/intent_abi.cpp.obj
...
[50/50] Linking CXX executable ../bin/RawrEngine.exe
```

### Step 3c: Build Tests

```cmd
ninja test_intent_guardrails
ninja SovereignTest_Puppeteer
```

### Step 3d: Run Tests

```cmd
..\bin\test_intent_guardrails.exe
..\bin\SovereignTest_Puppeteer.exe
```

## Expected Test Output

### test_intent_guardrails.exe

```
========================================
Intent-to-Execution Guardrails Tests
========================================

Test 1: Intent Configuration
    Guardrails enabled: YES
    Validation enabled: YES
    Transactions enabled: YES
    Firewall enabled: YES
    [PASS]

Test 2: Intent Validation
    Intent type: MODIFY_FUNCTION
    Validation result: ALLOWED
    [PASS]

Test 3: Capability Tokens
    Token issued: YES
    Token valid: YES
    Token revoked: YES
    [PASS]

Test 4: Patch Firewall
    Intent allowed: YES
    Rule applied: ALLOW_WITH_TOKEN
    [PASS]

Test 5: Patch Transaction
    Transaction created: YES
    Patches added: 1
    Validation passed: YES
    Applied: YES
    Committed: YES
    [PASS]

Test 6: Model Adapter
    Backends registered: 2
    Completion successful: YES
    [PASS]

Test 7: Toggle System
    Runtime toggle works: YES
    Emergency bypass works: YES
    [PASS]

========================================
All tests passed!
========================================
```

### SovereignTest_Puppeteer.exe

```
========================================
Sovereign Puppeteer Tests
========================================

Test 1: Symbol Table Generation
    Symbols found: [number]
    Symbol lookup: SUCCESS
    [PASS]

Test 2: Memory Operations
    Read memory: SUCCESS
    Write memory: SUCCESS
    [PASS]

Test 3: Patch Application
    Patch applied: SUCCESS
    Function modified: YES
    [PASS]

Test 4: VEH Watchdog
    Exception caught: YES
    Rollback triggered: YES
    [PASS]

Test 5: Protected Symbols
    Protected symbol blocked: YES
    [PASS]

========================================
All tests passed!
========================================
```

## Verification Checklist

- [ ] CMake configuration succeeds
- [ ] All source files compile without errors
- [ ] All object files created
- [ ] RawrEngine.exe links successfully
- [ ] test_intent_guardrails.exe links successfully
- [ ] SovereignTest_Puppeteer.exe links successfully
- [ ] test_intent_guardrails.exe runs and passes
- [ ] SovereignTest_Puppeteer.exe runs and passes
- [ ] Binaries exist in bin/ directory
- [ ] No linker warnings

## Troubleshooting

### CMake not found
```cmd
where cmake
```
If not found, add CMake to PATH or use full path.

### Ninja not found
```cmd
where ninja
```
If not found, install Ninja or use MSBuild generator:
```cmd
cmake .. -G "Visual Studio 17 2022" -A x64
```

### Compilation errors
Check that all source files exist:
```cmd
dir src\intent\*.cpp /s
dir src\guardrails\*.cpp /s
dir src\hotpatch\*.cpp /s
dir src\sovereign\puppeteer\*.cpp /s
```

### Linker errors
Check that all object files are included in CMakeLists.txt SOURCES list.

## Success Criteria

Build is successful when:
1. ✅ All 21 source files compile
2. ✅ All 3 executables link
3. ✅ All tests pass
4. ✅ No errors or warnings

## Next Steps After Build

1. Run integration tests
2. Test toggle system at runtime
3. Verify emergency bypass works
4. Test model adapter with different backends
5. Profile performance impact

---

**Date:** 2025-01-20
**Status:** Ready for manual verification
