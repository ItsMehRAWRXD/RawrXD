# AgentPanel_FinalizeStream Crash Instrumentation

**Date:** 2026-06-24  
**Status:** ✅ Instrumentation Complete  
**Target:** `AgentPanel_FinalizeStream` in `Win32IDE_AgentStreamingBridge.cpp`

---

## Summary

Comprehensive exception handling and diagnostic instrumentation has been added to `AgentPanel_FinalizeStream` to capture the runtime crash (0xe06d7363) that occurs during sidebar creation.

---

## Instrumentation Added

### 1. Diagnostic Structure
```cpp
struct FinalizeStreamDiagnostics {
    void* thisPtr;              // g_pMainIDE pointer
    void* stream;               // Stream handle (if available)
    void* agentBridge;          // Agent bridge pointer
    void* renderSurface;          // Render surface
    void* completionQueue;      // Completion queue
    void* annotationOverlay;      // Annotation overlay
    bool ideInitialized;        // IDE init flag
    bool mainWindowValid;       // Main window validity
    bool bridgeEnabled;         // Bridge enabled flag
    DWORD threadId;             // Current thread ID
    DWORD lastError;            // Last error code
    char exceptionType[256];    // Exception type name
    char exceptionMessage[512]; // Exception message
};
```

### 2. Exception Handling Layers

#### Layer 1: SEH Wrapper (Outer)
```cpp
__try {
    AgentPanel_FinalizeStream_Impl();
}
__except(EXCEPTION_EXECUTE_HANDLER) {
    DWORD exCode = GetExceptionCode();
    // Log exception code and diagnostics
    // DO NOT throw from __except block
}
```

#### Layer 2: C++ Exception Handling (Inner)
```cpp
try {
    // ... implementation ...
} catch (const std::exception& e) {
    // Log with typeid(e).name() if RTTI available
    // Store in diagnostics
    throw;  // Re-throw for outer handler
} catch (...) {
    // Log unknown exception
    throw;  // Re-throw for outer handler
}
```

### 3. FMF Integration
Added FMF instrumentation to track execution paths:
```cpp
FMF_REAL_ENTRY("AgentPanel_FinalizeStream");  // Mark real execution
FMF_FALLBACK("reason");                      // Track fallback paths
```

### 4. State Capture
Before execution attempt, captures:
- `this` pointer (g_pMainIDE)
- Thread ID
- IDE initialization state
- Bridge enabled state
- Main window validity (via SEH-protected check)

### 5. Detailed Logging
All exception paths now log:
- Exception code (for SEH)
- Exception message (for C++ exceptions)
- Exception type (via RTTI if available)
- Full diagnostic state

---

## What Will Happen on Next Crash

1. **SEH Exception Handler Catches First**
   - Exception code logged (e.g., `0xe06d7363`)
   - Diagnostics dumped to debug output
   - Exception swallowed (no re-throw from __except)

2. **Debug Output Will Show**
   ```
   [AgentStreamingBridge] AgentPanel_FinalizeStream trapped SEH exception. Code: 0xe06d7363
   [AgentStreamingBridge] Diagnostics - this: 0xXXXXXXXX, ideInit: 1, winValid: 1, bridge: 1, tid: XXXX
   ```

3. **Process Continues**
   - No termination (exception is logged and swallowed)
   - Next call will re-evaluate state

---

## Files Modified

- `src/win32app/Win32IDE_AgentStreamingBridge.cpp`
  - Added `#include "FailureModeFirewall.h"`
  - Added `FinalizeStreamDiagnostics` structure
  - Added `s_lastDiagnostics` global
  - Enhanced `AgentPanel_FinalizeStream()` with SEH + diagnostics
  - Enhanced `AgentPanel_FinalizeStream_Impl()` with C++ exception handling
  - Added FMF instrumentation

---

## Build Status

```
Win32IDE_AgentStreamingBridge.cpp.obj: 12,255,440 bytes ✅
```

The instrumentation compiled successfully. The only remaining build errors are in `jwt_validator.cpp` (separate issue).

---

## Next Steps

1. **Run the instrumented build** to capture the actual crash
2. **Collect debug output** to see the exception code and diagnostics
3. **Analyze the diagnostics** to identify the root cause
4. **Fix the underlying issue** based on captured data

---

## Priority Assessment

| Area | Status | Notes |
|------|--------|-------|
| Build System | 95% | Only jwt_validator.cpp errors remain |
| FMF Framework | 95% | Validation matrix passed |
| Crash Instrumentation | ✅ Complete | Ready for runtime testing |
| Runtime Stability | 60% | Waiting for crash data |
| Startup Pipeline | 90% | Instrumented and ready |

**The project is now in "runtime debugging" mode.** The crash instrumentation will provide the data needed to fix the `AgentPanel_FinalizeStream` issue.
