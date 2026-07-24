# RawrXD Evidence Milestone — 2026-07-24

## Executive Summary

The stack overflow regression (WIN32-STACK-OVERFLOW-001) has been fixed and verified. The system now demonstrates runtime stability through the Win32 startup path, with crash containment boundaries in place to prevent black-box failures.

---

## Regression Fix: WIN32-STACK-OVERFLOW-001

### Problem
- **Symptom**: `0xc00000FD` (stack overflow) during IDE startup
- **Location**: `Win32IDE::onCreate()` during `WM_CREATE` handling
- **Root Cause**: JSON configuration parsing via nlohmann::json during stack-constrained window creation

### Call Chain (Before Fix)
```
WM_CREATE
  |
  +-- TabManager::initialize()
        |
        +-- applySovereignTheme()
              |
              +-- GetSovereignConfig()
                    |
                    +-- nlohmann::json parse
                          |
                          +-- stack exhaustion
```

### Call Chain (After Fix)
```
WM_CREATE
  |
  +-- lightweight initialization
  |
  +-- window creation completes
          |
          +-- onCreateChildren()
                |
                +-- applySovereignTheme()
                      |
                      +-- JSON configuration load (full stack available)
```

### Files Modified
- `src/win32app/Win32IDE_TabManager.cpp` — deferred theme application
- `src/win32app/Win32IDE_TabManager.h` — made applySovereignTheme() public
- `src/win32app/Win32IDE_Core.cpp` — added deferred theme call in onCreateChildren()

### Verification Results
| Test | Result | Details |
|------|--------|---------|
| Build | ✅ PASS | rawrxd.exe (411,136 bytes) |
| Startup Smoke | ✅ PASS | No stack overflow during startup |
| Runtime Smoke | ✅ PASS | `--help` shows Sovereign Runtime v1.0-ALPHA |
| Validation Runner | ✅ PASS | No regression, all gates accessible |

---

## Evidence Chain Entry

```json
{
  "regression": "WIN32-STACK-OVERFLOW-001",
  "date": "2026-07-24",
  "symptom": "0xc00000FD during startup",
  "rootCause": "JSON configuration parsing during WM_CREATE",
  "fix": "Deferred theme initialization",
  "verification": {
    "build": "PASS",
    "binary": "rawrxd.exe",
    "startupSmokeTest": "PASS",
    "runtimeSmokeTest": "PASS"
  }
}
```

Full entry: `evidence/regression_WIN32-STACK-OVERFLOW-001.json`

---

## Crash Guard Implementation

Added minimal crash artifact writer to prevent black-box failures:

```cpp
// main_win32.cpp — WriteCrashArtifacts()
// Writes to crash/ directory on any unhandled exception:
//   - exception_code.txt
//   - stacktrace.txt
//   - timestamp.txt
//   - build_hash.txt
```

This ensures the next runtime issue produces actionable diagnostics.

---

## Maturity Shift Evidence

### Before This Fix
```
Executable:
  ⚠️ validation runner works
  ⚠️ IDE runtime unstable
```

### After This Fix
```
Executable:
  ✅ validation runner works
  ✅ Win32 runtime starts
  ✅ startup regression fixed
  ✅ crash containment installed
```

---

## Next Validation Target

The executable path to prove:

```
rawrxd.exe
   |
   v
startup ✅
   |
   v
load model ⬜
   |
   v
generate token ⬜
   |
   v
capture evidence ⬜
```

### Remaining Blockers

| Component | Status |
|-----------|--------|
| Win32 startup | ✅ |
| Theme system | ✅ |
| IDE construction | ✅ |
| Inference startup | ⬜ |
| Model loading | ⬜ |
| Generation loop | ⬜ |

---

## Recommended Next Actions

1. **Run rawrxd.exe with model load**
   ```
   rawrxd.exe --model <path>.gguf --prompt "Hello"
   ```

2. **Instrument inference pipeline**
   - tokenizer
   - embedding
   - attention
   - FFN
   - logits
   - sampler

3. **Produce first full evidence bundle**
   - Token generation proof
   - Performance metrics
   - Correctness validation

---

## Key Insight

> The stack overflow fix is a good example of the maturity shift: the system is now being hardened through measured failures instead of expanded through unchecked additions.

This is exactly why the evidence phase is valuable: the crash was found at the runtime boundary, not by static inspection. The fix establishes the correct architectural boundary (defer heavy initialization to post-WM_CREATE).

---

## Build Artifacts

| Artifact | Path | Size |
|----------|------|------|
| rawrxd.exe | build-ninja/bin/rawrxd.exe | 411,136 bytes |
| ValidationRunner.exe | build-ninja/bin/ValidationRunner.exe | ~2.5 MB |
| Evidence JSON | evidence/regression_WIN32-STACK-OVERFLOW-001.json | - |
| This Milestone | evidence/EVIDENCE_MILESTONE_2026-07-24.md | - |

---

*Generated: 2026-07-24*
*Status: Evidence Phase — Runtime Stability Achieved*
