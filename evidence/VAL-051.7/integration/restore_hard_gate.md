# VAL-051.7 — Gate 16: Restore B3 Hard Gate

## Document Identity
- **Gate:** 16
- **Version:** 1.0
- **Date:** 2026-08-22

---

## Current State

The B3 hard gate has a temporary continuation mode:

```cpp
#ifdef B3_CONTINUE_FOR_RESIDENCY_BASELINE
    fprintf(stderr, "[B3_CONTINUE] continuing for residency baseline capture\n");
#else
    return tokensGenerated;
#endif
```

This is enabled by compiling with `-DB3_CONTINUE_FOR_RESIDENCY_BASELINE=1`.

---

## Restoration Procedure

### Step 1: Remove continuation flag from build
```bash
# Remove from CMake or compile flags
# Rebuild without -DB3_CONTINUE_FOR_RESIDENCY_BASELINE
```

### Step 2: Verify hard gate is active
```cpp
// Hard gate: reject invalid hidden state
const double stateNorm = B3_L2Norm(layerInput, config.hiddenDim);
if (!(stateNorm > 1.0e-12) || !std::isfinite(stateNorm)) {
    fprintf(stderr, "[B3_FAIL] hidden state invalid pos=%zu norm=%.9e\n",
            currentPos, stateNorm);
    return tokensGenerated;  // Hard return, no continuation
}
```

### Step 3: Search for continuation artifacts
```bash
grep -r "B3_CONTINUE" src/
grep -r "B3_CONTINUE" tests/
```

### Step 4: Run original test
```bash
./test_val_051_3_multi_token.exe
# Expected: B3 failure at pos=5 with norm=0.000000000e+00
```

### Step 5: Confirm no production bypass remains
- No `#ifdef B3_CONTINUE` in production builds
- No runtime flag enabling continuation
- No configuration file with continuation mode

---

## A/B Pair

```
BASELINE_CONTINUE (instrumented, temporary)
        ↓
Residency implementation
        ↓
B3_HARD_GATE (production, permanent)
```

---

## Sign-off

| Check | Status |
|-------|--------|
| Continuation mode removed from source | ⬜ |
| Production build fails on B3 violation | ⬜ |
| No continuation artifacts in binaries | ⬜ |
| Original B3 failure still reproducible | ⬜ |
| Golden fixture unchanged | ⬜ |
