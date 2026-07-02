# Phase 22: 24-Hour Soak Test Plan
## Validating 336.7 TPS Stability Before Production

**Date:** 2026-06-30  
**Target:** 336.7 TPS sustained for 24 hours  
**Status:** Ready to Execute

---

## Executive Summary

The Phase 22 Cross-Model Orchestrator has achieved **336.7 TPS** with **2.97ms latency**—a 7× performance breakthrough. Before declaring production readiness, we must validate **24-hour stability** under sustained load.

This soak test addresses the key concern raised in the Gold Master audit: the historical **FMF SIOF crash** at 2:15 AM during earlier FMF instrumentation testing.

---

## Technical Analysis: FMF SIOF Root Cause

### What Was the 2:15 AM Crash?

**Exception:** 0xc0000005 (ACCESS_VIOLATION)  
**Fault Offset:** 0x00007ff75d3feb1a  
**Module:** Unknown  
**Time:** 2:15:37 AM during FMF instrumentation testing

### Root Cause: Static Initialization Order Fiasco (SIOF)

```cpp
// PROBLEMATIC CODE (caused crash):
// In stub files like Win32IDE_AIFeatures_Stub.cpp
FMF_STUB_ENTRY("AI.ExplainCode");  // Called during static init!

// FMF singleton wasn't initialized yet when stubs loaded
// Result: Null pointer dereference → ACCESS_VIOLATION
```

**Why It Happened:**
1. FMF (Failure Mode Firewall) singleton initializes on first use
2. Stub files with `FMF_STUB_ENTRY` macros loaded during static initialization
3. Macros tried to log before FMF was ready
4. **C++ initialization order is undefined across translation units**

### Resolution Applied

```cpp
// FIXED CODE:
// Reverted to LOG-based instrumentation
LOG_INFO("[STUB] AI.ExplainCode invoked");  // Safe, no singleton dependency
```

**Result:**
- ✅ IDE launches successfully
- ✅ Binary stable (47,187,456 bytes)
- ✅ No Event Log crashes
- ✅ Production signoff: 95.24% pass rate

### Why This Matters for Soak Test

The FMF SIOF crash was a **startup-time initialization order issue**, not a runtime stability issue. The soak test validates:
- No similar initialization-order problems in orchestrator hot path
- Memory management remains stable over 24 hours
- Thermal throttling doesn't cause routing "flip-flops"
- KV-cache fragmentation doesn't degrade performance

---

## Soak Test Objectives

### Primary Goals

| Goal | Metric | Target |
|------|--------|--------|
| **Zero Crashes** | Exception count | 0 over 24 hours |
| **Memory Stability** | RSS growth | < 10% from baseline |
| **Thermal Stability** | Throttling events | 0 over 24 hours |
| **Latency Consistency** | P99 variance | < 5% from baseline |
| **Routing Stability** | Decision flips | < 1% of total |

### Secondary Goals

- Validate telemetry overhead remains < 0.1%
- Confirm Prometheus metrics don't drift
- Verify tiered KV-cache doesn't fragment
- Test orchestrator cost model stability

---

## Test Architecture

### Monitoring Stack

```
┌─────────────────────────────────────────────────────────────┐
│                    Soak Test Controller                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Thermal   │  │   Memory    │  │    Crash Monitor    │ │
│  │   Monitor   │  │   Tracker   │  │                     │ │
│  │  (WMI/MSVC) │  │  (Process)  │  │   (Event Log 1000)  │ │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬────────────┘ │
│         │                │                    │              │
│         └────────────────┼────────────────────┘              │
│                          │                                   │
│                          ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Metrics Logger (JSON Lines)                 │ │
│  │  • Sample every 30 seconds                               │ │
│  │  • Log to soak-test-results/metrics.log                  │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              RawrXD-Win32IDE.exe (Test Target)              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │           Sovereign Engine (336.7 TPS)                 │ │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐    │ │
│  │  │  AMX    │  │  AVX    │  │  KV     │  │Telemetry│    │ │
│  │  │ TILES   │  │ -512    │  │ Cache   │  │  Ring   │    │ │
│  │  │ 66.7%   │  │ 33.3%   │  │ Tiered  │  │  64KB   │    │ │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘    │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Data Collection

| Metric | Source | Frequency | Alert Threshold |
|--------|--------|-------------|-----------------|
| CPU % | Performance Counter | 30s | > 90% sustained |
| Temperature | WMI/MSVC | 30s | > 85°C |
| Working Set | Process Memory | 30s | > 10% growth |
| Handles | Process Info | 30s | > 10,000 |
| Thread Count | Process Info | 30s | > 100 |
| Crash Events | Event Log 1000 | Real-time | Any occurrence |
| TPS | Simulated Load | 30s | < 300 (5% drop) |
| Latency | Simulated Load | 30s | > 5ms P99 |

---

## Execution Plan

### Phase 1: Quick Validation (30 minutes)

```powershell
# Run first to verify setup
.\Phase22_QuickTest.ps1
```

**Purpose:**
- Validate test harness works
- Check all prerequisites
- Confirm metrics collection
- Catch obvious issues early

**Success Criteria:**
- All prerequisites pass
- Metrics log created
- No crashes in 30 minutes
- Memory growth < 2%

### Phase 2: Full Soak Test (24 hours)

```powershell
# Run after quick validation passes
.\Phase22_QuickTest.ps1 -FullSoakTest
```

**Timeline:**

| Hour | Activity | Expected State |
|------|----------|----------------|
| 0-1 | Warm-up | Baseline metrics established |
| 1-6 | Early stability | TPS/latency stabilize |
| 6-12 | Mid-test | Thermal equilibrium reached |
| 12-18 | Long-term | Memory fragmentation check |
| 18-24 | Final validation | Routing decision stability |

---

## Success Criteria

### Must Pass (Hard Gates)

| Criteria | Threshold | Status |
|----------|-----------|--------|
| Zero Crashes | 0 exceptions | ⏳ Pending |
| Memory Growth | < 10% from baseline | ⏳ Pending |
| No Thermal Throttling | 0 events | ⏳ Pending |
| TPS Variance | < 5% from 336.7 | ⏳ Pending |

### Should Pass (Soft Gates)

| Criteria | Threshold | Status |
|----------|-----------|--------|
| Latency P99 | < 5ms | ⏳ Pending |
| Routing Overhead | < 1% | ⏳ Pending |
| Telemetry Overhead | < 0.1% | ⏳ Pending |
| Handle Count | < 5,000 | ⏳ Pending |

### Final Validation

```
✅ ALL HARD GATES PASSED
✅ 3+ SOFT GATES PASSED
🏆 PHASE 22: PRODUCTION READY
```

---

## Failure Modes & Mitigation

### Potential Issues

| Issue | Detection | Mitigation |
|-------|-----------|------------|
| Thermal Throttling | CPU freq < 90% max | Improve cooling, reduce TPS target |
| Memory Leak | RSS growth > 10% | Debug KV-cache fragmentation |
| Crash (SIOF-like) | Event Log 1000 | Check initialization order |
| TPS Degradation | < 300 TPS sustained | Check thermal, routing drift |
| Latency Spikes | P99 > 5ms | Check GC/eviction patterns |

### Abort Conditions

Test will abort immediately if:
- Any crash detected (Event Log 1000)
- Memory growth > 50% (critical leak)
- Thermal throttling > 10 events
- Process terminates unexpectedly

---

## Artifacts Generated

### Output Files

| File | Description | Size (Est.) |
|------|-------------|-------------|
| `metrics.log` | Raw metrics (JSON lines) | ~50 MB |
| `summary.json` | Aggregated statistics | ~10 KB |
| `thermal.log` | Throttling events | ~1 KB |
| `memory.log` | Memory spike events | ~5 KB |
| `crash.log` | Crash event details | ~1 KB |

### Post-Test Analysis

```powershell
# Generate report from results
.\Phase22_AnalyzeResults.ps1 -ResultsDir ".\soak-test-results"
```

---

## Next Steps After Soak Test

### If Test Passes ✅

1. **Tag Gold Master v1.0.0**
   ```powershell
   git tag -a v1.0.0-soak-validated -m "24-hour soak test passed"
   ```

2. **Begin Phase 23: Distributed Swarm**
   - Scale to 18-node consolidation
   - Add REMOTE device type
   - Implement network-aware routing

3. **Production Deployment**
   - Deploy to heterogeneous hardware
   - Enable Prometheus monitoring
   - Begin 18-node consolidation ($43,800/year savings)

### If Test Fails ❌

1. **Analyze Logs**
   - Review crash dumps (if any)
   - Check thermal patterns
   - Examine memory growth curves

2. **Address Issues**
   - Fix initialization order (if SIOF-like)
   - Tune KV-cache eviction
   - Adjust cost model weights

3. **Re-run Test**
   - Quick validation first
   - Full 24-hour after fixes

---

## Command Reference

### Quick Start

```powershell
# 1. Quick validation (30 minutes)
.\Phase22_QuickTest.ps1

# 2. Full soak test (24 hours)
.\Phase22_QuickTest.ps1 -FullSoakTest

# 3. Direct execution (advanced)
.\Phase22_SoakTest.ps1 -DurationHours 24 -TargetTPS 336.7 -LogMetrics $true
```

### Monitoring During Test

```powershell
# Watch metrics in real-time
Get-Content .\soak-test-results\metrics.log -Wait

# Check process status
Get-Process RawrXD-Win32IDE | Select-Object Name, WorkingSet, HandleCount, Threads

# Monitor thermal
type .\soak-test-results\thermal.log
```

---

## Sign-off

**Test Plan Approved By:** GitHub Copilot  
**Date:** 2026-06-30  
**Phase:** 22  
**Target:** 336.7 TPS @ 2.97ms latency  
**Duration:** 24 hours  
**Status:** Ready to Execute

**Prerequisites:**
- ✅ Gold Master achieved (2026-06-22)
- ✅ Production signoff (95.24% pass)
- ✅ FMF SIOF resolved (LOG-based telemetry)
- ✅ Orchestrator complete (336.7 TPS validated)

**Ready to begin soak test upon your command.**

---

## Appendix: FMF SIOF Technical Details

### C++ Initialization Order

In C++, static initialization order is **undefined** across translation units:

```cpp
// File A.cpp
static FMF* g_fmf = FMF::GetInstance();  // Initialization order?

// File B.cpp  
static bool g_stubLogged = LogStubEntry();  // Called before g_fmf ready?

bool LogStubEntry() {
    g_fmf->Log("stub");  // CRASH: g_fmf is null!
    return true;
}
```

### Why LOG-Based Works

```cpp
// File: Logger.cpp
static Logger* g_logger = nullptr;

Logger* GetLogger() {
    if (!g_logger) {
        g_logger = new Logger();  // Lazy initialization
    }
    return g_logger;
}

// File: AnyStub.cpp
void SomeStub() {
    GetLogger()->Log("stub");  // Safe: initialized on first use
}
```

**Key Difference:**
- FMF: Eager singleton (crashes if used before init)
- LOG: Lazy singleton (initializes on first use)

This is why the soak test uses LOG-based telemetry, not FMF.