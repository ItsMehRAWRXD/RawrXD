# RawrXD Arena Allocator Analysis & Telemetry Plan

**Date:** 2026-07-03  
**Scope:** SovereignArena memory management for 24-hour agent stress test  
**Status:** Critical issues identified, instrumentation required

---

## 1. Architecture Overview

### Current Arena Structure
```cpp
struct SovereignArena {
    void* base;           // VirtualAlloc'd region
    size_t size;          // Reserved size
    size_t committed;     // Actually committed pages
    size_t used;          // Bump pointer offset
    uint32_t extensionId; // For chained arenas
    uint32_t flags;       // ACTIVE | FROZEN | ASYNC
    SovereignArena* next; // Linked list for extensions
};
```

### Key Implementation Files
| File | Lines | Purpose |
|------|-------|---------|
| `src/script/masm/masm_interface.hpp` | 103-110 | C++ struct definition |
| `src/script/masm/interpreter.asm` | 175-230 | ARENA_ALLOC macro (hot path) |
| `src/cli/cli_stream.cpp` | 8-28 | Simple bump allocator |

---

## 2. Critical Issues Identified

### 🔴 Issue 1: No Commit-on-Demand in ARENA_ALLOC
**Location:** `interpreter.asm:175-230`

**Problem:** The `commit_more` branch in `ARENA_ALLOC` macro returns `null` instead of committing more pages:
```asm
commit_more:
    ; Commit more virtual memory (simplified - assumes space available)
    ; In full implementation: VirtualAlloc call
    xor rax, rax        ; Return null for now  ← BUG!
```

**Impact:** Agent will crash with OOM after ~1-2 hours of continuous operation as the arena fills up.

**Fix Required:**
```asm
commit_more:
    ; Calculate additional pages needed
    sub rax, rdx        ; rax = needed - committed
    add rax, 4095
    and rax, -4096      ; Round to page size
    
    ; VirtualAlloc commit
    mov rcx, [r13]      ; base
    add rcx, rdx        ; + committed
    mov rdx, rax        ; size
    mov r8, 0x1000      ; MEM_COMMIT
    mov r9, 0x04        ; PAGE_READWRITE
    call VirtualAlloc
    
    ; Update committed
    mov rax, [r13 + 8]  ; old committed
    add rax, rcx        ; + newly committed
    mov [r13 + 8], rax
    
    ; Retry allocation
    jmp ARENA_ALLOC
```

---

### 🔴 Issue 2: No Arena Extension Chaining
**Location:** `masm_interface.hpp:110`

**Problem:** The `next` pointer exists but is never used. When one arena fills, no secondary arena is allocated.

**Impact:** Hard limit at initial arena size (typically 64MB-1GB depending on config).

**Fix Required:** Implement arena chaining in `JsInterpreter_ArenaAlloc`:
```cpp
void* JsInterpreter_ArenaAlloc(SovereignArena* arena, size_t size) {
    // Try current arena
    if (arena->used + size <= arena->committed) {
        void* ptr = (char*)arena->base + arena->used;
        arena->used += size;
        return ptr;
    }
    
    // Try commit more
    if (arena->used + size <= arena->size) {
        CommitMorePages(arena, size);
        return JsInterpreter_ArenaAlloc(arena, size);
    }
    
    // Chain to extension arena
    if (!arena->next) {
        arena->next = JsInterpreter_CreateArena(
            max(size, ARENA_EXTENSION_SIZE)
        );
    }
    return JsInterpreter_ArenaAlloc(arena->next, size);
}
```

---

### 🟡 Issue 3: Double Alignment Penalty
**Location:** `interpreter.asm:195-200`

**Problem:** Alignment is applied twice:
```asm
mov rax, rcx
add rax, 15
and rax, -16        ; Align size
mov rcx, rax

mov rax, r14
add rax, 15
and rax, -16        ; Align bump pointer
mov r14, rax
```

**Impact:** Up to 30 bytes wasted per allocation (15 from size + 15 from bump).

**Fix:** Only align the final pointer, not both:
```asm
; Calculate aligned end pointer only
mov rax, r14
add rax, rcx
add rax, 15
and rax, -16        ; Align end
```

---

### 🟡 Issue 4: No Thread Safety
**Location:** `interpreter.asm:175-230`

**Problem:** `ARENA_ALLOC` macro has no synchronization. Multiple agent threads will corrupt `r14` (bump pointer).

**Impact:** Memory corruption, use-after-free, crashes under concurrent load.

**Fix Options:**
1. **Per-thread arenas** (recommended): Each agent thread gets its own arena
2. **Atomic bump**: `lock xadd` on bump pointer (slower)
3. **Arena pool**: Pre-allocated arena per thread from pool

---

## 3. Telemetry Instrumentation Plan

### Header: `src/core/Telemetry.hpp`

```cpp
#pragma once
#include <atomic>
#include <cstdint>

struct ArenaTelemetry {
    // Memory tracking
    std::atomic<uint64_t> totalAllocated{0};      // Total bytes ever allocated
    std::atomic<uint64_t> currentUsed{0};          // Current bump offset
    std::atomic<uint64_t> peakUsed{0};             // High water mark
    std::atomic<uint64_t> commitCalls{0};          // VirtualAlloc commits
    std::atomic<uint64_t> extensionCount{0};        // Arena chain length
    
    // Fragmentation metrics
    std::atomic<uint64_t> alignmentWaste{0};        // Bytes lost to alignment
    std::atomic<uint64_t> failedAllocs{0};          // Null returns from ARENA_ALLOC
    
    // Timing (microseconds)
    std::atomic<uint64_t> allocTimeUs{0};          // Cumulative allocation time
    std::atomic<uint64_t> allocCount{0};            // Number of allocations
    
    // Watermark monitoring
    float GetFragmentationRatio() const {
        uint64_t used = currentUsed.load();
        uint64_t waste = alignmentWaste.load();
        return used > 0 ? (float)waste / (float)used : 0.0f;
    }
    
    float GetAvgAllocTimeUs() const {
        uint64_t time = allocTimeUs.load();
        uint64_t count = allocCount.load();
        return count > 0 ? (float)time / (float)count : 0.0f;
    }
    
    void Reset() {
        totalAllocated = 0;
        currentUsed = 0;
        peakUsed = 0;
        commitCalls = 0;
        extensionCount = 0;
        alignmentWaste = 0;
        failedAllocs = 0;
        allocTimeUs = 0;
        allocCount = 0;
    }
};

// Global telemetry instance
inline ArenaTelemetry g_ArenaTelemetry;

// RAII timer for allocation latency
struct AllocTimer {
    AllocTimer() : start_(__rdtsc()) {}
    ~AllocTimer() {
        uint64_t end = __rdtsc();
        uint64_t us = (end - start_) / 1000; // Approximate
        g_ArenaTelemetry.allocTimeUs += us;
        g_ArenaTelemetry.allocCount++;
    }
    uint64_t start_;
};
```

---

## 4. Instrumentation Points

### Point 1: ARENA_ALLOC Macro (Hot Path)
**File:** `src/script/masm/interpreter.asm:175-230`

Add telemetry hooks:
```asm
ARENA_ALLOC_TELEMETRY MACRO size_reg
    ; Increment allocation count
    inc qword ptr [g_ArenaTelemetry + 56]    ; allocCount
    
    ; Track alignment waste
    mov rax, size_reg
    mov rdx, rax
    add rax, 15
    and rax, -16
    sub rax, rdx
    add qword ptr [g_ArenaTelemetry + 48], rax  ; alignmentWaste
ENDM
```

### Point 2: Arena Create/Destroy
**File:** `src/script/masm/interpreter.asm:2760-2784`

```asm
JsInterpreter_CreateArena PROC FRAME
    ; ... existing code ...
    
    ; Telemetry
    inc qword ptr [g_ArenaTelemetry + 32]    ; extensionCount
    
    ; ... rest of function ...
JsInterpreter_CreateArena ENDP
```

### Point 3: Failed Allocation Tracking
**File:** `src/script/masm/interpreter.asm:220-225`

```asm
oom:
    inc qword ptr [g_ArenaTelemetry + 40]    ; failedAllocs
    xor rax, rax
    jmp done
```

---

## 5. 24-Hour Stress Test Monitoring

### Checkpoint Script (PowerShell)

```powershell
# checkpoint_arena.ps1 - Run every 15 minutes
$telemetry = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    TotalAllocated = [System.Runtime.InteropServices.Marshal]::ReadInt64(
        [IntPtr]::Add($g_ArenaTelemetry, 0))
    CurrentUsed = [System.Runtime.InteropServices.Marshal]::ReadInt64(
        [IntPtr]::Add($g_ArenaTelemetry, 8))
    PeakUsed = [System.Runtime.InteropServices.Marshal]::ReadInt64(
        [IntPtr]::Add($g_ArenaTelemetry, 16))
    CommitCalls = [System.Runtime.InteropServices.Marshal]::ReadInt64(
        [IntPtr]::Add($g_ArenaTelemetry, 24))
    ExtensionCount = [System.Runtime.InteropServices.Marshal]::ReadInt64(
        [IntPtr]::Add($g_ArenaTelemetry, 32))
    AlignmentWaste = [System.Runtime.InteropServices.Marshal]::ReadInt64(
        [IntPtr]::Add($g_ArenaTelemetry, 40))
    FailedAllocs = [System.Runtime.InteropServices.Marshal]::ReadInt64(
        [IntPtr]::Add($g_ArenaTelemetry, 48))
}

$telemetry | ConvertTo-Json | Add-Content arena_telemetry.jsonl

# Alert conditions
if ($telemetry.FailedAllocs -gt 0) {
    Write-Error "ALERT: Arena allocation failures detected!"
}
if ($telemetry.ExtensionCount -gt 10) {
    Write-Warning "WARNING: High arena chaining ($($telemetry.ExtensionCount))"
}
```

---

## 6. Recommendations

### Immediate (Before Stress Test)
1. ✅ **Fix commit-on-demand** in `ARENA_ALLOC` macro
2. ✅ **Add arena chaining** support
3. ✅ **Implement per-thread arenas** for thread safety
4. ✅ **Add telemetry instrumentation** as outlined above

### Short-term (Week 1)
1. **Arena compaction**: Defragment by copying live objects to new arena
2. **Size class segregation**: Separate arenas for small (<1KB) vs large (>1MB) allocations
3. **Memory pressure callback**: Notify agent when arena reaches 80% capacity

### Long-term (Month 1)
1. **Generational arenas**: Separate arenas for short-lived vs long-lived objects
2. **Arena visualization**: Real-time graph of arena usage in VS Code extension
3. **Predictive allocation**: Pre-extend arena based on agent workload patterns

---

## 7. Success Criteria

For the 24-hour stress test to pass:

| Metric | Target | Critical Threshold |
|--------|--------|-------------------|
| Failed allocations | 0 | >0 = FAIL |
| Peak memory usage | <80% system RAM | >95% = FAIL |
| Arena extensions | <100 | >500 = WARN |
| Avg alloc latency | <1μs | >10μs = WARN |
| Fragmentation ratio | <10% | >30% = WARN |

---

## 8. Next Steps

1. **Apply fixes** to `interpreter.asm` (Issues 1-4)
2. **Add telemetry header** to build
3. **Instrument** ARENA_ALLOC macro
4. **Run 4-hour smoke test** with telemetry
5. **Analyze results** and tune arena sizes
6. **Proceed to 24-hour test**

---

**Prepared by:** Agent Analysis Framework  
**Review Status:** Pending human verification  
**Estimated fix time:** 2-3 hours
