# Agent Telemetry Integration Guide
## Injection Points for 24-Hour Stress Test

This document provides the exact code changes needed to instrument the RawrXD agent system for stress testing.

---

## 📁 Files Generated

| File | Purpose | Build Command |
|------|---------|---------------|
| `AgentTelemetry.asm` | MASM x64 atomic counters | `ml64 /c /Fo AgentTelemetry.obj AgentTelemetry.asm` |
| `AgentTelemetry.hpp` | C++ wrapper + RAII helpers | Include in C++ files |

---

## 🔧 Injection Point 1: Arena_Alloc (MASM)

**File:** `src/direct_io/quantum_auth.asm`
**Function:** `Arena_Alloc` (~line 15171)

### Current Code (simplified):
```asm
Arena_Alloc PROC FRAME pArena:DQ, allocSize:DQ
    ; ... free list check ...
    
@@bump_alloc:
    mov pResult, (ARENA_CONTEXT ptr [rbx]).pCurrent
    mov (ARENA_CONTEXT ptr [rbx]).pCurrent, rax
    add (ARENA_CONTEXT ptr [rbx]).used, size
    
    mov rax, pResult
    jmp @@done
```

### Add After `@@bump_alloc:`:
```asm
@@bump_alloc:
    mov pResult, (ARENA_CONTEXT ptr [rbx]).pCurrent
    mov (ARENA_CONTEXT ptr [rbx]).pCurrent, rax
    add (ARENA_CONTEXT ptr [rbx]).used, size
    
    ; === TELEMETRY INJECTION ===
    ; Record allocation size atomically
    push rax
    push rcx
    mov rcx, size           ; RCX = allocation size
    call AgentTelemetry_RecordAllocation
    pop rcx
    pop rax
    ; ===========================
    
    mov rax, pResult
    jmp @@done
```

---

## 🔧 Injection Point 2: Arena_Free (MASM)

**File:** `src/direct_io/quantum_auth.asm`
**Function:** `Arena_Free` (after Arena_Alloc)

### Add at function entry:
```asm
Arena_Free PROC FRAME pArena:DQ, pMem:DQ, size:DQ
    LOCAL pCtx:DQ
    LOCAL pMemory:DQ
    
    push rbx
    .endprolog
    
    ; === TELEMETRY INJECTION ===
    ; Record free size atomically
    push rax
    push rcx
    mov rcx, size           ; RCX = freed size
    call AgentTelemetry_RecordFree
    pop rcx
    pop rax
    ; ===========================
    
    ; ... rest of free logic ...
```

---

## 🔧 Injection Point 3: Agent_ExecuteCommand (C++)

**File:** Your agent execution loop (e.g., `src/agent/AgentLoop.cpp`)

### Option A: Manual Instrumentation
```cpp
#include "agent/telemetry/AgentTelemetry.hpp"

void Agent_ExecuteCommand(const char* command, char* output, size_t outLen) {
    // Track this iteration
    TELEMETRY_LOOP_ITERATION();
    
    // Track latency of command execution
    TELEMETRY_LATENCY();
    
    // ... existing command execution logic ...
    
    // If proposal generated:
    TELEMETRY_PROPOSAL_GENERATED();
    
    // If proposal applied:
    TELEMETRY_PROPOSAL_APPLIED();
}
```

### Option B: RAII Scoped Tracking
```cpp
#include "agent/telemetry/AgentTelemetry.hpp"

void Agent_ExecuteCommand(const char* command, char* output, size_t outLen) {
    RawrXD::Telemetry::ScopedLatency latencyTracker;
    
    AgentTelemetry_RecordLoopIteration();
    
    // ... existing logic ...
    
    if (generatedProposal) {
        AgentTelemetry_RecordProposalGenerated();
    }
}
```

---

## 🔧 Injection Point 4: SwarmChannel Send/Receive

**File:** Your swarm communication channel

### Send Side:
```cpp
#include "agent/telemetry/AgentTelemetry.hpp"

void SwarmChannel::Send(const Message& msg) {
    RawrXD::Telemetry::ScopedLatency latencyTracker;
    
    // ... existing send logic ...
    
    // Latency automatically recorded on scope exit
}
```

### Receive Side (if synchronous):
```cpp
Message SwarmChannel::Receive() {
    RawrXD::Telemetry::ScopedLatency latencyTracker;
    
    // ... blocking receive logic ...
    
    return msg;
}
```

---

## 🔧 Injection Point 5: ArenaAlloc (C Wrapper)

**File:** `src/cli/cli_stream.cpp`

### Current:
```cpp
void* ArenaAlloc(SovereignArena* arena, size_t size) {
    if (arena->bump_offset + size > arena->capacity) return nullptr;
    void* ptr = arena->base_ptr + arena->bump_offset;
    arena->bump_offset += (size + 7) & ~7;
    return ptr;
}
```

### Instrumented:
```cpp
#include "agent/telemetry/AgentTelemetry.hpp"

void* ArenaAlloc(SovereignArena* arena, size_t size) {
    if (arena->bump_offset + size > arena->capacity) return nullptr;
    void* ptr = arena->base_ptr + arena->bump_offset;
    arena->bump_offset += (size + 7) & ~7;
    
    // Track allocation
    TELEMETRY_RECORD_ALLOC(size);
    
    return ptr;
}
```

---

## 📊 Checkpointing (Every 15 Minutes)

Add to your main agent loop or a background thread:

```cpp
#include "agent/telemetry/AgentTelemetry.hpp"
#include <chrono>
#include <fstream>

void TelemetryCheckpointThread() {
    using namespace std::chrono;
    
    auto lastCheckpoint = steady_clock::now();
    int checkpointNum = 0;
    
    while (g_agentRunning) {
        std::this_thread::sleep_for(seconds(1));
        
        auto now = steady_clock::now();
        auto elapsed = duration_cast<minutes>(now - lastCheckpoint).count();
        
        if (elapsed >= 15) {  // 15 minutes
            checkpointNum++;
            
            // Dump telemetry to file
            char filename[256];
            snprintf(filename, sizeof(filename), 
                     "telemetry/checkpoint_%03d.bin", checkpointNum);
            
            std::ofstream out(filename, std::ios::binary);
            uint8_t buffer[128];
            AgentTelemetry_DumpToBuffer(buffer);
            out.write(reinterpret_cast<char*>(buffer), sizeof(buffer));
            out.close();
            
            // Reset counters for next interval
            AgentTelemetry_Reset();
            
            lastCheckpoint = now;
        }
    }
}
```

---

## 🔗 Linking

Add to your build:

```cmake
# CMakeLists.txt
add_library(AgentTelemetry STATIC
    src/agent/telemetry/AgentTelemetry.asm
)

target_link_libraries(RawrXD-Agent
    AgentTelemetry
    # ... other deps ...
)
```

Or manual build:
```batch
ml64 /c /Fo AgentTelemetry.obj AgentTelemetry.asm
cl /O2 /EHsc /c AgentCode.cpp
link /OUT:RawrXD-Agent.exe AgentCode.obj AgentTelemetry.obj ...
```

---

## ✅ Verification

After integration, verify telemetry is working:

```cpp
#include "agent/telemetry/AgentTelemetry.hpp"
#include <stdio.h>

void TestTelemetry() {
    AgentTelemetry_Reset();
    
    // Simulate allocations
    for (int i = 0; i < 100; i++) {
        TELEMETRY_RECORD_ALLOC(1024);
    }
    
    uint64_t used = AgentTelemetry_GetArenaUsed();
    printf("Arena used: %llu bytes (expected: ~102400)\n", used);
    
    // Should print ~102400 bytes
}
```

---

## 📈 Success Criteria for 24-Hour Test

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Memory Stability** | Flat growth after hour 2 | `arenaUsedBytes` delta < 1% per hour |
| **Deterministic Fidelity** | < 0.001% variance | `stateChecksum` Hamming distance |
| **Proposal Rate** | > 5/hour | `proposalsGenerated` counter |
| **Swarm Latency** | < 100μs avg | `totalSwarmLatencyUs / loopCount` |
| **Seal Gate** | 🟢 throughout | CI pipeline stays green |

---

**Next Step:** Apply these injections and run a 1-hour smoke test to verify telemetry collection before the full 24-hour run.
