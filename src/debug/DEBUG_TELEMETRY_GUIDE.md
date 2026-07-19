# RawrXD Debugger Telemetry System

## Overview

The debugger telemetry system provides **producer/consumer observability** for the IDE's debugging subsystem. It tracks sequence numbers, state age, and memory usage to validate high-frequency debugging scenarios.

## Architecture

```
Debugger Engine Thread (Producer)
        |
        |  seq=1..N, timestamp
        v
+-----------------------------------+
|      DebugBridge::PostEvent       |
|  - Assign sequence number         |
|  - Record submit timestamp        |
|  - Coalesce stale events (>10 gap)|
+-----------------------------------+
        |
        | PostMessage(WM_APP_DEBUG_EVENT)
        v
+-----------------------------------+
|         UI Thread (Consumer)      |
|  DebugBridge::ProcessEvent        |
|  - Record render timestamp        |
|  - Calculate state age            |
|  - Update telemetry               |
+-----------------------------------+
        |
        v
    Rendered Debug View
```

## Key Metrics

### Sequence Tracking
```cpp
struct DebugTelemetry {
    std::atomic<uint64_t> submittedSequence;  // Last seq from backend
    std::atomic<uint64_t> renderedSequence;   // Last seq rendered by UI
    std::atomic<uint64_t> droppedEvents;      // Events coalesced
    std::atomic<uint64_t> totalEvents;        // Total generated
    
    uint64_t GetSequenceGaps() const;         // submitted - rendered
};
```

**Expected healthy values:**
```
Submitted Sequence: 25000
Rendered Sequence:    800
Sequence Gaps:     24200  <-- UI consuming current state, not history
```

### State Age Tracking
```cpp
struct DebugBridgeEvent {
    uint64_t sequence;
    uint64_t submitTimestamp;   // Backend time
    uint64_t renderTimestamp;   // UI time (set when rendered)
    
    uint64_t GetStateAgeMs() const {
        return renderTimestamp - submitTimestamp;
    }
};
```

**Expected healthy values:**
```
Last Rendered Seq: 800
State Age: 12ms      <-- Fresh state

Problem:
Last Rendered Seq: 800
State Age: 2500ms    <-- UI falling behind
```

### Memory Stability
```cpp
struct DebugTelemetry {
    std::atomic<uint64_t> arenaHighWater;  // Peak memory usage
    std::atomic<uint64_t> currentArena;      // Current usage
};
```

**Expected healthy pattern:**
```
Arena High Water: increases during capture
Arena High Water: stabilizes after repeated stepping
```

The important result is **not** a low peak—it's that the peak **stops growing**.

## Event Coalescing

When the UI falls behind (>10 events), non-critical events are dropped:

```cpp
bool DebugBridge::ShouldCoalesceEvent(DebugBridgeEvent* newEvent) {
    if (gaps > 10) {
        switch (newEvent->type) {
            case SingleStep:      // Drop - intermediate steps
            case OutputDebugString: // Drop - console output
                return true;
            default:
                break;             // Keep - breakpoints, exceptions
        }
    }
    return false;
}
```

This ensures:
- Breakpoints and exceptions are never lost
- UI stays responsive during high-frequency stepping
- No memory explosion from event queue buildup

## Stress Test Programs

### stress_target.exe
**Purpose:** High-frequency stepping validation

```cpp
// Tight computational loop
while (g_running) {
    g_counter++;  // Millions of increments per second
    FunctionC();  // Periodic call stack depth
}
```

**Validates:**
- Breakpoint handling throughput
- Single-stepping performance
- Call stack capture
- Sequence gap management

### stress_memory.exe
**Purpose:** Memory/register inspection stress

```cpp
// Complex data structures
MemoryStressor* g_stressor;  // Linked list, arrays, buffers

// Deep call stacks + register capture
StackInspectionStress(20);   // 20 frames deep
```

**Validates:**
- Memory window refresh
- Variable inspection
- Register capture
- Stack walking
- Arena stability

## Telemetry Output

### Debug Output (Real-time)
```
[DebugTelemetry] Submitted: 25000 | Rendered: 800 | Gaps: 24200
               Dropped: 24200 | Total: 25000
               LastAge: 12ms | MaxAge: 45ms | Arena: 5242880
```

### Log File (ghost_performance.log)
```
[2026-07-19 18:30:15] INFERENCE_COMPLETE | Latency: 245.00ms | Tokens: 16 | Confidence: 0.850 | Bridge: Zero-copy IPC
[2026-07-19 18:30:15] DEBUG_EVENT | Seq: 25000 | Age: 12ms | Type: BreakpointHit
```

## Validation Matrix

| Test | Validates | Expected Result |
|------|-----------|-----------------|
| stress_target.cpp | Stepping throughput | High sequence gaps, low state age |
| stress_memory.cpp | Register/memory pressure | Arena stabilizes |
| Sequence gaps | State coalescing | Gaps > 0, UI responsive |
| Latency tracking | UI responsiveness | LastAge < 100ms |
| Arena high water | Memory stability | Peak stops growing |
| CDB engine events | Backend correctness | Events received, processed |

## Integration Points

### From IDE UI
```cpp
// In WM_APP_DEBUG_EVENT handler
DebugBridgeEvent* event = (DebugBridgeEvent*)lParam;
DebugBridge::Instance().ProcessEvent(event);

// Periodic telemetry logging
DebugBridge::Instance().LogTelemetrySummary();
```

### From Debug Backend
```cpp
// When breakpoint hit
DebugBridgeEvent* event = new DebugBridgeEvent();
event->type = DebugBridgeEventType::BreakpointHit;
event->breakpoint.address = addr;
// sequence and timestamp auto-assigned
DebugBridge::Instance().PostEvent(event);
```

## Performance Targets

| Metric | Target | Acceptable |
|--------|--------|------------|
| State Age | < 50ms | < 100ms |
| Sequence Gaps | > 10000 | > 1000 |
| Arena Growth | Stops after 10s | Stops after 30s |
| Event Drop Rate | < 99% | < 95% |

## Next Steps

1. **Run stress tests** through actual RawrXD IDE
2. **Capture baseline telemetry** for debugger subsystem
3. **Compare shared memory vs process bridge** for debugger events
4. **Profile arena usage** during memory window refresh

## Files Modified

- `src/debug/DebugBridge.hpp` - Added sequence tracking, telemetry
- `src/debug/DebugBridge.cpp` - Implemented coalescing, metrics
- `src/debug/stress_target.cpp` - New stepping stress test
- `src/debug/stress_memory.cpp` - New memory stress test
- `CMakeLists.txt` - Added stress test targets
