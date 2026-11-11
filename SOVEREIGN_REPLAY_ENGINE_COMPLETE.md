# Intent Replay Engine - Implementation Complete

## Executive Summary

The **Intent Replay Engine** makes every autonomous action **deterministically reproducible**. This enables debugging failed intents, regression testing, audit trails, and distributed replay across nodes.

## Core Concept

```
Every autonomous action becomes reproducible:
  intent.json + context hash + patch + validation = replay
```

## Components Implemented

### 1. Replay Journal - Persistent Storage
**File:** `src/kernel/IntentReplayEngine.hpp/cpp`

- **Record Storage:** JSON-based persistent journal
- **Fast Queries:** Indexed by intent type, agent, success/failure
- **Similarity Search:** Find records matching current context
- **Pruning:** Automatic cleanup of old records

```cpp
// Start recording
uint64_t recordId = REPLAY_JOURNAL.StartRecording(intent);

// Record snapshots, events, leases
REPLAY_JOURNAL.RecordSnapshot(recordId, snapshot, isPre);
REPLAY_JOURNAL.RecordEvent(recordId, event);
REPLAY_JOURNAL.RecordLease(recordId, lease);

// Finalize
REPLAY_JOURNAL.FinalizeRecord(recordId);

// Query
auto failed = REPLAY_JOURNAL.GetFailedRecords(100);
auto similar = REPLAY_JOURNAL.FindSimilarRecord(intent, context);
```

### 2. Context Snapshots - Complete System State

| Snapshot Type | Captures |
|---------------|----------|
| **FileSystem** | File hashes, timestamps, paths |
| **Memory** | Symbol addresses, memory regions |
| **Build** | CMake cache, object files, executable hash |
| **Agent** | Agent ID, type, intent history |
| **Kernel** | Active leases, last beacon |

```cpp
// Capture full system state
ContextSnapshot snapshot = SNAPSHOT_MANAGER.CaptureFullSnapshot();
std::string hash = snapshot.ComputeContextHash();

// Compare snapshots
auto diff = SNAPSHOT_MANAGER.CompareSnapshots(before, after);
if (!diff.identical) {
    for (const auto& change : diff.differences) {
        std::cout << change << "\n";
    }
}
```

### 3. Replay Session - Execute Replays

**Replay Modes:**
- **EXACT:** Exact replay with same inputs
- **ADAPTIVE:** Adapt to current context
- **DRY_RUN:** Simulate without side effects
- **DEBUG:** Step-through debugging

```cpp
// Replay a record
ReplayOptions opts;
opts.mode = ReplayMode::EXACT;
opts.stopOnMismatch = true;
opts.validateResults = true;

ReplayResult result = REPLAY_ENGINE.ReplayIntent(recordId, opts);

if (result.success) {
    std::cout << "Replay succeeded\n";
    std::cout << "Original time: " << result.originalTimeMs << " ms\n";
    std::cout << "Replay time: " << result.replayTimeMs << " ms\n";
} else if (!result.contextMatched) {
    std::cout << "Context mismatch:\n" << result.contextDiff;
}
```

### 4. Scoped Recording - RAII Helper

```cpp
void ExecuteIntent(IntentRequest& intent) {
    ScopedReplayRecording recording(intent);
    
    try {
        // Execute intent
        auto result = EXECUTION_PIPELINE.Execute(intent);
        
        if (result.IsSuccess()) {
            recording.MarkSuccess();
        } else {
            recording.MarkFailed(result.errorMessage);
        }
    } catch (const std::exception& e) {
        recording.MarkFailed(e.what());
        throw;
    }
}
// Auto-finalizes on scope exit
```

## Replay Record Structure

```json
{
  "recordId": 12345,
  "timestamp": 1699123456789,
  "intentType": "MODIFY_FUNCTION",
  "agentId": 42,
  "succeeded": true,
  "executionTimeMs": 150,
  "contextHash": "a1b2c3d4...",
  "patchHash": "e5f6g7h8...",
  "errorMessage": "",
  
  "preSnapshot": {
    "filesystem": { "fileHashes": {...} },
    "memory": { "symbolAddresses": {...} },
    "build": { "executableHash": "..." }
  },
  
  "events": [
    { "type": "INTENT_STARTED", "timestamp": ... },
    { "type": "RESOURCE_ACQUIRED", ... },
    { "type": "INTENT_COMPLETED", ... }
  ],
  
  "leases": [
    { "resourceType": "TERMINAL", "duration": 300 }
  ]
}
```

## Use Cases

### 1. Debugging Failed Intents
```cpp
// Get recent failures
auto failed = REPLAY_JOURNAL.GetFailedRecords(10);

// Replay with debugging
ReplayOptions opts;
opts.mode = ReplayMode::DEBUG;

auto result = REPLAY_ENGINE.ReplayIntent(failed[0].recordId, opts);
// Step through execution
```

### 2. Regression Testing
```cpp
// Replay all MODIFY_FUNCTION intents
auto results = REPLAY_ENGINE.ReplayIntentType("MODIFY_FUNCTION", opts);

int passed = 0, failed = 0;
for (const auto& result : results) {
    if (result.success && result.resultMatched) passed++;
    else failed++;
}

std::cout << "Regression: " << passed << " passed, " 
          << failed << " failed\n";
```

### 3. Audit Trails
```cpp
// Generate report for compliance
std::string report = REPLAY_ENGINE.GenerateReplayReport(recordId);
// Includes: intent, context, execution, result, timing
```

### 4. Distributed Replay
```cpp
// Export records
REPLAY_JOURNAL.ExportRecords("/shared/replay_journal");

// On another node
REPLAY_JOURNAL.ImportRecords("/shared/replay_journal");

// Replay with local context adaptation
ReplayOptions opts;
opts.mode = ReplayMode::ADAPTIVE;
REPLAY_ENGINE.ReplayIntent(recordId, opts);
```

## Integration with Agent Kernel

```
Intent Submission
      |
      v
Replay Engine (Start Recording)
      |
      v
Agent Kernel (Execute)
      |
      v
Replay Engine (Capture Events)
      |
      v
Patch Firewall (Validate)
      |
      v
Replay Engine (Record Result)
      |
      v
Journal Storage
```

## Files Created

1. `src/kernel/IntentReplayEngine.hpp` - Header
2. `src/kernel/IntentReplayEngine.cpp` - Implementation

**Total: ~800 lines**

## Total Sovereign Architecture

| Component | Lines |
|-----------|-------|
| Intent Guardrails | ~3,500 |
| Sovereign Puppeteer | ~2,970 |
| Agent Kernel | ~2,500 |
| **Intent Replay Engine** | **~800** |
| **Total** | **~9,800** |

## Next Steps

1. **Build System Telemetry** - Convert compiler/linker output to structured events
2. **Repository Memory Graph** - Persistent AST + symbols + dependencies
3. **Control Plane UI** - Visualize agents, intents, resources, replays
4. **HiveSync** - Distributed replay across nodes

---

**Every action is now reproducible.**

**Failed intents can be debugged.**

**Regressions can be detected.**

**The system is observable.**
