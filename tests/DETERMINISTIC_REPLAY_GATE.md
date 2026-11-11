# RawrXD IDE Deterministic Replay Gate

## Overview

The **Deterministic Replay Gate** is a CI/CD validation system that ensures the RawrXD IDE's GhostText completion system behaves deterministically and reproducibly. It validates that:

1. **Version Stamping Works**: Completions are tagged with editor versions and stale completions are rejected
2. **Race Conditions Are Handled**: Concurrent edits during inference don't corrupt state
3. **Cancellations Are Clean**: Pending completions can be cancelled without side effects
4. **Behavior Is Reproducible**: Same inputs produce same outputs across runs

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Deterministic Replay Gate                 │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │   MockEditor │  │ MockGhostText│  │ EventJournal │        │
│  │              │  │    Engine    │  │              │        │
│  │ - Version    │  │              │  │ - Records    │        │
│  │ - Content    │  │ - Async      │  │ - Exports    │        │
│  │ - Snapshots  │  │ - Completion │  │ - Validates  │        │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘        │
│         │                 │                 │                │
│         └─────────────────┼─────────────────┘                │
│                           │                                  │
│                    ┌──────┴───────┐                          │
│                    │   Scenario   │                          │
│                    │  Executor    │                          │
│                    └──────┬───────┘                          │
│                           │                                  │
│                    ┌──────┴───────┐                          │
│                    │ReplayValidator│                          │
│                    └───────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

## Test Scenarios

### Scenario A: SingleKeystroke
**Purpose**: Verify basic completion flow

**Steps**:
1. Type "func" into editor
2. Increment version to 1
3. Request completion
4. Wait for completion
5. Verify completion text is "tion" (completing to "function")
6. Verify completion version matches request version

**Pass Criteria**:
- Completion received within timeout
- Version matches exactly
- Text matches expected

### Scenario B: RapidTypingBurst
**Purpose**: Verify version monotonicity under rapid input

**Steps**:
1. Simulate 10 keystrokes in 100ms (10ms interval)
2. Request completion every 3rd keystroke
3. Record all versions

**Pass Criteria**:
- All versions are strictly monotonic (no skips, no duplicates)
- No crashes or hangs

### Scenario C: CancelAndRetry
**Purpose**: Verify clean cancellation and retry

**Steps**:
1. Type "func", request completion
2. Cancel after 20ms
3. Type "tion", increment version
4. Request new completion
5. Verify new completion uses new version

**Pass Criteria**:
- Cancellation succeeds
- Retry uses correct version
- No stale completion injected

### Scenario D: ConcurrentEdit
**Purpose**: Verify stale completion rejection

**Steps**:
1. Type "ret", request completion
2. Wait 30ms (during inference)
3. Type "val", increment version
4. Wait for completion
5. Verify completion is for old version (would be rejected in real IDE)

**Pass Criteria**:
- Completion version detected as stale
- Editor state not corrupted

### Scenario E: StressSequence
**Purpose**: Verify stability under mixed operations

**Steps**:
1. Run 5 iterations of mixed operations
2. Alternate between completions and cancellations

**Pass Criteria**:
- All iterations complete
- No crashes or memory corruption

## Event Journal Format

The gate exports a JSON journal for each scenario:

```json
{
  "gateVersion": "1.0.0",
  "timestamp": 1234567890123456,
  "events": [
    {
      "sequenceId": 1,
      "timestampUs": 1234567890123456,
      "type": "Keystroke",
      "version": 1,
      "data": "func"
    },
    {
      "sequenceId": 2,
      "timestampUs": 1234567890123556,
      "type": "CompletionRequested",
      "version": 1,
      "data": "reqId=1"
    },
    {
      "sequenceId": 3,
      "timestampUs": 1234567890124556,
      "type": "CompletionReceived",
      "version": 1,
      "data": "tion"
    }
  ]
}
```

## Build Instructions

### Using Batch Script
```batch
# From tests directory
cd d:\RawrXD\tests
build_deterministic_replay_gate.bat

# Or build and run
cd d:\RawrXD\tests
build_deterministic_replay_gate.bat --run
```

### Using PowerShell
```powershell
# From tests directory
cd d:\RawrXD\tests
.\Run-DeterministicReplayGate.ps1

# Run specific scenario
.\Run-DeterministicReplayGate.ps1 -Scenario SingleKeystroke

# Run 10 iterations for statistical validation
.\Run-DeterministicReplayGate.ps1 -Iterations 10

# Compare to baseline
.\Run-DeterministicReplayGate.ps1 -CompareBaseline
```

### Using CMake
```cmake
# Add to CMakeLists.txt
include(tests/CMakeLists_DeterministicReplayGate.txt)

# Build
cmake --build build-ninja --target deterministic_replay_gate

# Run
cmake --build build-ninja --target run_deterministic_gate
```

## CI/CD Integration

### GitHub Actions
```yaml
name: Deterministic Replay Gate

on: [push, pull_request]

jobs:
  deterministic-gate:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Gate
        run: |
          cd tests
          .\build_deterministic_replay_gate.bat
      
      - name: Run Gate
        run: |
          .\build-ninja\tests\deterministic_replay_gate.exe
      
      - name: Upload Artifacts
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: replay-gate-results
          path: tests/replay_gate_*.json
```

### Azure DevOps
```yaml
steps:
- script: |
    cd tests
    build_deterministic_replay_gate.bat
  displayName: 'Build Deterministic Replay Gate'

- script: |
    .\build-ninja\tests\deterministic_replay_gate.exe
  displayName: 'Run Deterministic Replay Gate'

- task: PublishBuildArtifacts@1
  condition: always()
  inputs:
    pathToPublish: 'tests/replay_gate_output'
    artifactName: 'replay-gate-results'
```

## Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | All scenarios passed | Continue pipeline |
| 1 | Determinism violation | Block merge, investigate |
| 2 | Infrastructure failure | Retry, check build env |
| 3 | Timeout | Check for deadlocks |
| 4 | Validation failure | Review journal output |

## Debugging Failures

### Version Mismatch
```
[Gate] Version mismatch: expected 2, got 1
```
**Cause**: Completion used stale version
**Fix**: Check `InterlockedIncrement` in editor, verify version capture timing

### Timeout
```
[Gate] Timeout waiting for completion
```
**Cause**: Completion thread hung or deadlock
**Fix**: Check thread synchronization, verify worker thread is running

### Non-monotonic Versions
```
[Gate] Version skip detected: 2 -> 2
```
**Cause**: Version not incremented atomically
**Fix**: Use `InterlockedIncrement` instead of `++version`

## Integration with Existing Infrastructure

### Link with ContextCorrectnessHarness
The gate can be extended to use the real `ContextCorrectnessHarness`:

```cpp
// In deterministic_replay_gate.cpp
#include "../src/test_harness/ContextCorrectnessHarness.h"

// Replace MockEditor with real harness
ContextCorrectnessHarness harness;
harness.initialize();
```

### Link with ReplayHarness
For full agentic pipeline testing:

```cpp
#include "../src/test_harness/replay_harness.hpp"

ReplayHarness::instance().startRecording(config);
// ... run scenarios ...
ReplayHarness::instance().stopRecording(targets);
```

## Performance Baselines

Expected performance on reference hardware (Intel i7-12700K, 32GB RAM):

| Scenario | Expected Duration | Variance |
|----------|------------------|----------|
| SingleKeystroke | 50-150ms | ±20ms |
| RapidTypingBurst | 100-200ms | ±30ms |
| CancelAndRetry | 100-200ms | ±25ms |
| ConcurrentEdit | 100-200ms | ±25ms |
| StressSequence | 500-1000ms | ±100ms |

## Future Enhancements

1. **Real IDE Integration**: Hook into actual RawrXD_IDE_Win32.exe
2. **GPU Scenarios**: Test CUDA/Vulkan completion paths
3. **Network Scenarios**: Test LSP integration determinism
4. **Memory Validation**: Add AddressSanitizer integration
5. **Fuzz Testing**: Randomized input sequences

## References

- `RawrXD_IDE_Win32.cpp` - Main IDE implementation
- `SovereignBridge_Deep2.cpp` - Inference bridge
- `replay_harness.hpp` - Existing replay infrastructure
- `ContextCorrectnessHarness.h` - Context validation
