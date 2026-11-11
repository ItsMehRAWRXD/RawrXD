# RawrXD N-EVM - Deterministic Replay Harness

## Overview

The Deterministic Replay Harness enables recording, replaying, and bisecting execution sequences for debugging validation failures and regression analysis.

## Features

### Execution Recording

Records every significant event during validation:
- Kernel launches (name, parameters)
- Memory allocations/frees
- KV cache operations (read/write/migrate/evict)
- Tensor operations
- RNG state changes
- Synchronization points
- Math mode switches
- Performance profile changes
- Manual checkpoints

### State Snapshots

Captures complete system state at checkpoints:
- Memory allocation state
- KV cache state (pages, residency)
- Tensor registry
- RNG state
- Timestamp

### Replay Control

- Step-by-step replay
- Replay to specific checkpoint
- Replay to sequence ID
- Reset and restart

### Regression Bisection

Automatically finds first bad event:
```cpp
auto result = RegressionBisector::Bisect("good.json", "bad.json");
// result.first_bad_sequence = 1523
// result.context_before = [...]  // 10 events before
// result.context_after = [...]   // 10 events after
// result.root_cause_analysis = "KV cache corruption detected"
```

## Usage

### Recording Execution

```cpp
ReplayHarness harness;

// Configure recording
ReplayHarness::Config config;
config.record_kernels = true;
config.record_memory = true;
config.record_kv_cache = true;
config.auto_checkpoint = true;
config.checkpoint_interval_ms = 60000;  // 1 minute

harness.StartRecording();

// Your validation code here
harness.RecordKernelLaunch("matmul_f32", params);
harness.RecordMemoryAllocation(ptr, size, "device");
harness.RecordKVCacheOperation(page_id, layer, seq_pos, "read");
harness.RecordCheckpoint("after_attention");

harness.StopRecording();
harness.SaveRecording("execution.json");
```

### Replaying Execution

```cpp
ReplayHarness harness;
harness.LoadRecording("execution.json");

// Replay all events
while (harness.ReplayNextEvent()) {
    // Event replayed
}

// Or replay to specific point
harness.ReplayToCheckpoint("after_attention");

// Or replay to sequence ID
harness.ReplayToSequenceId(1523);
```

### Comparing Executions

```cpp
// Compare current execution with recording
auto result = harness.CompareWithRecording(current_sequence);

if (!result.identical) {
    std::cout << "Divergence at sequence " << result.first_divergence << "\n";
    std::cout << "Expected: " << result.expected_value << "\n";
    std::cout << "Actual: " << result.actual_value << "\n";
}
```

### Bisecting Regressions

```cpp
// Find first bad event between known good and bad recordings
auto result = RegressionBisector::Bisect("good.json", "bad.json");

std::cout << "First bad sequence: " << result.first_bad_sequence << "\n";
std::cout << "Event type: " << ExecutionEventTypeToString(result.bad_event.type) << "\n";
std::cout << result.root_cause_analysis << "\n";

// Context around failure
for (const auto& event : result.context_before) {
    std::cout << "Before: [" << event.sequence_id << "] "
              << event.kernel_name << "\n";
}
```

## Event Types

| Event Type | Description | Data Captured |
|------------|-------------|---------------|
| KernelLaunch | GPU kernel execution | Name, parameters |
| MemoryAllocation | Memory alloc/free | Address, size, pool |
| KVCacheOperation | KV cache access | Page ID, layer, position, operation |
| TensorOperation | Tensor lifecycle | Name, shape, dtype, operation |
| RandomNumber | RNG state | Seed, position |
| Synchronization | Device sync | - |
| MathModeChange | Math mode switch | Old -> new |
| ProfileSwitch | Profile change | Old -> new |
| Checkpoint | Manual checkpoint | Label |

## File Format

### Execution Sequence JSON

```json
{
  "events": [
    {
      "sequence_id": 0,
      "type": "KernelLaunch",
      "timestamp_ns": 1699123456789012345,
      "kernel_name": "matmul_f32",
      "data": "...",
      "checksum": 1234567890
    },
    {
      "sequence_id": 1,
      "type": "KVCacheOperation",
      "timestamp_ns": 1699123456789012346,
      "kv_info": {
        "page_id": 42,
        "layer_id": 3,
        "sequence_pos": 128,
        "operation": "read"
      }
    }
  ],
  "total_events": 2
}
```

### State Snapshot JSON

```json
{
  "sequence_id": 100,
  "timestamp": "2026-07-20 14:30:52",
  "memory": {
    "total_allocated": 8589934592,
    "peak_allocated": 9663676416
  },
  "kv_cache": {
    "total_pages": 1024,
    "resident_pages": 896,
    "migrated_pages": 128
  },
  "tensors": {
    "active_tensors": 256,
    "total_memory": 4294967296
  },
  "rng": {
    "seed": 42,
    "sequence_position": 1234567
  }
}
```

## Integration with Validation

### Automatic Recording in Stress Test

```cpp
// In ExtendedStressTest::Run()
ReplayHarness harness;
harness.StartRecording();

for (uint32_t step = 0; step < config_.num_steps; ++step) {
    harness.RecordCheckpoint("step_" + std::to_string(step));
    
    if (!ExecuteStep(step)) {
        // Failure - save recording
        harness.SaveRecording("failure_recording.json");
        return false;
    }
}

harness.StopRecording();
```

### CI/CD Integration

```yaml
# Upload failure recordings as artifacts
- name: Upload replay recordings
  if: failure()
  uses: actions/upload-artifact@v4
  with:
    name: failure-recordings
    path: |
      *.json
      *.json.snapshots.json
```

## Performance

- Recording overhead: ~5-10%
- Snapshot size: ~1-10 KB per checkpoint
- Typical recording: ~100-1000 events per validation run
- File size: ~100 KB - 10 MB depending on detail level

## Use Cases

### 1. Debugging Intermittent Failures

```cpp
// Run until failure
while (true) {
    ReplayHarness harness;
    harness.StartRecording();
    
    bool passed = RunValidation();
    
    if (!passed) {
        harness.SaveRecording("failure_" + timestamp + ".json");
        break;
    }
}

// Analyze failure
auto result = RegressionBisector::Bisect("last_good.json", "failure.json");
```

### 2. Regression Bisection

```cpp
// Automated bisection
auto result = RegressionBisector::AutomatedBisect(
    [](const ExecutionSequence& seq) { return Validate(seq); },
    baseline_sequence
);
```

### 3. State Comparison

```cpp
// Compare states at checkpoints
auto good_snapshots = LoadSnapshots("good.json.snapshots.json");
auto bad_snapshots = LoadSnapshots("bad.json.snapshots.json");

for (size_t i = 0; i < good_snapshots.size(); ++i) {
    if (good_snapshots[i].memory.total_allocated != 
        bad_snapshots[i].memory.total_allocated) {
        std::cout << "Memory divergence at checkpoint " << i << "\n";
    }
}
```

## Best Practices

1. **Use Checkpoints**: Mark significant points in execution
2. **Auto-Checkpoint**: Enable for long-running tests
3. **Selective Recording**: Disable unnecessary event types
4. **Storage**: Archive recordings for failed runs only
5. **Comparison**: Always compare with known good recording

## Troubleshooting

### Recording Too Large

- Disable tensor operation recording
- Increase checkpoint interval
- Filter out frequent events

### Replay Mismatch

- Check for non-deterministic operations
- Verify RNG seed consistency
- Ensure same hardware/software

### Bisection Not Finding Issue

- Verify good recording is actually good
- Check for multiple divergence points
- Increase context window size

## API Reference

See `nevm_replay_harness.hpp` for complete API documentation.

## License

Copyright (c) 2026 RawrXD Project. All rights reserved.
