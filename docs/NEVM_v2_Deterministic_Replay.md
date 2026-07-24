# RawrXD N-EVM v0.2 - Deterministic Replay System
## Reproducible Execution for Benchmarking and Debugging

---

## Overview

The deterministic replay system captures complete execution traces, enabling:
- **Reproducible benchmarks** - Same inputs produce identical execution
- **Performance regression detection** - Compare traces across versions
- **Debugging** - Step through execution event by event
- **Analysis** - Understand precision controller decisions

---

## Trace Event Types

### 15 Event Types Captured

| Event | Description | Use Case |
|-------|-------------|----------|
| `TOKEN_START/END` | Token generation boundaries | Measure latency |
| `LAYER_START/END` | Layer execution | Profile per-layer performance |
| `KERNEL_CALL` | Kernel invocation | Identify hot kernels |
| `PRECISION_SELECT` | Precision controller decision | Debug precision choices |
| `RESIDENCY_TRANSITION` | Block state changes | Verify residency correctness |
| `PREFETCH_START/COMPLETE` | Prefetch operations | Measure prefetch effectiveness |
| `MEMORY_ACCESS` | Tensor memory access | Track memory patterns |
| `TLB_HIT/MISS` | TLB cache events | Verify MMU efficiency |
| `STALL_CYCLE` | Pipeline stalls | Identify bottlenecks |
| `ERROR_METRIC` | Quantization error | Track quality vs speed |
| `SAMPLING` | Token sampling | Debug sampling behavior |

---

## Precision Map Snapshots

### Captures Complete Precision Assignment

```cpp
struct PrecisionMapSnapshot {
    uint64_t timestamp_ns;
    uint64_t token_id;
    uint32_t layer_id;
    
    // Block-level precision assignments
    struct BlockPrecision {
        SubLayerBlockID block_id;      // {layer, tensor, head, block}
        PrecisionMode precision;       // Q2, Q4, Q8, FP16, etc.
        float importance;              // Why this precision
    };
    std::vector<BlockPrecision> block_precisions;
    
    // Summary
    std::map<PrecisionMode, uint32_t> precision_distribution;
    float effective_bits_per_param;
    size_t total_memory_bytes;
};
```

### Example Snapshot

```json
{
  "timestamp_ns": 1234567890,
  "token_id": 42,
  "layer_id": 12,
  "block_precisions": [
    {"block_id": "12:Q:0:0", "precision": "Q4", "importance": 0.3},
    {"block_id": "12:Q:1:0", "precision": "Q8", "importance": 0.7},
    {"block_id": "12:K:0:0", "precision": "Q4", "importance": 0.4},
    {"block_id": "12:O:0:0", "precision": "FP16", "importance": 0.9}
  ],
  "precision_distribution": {
    "Q2": 10,
    "Q4": 45,
    "Q8": 30,
    "FP16": 15
  },
  "effective_bits_per_param": 4.2,
  "total_memory_bytes": 1258291200
}
```

---

## Residency Map Snapshots

### Captures Complete Memory State

```cpp
struct ResidencyMapSnapshot {
    uint64_t timestamp_ns;
    
    struct BlockResidency {
        VirtualTensorAddress vta;
        ResidencyState state;          // COMPRESSED, FAST_RESIDENT, etc.
        PrecisionMode format;
        ResidencyTarget tier;          // VRAM, RAM, etc.
        uint64_t last_access_tick;
        uint64_t access_count;
    };
    std::vector<BlockResidency> block_residencies;
    
    // Summary by state
    std::map<ResidencyState, uint32_t> state_distribution;
    size_t total_resident_bytes;
    float memory_pressure;
};
```

---

## Deterministic Execution Mode

### Configuration

```cpp
DeterministicExecutionMode::Config config;
config.random_seed = 42;                    // Fixed seed
config.fixed_precision = true;              // Disable adaptive
config.forced_precision = PrecisionMode::Q4; // Force Q4
config.fixed_prefetch = true;               // Deterministic prefetch
config.record_determinism_check = true;     // Verify reproducibility
```

### Usage

```cpp
// Initialize deterministic mode
DeterministicExecutionMode deterministic(config);
deterministic.Initialize();

// Run with trace recording
TraceRecorder recorder(TraceRecorder::DefaultConfig());
recorder.StartRecording(token_id);

// Execute token
vm.Execute(...);

recorder.StopRecording();

// Export trace
recorder.ExportJSON("token_42_trace.json");
recorder.ExportChromeTrace("token_42_chrome.json");
```

---

## Benchmark Validation Workflow

### Step 1: Capture Baseline Trace

```cpp
// Run with deterministic settings
DeterministicExecutionMode::Config config;
config.random_seed = 42;
config.fixed_precision = false;  // Allow adaptive
config.record_determinism_check = true;

// Execute 100 tokens, capture traces
for (uint32_t i = 0; i < 100; ++i) {
    recorder.StartRecording(i);
    vm.GenerateToken(...);
    recorder.StopRecording();
}

// Export baseline
recorder.ExportJSON("baseline_traces.json");
```

### Step 2: Modify Code (e.g., optimize prefetch)

### Step 3: Capture New Trace

```cpp
// Same deterministic settings
// Execute same 100 tokens
recorder.ExportJSON("optimized_traces.json");
```

### Step 4: Compare Traces

```cpp
// Load both traces
TraceReplayer replayer1;
TraceReplayer replayer2;

replayer1.LoadTrace("baseline_traces.json");
replayer2.LoadTrace("optimized_traces.json");

// Compare
std::string diff_report;
bool match = TraceReplayer::CompareTraces(
    "baseline_traces.json",
    "optimized_traces.json",
    diff_report
);

// Analyze differences
if (!match) {
    std::cout << "Traces differ:\n" << diff_report << "\n";
}
```

---

## Chrome Tracing Integration

### Export to Chrome Trace Format

```cpp
recorder.ExportChromeTrace("execution_trace.json");
```

### View in Chrome

1. Open Chrome
2. Navigate to `chrome://tracing`
3. Load `execution_trace.json`
4. Visualize execution timeline

### What You See

```
Time →

Thread 0: [TOKEN_START][LAYER_0][LAYER_1][LAYER_2]...[TOKEN_END]
Thread 1:      [PREFETCH][PREFETCH][PREFETCH]
              ↑ Overlapped with execution
```

---

## Key Metrics for Benchmark

### Per-Token Metrics

```cpp
struct TokenMetrics {
    uint32_t token_id;
    float latency_ms;
    uint32_t num_layers;
    uint32_t num_kernels;
    uint32_t precision_switches;
    uint32_t stall_cycles;
    float prefetch_hit_rate;
    size_t memory_used_bytes;
    float effective_bits;
};
```

### Critical Metrics

| Metric | Target | Why |
|--------|--------|-----|
| `tokens/sec per GB` | > 20 | Memory efficiency |
| `prefetch_hit_rate` | > 85% | Scheduler quality |
| `precision_switches/token` | < 5 | Stability |
| `stall_cycles` | < 100 | Pipeline health |
| `output_divergence` | < 0.1% | Accuracy |

---

## Regression Detection

### Automated Comparison

```cpp
// CI/CD pipeline
bool ValidateNoRegression(const std::string& baseline_path,
                           const std::string& current_path) {
    TraceReplayer baseline;
    TraceReplayer current;
    
    baseline.LoadTrace(baseline_path);
    current.LoadTrace(current_path);
    
    auto base_analysis = baseline.AnalyzeTrace();
    auto curr_analysis = current.AnalyzeTrace();
    
    // Check for regressions
    bool pass = true;
    
    if (curr_analysis.avg_token_latency_ms > 
        base_analysis.avg_token_latency_ms * 1.05f) {
        std::cerr << "Latency regression detected!\n";
        pass = false;
    }
    
    if (curr_analysis.total_stall_cycles > 
        base_analysis.total_stall_cycles * 1.2f) {
        std::cerr << "Stall cycle regression detected!\n";
        pass = false;
    }
    
    return pass;
}
```

---

## Debugging Workflow

### Step 1: Identify Anomalous Token

```cpp
// Find token with high latency
for (const auto& trace : traces) {
    if (trace.total_latency_ms > 100.0f) {  // > 100ms
        std::cout << "Slow token: " << trace.token_id << "\n";
        
        // Export for analysis
        TraceReplayer replayer;
        replayer.LoadTrace(trace);
        replayer.ExportJSON("slow_token.json");
    }
}
```

### Step 2: Replay and Step Through

```cpp
TraceReplayer replayer;
replayer.LoadTrace("slow_token.json");
replayer.StartReplay();

// Step through events
while (replayer.IsReplaying()) {
    const TraceEvent* evt = replayer.GetCurrentEvent();
    
    if (evt->type == TraceEventType::STALL_CYCLE) {
        auto* stall = static_cast<const StallCycleEvent*>(evt);
        std::cout << "Stall: " << stall->reason << "\n";
    }
    
    if (evt->type == TraceEventType::PRECISION_SELECT) {
        auto* prec = static_cast<const PrecisionSelectEvent*>(evt);
        std::cout << "Precision: " << prec->selected_precision
                  << " (" << prec->reason << ")\n";
    }
    
    replayer.StepNext();
}
```

---

## Summary

### What the Trace System Provides

1. **Reproducibility** - Same inputs → same execution
2. **Visibility** - See every precision decision, residency transition
3. **Debugging** - Step through execution event by event
4. **Validation** - Prove correctness vs baseline
5. **Regression Detection** - Automated CI/CD checks

### Files Created

- `nevm_trace.hpp/cpp` - Complete trace system (1500 lines)

### Integration with N-EVM

```cpp
// In TransformerEngine::ExecuteLayer()
void TransformerEngine::ExecuteLayer(uint32_t layer_id, ...) {
    // Record layer start
    LayerStartEvent evt;
    evt.layer_id = layer_id;
    evt.timestamp_ns = GetTimestampNs();
    recorder.RecordLayerStart(evt);
    
    // Execute...
    
    // Record layer end
    LayerEndEvent end_evt;
    end_evt.layer_id = layer_id;
    end_evt.layer_latency_ms = elapsed_ms;
    end_evt.precision_switches = switches;
    recorder.RecordLayerEnd(end_evt);
}
```

---

## Next Step: Benchmark Execution

With the trace system in place, the validation milestone is:

```
Test: Llama 3.2 3B Q4_K_M

Baseline: llama.cpp
NEVM:     RawrXD N-EVM v0.2

Metrics:
  - tokens/sec
  - tokens/sec per GB
  - prefill tok/sec
  - decode tok/sec
  - VRAM usage
  - RAM usage
  - prefetch hit rate
  - precision switches/token
  - stall cycles
  - output divergence

Validation:
  - Capture traces from both
  - Compare event sequences
  - Verify output divergence < 0.1%
  - Measure performance gains
```

---

*RawrXD N-EVM v0.2 - Deterministic Replay System*  
*Ready for benchmark validation*
