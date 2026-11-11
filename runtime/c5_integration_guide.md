# C5: MASM Telemetry Integration Guide

## Overview

This guide shows how to integrate the MASM telemetry core with your transformer execution for real-time, cycle-accurate performance monitoring.

## Architecture

```
C++ Transformer Execution
    ↓
MASM Telemetry Bridge (telemetry_masm_bridge.hpp)
    ↓
MASM Telemetry Core (telemetry_masm.asm)
    ↓
Ring Buffer (lock-free, RDTSC timestamps)
    ↓
Output (file, shared memory, or IDE dashboard)
```

## Quick Start

### 1. Build MASM Telemetry Core

```bash
cd d:\src\runtime
build_telemetry_masm.bat
```

Output:
- `telemetry_masm.obj` - Object file
- `telemetry_masm.lib` - Static library

### 2. Link with Your Project

```cmake
target_link_libraries(your_target PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/telemetry_masm.lib
)
```

### 3. Initialize Telemetry

```cpp
#include "telemetry_masm_bridge.hpp"

int main() {
    // Initialize with 1MB ring buffer
    if (!InitializeMasmTelemetry(1024 * 1024)) {
        std::cerr << "Failed to initialize telemetry\n";
        return 1;
    }
    
    // ... your code ...
    
    ShutdownMasmTelemetry();
    return 0;
}
```

## Integration with Transformer Execution

### Option 1: RAII Scopes (Recommended)

```cpp
bool StreamingMultiLayerBackend::ExecuteLayer(uint32_t layer_idx, uint32_t position) {
    // Automatic START/END logging
    MASM_TELEMETRY_SCOPE(
        TELEMETRY_LAYER_EXEC_START + layer_idx,
        TELEMETRY_LAYER_EXEC_END + layer_idx
    );
    
    // ... layer execution ...
    
    return true;
}
```

### Option 2: Manual Logging

```cpp
void StreamingMultiLayerBackend::RMSNorm(...) {
    uint64_t tsc_start = MasmTelemetry_Rdtsc();
    
    // ... RMSNorm computation ...
    
    uint64_t tsc_end = MasmTelemetry_Rdtsc();
    uint64_t duration = tsc_end - tsc_start;
    
    MasmTelemetry_Log(TELEMETRY_OP_RMSNORM_END, duration, size);
}
```

### Option 3: Operation Helpers

```cpp
void StreamingMultiLayerBackend::MatMulRow(...) {
    OpTelemetry::MatMul(out_dim, in_dim, 1);
    
    // ... matmul ...
    
    uint64_t duration = MasmTelemetry_Rdtsc() - start;
    OpTelemetry::MatMulEnd(duration);
}
```

## Phase ID Taxonomy

| Range | Category | Example |
|-------|----------|---------|
| 0x0000-0x0FFF | System | INIT, SHUTDOWN |
| 0x1000-0x1FFF | Layer | LAYER_LOAD, LAYER_EXEC |
| 0x2000-0x2FFF | Operation | RMSNORM, MATMUL, ATTENTION |
| 0x3000-0x3FFF | Memory | MMAP, ALLOC |
| 0x4000-0x4FFF | Custom | USER_DEFINED |

## Performance Impact

- **Logging overhead**: ~10-20 cycles per event
- **Buffer full**: Events dropped (no blocking)
- **Memory**: Configurable (default 1MB = ~32K events)

## Real-Time Dashboard

To view telemetry in real-time:

1. **Export to shared memory** (modify `MasmTelemetry_Flush`)
2. **Read from RawrXD IDE** (via memory-mapped file)
3. **Display live metrics** (tokens/sec, layer latency, etc.)

Example metrics:
```
Layer 0:  2.3ms  (RMSNorm: 0.1ms, MatMul: 1.8ms, Attention: 0.3ms, MLP: 0.1ms)
Layer 1:  2.4ms  (...)
...
Total:    78ms   (33 tokens/sec)
```

## Validation

Run the test:
```bash
./test_telemetry_masm
```

Expected output:
```
=== MASM Telemetry Integration Test ===

[Test 1] Initialize telemetry...
  PASSED: Telemetry initialized

[Test 2] Log simple events...
  PASSED: 4 events logged

...

=== All Tests PASSED ===
```

## Next Steps

1. ✅ Build and test MASM telemetry
2. → Integrate with `StreamingMultiLayerBackend`
3. → Add real-time dashboard
4. → Profile and optimize bottlenecks
5. → Compare with llama.cpp performance

## Troubleshooting

### Link errors
- Ensure `telemetry_masm.lib` is linked
- Check calling convention (x64 ABI)

### No events logged
- Verify `InitializeMasmTelemetry()` called
- Check buffer not full (call `Flush`)

### High overhead
- Reduce event frequency
- Use sampling (log every Nth event)
- Increase buffer size
