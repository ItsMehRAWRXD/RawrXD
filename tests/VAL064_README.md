# VAL-064 Performance Certification System

## Overview

VAL-064 is the performance certification validation for RawrXD. It certifies that the system meets throughput, latency, and memory utilization requirements on the reference hardware configuration.

## Reference Hardware

- **Primary GPU**: R9700 AI PRO 32GB
- **Secondary GPU**: RX 7800 XT 16GB
- **Total VRAM**: 48GB
- **Target Model**: deep2-q4_k_m.gguf
- **Workload**: 2048 prompt tokens / 512 generated tokens

## Certification Thresholds

| Metric | Minimum | Maximum |
|--------|---------|---------|
| Prefill TPS | 1000 tps | - |
| Decode TPS | 50 tps | - |
| First Token Latency | - | 500 ms |
| VRAM Usage | - | 45 GB |
| RAM Usage | - | 64 GB |

## Files

### Core Implementation

- `VAL064_PerformanceCertification.cpp` - Original scaffold implementation
- `VAL064_CertificationHarness.cpp` - Enhanced harness with live telemetry
- `VAL064_TelemetryAdapter.hpp` - Telemetry provider interface
- `VAL064_TelemetryAdapter.cpp` - Telemetry provider implementations
- `build_val064.bat` - Build script

### Evidence Artifacts

Located in `d:\evidence\performance\`:

- `VAL064_PREFILL.json` - Prefill benchmark results
- `VAL064_DECODE.json` - Decode benchmark results
- `VAL064.json` - Combined certification record (generated)

## Usage

### Quick Start (Static Mode)

Run with static values (certification scaffold):

```cmd
VAL064_CertificationHarness.exe --static
```

### Live Telemetry Mode

Run with live telemetry from RawrXD runtime:

```cmd
REM Auto-detect telemetry provider
VAL064_CertificationHarness.exe --telemetry auto --samples 5

REM Use file-based telemetry
VAL064_CertificationHarness.exe --telemetry file --samples 10 --interval 500

REM Use shared memory telemetry (fastest)
VAL064_CertificationHarness.exe --telemetry shared_memory --samples 3
```

### Full Options

```cmd
VAL064_CertificationHarness.exe \
    --benchmark VAL-064-performance \
    --model deep2-q4_k_m.gguf \
    --tokens 512 \
    --context 2048 \
    --backend auto \
    --telemetry auto \
    --json-output evidence/performance/VAL064.json \
    --samples 5 \
    --interval 1000
```

## Telemetry Providers

### 1. Shared Memory Provider (Recommended)

Fastest, most real-time. Requires RawrXD to expose telemetry via Windows shared memory.

**Setup**: RawrXD must create a shared memory section named `Global\RawrXD_Telemetry` with the following structure:

```cpp
struct SharedTelemetryData {
    uint32_t version;           // Set to 1
    uint32_t sequence;          // Increment on each update
    double prefill_tps;         // Prefill throughput
    double decode_tps;          // Decode throughput
    double first_token_ms;      // First token latency
    double peak_vram_mb;        // Peak VRAM usage
    double peak_ram_mb;         // Peak RAM usage
    int prompt_tokens;          // Number of prompt tokens
    int generated_tokens;       // Number of generated tokens
    uint64_t timestamp_ns;      // Timestamp in nanoseconds
    bool valid;                 // Data validity flag
    char error_message[256];    // Error message if invalid
};
```

### 2. File Provider

Reads telemetry from a JSON file. Good for batch processing or when shared memory is not available.

**Setup**: RawrXD writes telemetry to `evidence/performance/telemetry_live.json`:

```json
{
  "prefill_tps": 5000.0,
  "decode_tps": 182.0,
  "first_token_ms": 83.0,
  "peak_vram_mb": 32768.0,
  "peak_ram_mb": 16384.0,
  "prompt_tokens": 2048,
  "generated_tokens": 512
}
```

### 3. Mock Provider

Returns static values for testing. Always available.

## Integration with RawrXD Runtime

To bind VAL-064 to live telemetry, RawrXD must:

1. **Track inference timing**:
   - Measure prefill time (prompt processing)
   - Measure decode time (token generation)
   - Calculate TPS for each phase

2. **Track memory usage**:
   - Query GPU memory via Vulkan/ROCm APIs
   - Track system RAM usage
   - Record peak values during inference

3. **Export telemetry**:
   - Write to shared memory (preferred) or file
   - Update at end of each inference batch
   - Set `valid=true` when data is ready

### Example Integration Points

```cpp
// In NativeBackend after inference completes:
void NativeBackend::OnInferenceComplete(const InferenceResult& result) {
    TelemetryData data;
    data.prefill_tps = result.prefill_tokens / result.prefill_time_ms * 1000.0;
    data.decode_tps = result.generated_tokens / result.decode_time_ms * 1000.0;
    data.first_token_ms = result.time_to_first_token_ms;
    data.peak_vram_mb = GetPeakVRAMUsage();
    data.peak_ram_mb = GetPeakRAMUsage();
    data.valid = true;
    
    TelemetryExporter::Export(data);
}
```

## Build Instructions

### Prerequisites

- Visual Studio 2022 with C++ support
- nlohmann/json library (in `d:\3rdparty`)

### Build

```cmd
cd d:\src\tests
build_val064.bat
```

Output: `d:\bin\VAL064_CertificationHarness.exe`

## Certification Workflow

1. **Prepare**: Ensure RawrXD is running and telemetry is enabled
2. **Run**: Execute certification harness with `--telemetry auto`
3. **Validate**: Harness collects samples and validates against thresholds
4. **Export**: Results written to `evidence/performance/VAL064.json`
5. **Review**: Check certification status and any warnings/errors

## Output Format

```json
{
  "benchmark": "VAL-064-performance",
  "model": "deep2-q4_k_m.gguf",
  "backend": "R9700+7800XT",
  "prompt_tokens": 2048,
  "generated_tokens": 512,
  "prefill_tps": 5000.0,
  "decode_tps": 182.0,
  "first_token_ms": 83.0,
  "peak_vram_mb": 32768.0,
  "peak_ram_mb": 16384.0,
  "certification_status": "PASSED",
  "passed": true,
  "timestamp": "2026-07-30T12:34:56"
}
```

## Status

- [x] Certification scaffold implemented
- [x] Telemetry adapter framework
- [x] File-based telemetry provider
- [x] Shared memory telemetry provider
- [x] Threshold validation
- [ ] RawrXD runtime telemetry export (pending)
- [ ] Live certification execution (pending)

## Next Steps

To complete VAL-064 certification:

1. Implement telemetry export in RawrXD NativeBackend
2. Run certification harness against live system
3. Verify all thresholds are met
4. Archive certification record in `evidence/performance/`
