# RawrXD Validation Harness

C++ components for the RawrXD Production Validation Framework.

## Components

| File | Purpose | Output |
|------|---------|--------|
| `ValidationHarness.cpp` | Full validation suite | boot.log, gateway.log, inference_trace.json |
| `HardwareValidator.cpp` | GPU detection | hardware_report.json |
| `RealInferenceBenchmark.cpp` | Live inference testing | benchmark_results.json |
| `TelemetryCollector.cpp` | Real-time GPU monitoring | telemetry_report.json |

## Building

### Option 1: Visual Studio (Recommended)

```cmd
cd d:\RawrXD\validation\harness
build.bat
```

### Option 2: CMake

```cmd
cd d:\RawrXD\validation\harness
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### Option 3: MinGW

```cmd
cd d:\RawrXD\validation\harness
mkdir build && cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
mingw32-make
```

## Usage

### ValidationHarness.exe

Full validation suite that tests boot sequence, gateway endpoints, and generates telemetry.

```cmd
ValidationHarness.exe [options]

Options:
  --output-dir PATH    Output directory for artifacts (default: validation_output)
  --target URL         Target RawrXD URL (default: http://127.0.0.1:8080)
  --iterations N       Number of inference iterations (default: 100)
  --verbose            Enable verbose output

Example:
  ValidationHarness.exe --output-dir output --target http://127.0.0.1:8080 --iterations 100
```

### HardwareValidator.exe

Detects and validates GPU configuration.

```cmd
HardwareValidator.exe [output_file]

Example:
  HardwareValidator.exe hardware_report.json
```

Checks for:
- Radeon AI PRO R9700 (32GB)
- RX 7800 XT (16GB)
- Multi-GPU readiness

Exit codes:
- 0: Multi-GPU ready (both GPUs detected)
- 1: Single GPU or no GPUs detected

### RealInferenceBenchmark.exe

Benchmarks live inference performance.

```cmd
RealInferenceBenchmark.exe [options]

Options:
  --host HOST          Target host (default: 127.0.0.1)
  --port PORT          Target port (default: 8080)
  --model NAME         Model name (default: BigDaddyG-UNLEASHED-Q4_K_M)
  --runs N             Benchmark runs (default: 50)
  --warmup N           Warmup runs (default: 5)
  --output FILE        Output file (default: benchmark_results.json)
  --no-streaming       Disable streaming mode
  --verbose            Enable verbose output

Example:
  RealInferenceBenchmark.exe --host 127.0.0.1 --port 8080 --runs 100 --output results.json
```

### TelemetryCollector.exe

Collects real-time GPU telemetry.

```cmd
TelemetryCollector.exe [options]

Options:
  --duration SECONDS   Collection duration (default: 60)
  --interval MS        Sample interval in ms (default: 1000)
  --output FILE        Output file (default: telemetry_report.json)

Example:
  TelemetryCollector.exe --duration 120 --interval 500 --output gpu_telemetry.json
```

## Output Formats

### hardware_report.json

```json
{
  "timestamp": "2026-07-30 14:30:00",
  "r9700_detected": true,
  "rx7800xt_detected": true,
  "multi_gpu_ready": true,
  "gpu_count": 2,
  "gpus": [
    {
      "name": "AMD Radeon AI PRO R9700",
      "device_id": "PCI\\VEN_1002\u0026DEV_744C",
      "driver_version": "31.0.14001.0",
      "adapter_ram_gb": 32,
      "is_r9700": true,
      "is_rx7800xt": false
    }
  ]
}
```

### benchmark_results.json

```json
{
  "config": {
    "target": "127.0.0.1:8080",
    "model": "BigDaddyG-UNLEASHED-Q4_K_M",
    "streaming": true,
    "benchmark_runs": 50
  },
  "summary": {
    "total_runs": 50,
    "successful_runs": 48,
    "failed_runs": 2,
    "success_rate": 0.96
  },
  "performance": {
    "avg_tps": 118.5,
    "min_tps": 95.2,
    "max_tps": 142.8,
    "avg_latency_ms": 380.2,
    "avg_ttft_ms": 115.7
  },
  "certification": {
    "tps_target": 100,
    "tps_passed": true,
    "latency_target_ms": 5000,
    "latency_passed": true,
    "ttft_target_ms": 250,
    "ttft_passed": true
  }
}
```

### telemetry_report.json

```json
{
  "gpu_telemetry": {
    "timestamp": "2026-07-30 14:30:00",
    "sample_count": 60,
    "averages": {
      "gpu_utilization": 78.5,
      "memory_utilization": 65.2,
      "temperature": 72.3,
      "power_draw": 215.4,
      "vram_used_mb": 18432
    }
  },
  "inference_telemetry": {
    "total_requests": 45,
    "statistics": {
      "avg_tps": 118.5,
      "min_tps": 95.2,
      "max_tps": 142.8,
      "avg_latency_ms": 380.2,
      "avg_ttft_ms": 115.7
    },
    "gpu_breakdown": {
      "GPU0": { "request_count": 28, "avg_tps": 125.3 },
      "GPU1": { "request_count": 17, "avg_tps": 108.2 }
    }
  }
}
```

## Certification Targets

| Metric | Target | Description |
|--------|--------|-------------|
| Boot Time | < 5000ms | IDE startup time |
| TPS | ≥ 100 | Tokens per second |
| Latency | < 5000ms | Request latency |
| TTFT | < 250ms | Time to first token |
| Success Rate | ≥ 95% | Request success rate |
| GPU Temp | < 85°C | Maximum GPU temperature |

## Dependencies

- Windows SDK 10.0.22000 or later
- Visual Studio 2022 (or MinGW/Clang)
- nlohmann/json (header-only, included)

## Troubleshooting

### Build Errors

**"nlohmann/json not found"**
```
Ensure 3rdparty/json/include/nlohmann/json.hpp exists
```

**"Unresolved external symbol"**
```
Make sure you're linking against ws2_32.lib and pdh.lib
```

### Runtime Errors

**"Failed to connect"**
- Verify RawrXD is running on the target URL
- Check firewall settings
- Try different port

**"No GPUs detected"**
- Run as Administrator
- Check AMD drivers are installed
- Verify GPUs in Device Manager

**"WMI query failed"**
- Ensure WMI service is running
- Run as Administrator
- Check Windows Management Instrumentation service

## Development

### Adding New Tests

1. Create new .cpp file in harness directory
2. Add to CMakeLists.txt
3. Update build.bat
4. Add to Validate-Production.ps1

### Code Style

- Use C++17 features
- Follow existing naming conventions
- Add comments for complex logic
- Use RAII for resource management

## License

Part of the RawrXD project. See main LICENSE file.
