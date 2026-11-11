# RawrXD Standardized Benchmark Harness

## Overview

A reproducible, consistent benchmark suite for measuring RawrXD inference performance with per-component profiling.

## Features

- **Reproducible**: Fixed random seed, consistent sampling parameters
- **Comprehensive**: Measures tokens/sec, latency, memory, per-component timing
- **Statistical**: Multiple iterations with min/max/stddev
- **Exportable**: JSON and console output formats
- **Comparable**: Baseline comparison tools

## Usage

### Quick Benchmark

```bash
cd d:\src\benchmark
run_standardized_benchmark.exe d:\rawrxd\src\codestral22b.gguf --quick
```

### Full Benchmark

```bash
run_standardized_benchmark.exe d:\rawrxd\src\codestral22b.gguf \
    --tokens 100 \
    --iterations 10 \
    --warmup 3 \
    --temperature 1.0 \
    --top-k 40 \
    --seed 42 \
    --output results.json
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--prompt` | Input prompt text | "The quick brown fox..." |
| `--tokens` | Tokens to generate | 100 |
| `--iterations` | Benchmark iterations | 10 |
| `--warmup` | Warmup iterations | 3 |
| `--temperature` | Sampling temperature | 1.0 |
| `--top-k` | Top-k sampling | 40 |
| `--seed` | Random seed | 42 |
| `--output` | Output file | benchmark_results.json |
| `--format` | Output format (json/console) | json |
| `--quick` | Quick mode (5 iter, 50 tokens) | - |

## Output Format

### JSON Output

```json
{
  "timestamp": "2026-07-09 14:30:00",
  "passed": true,
  "system_info": {
    "cpu_cores": 16,
    "cpu_threads": 32,
    "has_avx2": true,
    "has_avx512": true,
    "total_memory_gb": 128
  },
  "model_info": {
    "path": "d:\\rawrxd\\src\\codestral22b.gguf",
    "file_size_gb": 11.8,
    "vocab_size": 32064,
    "hidden_size": 4096,
    "num_layers": 40,
    "num_heads": 32
  },
  "overall": {
    "tokens_per_second": 31.5,
    "time_to_first_token_ms": 45.2,
    "avg_latency_per_token_ms": 31.7,
    "total_time_ms": 3174.6,
    "tokens_generated": 100,
    "tps_min": 29.8,
    "tps_max": 33.2,
    "tps_stddev": 1.1
  },
  "component_timings": [
    {"name": "embedding", "total_ms": 150.2, "mean_ms": 1.5, "percentage": 4.7},
    {"name": "attention", "total_ms": 1800.5, "mean_ms": 18.0, "percentage": 56.7},
    {"name": "mlp", "total_ms": 1100.3, "mean_ms": 11.0, "percentage": 34.7},
    {"name": "sampling", "total_ms": 123.6, "mean_ms": 1.2, "percentage": 3.9}
  ]
}
```

### Console Output

```
========================================
RawrXD Standardized Benchmark Report
========================================

Timestamp: 2026-07-09 14:30:00
Status: PASSED

System Information:
  CPU Cores: 16
  CPU Threads: 32
  AVX2: Yes
  AVX-512: Yes
  Total Memory: 128 GB

Model Information:
  Path: d:\rawrxd\src\codestral22b.gguf
  File Size: 11.8 GB
  Vocab Size: 32064
  Hidden Size: 4096
  Layers: 40
  Heads: 32

Performance Metrics:
  Tokens/sec: 31.50
  Time to first token: 45.20 ms
  Avg latency/token: 31.70 ms
  Total time: 3174.60 ms
  Tokens generated: 100

Statistical Analysis:
  TPS min: 29.80
  TPS max: 33.20
  TPS stddev: 1.10

Component Breakdown:
  embedding          150.20 ms (4.7%)
  attention         1800.50 ms (56.7%)
  mlp               1100.30 ms (34.7%)
  sampling           123.60 ms (3.9%)

========================================
```

## Per-Component Profiling

The benchmark automatically profiles:

1. **Embedding Lookup** - Token to embedding conversion
2. **Attention** - Q/K/V projection, attention scores, softmax
3. **MLP** - Gate, up, down projections with SiLU
4. **Sampling** - Temperature scaling, top-k selection
5. **Model Load** - Time to load weights from disk

## Comparison Tool

Compare two benchmark runs:

```cpp
auto baseline = QuickBenchmark("model_baseline.gguf");
auto current = QuickBenchmark("model_current.gguf");
auto comparison = CompareBenchmarks(baseline, current);

// Output:
// TPS change: +15.3%
// Latency change: -12.1%
// Winner: current
```

## Files

- `standardized_benchmark.hpp/cpp` - Core benchmark implementation
- `run_standardized_benchmark.cpp` - Command-line runner
- `build_benchmark.bat` - Build script

## Build

```bash
cd d:\src\benchmark
build_benchmark.bat
```

## Requirements

- C++17 compiler
- RawrXD inference library
- Windows (for memory profiling)

---

*Created: 2026-07-09*  
*Status: Ready for use*
