# RawrXD Benchmark Suite — Phase D.5 Refined

A comprehensive benchmark suite featuring a **4-tier structure** with statistical rigor, fair comparisons, and comprehensive CI integration.

> **Version**: 2.1.0 (Phase D.5 Refined)  
> **Previous**: v1.0/v2.0 (see legacy documentation)

## Overview

This benchmark suite provides rigorous, repeatable, publishable evidence of performance across four distinct tiers:

```
┌─────────────────────────────────────────────────────────────┐
│  TIER 1: Runtime Performance (Apples-to-Apples)            │
│  → Inference TPS, latency, context scaling                  │
├─────────────────────────────────────────────────────────────┤
│  TIER 2: Agentic Capability (Comparable Features)          │
│  → Planning, tool use, structured output, code gen          │
├─────────────────────────────────────────────────────────────┤
│  TIER 3: Sovereign-Only Features (Self-Contained)          │
│  → SEG, rollback, swarm, recovery, oscillation            │
├─────────────────────────────────────────────────────────────┤
│  TIER 4: Long-Term Reliability (Soak Tests)                │
│  → Memory growth, TPS drift, MTBF, determinism            │
└─────────────────────────────────────────────────────────────┘
                    ↓
         Developer Workflow Benchmark
         (End-to-end IDE tasks)
```

## What's New in Phase D.5 Refined

### 4-Tier Structure
- **Tier 1**: Fair apples-to-apples comparisons where both systems solve the same problem
- **Tier 2**: Comparable agentic capabilities (planning, tools, structured output)
- **Tier 3**: Self-contained demonstrations of Sovereign-unique features
- **Tier 4**: Extended soak tests for stability validation

### Statistical Rigor
- **Warmup protocol**: 5 runs discarded, 30 runs measured
- **Fixed random seed**: 42 (reproducibility)
- **Temperature**: 0 (deterministic)
- **Confidence intervals**: 95% CI reported for all metrics
- **Significance testing**: CI overlap, 2× SE rule

### Developer Workflow Benchmark
End-to-end tasks mirroring real IDE usage:
1. Explain repository
2. Locate bug
3. Generate patch
4. Compile code
5. Run tests
6. Produce summary

### CI Integration
- Automated regression detection on every PR
- Configurable thresholds (20% critical, 10% warning)
- PR comments with comparison tables and trend sparklines
- Automatic baseline updates on main branch

## Quick Start

### Build

```bash
cd d:\rawrxd\benchmarks\sovereign_vs_ollama
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### Run Benchmarks

```bash
# Run complete benchmark suite
./benchmark_runner --full

# Run specific tier
./benchmark_runner --tier 1  # Runtime Performance
./benchmark_runner --tier 2  # Agentic Capability
./benchmark_runner --tier 3  # Sovereign Features
./benchmark_runner --tier 4  # Long-Term Reliability

# Run developer workflow benchmark
./benchmark_runner --workflow

# Run soak test (1 hour)
./benchmark_runner --tier4 --soak-duration 3600
```

### Compare Against Baseline

```bash
# Compare current results against baseline
./benchmark_runner --compare \
    --baseline baseline.json \
    --current results.json \
    --critical-threshold 0.20 \
    --warning-threshold 0.10
```

### Generate Dashboard

```bash
# Generate HTML qualification dashboard
./benchmark_runner --generate-dashboard \
    --tier1-input tier1_results.json \
    --tier2-input tier2_results.json \
    --tier3-input tier3_results.json \
    --tier4-input tier4_results.json \
    --workflow-input workflow_results.json \
    --output qualification_dashboard.html
```

## Legacy Benchmarks (v1.0/v2.0)

The original benchmark suite is still available:

### Batch 1: Core Performance

1. **Inference TPS** - Raw token throughput (prompt processing + generation)
2. **Agent Spawn** - Agent creation, initialization, and teardown performance
3. **Swarm16** - 16-agent parallel task execution
4. **SEG Execution** - Sovereign Execution Graph creation and execution
5. **Decision Making** - Decision quality and speed under various scenarios

### Batch 2: Advanced Capabilities

6. **Self-Correction** - Recovery from injected failures
7. **Response Quality** - Structure, correctness, depth, coherence, actionability
8. **Context Handling** - Long-context retrieval accuracy (1K-32K tokens)
9. **Autonomous Runtime** - Full autonomous execution loop
10. **Resource Usage** - CPU/GPU/Memory usage under sustained load

## Statistical Rigor

All benchmarks follow strict statistical protocols:

- **Warmup runs:** 5 (discarded)
- **Measured runs:** 30 (used for statistics)
- **Random seed:** 42 (fixed for reproducibility)
- **Temperature:** 0 (deterministic)
- **Confidence intervals:** 95% CI reported for all metrics

Example output:
```
Decode TPS: 125.4 tok/s (±2.3 95% CI)
TTFT: 45.2 ms (±0.8 95% CI)
```

## CI Integration

The GitHub Actions workflow (`.github/workflows/performance-regression.yml`) automatically:

1. Builds the benchmark suite
2. Runs all tiers against baseline
3. Detects regressions with configurable thresholds
4. Posts results as PR comments
5. Updates baseline on main branch merges

### Regression Thresholds

| Severity | Threshold | Action |
|----------|-----------|--------|
| Critical | ≥20% regression | ❌ Block merge |
| Warning | ≥10% regression | ⚠️ Notify |
| Improvement | ≥10% improvement | 🎉 Celebrate |

## Legacy Quick Start

### Prerequisites

- CMake 3.16+
- C++17 compiler
- libcurl
- RawrXD Sovereign Runtime running on `http://localhost:8080`
- Ollama running on `http://localhost:11434`

### Build

```powershell
cd d:\rawrxd\benchmarks\sovereign_vs_ollama
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

### Run Benchmarks

```powershell
# Run all benchmarks against Sovereign
.\sovereign_vs_ollama_benchmark.exe --backend sovereign --model phi-3-mini-Q4

# Run all benchmarks against Ollama
.\sovereign_vs_ollama_benchmark.exe --backend ollama --model phi3:mini

# Run specific benchmark
.\sovereign_vs_ollama_benchmark.exe --backend sovereign --benchmark inference_tps

# Verbose output
.\sovereign_vs_ollama_benchmark.exe --backend sovereign --verbose

# Custom runs
.\sovereign_vs_ollama_benchmark.exe --backend sovereign --runs 100 --warmup 20
```

### Automated Comparison Script

```powershell
# Run comparison script
.\run_comparison.ps1
```

This will:
1. Run all benchmarks against Sovereign
2. Run all benchmarks against Ollama
3. Generate comparative report

## Command Line Options

```
Options:
  --backend <type>       Backend to test: sovereign, ollama (default: sovereign)
  --model <name>         Model name (default: phi-3-mini-Q4)
  --swarm-size <n>       Number of agents in swarm (default: 16)
  --warmup <n>           Warmup runs (default: 10)
  --runs <n>             Measured runs (default: 50)
  --benchmark <name>     Run specific benchmark (default: all)
  --output <path>        Output directory for reports (default: reports)
  --verbose              Enable verbose output
  --help                 Show help message

Benchmarks:
  inference_tps          Raw inference token throughput
  agent_spawn            Agent creation and teardown performance
  swarm16                16-agent parallel task execution
  seg_execution          Sovereign Execution Graph performance
  decision_making        Decision quality and speed
  self_correction        Recovery from injected failures
  response_quality       Response structure and quality
  context_handling       Long-context retrieval accuracy
  autonomous_runtime     Full autonomous execution loop
  resource_usage         CPU/GPU/Memory usage under load
  all                    Run all benchmarks (default)
```

## Output

### JSON Report

```json
{
  "benchmark_id": "inference_tps_sovereign",
  "benchmark_name": "Inference TPS",
  "category": "inference",
  "backend": "sovereign",
  "timestamp": "2026-07-13 10:30:00",
  "latency": {
    "mean_ms": 245.5,
    "p95_ms": 312.3,
    "p99_ms": 389.1
  },
  "throughput": {
    "mean_tps": 89.4,
    "p95_tps": 102.1
  },
  "success_rate": 0.98,
  "quality": {
    "overall_score": 78.5
  },
  "resources": {
    "cpu_percent": 45.2,
    "memory_mb": 2048.0,
    "vram_mb": 6144.0
  }
}
```

### Markdown Report

```markdown
# Sovereign vs Ollama Agentic Benchmark Report

## Inference
| Backend | Mean TPS | P95 Latency | Success Rate | Quality Score |
|---------|----------|-------------|--------------|---------------|
| sovereign | 89.4 | 312.3 ms | 98% | 78.5 |
| ollama | 82.1 | 345.7 ms | 95% | 72.3 |

## Sovereign Intelligence Score (SIS)
| Component | Weight | Sovereign | Ollama | Delta |
|-----------|--------|-----------|--------|-------|
| Inference | 15% | 85.0 | 75.0 | +10.0 |
| ...

Overall SIS:
- Sovereign: 91.8
- Ollama: 62.4
- Advantage: +47%
```

## Hardware Requirements

- **CPU**: Modern multi-core processor (16+ threads recommended)
- **RAM**: 32GB+ recommended for large models
- **GPU**: Optional but recommended (Vulkan/CUDA/Metal)
- **Storage**: 10GB+ for models and logs

## Model Recommendations

| Model | Size | Use Case |
|-------|------|----------|
| phi-3-mini | 3.8B | Fast testing |
| llama-3.1-8B | 8B | Balanced |
| llama-3.1-70B | 70B | Production |

## Architecture

```
benchmarks/sovereign_vs_ollama/
├── include/
│   ├── benchmark_common.hpp      # Core types and interfaces
│   └── json_reporter.hpp         # JSON/Markdown reporting
├── backends/
│   ├── sovereign_adapter.hpp     # RawrXD Sovereign adapter
│   ├── ollama_adapter.hpp      # Ollama adapter
│   └── backend_factory.hpp     # Adapter factory
├── src/
│   ├── inference_tps_benchmark.hpp
│   ├── agent_spawn_benchmark.hpp
│   ├── swarm16_benchmark.hpp
│   ├── seg_execution_benchmark.hpp
│   ├── decision_making_benchmark.hpp
│   ├── self_correction_benchmark.hpp
│   ├── response_quality_benchmark.hpp
│   ├── context_handling_benchmark.hpp
│   ├── autonomous_runtime_benchmark.hpp
│   └── resource_usage_benchmark.hpp
├── reports/                       # Generated reports
├── CMakeLists.txt
└── README.md
```

## Phase D.5 Refined Files

```
benchmarks/sovereign_vs_ollama/
├── include/
│   ├── benchmark_common.hpp          # Core types (legacy)
│   ├── json_reporter.hpp             # Reporting (legacy)
│   └── benchmark_tiers.hpp           # NEW: 4-tier structures + statistics
├── src/
│   ├── main.cpp                      # NEW: Entry point for refined runner
│   ├── benchmark_tiers.cpp           # NEW: 4-tier implementation
│   └── ci_regression_checker.cpp     # NEW: CI integration
├── backends/                         # Legacy adapters
├── reports/                          # Generated reports
├── CMakeLists.txt                    # Updated for v2.1
├── README.md                         # This file
└── .github/workflows/
    └── performance-regression.yml    # NEW: CI workflow
```

## Documentation

- `PHASE_D5_REFINED_BENCHMARK_SPEC.md` — Complete refined specification
- `PHASE_D5_VERIFICATION_PERFORMANCE.md` — Original D.5 documentation

## Contributing

1. Add new benchmarks in `src/`
2. Follow existing patterns
3. Update this README
4. Submit PR

## License

Copyright (c) 2026 RawrXD Team

## License

MIT License - See LICENSE file

## Contact

RawrXD Team - benchmarks@rawrxd.dev
