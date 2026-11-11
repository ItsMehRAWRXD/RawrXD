# Sovereign vs Ollama Benchmark Suite v2.0

A comprehensive, production-grade benchmark suite comparing **RawrXD Sovereign Runtime** vs **Ollama/llama.cpp** across agentic, autonomous, swarm, and inference performance metrics.

## Overview

This benchmark suite measures the complete agentic execution stack with rigorous methodology for reproducible, defensible performance claims.

```
Prompt
 ↓
Tokenizer
 ↓
Inference Runtime
 ↓
Agent Planner
 ↓
Swarm Coordination (16 agents)
 ↓
Execution Graph (SEG)
 ↓
Decision Loop
 ↓
Self-Correction
 ↓
Final Response
```

## Key Features v2.0

### 🔬 Rigorous Methodology
- **Benchmark Manifests**: Every run captures full system state for reproducibility
- **Hardware Lock**: CPU affinity, GPU isolation, turbo boost disabled
- **Fixed Seeds**: Deterministic runs with seed=42
- **Statistical Rigor**: Mean, median, p95, p99, stddev for all metrics

### 📊 Comprehensive Metrics
- **12 Benchmarks** covering all dimensions
- **Composite Scoring**: SIS, SAI, and category scores
- **Regression Tracking**: SQLite database with trend analysis
- **Machine-Readable Outputs**: JSON, CSV, and SQLite

### 🎯 Fair Comparison
- **Capability Matching**: Reports "Not Supported" vs failed scores
- **Equivalent Workloads**: Same prompts, same models, same hardware
- **Multiple Durations**: 1min, 10min, 60min stability tests

## Benchmarks

### Core Performance (5)

| # | Benchmark | Measures |
|---|-----------|----------|
| 1 | **Inference TPS** | Raw token throughput (prompt + generation) |
| 2 | **Agent Spawn** | Creation, initialization, teardown latency |
| 3 | **Swarm16** | 16-agent parallel task execution |
| 4 | **SEG Execution** | Sovereign Execution Graph efficiency |
| 5 | **Decision Making** | Decision quality under resource pressure |

### Advanced Capabilities (5)

| # | Benchmark | Measures |
|---|-----------|----------|
| 6 | **Self-Correction** | Recovery from injected failures |
| 7 | **Response Quality** | Structure, correctness, depth, coherence |
| 8 | **Context Handling** | 1K-32K token retrieval accuracy |
| 9 | **Autonomous Runtime** | Full Observe→Analyze→Decide→Execute→Learn loop |
| 10 | **Resource Usage** | CPU/GPU/Memory under sustained load |

### Production Readiness (2)

| # | Benchmark | Measures |
|---|-----------|----------|
| 11 | **Long-Duration Stability** | TPS drift, memory growth, degradation over time |
| 12 | **Developer Productivity** | End-to-end: find bug → explain → patch → build → test → PR |

## Quick Start

### Prerequisites

- CMake 3.16+
- C++17 compiler
- libcurl
- SQLite3
- RawrXD Sovereign Runtime on `http://localhost:8080`
- Ollama on `http://localhost:11434`

### Build

```powershell
cd d:\rawrxd\benchmarks\sovereign_vs_ollama
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

### Run Complete Suite

```powershell
# Run all benchmarks on both backends with comparison
.\sovereign_vs_ollama_benchmark.exe --backend both --model phi-3-mini-Q4 --ollama-model phi3:mini

# With regression checking and CSV export
.\sovereign_vs_ollama_benchmark.exe --backend both --check-regressions --export-csv

# Long-duration stability test (60 minutes)
.\sovereign_vs_ollama_benchmark.exe --backend both --stability-minutes 60
```

### Run Individual Benchmarks

```powershell
# Specific benchmark
.\sovereign_vs_ollama_benchmark.exe --backend sovereign --benchmarks inference_tps

# Multiple benchmarks
.\sovereign_vs_ollama_benchmark.exe --backend sovereign --benchmarks "inference_tps,swarm16,developer_productivity"

# Verbose output
.\sovereign_vs_ollama_benchmark.exe --backend sovereign --benchmarks swarm16 --verbose
```

## Command Line Options

```
Options:
  --backend <type>           Backend: sovereign, ollama, both (default: both)
  --model <name>             Model name (default: phi-3-mini-Q4)
  --ollama-model <name>      Ollama model name (default: phi3:mini)
  --swarm-size <n>           Number of agents (default: 16)
  --warmup <n>               Warmup runs (default: 10)
  --runs <n>                 Measured runs (default: 50)
  --stability-minutes <n>    Stability test duration (default: 10)
  --benchmarks <list>        Comma-separated list (default: all)
  --output <path>            Output directory (default: reports)
  --seed <n>                 Random seed (default: 42)
  --temperature <f>        Temperature (default: 0.0)
  --check-regressions      Enable regression checking
  --export-csv             Export results to CSV
  --verbose                Enable verbose output
  --help                   Show help

Benchmarks:
  inference_tps, agent_spawn, swarm16, seg_execution, decision_making,
  self_correction, response_quality, context_handling, autonomous_runtime,
  resource_usage, stability, developer_productivity, all
```

## Output Files

### Reports Directory Structure

```
reports/
├── manifest_sovereign.json          # System configuration
├── manifest_ollama.json
├── orchestrator_result.json         # Aggregated results
├── comparison_report.md             # Side-by-side comparison
├── benchmark_history.csv            # Historical data
├── benchmark_history.db             # SQLite database
├── inference_tps_sovereign.json     # Individual results
├── swarm16_ollama.json
└── ...
```

## Composite Scores

### Sovereign Intelligence Score (SIS)

Weighted composite of all benchmarks:

| Component | Weight | Description |
|-----------|--------|-------------|
| Inference | 15% | Raw token throughput |
| Agent Speed | 15% | Agent lifecycle performance |
| Planning | 15% | Decision and planning quality |
| SEG Efficiency | 15% | Execution graph efficiency |
| Swarm | 15% | Multi-agent coordination |
| Decision | 10% | Decision-making accuracy |
| Recovery | 10% | Self-correction capability |
| Response Quality | 5% | Output quality metrics |

### Sub-Scores

- **Inference Score**: Token throughput and latency
- **Agentic Score**: Agent spawn, swarm, autonomous runtime
- **Orchestration Score**: SEG, swarm coordination, decisions
- **Reliability Score**: Self-correction, context handling, stability
- **Quality Score**: Response structure and correctness
- **Efficiency Score**: Resource utilization per unit work

## Architecture

```
benchmarks/sovereign_vs_ollama/
├── include/
│   ├── benchmark_common.hpp         # Core types and interfaces
│   ├── benchmark_manifest.hpp       # Reproducibility manifests
│   ├── benchmark_orchestrator.hpp   # Execution orchestration
│   ├── results_aggregator.hpp       # Composite scoring
│   ├── regression_tracker.hpp       # Historical tracking
│   └── json_reporter.hpp            # Report generation
├── backends/
│   ├── sovereign_adapter.hpp        # RawrXD Sovereign adapter
│   ├── ollama_adapter.hpp           # Ollama adapter
│   └── backend_factory.hpp          # Adapter factory
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
│   ├── resource_usage_benchmark.hpp
│   ├── stability_benchmark.hpp
│   └── developer_productivity_benchmark.hpp
├── reports/                          # Generated reports
├── CMakeLists.txt
├── benchmark_suite_v2.cpp            # Main runner
├── run_comparison.ps1                # PowerShell automation
└── README.md
```

## License

MIT License - See LICENSE file

## Contact

RawrXD Team - benchmarks@rawrxd.dev
