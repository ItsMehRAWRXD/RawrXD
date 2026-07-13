# RawrXD TPS Benchmark Suite

Comprehensive TPS (Tokens Per Second) benchmarking suite for RawrXD, covering MASM assembly, C++ core, Swarm distributed processing, Chat features, and Agentic/Autonomous operations.

## Overview

This benchmark suite measures token processing throughput across different components of the RawrXD system:

| Benchmark | Description | Target TPS |
|-----------|-------------|------------|
| MASM Hello World | Raw x64 assembly token processing | 100M+ |
| C++ Hello World | Modern C++ STL token processing | 50M+ |
| Swarm TPS | Distributed agent coordination | 100K+ |
| Chat TPS | Message/context processing | 10K+ |
| Agentic TPS | Autonomous task execution | 5K+ |

## Quick Start

### Build All Benchmarks

```powershell
# Using PowerShell
.\run_all_benchmarks.ps1

# Or using batch file
.\build_benchmarks.bat
```

### Run Individual Benchmarks

```powershell
cd build

# Run MASM benchmark
.\masm_hello_world.exe

# Run C++ benchmark
.\cpp_hello_world.exe

# Run Swarm benchmark
.\swarm_tps_benchmark.exe

# Run Chat benchmark
.\chat_tps_benchmark.exe

# Run Agentic benchmark
.\agentic_tps_benchmark.exe
```

## Benchmark Details

### 1. MASM Hello World (`masm_hello_world.asm`)

Pure x64 assembly benchmark measuring raw token processing throughput.

**Features:**
- Direct Windows API calls (no CRT)
- High-precision QueryPerformanceCounter timing
- SIMD-friendly token operations
- Fixed-point arithmetic for TPS calculation

**Build:**
```batch
ml64.exe /c /W3 /nologo /Fo masm_hello_world.obj masm_hello_world.asm
link.exe /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB /LARGEADDRESSAWARE:NO /OUT:masm_hello_world.exe masm_hello_world.obj
```

### 2. C++ Hello World (`cpp_hello_world.cpp`)

Modern C++17 benchmark with STL containers and algorithms.

**Features:**
- Token embedding simulation
- Batch processing
- Memory-efficient lookups
- AVX2 optimizations

**Build:**
```batch
cl.exe /O2 /arch:AVX2 /EHsc /MT /std:c++17 /W3 /Fe:cpp_hello_world.exe cpp_hello_world.cpp
```

### 3. Swarm TPS Benchmark (`swarm_tps_benchmark.cpp`)

Distributed multi-agent token processing benchmark.

**Features:**
- Multi-threaded agent simulation
- Task queue with work distribution
- Consensus voting simulation
- Shard aggregation

**Configuration:**
- `NUM_AGENTS = 8` - Number of concurrent agents
- `TASK_QUEUE_SIZE = 10000` - Task queue depth
- `BENCHMARK_DURATION_SEC = 10` - Benchmark duration

### 4. Chat TPS Benchmark (`chat_tps_benchmark.cpp`)

Chat message processing throughput benchmark.

**Features:**
- Multi-session simulation
- Context management
- Tokenization simulation
- Response generation

**Configuration:**
- `NUM_CHAT_SESSIONS = 16` - Concurrent sessions
- `MESSAGES_PER_SESSION = 1000` - Messages per session
- `MAX_CONTEXT_LENGTH = 4096` - Max context tokens

### 5. Agentic TPS Benchmark (`agentic_tps_benchmark.cpp`)

Autonomous agent task processing benchmark.

**Features:**
- Priority task queue
- Multi-agent coordination
- Task planning simulation
- Subtask generation

**Configuration:**
- `NUM_AGENTS = 8` - Autonomous agents
- `TASKS_PER_AGENT = 5000` - Tasks per agent
- `PLANNING_DEPTH = 5` - Planning recursion depth

## Running the Full Suite

### PowerShell (Recommended)

```powershell
# Build and run all benchmarks
.\run_all_benchmarks.ps1

# Build only
.\run_all_benchmarks.ps1 -BuildOnly

# Run only (skip build)
.\run_all_benchmarks.ps1 -RunOnly

# Run specific benchmark
.\run_all_benchmarks.ps1 -Filter "Swarm"

# Run with multiple iterations
.\run_all_benchmarks.ps1 -Iterations 5
```

### Batch File

```batch
# Build all
build_benchmarks.bat

# Run individually
cd build
for %%f in (*.exe) do %%f
```

## Output Format

Each benchmark outputs:

```
================================================================================
[Benchmark Name] TPS Benchmark
================================================================================

[1/3] Warmup...
  Warmup TPS: [X]

[2/3] Benchmarking...

[3/3] Results:
--------------------------------------------------------------------------------
  Duration:            [X.XX] s
  Total Operations:    [X]
  Total Tokens:        [X]
  TPS:                 [X.XX] tok/s
  ns/op:               [X.XX] ns
  Throughput:          [X.XX] MB/s
--------------------------------------------------------------------------------

Performance Rating:
  [EXCELLENT/VERY GOOD/GOOD/MODERATE/NEEDS OPTIMIZATION]

Benchmark complete.
```

## Results Interpretation

### Performance Ratings

| Rating | MASM/C++ | Swarm | Chat | Agentic |
|--------|----------|-------|------|---------|
| EXCELLENT | >100M TPS | >1M TPS | >100K TPS | >50K TPS |
| VERY GOOD | >10M TPS | >100K TPS | >10K TPS | >10K TPS |
| GOOD | >1M TPS | >10K TPS | >1K TPS | >5K TPS |
| MODERATE | >100K TPS | >1K TPS | >100 TPS | >1K TPS |
| NEEDS OPTIMIZATION | <100K TPS | <1K TPS | <100 TPS | <1K TPS |

### Metrics Explained

- **TPS (Tokens Per Second)**: Primary throughput metric
- **ns/op**: Nanoseconds per operation (lower is better)
- **Throughput**: Data throughput in MB/s
- **Latency**: Average time per operation

## Troubleshooting

### Build Errors

**"ml64.exe not found"**
- Ensure VS2022 Enterprise is installed at `C:\VS2022Enterprise`
- Or modify paths in `build_benchmarks.bat`

**"cl.exe not found"**
- Run from Developer Command Prompt
- Or ensure VS environment is set up

### Runtime Errors

**"Access violation"**
- Check stack alignment in MASM code
- Ensure proper shadow space allocation

**"Low TPS results"**
- Close other applications
- Disable power saving modes
- Run with elevated privileges

## Advanced Usage

### Custom Build Flags

Edit `build_benchmarks.bat` to add custom flags:

```batch
# Enable AVX-512
set "CXXFLAGS=/O2 /arch:AVX512 /EHsc /MT /std:c++17"

# Profile-guided optimization
set "CXXFLAGS=/O2 /arch:AVX2 /EHsc /MT /std:c++17 /favor:INTEL64"
```

### Profiling

```powershell
# Run with Visual Studio profiler
devenv /debugexe build\cpp_hello_world.exe

# Or use Windows Performance Recorder
wpr -start GeneralProfile
.\build\cpp_hello_world.exe
wpr -stop benchmark.etl
```

## Contributing

When adding new benchmarks:

1. Follow the existing code structure
2. Include warmup phase
3. Output consistent metrics
4. Add to `run_all_benchmarks.ps1`
5. Update this README

## License

Part of the RawrXD project. See main project LICENSE.
