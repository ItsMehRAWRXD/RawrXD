# Configuration Reference

## Overview

The RawrXD Benchmark Suite supports multiple configuration sources with a well-defined precedence order. This document describes all available configuration options.

## Configuration Precedence

Configuration is loaded in the following order (later sources override earlier):

1. **Default values** - Built-in defaults
2. **Configuration file** - `benchmark.conf` or specified file
3. **Environment variables** - `RAWRXD_BENCHMARK_*`
4. **Command-line arguments** - Highest precedence

## Configuration File

### File Location

The benchmark suite searches for configuration files in this order:

1. Path specified by `--config` argument
2. `./benchmark.conf` (current directory)
3. `~/.rawrxd/benchmark.conf` (user home)
4. `/etc/rawrxd/benchmark.conf` (system-wide)

### File Format

Configuration files use simple `key=value` format:

```ini
# RawrXD Benchmark Configuration
# Lines starting with # are comments

# Backend selection
backend=sovereign

# Model configuration
model_name=phi-3-mini-Q4
max_tokens=512
temperature=0.0

# Benchmark control
warmup_runs=10
measured_runs=50

# Output
output_dir=./reports
verbose=false
```

### Complete Configuration File Example

```ini
# ============================================
# RawrXD Benchmark Suite Configuration
# ============================================

# --------------------------------------------
# Backend Selection
# --------------------------------------------
# Options: sovereign, ollama
backend=sovereign

# --------------------------------------------
# Model Configuration
# --------------------------------------------
model_name=phi-3-mini-Q4
model_path=/path/to/model.gguf
max_tokens=512
temperature=0.0
context_length=4096

# --------------------------------------------
# Swarm Configuration
# --------------------------------------------
swarm_size=16

# --------------------------------------------
# GPU Configuration
# --------------------------------------------
gpu_backend=vulkan
gpu_layers=99
threads=16

# --------------------------------------------
# Ollama Settings
# --------------------------------------------
ollama_url=http://localhost:11434
ollama_model=phi3:mini

# --------------------------------------------
# Sovereign Settings
# --------------------------------------------
sovereign_endpoint=http://localhost:8080
enable_seg=true
enable_learning=true
enable_telemetry=true

# --------------------------------------------
# Benchmark Control
# --------------------------------------------
warmup_runs=10
measured_runs=50
verbose=false
output_dir=./reports

# --------------------------------------------
# HTTP Client Settings
# --------------------------------------------
connect_timeout_ms=5000
read_timeout_ms=30000
total_timeout_ms=60000
max_retries=3
retry_delay_ms=1000
enable_connection_pool=true
max_connections=10

# --------------------------------------------
# Validation Settings
# --------------------------------------------
enable_validation=true
fail_on_validation_error=false

# --------------------------------------------
# Baseline Settings
# --------------------------------------------
enable_baseline=true
baseline_path=./baselines.json
```

## Environment Variables

All configuration options can be set via environment variables with the prefix `RAWRXD_BENCHMARK_`:

| Variable | Description | Example |
|----------|-------------|---------|
| `RAWRXD_BENCHMARK_BACKEND` | Backend type | `sovereign` |
| `RAWRXD_BENCHMARK_ENDPOINT` | Backend endpoint | `http://localhost:8080` |
| `RAWRXD_BENCHMARK_MODEL` | Model name | `phi-3-mini-Q4` |
| `RAWRXD_BENCHMARK_SWARM_SIZE` | Number of agents | `16` |
| `RAWRXD_BENCHMARK_WARMUP_RUNS` | Warmup iterations | `10` |
| `RAWRXD_BENCHMARK_MEASURED_RUNS` | Measured iterations | `50` |
| `RAWRXD_BENCHMARK_OUTPUT_DIR` | Output directory | `./reports` |
| `RAWRXD_BENCHMARK_VERBOSE` | Verbose output | `true` |

### Environment Variable Precedence

```bash
# Set backend via environment
export RAWRXD_BENCHMARK_BACKEND=ollama
export RAWRXD_BENCHMARK_ENDPOINT=http://localhost:11434
export RAWRXD_BENCHMARK_MODEL=phi3:mini

# Run benchmark
./benchmark_runner
```

## Command-Line Arguments

### Basic Usage

```bash
./benchmark_runner [options]
```

### Available Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--backend` | `-b` | Backend type (sovereign, ollama) | `sovereign` |
| `--model` | `-m` | Model name | `phi-3-mini-Q4` |
| `--endpoint` | `-e` | Backend endpoint URL | `http://localhost:8080` |
| `--swarm-size` | `-s` | Number of agents in swarm | `16` |
| `--max-tokens` | `-t` | Maximum tokens to generate | `512` |
| `--temperature` | `-T` | Sampling temperature | `0.0` |
| `--warmup-runs` | `-w` | Number of warmup runs | `10` |
| `--measured-runs` | `-r` | Number of measured runs | `50` |
| `--output-dir` | `-o` | Output directory | `./reports` |
| `--config` | `-c` | Configuration file path | - |
| `--verbose` | `-v` | Enable verbose output | `false` |
| `--help` | `-h` | Show help message | - |

### Examples

```bash
# Basic usage with Sovereign
./benchmark_runner --backend sovereign --model phi-3-mini-Q4

# Use Ollama
./benchmark_runner --backend ollama --endpoint http://localhost:11434 --model phi3:mini

# Custom configuration
./benchmark_runner --backend sovereign --warmup-runs 5 --measured-runs 30 --verbose

# Specify output directory
./benchmark_runner --output-dir ./my_reports --format json

# Load from config file
./benchmark_runner --config ./my_config.conf
```

## Backend-Specific Configuration

### Sovereign Configuration

```cpp
BenchmarkConfig config;
config.backend = BackendType::SOVEREIGN;
config.sovereign_endpoint = "http://localhost:8080";
config.model_name = "phi-3-mini-Q4";
config.enable_seg = true;        // Enable execution graphs
config.enable_learning = true;   // Enable learning features
config.enable_telemetry = true;  // Enable telemetry collection
```

### Ollama Configuration

```cpp
BenchmarkConfig config;
config.backend = BackendType::OLLAMA;
config.ollama_url = "http://localhost:11434";
config.ollama_model = "phi3:mini";
```

### Environment Variables for Backends

```bash
# Sovereign
export RAWRXD_BENCHMARK_BACKEND=sovereign
export RAWRXD_BENCHMARK_ENDPOINT=http://localhost:8080
export RAWRXD_BENCHMARK_MODEL=phi-3-mini-Q4

# Ollama
export RAWRXD_BENCHMARK_BACKEND=ollama
export RAWRXD_BENCHMARK_ENDPOINT=http://localhost:11434
export RAWRXD_BENCHMARK_MODEL=phi3:mini
```

## HTTP Client Configuration

### Connection Settings

```cpp
HttpClient client;
client.Initialize();

// Set timeouts (milliseconds)
client.SetDefaultTimeout(
    5000,   // connect_timeout_ms
    30000,  // read_timeout_ms
    60000   // total_timeout_ms
);

// Set retry policy
client.SetRetryPolicy(
    3,      // max_retries
    1000,   // retry_delay_ms
    true    // exponential_backoff
);

// Enable connection pooling
client.EnableConnectionPool(10);  // max_connections
```

### Environment Variables

```bash
export RAWRXD_BENCHMARK_CONNECT_TIMEOUT_MS=5000
export RAWRXD_BENCHMARK_READ_TIMEOUT_MS=30000
export RAWRXD_BENCHMARK_MAX_RETRIES=3
export RAWRXD_BENCHMARK_ENABLE_POOL=true
export RAWRXD_BENCHMARK_MAX_CONNECTIONS=10
```

## Validation Configuration

### Result Validation

```cpp
BenchmarkConfig config;
config.enable_validation = true;
config.fail_on_validation_error = false;  // Continue on validation errors
```

### Validation Checks

When enabled, the following validations are performed:

- **Success Rate**: Must be ≥ 95%
- **Latency Range**: Must be within category-specific bounds
- **Outlier Detection**: Flags samples > 3 standard deviations
- **Sample Size**: Must have ≥ 30 samples
- **Confidence Interval**: Width must be < 20% of mean
- **Bimodality**: Detects unstable distributions
- **Trend Analysis**: Detects increasing/decreasing trends

## Baseline Configuration

### Baseline Settings

```cpp
BaselineConfig baseline_config;
baseline_config.min_runs = 30;
baseline_config.max_runs = 100;
baseline_config.confidence_level = 0.95;
baseline_config.max_cv = 0.1;  // 10% coefficient of variation
baseline_config.outlier_threshold = 3.0;  // 3 standard deviations
baseline_config.require_stable_consecutive = true;
baseline_config.stable_consecutive_count = 3;
baseline_config.stability_threshold = 0.05;  // 5% relative change
```

### Environment Variables

```bash
export RAWRXD_BENCHMARK_BASELINE_MIN_RUNS=30
export RAWRXD_BENCHMARK_BASELINE_MAX_CV=0.1
export RAWRXD_BENCHMARK_BASELINE_PATH=./baselines.json
```

## Configuration Validation

The benchmark suite validates configuration on startup:

```cpp
std::string error;
if (!ConfigurationManager::Validate(config, error)) {
    std::cerr << "Configuration error: " << error << std::endl;
    return 1;
}
```

### Validation Rules

| Parameter | Min | Max | Notes |
|-------------|-----|-----|-------|
| `swarm_size` | 1 | 1024 | Number of agents |
| `max_tokens` | 1 | 32768 | Tokens per generation |
| `temperature` | 0.0 | 2.0 | Sampling temperature |
| `warmup_runs` | 0 | 100 | Warmup iterations |
| `measured_runs` | 1 | 10000 | Measured iterations |
| `context_length` | 256 | 131072 | Context window size |

## Configuration Merging

When multiple sources provide configuration, they are merged:

```cpp
// Load from file
auto file_config = ConfigurationManager::LoadFromFile("benchmark.conf");

// Load from environment
auto env_config = ConfigurationManager::LoadFromEnvironment();

// Load from args
auto args_config = ConfigurationManager::LoadFromArgs(argc, argv);

// Merge (later overrides earlier)
auto config = ConfigurationManager::Merge(file_config, env_config);
config = ConfigurationManager::Merge(config, args_config);
```

## Complete Example

### Configuration File (`benchmark.conf`)

```ini
# Backend
backend=sovereign
sovereign_endpoint=http://localhost:8080

# Model
model_name=phi-3-mini-Q4
max_tokens=512
temperature=0.0

# Benchmark
warmup_runs=10
measured_runs=50
swarm_size=16

# Output
output_dir=./reports
verbose=true
```

### Environment Setup

```bash
export RAWRXD_BENCHMARK_GPU_LAYERS=99
export RAWRXD_BENCHMARK_THREADS=16
```

### Command Line

```bash
./benchmark_runner --config benchmark.conf --measured-runs 100
```

In this example:
- Backend: `sovereign` (from file)
- Model: `phi-3-mini-Q4` (from file)
- Measured runs: `100` (from command line, overrides file)
- GPU layers: `99` (from environment)
- Threads: `16` (from environment)

## Debugging Configuration

### Print Configuration

```cpp
ConfigurationManager::Print(config);
```

Output:
```
Benchmark Configuration:
  Backend: sovereign
  Model: phi-3-mini-Q4
  Swarm Size: 16
  Context Length: 4096
  Max Tokens: 512
  Temperature: 0
  GPU Backend: vulkan
  GPU Layers: 99
  Threads: 16
  Warmup Runs: 10
  Measured Runs: 50
  Output Directory: ./reports
  Verbose: true
  Sovereign Endpoint: http://localhost:8080
  Enable SEG: true
  Enable Learning: true
  Enable Telemetry: true
```

### Configuration Dump

```cpp
// Save current configuration
ConfigurationManager::SaveToFile(config, "current_config.conf");
```

## See Also

- [HTTP Client API](http_client_api.md)
- [Backend Adapter Guide](backend_adapter_guide.md)
- [Troubleshooting Guide](troubleshooting.md)
- [Benchmark Runner Guide](benchmark_runner_guide.md)
