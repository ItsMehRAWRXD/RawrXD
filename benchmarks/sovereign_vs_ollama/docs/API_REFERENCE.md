# API Reference

Complete API documentation for the RawrXD Benchmark Suite.

## Table of Contents

- [C++ API](#c-api)
  - [BenchmarkBase](#benchmarkbase)
  - [StatisticalSummary](#statisticalsummary)
  - [Backend Adapters](#backend-adapters)
- [CLI Reference](#cli-reference)
- [Python Scripts](#python-scripts)
- [Configuration Schema](#configuration-schema)

## C++ API

### BenchmarkBase

Base class for all benchmarks.

```cpp
#include "benchmark_tiers.hpp"

namespace Benchmark {

class BenchmarkBase {
public:
    explicit BenchmarkBase(const std::string& name);
    virtual ~BenchmarkBase() = default;
    
    // Main entry point
    virtual void Run() = 0;
    
    // Configuration
    void SetIterations(int warmup, int measured);
    void SetSeed(int seed);
    void SetTimeout(int seconds);
    
    // Results
    StatisticalSummary GetResults() const;
    bool WasSuccessful() const;
    
protected:
    // Utility methods
    StatisticalSummary CalculateStatistics(const std::vector<double>& samples);
    void ReportProgress(int current, int total);
};

} // namespace Benchmark
```

#### Example: Custom Benchmark

```cpp
#include "benchmark_tiers.hpp"
#include <iostream>

namespace Benchmark {

class MyCustomBenchmark : public BenchmarkBase {
public:
    MyCustomBenchmark() : BenchmarkBase("my_custom") {}
    
    void Run() override {
        std::vector<double> samples;
        
        // Warmup
        for (int i = 0; i < 5; ++i) {
            RunIteration();
        }
        
        // Measured runs
        for (int i = 0; i < 30; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            RunIteration();
            auto end = std::chrono::high_resolution_clock::now();
            
            double ms = std::chrono::duration<double, std::milli>(end - start).count();
            samples.push_back(ms);
            
            ReportProgress(i + 1, 30);
        }
        
        results_ = CalculateStatistics(samples);
    }
    
private:
    void RunIteration() {
        // Your benchmark logic here
    }
    
    StatisticalSummary results_;
};

} // namespace Benchmark
```

### StatisticalSummary

Container for statistical results.

```cpp
struct StatisticalSummary {
    uint32_t sample_count = 0;
    
    // Central tendency
    double mean = 0.0;
    double median = 0.0;
    
    // Dispersion
    double std_dev = 0.0;
    double min = 0.0;
    double max = 0.0;
    
    // Percentiles
    double p95 = 0.0;
    double p99 = 0.0;
    
    // Confidence interval (95%)
    double ci_half_width = 0.0;
    
    // Helper methods
    double GetCIUpper() const { return mean + ci_half_width; }
    double GetCILower() const { return mean - ci_half_width; }
    bool IsSignificant(double threshold_percent) const;
};
```

### Backend Adapters

#### SovereignAdapter

```cpp
namespace Backends {

class SovereignAdapter {
public:
    explicit SovereignAdapter(const std::string& base_url = "http://localhost:8080");
    
    // Connection
    bool IsAvailable() const;
    bool HealthCheck() const;
    
    // Inference
    InferenceResult RunInference(const InferenceRequest& request);
    
    // Streaming
    void RunInferenceStreaming(const InferenceRequest& request, 
                               std::function<void(const InferenceResult&)> callback);
    
    // Batch
    std::vector<InferenceResult> RunBatchInference(
        const std::vector<InferenceRequest>& requests);
};

struct InferenceRequest {
    std::string model;
    std::string prompt;
    int max_tokens = 256;
    float temperature = 0.0f;
    int seed = 42;
    std::optional<std::string> system_prompt;
    std::optional<std::map<std::string, std::string>> extra_params;
};

struct InferenceResult {
    bool success = false;
    std::string response;
    int tokens_generated = 0;
    double total_latency_ms = 0.0;
    double tokens_per_second = 0.0;
    double ttft_ms = 0.0;  // Time to first token
    std::optional<std::string> error_message;
};

} // namespace Backends
```

#### OllamaAdapter

```cpp
namespace Backends {

class OllamaAdapter {
public:
    explicit OllamaAdapter(const std::string& base_url = "http://localhost:11434");
    
    bool IsAvailable() const;
    std::vector<std::string> ListModels() const;
    InferenceResult RunInference(const InferenceRequest& request);
};

} // namespace Backends
```

## CLI Reference

### benchmark_runner

```
Usage: benchmark_runner [OPTIONS]

Options:
  --help, -h                  Show help message
  --version, -v               Show version information
  
Backend Options:
  --backend BACKEND           Backend to test (sovereign|ollama) [default: sovereign]
  --backend-url URL           Custom backend URL
  
Benchmark Selection:
  --tier TIER                 Run benchmarks from tier (can be repeated)
                              tier1, tier2, tier3, tier4, workflow, stress, all
  --benchmark NAME            Run specific benchmark (can be repeated)
  --exclude NAME              Exclude specific benchmark
  
Execution Options:
  --iterations N              Number of measured iterations [default: 30]
  --warmup N                  Number of warmup iterations [default: 5]
  --seed N                    Random seed [default: 42]
  --timeout SECONDS           Timeout per benchmark [default: 3600]
  --parallel                  Run benchmarks in parallel
  --workers N                 Number of parallel workers [default: 4]
  
Output Options:
  --format FORMAT             Output format (json|html|markdown|console) [default: console]
  --output FILE               Output file path
  --verbose                   Enable verbose output
  --quiet                     Suppress non-error output
  
Configuration:
  --profile FILE              Load workload profile from JSON file
  --save-profile FILE         Save current configuration to profile
  
Comparison:
  --compare FILE              Compare against baseline results
  --threshold PERCENT         Regression threshold percentage [default: 10.0]
  --fail-on-regression        Exit with error code if regression detected
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Benchmark failed |
| 2 | Threshold violation |
| 3 | Regression detected |
| 4 | Configuration error |
| 5 | Timeout |

## Python Scripts

### check_regression.py

```python
"""
Check benchmark results for performance regressions.
"""

from check_regression import RegressionChecker, MetricThreshold

# Create checker with custom thresholds
checker = RegressionChecker([
    MetricThreshold("latency_ms", "lower_is_better", 10.0, 20.0),
    MetricThreshold("throughput_tps", "higher_is_better", -10.0, -20.0),
])

# Load results
current = checker.load_results("results/current.json")
baseline = checker.load_results("results/baseline.json")

# Check for regressions
report = checker.check_all(current, baseline)

# Print report
checker.print_report(report, verbose=True)
```

### run_benchmarks.py

```python
"""
Automated benchmark execution.
"""

from run_benchmarks import BenchmarkRunner

config = {
    'mode': 'standard',
    'backend': 'sovereign',
    'backend_url': 'http://localhost:8080',
    'tiers': ['tier1', 'tier2'],
    'parallel': True,
    'workers': 4,
    'notify': ['slack', 'discord'],
}

runner = BenchmarkRunner(config)
exit_code = runner.run()
```

## Configuration Schema

### Workload Profile JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["name", "benchmarks"],
  "properties": {
    "name": {
      "type": "string",
      "description": "Profile name"
    },
    "description": {
      "type": "string",
      "description": "Profile description"
    },
    "version": {
      "type": "string",
      "pattern": "^\\d+\\.\\d+\\.\\d+$",
      "description": "Semantic version"
    },
    "benchmarks": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["benchmark_name"],
        "properties": {
          "benchmark_name": {
            "type": "string",
            "enum": [
              "inference_tps",
              "context_scaling",
              "concurrent_load",
              "latency_percentiles",
              "resource_monitoring",
              "planning_task",
              "tool_use",
              "seg_mutation",
              "swarm_coordination",
              "autonomous_recovery",
              "memory_leak",
              "performance_drift",
              "determinism",
              "workflow_explain_repo",
              "workflow_bug_fix",
              "stress_overload",
              "chaos_fault_injection",
              "degradation_curve",
              "resource_pressure",
              "mutation_storm",
              "swarm_overload"
            ]
          },
          "iterations": {
            "type": "integer",
            "minimum": 1,
            "default": 30
          },
          "warmup_iterations": {
            "type": "integer",
            "minimum": 0,
            "default": 5
          },
          "timeout_seconds": {
            "type": "number",
            "minimum": 1,
            "default": 300
          },
          "enabled": {
            "type": "boolean",
            "default": true
          },
          "parameters": {
            "type": "object",
            "additionalProperties": {
              "type": "string"
            }
          }
        }
      }
    },
    "environment": {
      "type": "object",
      "properties": {
        "backend_url": {
          "type": "string",
          "format": "uri"
        },
        "model_name": {
          "type": "string"
        },
        "env_vars": {
          "type": "object",
          "additionalProperties": {
            "type": "string"
          }
        }
      }
    },
    "thresholds": {
      "type": "object",
      "properties": {
        "max_latency_ms": {
          "type": "number",
          "minimum": 0
        },
        "min_throughput_tps": {
          "type": "number",
          "minimum": 0
        },
        "max_error_rate": {
          "type": "number",
          "minimum": 0,
          "maximum": 1
        },
        "max_regression_percent": {
          "type": "number",
          "minimum": 0
        }
      }
    }
  }
}
```

### Example Profile

```json
{
  "name": "ci_smoke_test",
  "description": "Quick smoke test for CI pipeline",
  "version": "1.0.0",
  "benchmarks": [
    {
      "benchmark_name": "inference_tps",
      "iterations": 10,
      "warmup_iterations": 2,
      "timeout_seconds": 60,
      "parameters": {
        "model": "phi-4",
        "max_tokens": "128",
        "prompt": "Explain quantum computing"
      }
    },
    {
      "benchmark_name": "determinism",
      "iterations": 20,
      "enabled": true
    }
  ],
  "environment": {
    "backend_url": "http://localhost:8080",
    "model_name": "phi-4"
  },
  "thresholds": {
    "max_latency_ms": 2000,
    "min_throughput_tps": 10,
    "max_error_rate": 0.05
  }
}
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BENCHMARK_BACKEND` | Backend type | `sovereign` |
| `BENCHMARK_BACKEND_URL` | Backend URL | `http://localhost:8080` |
| `BENCHMARK_RESULTS_DIR` | Results output directory | `./results` |
| `BENCHMARK_TIMEOUT` | Global timeout (seconds) | `3600` |
| `BENCHMARK_VERBOSE` | Enable verbose output | `false` |
| `SLACK_WEBHOOK_URL` | Slack notification webhook | - |
| `DISCORD_WEBHOOK_URL` | Discord notification webhook | - |
| `AWS_ACCESS_KEY_ID` | S3 upload credentials | - |
| `BENCHMARK_S3_BUCKET` | S3 results bucket | - |

## HTTP API

### Results Database API

```bash
# Store result
curl -X POST http://localhost:8080/api/results \
  -H "Content-Type: application/json" \
  -d '{
    "benchmark": "inference_tps",
    "backend": "sovereign",
    "metrics": {
      "mean_latency_ms": 125.5,
      "throughput_tps": 45.2
    }
  }'

# Query results
curl "http://localhost:8080/api/results?benchmark=inference_tps&limit=100"

# Get trends
curl "http://localhost:8080/api/trends?days=7"
```

## TypeScript Definitions

For JavaScript/TypeScript integration:

```typescript
// types/benchmark.d.ts

interface StatisticalSummary {
  sample_count: number;
  mean: number;
  median: number;
  std_dev: number;
  min: number;
  max: number;
  p95: number;
  p99: number;
  ci_half_width: number;
}

interface BenchmarkResult {
  name: string;
  tier: string;
  success: boolean;
  latency_ms: StatisticalSummary;
  throughput_tps: StatisticalSummary;
  error_rate: number;
  duration_seconds: number;
  custom_metrics?: Record<string, number>;
}

interface BenchmarkSuite {
  timestamp: string;
  backend: string;
  results: BenchmarkResult[];
  summary: {
    total: number;
    passed: number;
    failed: number;
    duration_seconds: number;
  };
}
```

## See Also

- [Contributing Guide](./CONTRIBUTING.md)
- [Architecture Overview](./ARCHITECTURE.md)
- [Troubleshooting](./TROUBLESHOOTING.md)
