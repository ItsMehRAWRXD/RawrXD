# Contributing Guide

Thank you for your interest in contributing to the RawrXD Benchmark Suite! This document provides guidelines for contributing new benchmarks, features, and improvements.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Adding a New Benchmark](#adding-a-new-benchmark)
- [Code Style](#code-style)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Create a feature branch** (`git checkout -b feature/my-benchmark`)
4. **Make your changes**
5. **Run tests** (`./scripts/validate_suite.py`)
6. **Submit a Pull Request**

## Development Setup

### Prerequisites

- C++17 compatible compiler (GCC 11+, Clang 14+, MSVC 2022+)
- CMake 3.20+
- Python 3.9+ (for scripts)
- Docker (optional, for containerized testing)

### Build

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/benchmarks.git
cd benchmarks

# Create build directory
cmake -B build -DCMAKE_BUILD_TYPE=Debug

# Build
cmake --build build --parallel

# Run tests
./scripts/validate_suite.py
```

### IDE Setup

#### VS Code

Recommended extensions:
- C/C++ (Microsoft)
- CMake Tools
- Python
- Markdown All in One

```json
// .vscode/settings.json
{
  "C_Cpp.default.configurationProvider": "ms-vscode.cmake-tools",
  "C_Cpp.default.cppStandard": "c++17",
  "cmake.buildDirectory": "${workspaceFolder}/build",
  "cmake.configureOnOpen": true
}
```

#### CLion

Open the project root directory. CLion will automatically detect the CMake configuration.

## Adding a New Benchmark

### Step 1: Choose the Right Tier

| Tier | Use Case | Examples |
|------|----------|----------|
| Tier 1 | Core inference metrics | TPS, latency, context scaling |
| Tier 2 | Agentic capabilities | Planning, tool use |
| Tier 3 | Sovereign-specific features | Swarm, SEG mutations |
| Tier 4 | Long-running stability | Memory leaks, drift |
| Workflow | End-to-end scenarios | Bug fixes, explanations |
| Stress | Extreme conditions | Overload, chaos |

### Step 2: Create the Benchmark File

Create `src/my_benchmark.cpp`:

```cpp
// my_benchmark.cpp
// Batch X: [Benchmark Name]
//
// Measures: [What this benchmark measures]
// Features: [Key features]
// Output: [What metrics are reported]

#include "benchmark_tiers.hpp"
#include "backends/sovereign_adapter.hpp"
#include <iostream>
#include <iomanip>
#include <vector>

namespace Benchmark {

class MyBenchmark {
public:
    struct Config {
        std::string model = "phi-4";
        std::string prompt = "Default prompt";
        int max_tokens = 256;
        float temperature = 0.0f;
        int seed = 42;
        // Add your configuration parameters
    };

    struct Results {
        StatisticalSummary metric_name;
        double custom_metric = 0.0;
        bool success = false;
    };

    explicit MyBenchmark(const Config& config = Config())
        : config_(config) {}

    // Run against Sovereign backend
    Results RunSovereign(const std::string& base_url = "http://localhost:8080") {
        std::cout << "[MyBenchmark] Testing Sovereign backend...\n";
        
        Backends::SovereignAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.success = false;
            return results;
        }

        return RunBenchmark([&adapter](const Backends::InferenceRequest& req) {
            return adapter.RunInference(req);
        });
    }

    // Run against Ollama backend (if applicable)
    Results RunOllama(const std::string& base_url = "http://localhost:11434") {
        std::cout << "[MyBenchmark] Testing Ollama backend...\n";
        
        Backends::OllamaAdapter adapter(base_url);
        if (!adapter.IsAvailable()) {
            Results results;
            results.success = false;
            return results;
        }

        return RunBenchmark([&adapter](const Backends::InferenceRequest& req) {
            return adapter.RunInference(req);
        });
    }

    // Print formatted results
    static void PrintResults(const Results& results, const std::string& backend_name) {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "MyBenchmark Results: " << backend_name << "\n";
        std::cout << std::string(70, '=') << "\n\n";

        if (!results.success) {
            std::cout << "FAILED\n";
            return;
        }

        std::cout << std::fixed << std::setprecision(2);
        std::cout << "Metric: " << results.metric_name.mean << " ± " 
                  << results.metric_name.ci_half_width << "\n";
        std::cout << "Custom: " << results.custom_metric << "\n";
    }

private:
    Config config_;

    // Template for backend-agnostic execution
    template<typename BackendFunc>
    Results RunBenchmark(BackendFunc backend_call) {
        Results results;
        
        std::vector<double> samples;
        
        // Warmup runs (discarded)
        std::cout << "  Warmup (5 runs)...\n";
        for (int i = 0; i < 5; ++i) {
            RunIteration(backend_call);
        }
        
        // Measured runs
        std::cout << "  Measuring (30 runs)...\n";
        for (int i = 0; i < 30; ++i) {
            auto result = RunIteration(backend_call);
            if (result.success) {
                samples.push_back(result.metric_value);
            }
            
            // Progress indicator
            if ((i + 1) % 10 == 0) {
                std::cout << "    " << (i + 1) << "/30 completed\n";
            }
        }
        
        if (!samples.empty()) {
            results.metric_name = CalculateStatistics(samples);
            results.success = true;
        }
        
        return results;
    }

    struct IterationResult {
        bool success = false;
        double metric_value = 0.0;
    };

    template<typename BackendFunc>
    IterationResult RunIteration(BackendFunc backend_call) {
        IterationResult result;
        
        Backends::InferenceRequest req;
        req.model = config_.model;
        req.prompt = config_.prompt;
        req.temperature = config_.temperature;
        req.max_tokens = config_.max_tokens;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        auto inference_result = backend_call(req);
        
        auto end = std::chrono::high_resolution_clock::now();
        
        if (inference_result.success) {
            result.success = true;
            result.metric_value = std::chrono::duration<double, std::milli>(
                end - start).count();
        }
        
        return result;
    }

    StatisticalSummary CalculateStatistics(const std::vector<double>& samples) {
        StatisticalSummary summary;
        if (samples.empty()) return summary;
        
        summary.sample_count = static_cast<uint32_t>(samples.size());
        summary.mean = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
        
        auto [min_it, max_it] = std::minmax_element(samples.begin(), samples.end());
        summary.min = *min_it;
        summary.max = *max_it;
        
        double variance = 0.0;
        for (double s : samples) {
            variance += (s - summary.mean) * (s - summary.mean);
        }
        variance /= samples.size();
        summary.std_dev = std::sqrt(variance);
        
        std::vector<double> sorted = samples;
        std::sort(sorted.begin(), sorted.end());
        summary.median = sorted[sorted.size() / 2];
        summary.p95 = sorted[static_cast<size_t>(sorted.size() * 0.95)];
        
        // 95% CI using t-distribution (t=2.045 for 30 samples)
        double t_value = 2.045;
        summary.ci_half_width = t_value * (summary.std_dev / std::sqrt(samples.size()));
        
        return summary;
    }
};

// C API for runner integration
void RunMyBenchmark(const std::string& backend = "sovereign") {
    MyBenchmark benchmark;
    
    MyBenchmark::Results results;
    if (backend == "sovereign") {
        results = benchmark.RunSovereign();
    } else if (backend == "ollama") {
        results = benchmark.RunOllama();
    } else {
        std::cout << "Unknown backend: " << backend << "\n";
        return;
    }
    
    MyBenchmark::PrintResults(results, backend);
}

} // namespace Benchmark
```

### Step 3: Register in Runner

Add to `src/benchmark_runner_main.cpp`:

```cpp
// Forward declaration
namespace Benchmark {
    void RunMyBenchmark(const std::string& backend);
}

// In RegisterAllBenchmarks():
benchmarks_.push_back({"my_benchmark", "tier1", "Description of my benchmark",
    Benchmark::RunMyBenchmark, {"sovereign", "ollama"}});
```

### Step 4: Add Tests

Create `tests/test_my_benchmark.cpp`:

```cpp
#include <gtest/gtest.h>
#include "my_benchmark.hpp"

using namespace Benchmark;

TEST(MyBenchmark, BasicFunctionality) {
    MyBenchmark benchmark;
    
    // Test with mock backend or skip if no backend available
    auto results = benchmark.RunSovereign();
    
    // If backend not available, test should pass but skip
    if (!results.success) {
        GTEST_SKIP() << "Backend not available";
    }
    
    EXPECT_TRUE(results.success);
    EXPECT_GT(results.metric_name.mean, 0);
}

TEST(MyBenchmark, StatisticalValidity) {
    MyBenchmark::Config config;
    config.seed = 42;
    
    MyBenchmark benchmark(config);
    
    // Run twice with same seed, should get similar results
    auto results1 = benchmark.RunSovereign();
    auto results2 = benchmark.RunSovereign();
    
    if (!results1.success || !results2.success) {
        GTEST_SKIP() << "Backend not available";
    }
    
    // Results should be within 20% of each other
    double diff = std::abs(results1.metric_name.mean - results2.metric_name.mean);
    double avg = (results1.metric_name.mean + results2.metric_name.mean) / 2;
    EXPECT_LT(diff / avg, 0.2);
}
```

### Step 5: Document

Add to `docs/BENCHMARKS.md`:

```markdown
### my_benchmark

**Tier**: tier1
**Backends**: sovereign, ollama

Measures [description of what it measures].

**Configuration**:
- `model`: Model to use (default: "phi-4")
- `prompt`: Input prompt (default: "...")
- `max_tokens`: Maximum tokens to generate (default: 256)

**Metrics**:
- `metric_name`: Description of metric
- `custom_metric`: Description of custom metric

**Example**:
```bash
./benchmark_runner --benchmark my_benchmark --backend sovereign
```
```

## Code Style

### C++ Style Guide

We follow the [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html) with modifications:

- **Indentation**: 4 spaces (no tabs)
- **Line length**: 100 characters maximum
- **Naming**:
  - Classes: `PascalCase`
  - Functions: `snake_case`
  - Variables: `snake_case_` (trailing underscore for members)
  - Constants: `kPascalCase`
  - Macros: `ALL_CAPS`

```cpp
// Good
class MyBenchmark {
public:
    void RunBenchmark();
    
private:
    int iteration_count_;
    static constexpr int kDefaultIterations = 30;
};

// Bad
class my_benchmark {
public:
    void runBenchmark();
private:
    int iterationCount;
};
```

### Python Style Guide

Follow [PEP 8](https://pep8.org/):

```python
# Good
def calculate_statistics(samples: List[float]) -> StatisticalSummary:
    """Calculate statistics for a set of samples."""
    mean = sum(samples) / len(samples)
    return StatisticalSummary(mean=mean)

# Bad
def CalculateStatistics(samples):
    mean = sum(samples)/len(samples)
    return StatisticalSummary(mean)
```

## Testing

### Running Tests

```bash
# Build tests
cmake -B build -DBUILD_TESTS=ON
cmake --build build

# Run all tests
ctest --test-dir build --output-on-failure

# Run specific test
./build/tests/test_benchmarks --gtest_filter="MyBenchmark.*"
```

### Test Categories

1. **Unit Tests**: Test individual components
2. **Integration Tests**: Test full benchmark execution
3. **Validation Tests**: Verify statistical correctness
4. **Performance Tests**: Ensure benchmarks run in reasonable time

### Writing Tests

```cpp
// Use descriptive test names
TEST(MyBenchmark, CalculatesCorrectMean) {
    std::vector<double> samples = {1.0, 2.0, 3.0, 4.0, 5.0};
    auto stats = CalculateStatistics(samples);
    
    EXPECT_DOUBLE_EQ(stats.mean, 3.0);
    EXPECT_DOUBLE_EQ(stats.min, 1.0);
    EXPECT_DOUBLE_EQ(stats.max, 5.0);
}

// Use parameterized tests for multiple inputs
class MyBenchmarkParamTest : public ::testing::TestWithParam<int> {};

TEST_P(MyBenchmarkParamTest, HandlesDifferentSizes) {
    int size = GetParam();
    // Test with different input sizes
}

INSTANTIATE_TEST_SUITE_P(
    Sizes,
    MyBenchmarkParamTest,
    ::testing::Values(10, 30, 100)
);
```

## Submitting Changes

### Pull Request Process

1. **Update documentation** for any changed functionality
2. **Add tests** for new features
3. **Ensure all tests pass** (`./scripts/validate_suite.py`)
4. **Update CHANGELOG.md** with your changes
5. **Submit PR** with clear description

### PR Checklist

- [ ] Code follows style guide
- [ ] Tests added and passing
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] No compiler warnings
- [ ] Benchmark runs successfully

### Commit Message Format

```
type(scope): subject

body

footer
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, semicolons, etc)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Build process, dependencies

Example:
```
feat(benchmarks): add context_scaling benchmark

Implements context length scaling benchmark that measures
performance from 1K to 128K tokens.

- Tests 8 different context lengths
- Reports TPS and latency for each
- Includes memory usage tracking

Closes #123
```

## Review Process

1. **Automated checks** must pass (CI/CD)
2. **Code review** by at least one maintainer
3. **Benchmark validation** (if adding/modifying benchmarks)
4. **Documentation review**

## Getting Help

- 📖 [Documentation](../README.md)
- 💬 [GitHub Discussions](https://github.com/ItsMehRAWRXD/benchmarks/discussions)
- 🐛 [Issue Tracker](https://github.com/ItsMehRAWRXD/benchmarks/issues)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to RawrXD Benchmark Suite!**
