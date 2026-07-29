# RawrXD N-EVM Test Suite - Quick Reference

## Building Tests

### Windows (MSVC)
```batch
# Using build script
test_build.bat all release
test_build.bat all debug
test_build.bat test_math_mode release run

# Using CMake
mkdir build && cd build
cmake -S ../src/nevm/tests -B . -G "Visual Studio 17 2022"
cmake --build . --config Release
ctest -C Release
```

### Linux/macOS
```bash
# Using CMake
mkdir build && cd build
cmake -S ../src/nevm/tests -B . -G Ninja
cmake --build .
ctest

# With coverage
cmake -S ../src/nevm/tests -B . -DENABLE_COVERAGE=ON
make coverage

# With sanitizers
cmake -S ../src/nevm/tests -B . -DENABLE_SANITIZERS=ON
```

## Running Tests

### Basic Usage
```bash
# Run all tests
./nevm_tests

# Run with verbose output
./nevm_tests --verbose

# Run specific test pattern
./nevm_tests --filter "MathMode_*"
./nevm_tests --filter "*Determinism*"

# List all tests
./nevm_tests --list

# Stop on first failure
./nevm_tests --stop-on-failure

# Repeat tests
./nevm_tests --repeat 5

# Set timeout
./nevm_tests --timeout 60
```

### Output Formats
```bash
# Console output (default)
./nevm_tests --format console

# JUnit XML (for CI/CD)
./nevm_tests --format junit --output results.xml

# JSON output
./nevm_tests --format json --output results.json
```

## Test Organization

### Test Categories

| Prefix | Component | File |
|--------|-----------|------|
| `MathMode_*` | Math mode controller | test_math_mode.cpp |
| `Determinism_*` | Determinism safeguards | test_determinism.cpp |
| `KVIntegrity_*` | KV cache integrity | test_kv_integrity.cpp |
| `ExecutionPlan_*` | Execution plan versioning | test_execution_plan.cpp |
| `Performance*Budget*` | Performance budgets | test_performance_thresholds.cpp |
| `Regression*` | Regression detection | test_performance_thresholds.cpp |
| `GoldenOutput*` | Golden output comparison | test_golden_output.cpp |
| `ValidationSchema*` | Validation schema | test_validation_schema.cpp |
| `ExitCode*` | Exit code mapping | test_validation_schema.cpp |
| `Integration_*` | Integration tests | test_integration.cpp |

### Filter Examples

```bash
# Run all math mode tests
./nevm_tests --filter "MathMode_*"

# Run all performance-related tests
./nevm_tests --filter "Performance*"

# Run all KV integrity tests
./nevm_tests --filter "KVIntegrity_*"

# Run specific test
./nevm_tests --filter "MathMode_StringConversion"

# Run multiple patterns (run all)
./nevm_tests --filter "*Math*"
./nevm_tests --filter "*Determinism*"
```

## CI/CD Integration

### GitHub Actions
```yaml
- name: Build and Test
  run: |
    cmake -B build -S src/nevm/tests
    cmake --build build
    ctest --test-dir build --output-on-failure

- name: Upload Results
  uses: actions/upload-artifact@v3
  with:
    name: test-results
    path: build/results.xml
```

### Azure DevOps
```yaml
- task: CMake@1
  inputs:
    cmakeArgs: '-S src/nevm/tests -B build'

- task: CMake@1
  inputs:
    cmakeArgs: '--build build'

- task: PublishTestResults@2
  inputs:
    testResultsFormat: 'JUnit'
    testResultsFiles: '**/results.xml'
```

## Test Utilities

### Random Data Generation
```cpp
#include "test_data_utils.hpp"
using namespace RawrXD::NEVM::TestUtils;

RandomGenerator rng(42);
auto floats = rng.GenerateFloats(1000, -1.0f, 1.0f);
auto ints = rng.GenerateInts(100, 0, 100);
auto bytes = rng.GenerateBytes(1024);
auto gaussian = rng.GenerateGaussian(1000, 0.0f, 1.0f);
```

### Test Fixtures
```cpp
auto matrix = TestFixtures::SmallMatrix(10, 10);
auto identity = TestFixtures::IdentityMatrix(5);
auto sequential = TestFixtures::Sequential(100, 0.0f, 0.1f);
auto tokens = TestFixtures::TokenSequence(50, 32000);
```

### Performance Timing
```cpp
Timer timer;
// ... code to measure ...
double elapsed_ms = timer.ElapsedMs();
```

### Comparison Utilities
```cpp
bool equal = Comparison::ArraysEqual(a, b, n, 1e-5f);
float max_diff = Comparison::MaxDifference(a, b, n);
float mse = Comparison::MeanSquaredError(a, b, n);
```

## Mock Objects

### Mock Model Weights
```cpp
auto weights = MockModelWeights::Create(
    /*vocab_size=*/32000,
    /*hidden_size=*/4096,
    /*num_layers=*/32
);
```

### Mock Inference Context
```cpp
MockInferenceContext ctx;
ctx.AddToken(1);
ctx.AddToken(2);
ctx.GenerateLogits(32000);
```

### Mock KV Cache
```cpp
auto cache = MockKVCache::Create(
    /*layers=*/32,
    /*heads=*/32,
    /*dim=*/128,
    /*max_seq=*/2048
);
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All tests passed |
| 1 | One or more tests failed |
| 2 | Test framework error |

## Troubleshooting

### Build Issues
```bash
# Clean build
rm -rf build
mkdir build && cd build
cmake -S ../src/nevm/tests -B . -G Ninja
cmake --build .

# Verbose build
cmake --build . --verbose
```

### Test Failures
```bash
# Run with verbose output
./nevm_tests --verbose --filter "FailedTest"

# Run single test multiple times
./nevm_tests --filter "TestName" --repeat 10

# Check for memory issues (Linux)
./nevm_tests --filter "TestName" 2>&1 | valgrind --leak-check=full
```

### Coverage Issues
```bash
# Generate coverage report (Linux)
mkdir build && cd build
cmake -S ../src/nevm/tests -B . -DENABLE_COVERAGE=ON
cmake --build .
ctest
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' --output-file coverage.info
genhtml coverage.info --output-directory coverage_html
```

## Performance Benchmarks

### Running Benchmarks
```bash
# Run with timing
./nevm_tests --verbose 2>&1 | grep "duration"

# Profile with perf (Linux)
perf record ./nevm_tests
perf report
```

### Expected Performance
- Unit tests: < 1ms each
- Integration tests: < 100ms each
- Full suite: < 5 seconds

## Contributing

### Adding New Tests
1. Create test in appropriate file
2. Follow naming convention: `Component_Scenario_Expected`
3. Use assertion macros
4. Add to TESTING.md documentation

### Test Checklist
- [ ] Test compiles without warnings
- [ ] Test passes consistently
- [ ] Test has no memory leaks
- [ ] Test is deterministic
- [ ] Test has proper documentation

## Support

For issues or questions:
- Check TESTING.md for detailed documentation
- Review existing test patterns
- Contact the N-EVM team
