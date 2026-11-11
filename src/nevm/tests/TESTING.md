# RawrXD N-EVM Test Suite Documentation

## Overview

The RawrXD N-EVM test suite provides comprehensive validation of all framework components. The test suite uses a custom lightweight testing framework with no external dependencies.

## Test Framework

### Custom Test Framework

The test framework is defined in `test_main.cpp` and provides:

- **TEST Macro**: Automatic test registration
- **ASSERT_* Macros**: Comprehensive assertion library
- **TestRegistry**: Singleton pattern for test management
- **Automatic Timing**: Each test measures execution time

### Assertion Macros

| Macro | Description |
|-------|-------------|
| `ASSERT_TRUE(expr)` | Assert expression is true |
| `ASSERT_FALSE(expr)` | Assert expression is false |
| `ASSERT_EQ(a, b)` | Assert a equals b |
| `ASSERT_NE(a, b)` | Assert a not equals b |
| `ASSERT_LT(a, b)` | Assert a < b |
| `ASSERT_GT(a, b)` | Assert a > b |
| `ASSERT_LE(a, b)` | Assert a <= b |
| `ASSERT_GE(a, b)` | Assert a >= b |
| `ASSERT_NEAR(a, b, eps)` | Assert |a - b| < eps |
| `ASSERT_THROW(expr, exc)` | Assert expression throws exception |
| `ASSERT_NO_THROW(expr)` | Assert expression doesn't throw |

## Test Files

### 1. test_math_mode.cpp (7 tests)

Tests for the MathModeController component.

**Coverage:**
- String conversion for all math modes
- Configuration for Fast, Reproducible, and BitExact modes
- JSON export/import
- Overhead calculation
- Validation
- Mode switching

**Key Tests:**
- `MathMode_StringConversion` - Verify mode to string mapping
- `MathMode_Configuration_AllModes` - Test all three math modes
- `MathMode_OverheadCalculation` - Verify overhead percentages

### 2. test_determinism.cpp (11 tests)

Tests for determinism safeguards.

**Coverage:**
- Tree reduction summation
- Kahan summation
- Sequential summation
- Consistency verification
- SoftMax variants (basic, Kahan, large values)
- GEMM operations (basic, Kahan, identity)

**Key Tests:**
- `Determinism_TreeSum` - Tree reduction accuracy
- `Determinism_KahanSum` - Kahan summation precision
- `Determinism_SoftMax_Kahan` - Numerically stable SoftMax
- `Determinism_GEMM_Identity` - Matrix identity verification

### 3. test_kv_integrity.cpp (8 tests)

Tests for KV cache integrity system.

**Coverage:**
- Checksum calculation
- KVPageIntegrity validation
- Integrity tracker registration
- Verification operations
- Update operations
- Violation detection
- Migration guards

**Key Tests:**
- `KVIntegrity_ChecksumCalculator` - Hash consistency
- `KVIntegrity_KVIntegrityTracker_Verify` - Data integrity checks
- `KVIntegrity_KVMigrationGuard` - Migration safety

### 4. test_execution_plan.cpp (12 tests)

Tests for execution plan versioning.

**Coverage:**
- Current version constants
- Version string formatting
- Version parsing
- Compatibility checking
- Version comparison
- Plan validation
- JSON serialization

**Key Tests:**
- `ExecutionPlanVersion_Compatibility_*` - Version compatibility rules
- `ExecutionPlanVersion_ValidatePlan` - JSON plan validation
- `ExecutionPlanVersion_Compare` - Version ordering

### 5. test_performance_thresholds.cpp (20 tests)

Tests for performance budgets and regression detection.

**Coverage:**
- Default threshold values
- Validation (pass/fail scenarios)
- JSON serialization
- Budget allocation
- Budget consumption
- Overflow detection
- Regression detection
- Delta calculation

**Key Tests:**
- `PerformanceBudget_Allocate_Overflow` - Budget limits
- `PerformanceBudget_Consume_Exceed` - Consumption tracking
- `RegressionChecker_*` - Regression detection scenarios

### 6. test_golden_output.cpp (18 tests)

Tests for golden output comparison.

**Coverage:**
- Golden output creation
- Hash computation
- JSON serialization
- Exact comparison
- Token mismatch detection
- Length mismatch handling
- Logit tolerance checking
- Tester registration
- Validation workflows
- Statistics tracking

**Key Tests:**
- `GoldenOutput_Compare_Exact` - Perfect match
- `GoldenOutput_Compare_LogitWithinTolerance` - Approximate matching
- `GoldenOutputTester_*` - Full validation workflows

### 7. test_validation_schema.cpp (22 tests)

Tests for validation schema and exit codes.

**Coverage:**
- Default gate definitions
- Gate retrieval
- Gate addition/removal
- Enable/disable operations
- JSON serialization
- Exit code mapping
- Description lookup
- Success/failure detection

**Key Tests:**
- `ValidationSchema_Defaults` - All 11 gates present
- `ExitCodeMapper_*` - Exit code mapping for all gates
- `ValidationSchema_EnableDisable` - Gate toggling

### 8. test_integration.cpp (16 tests)

End-to-end integration tests.

**Coverage:**
- Framework initialization
- Math mode switching
- Determinism verification
- KV integrity workflows
- Performance budgeting
- Golden output validation
- Execution plan versioning
- Schema configuration
- Exit code propagation
- Full pipeline validation
- Component interactions

**Key Tests:**
- `Integration_EndToEnd_ValidationPipeline` - Complete workflow
- `Integration_MathMode_Determinism_Interaction` - Cross-component
- `Integration_ValidationResult_Propagation` - Result flow

## Test Statistics

| Component | Test Count | Coverage |
|-----------|------------|----------|
| Math Mode | 7 | 100% |
| Determinism | 11 | 100% |
| KV Integrity | 8 | 100% |
| Execution Plan | 12 | 100% |
| Performance | 20 | 100% |
| Golden Output | 18 | 100% |
| Validation Schema | 22 | 100% |
| Integration | 16 | Core flows |
| **Total** | **114** | **Comprehensive** |

## Building Tests

### Using Build Script

```batch
:: Build all tests (release)
test_build.bat all release

:: Build all tests (debug)
test_build.bat all debug

:: Build and run all tests
test_build.bat all release run

:: Build specific test
test_build.bat test_math_mode release

:: Build and run specific test
test_build.bat test_math_mode release run
```

### Manual Build

```batch
:: Create build directory
mkdir build\tests

:: Compile test main
ccl /std:c++17 /W4 /EHsc /O2 /I..\..\..\src\nevm /Fo"build\tests\" test_main.cpp

:: Compile individual tests
for %%f in (test_*.cpp) do (
    cl /std:c++17 /W4 /EHsc /O2 /I..\..\..\src\nevm /Fo"build\tests\" %%f
)

:: Link all tests
link /OUT:"build\tests\nevm_tests.exe" build\tests\*.obj kernel32.lib user32.lib
```

## Running Tests

### Run All Tests

```batch
build\tests\nevm_tests.exe
```

### Run with Verbose Output

```batch
build\tests\nevm_tests.exe --verbose
```

### Run Specific Test

```batch
build\tests\nevm_tests.exe --filter "MathMode_*"
```

### Run with Report

```batch
build\tests\nevm_tests.exe --report results.xml
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All tests passed |
| 1 | One or more tests failed |
| 2 | Test framework error |

## CI/CD Integration

### GitHub Actions

```yaml
- name: Build Tests
  run: test_build.bat all release

- name: Run Tests
  run: build\tests\nevm_tests.exe

- name: Upload Results
  uses: actions/upload-artifact@v3
  with:
    name: test-results
    path: test_results.xml
```

### Azure DevOps

```yaml
- task: CmdLine@2
  inputs:
    script: 'test_build.bat all release run'

- task: PublishTestResults@2
  inputs:
    testResultsFormat: 'JUnit'
    testResultsFiles: '**/test_results.xml'
```

## Adding New Tests

### 1. Create Test File

Create `test_<component>.cpp`:

```cpp
#include "../nevm_<component>.hpp"
using namespace RawrXD::NEVM;

TEST(Component_TestName) {
    // Setup
    Component comp;
    
    // Execute
    bool result = comp.Method();
    
    // Assert
    ASSERT_TRUE(result);
    ASSERT_EQ(expected, actual);
    
    return true;
}
```

### 2. Update Build Script

Add to `test_build.bat`:

```batch
set "TEST_FILES=%TEST_FILES% test_<component>.cpp"
```

### 3. Document

Update this README with:
- Test file description
- Coverage summary
- Key test cases

## Best Practices

1. **One Assertion Per Test**: Keep tests focused
2. **Descriptive Names**: Use `Component_Scenario_Expected` pattern
3. **Setup/Teardown**: Use RAII for resource management
4. **Edge Cases**: Test boundaries and error conditions
5. **Documentation**: Comment complex test logic
6. **Isolation**: Tests should not depend on each other

## Troubleshooting

### Compilation Errors

- Verify include paths are correct
- Check C++17 support is enabled
- Ensure all dependencies are available

### Link Errors

- Verify all object files are included
- Check library paths and names

### Test Failures

- Run with `--verbose` for details
- Check for uninitialized variables
- Verify test isolation

## Maintenance

- Update tests when adding new features
- Review and update tests quarterly
- Maintain >90% code coverage
- Document breaking changes

## Support

For issues or questions:
- Check existing test patterns
- Review component documentation
- Contact the N-EVM team
