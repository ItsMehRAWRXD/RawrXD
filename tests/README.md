# RawrXD Validation Framework

Comprehensive testing infrastructure for RawrXD v15.0 - covering correctness, regression, and performance.

## Quick Start

```bash
# Run all tests
cd tests
./run_validation.bat

# Run specific category
./run_validation.bat kernels
./run_validation.bat regression
./run_validation.bat performance

# Generate HTML report
./generate_report.bat
```

## Test Categories

| Category | Tests | Purpose | Status |
|----------|-------|---------|--------|
| **CPU** | 2 | AVX2 kernel validation | ✅ Complete |
| **Tokenizer** | 1 | BPE tokenization | ✅ Complete |
| **GGUF** | 1 | Format validation | ✅ Complete |
| **Kernels** | 8 | Core kernel tests | ✅ Complete |
| **Sampler** | 1 | Temperature scaling | ✅ Complete |
| **Integration** | 1 | E2E inference | ✅ Complete |
| **Regression** | 9 | Golden reference tests | ✅ Complete |
| **Performance** | 3 | Benchmark baselines | ✅ Complete |
| **Total** | **26** | | **100%** |

## Directory Structure

```
tests/
├── run_validation.bat      # Main test runner
├── generate_report.bat     # HTML/JSON report generator
├── analyze_coverage.py     # Coverage analysis tool
├── dashboard.html          # Interactive dashboard
├── ci.yml                  # GitHub Actions workflow
│
├── cpu/                    # CPU kernel tests
├── gpu/                    # GPU tests (placeholder)
├── tokenizer/              # Tokenization tests
├── gguf/                   # GGUF format tests
├── kernels/                # Core kernel tests (8)
├── transformer/            # Transformer tests
├── sampler/                # Sampling tests
├── integration/            # E2E tests
├── regression/             # Milestone 2
└── performance/            # Milestone 3
```

## Milestones

### Milestone 1: Core Validation (14 tests)
- AVX2 kernel validation
- Tokenizer correctness
- GGUF format validation
- 8 core kernel tests
- Sampler validation
- Integration pipeline

### Milestone 2: Golden References (9 tests)
- Reference generator for 3 models
- Logit/hidden state/token comparison
- Hash verification
- Manifest integrity

### Milestone 3: Performance Baselines (3 tests)
- Quick smoke test (matmul, softmax, RMSNorm)
- Extended matmul benchmarks
- Extended attention benchmarks
- Throughput and bandwidth metrics

## Tools

### Report Generator
```bash
./generate_report.bat
# Creates:
#   reports/report_YYYYMMDD_HHMMSS.json
#   reports/report_YYYYMMDD_HHMMSS.html
#   reports/latest.json
#   reports/latest.html
```

### Coverage Analyzer
```bash
python analyze_coverage.py
# Generates coverage_report.json
```

### Dashboard
Open `dashboard.html` in a browser for interactive test results.

## CI/CD Integration

See `ci.yml` for GitHub Actions workflow:
- Smoke tests on every push
- Full validation on PRs
- Performance benchmarks
- Coverage analysis
- Release validation

## Adding Tests

1. Create `tests/category/test_name.c`
2. Return 0 on success, non-zero on failure
3. Compile: `gcc -O2 -o test_name.exe test_name.c -lm`
4. Run: `./run_validation.bat category`

## Performance Baselines

| Kernel | Config | Baseline | Tolerance |
|--------|--------|----------|-----------|
| Matmul | 128³ x100 | <1000ms | 50% |
| Softmax | 1024 x1000 | <100ms | 50% |
| RMSNorm | 4096 x500 | <60ms | 50% |

## Success Criteria

- ✅ 26/26 tests passing
- ✅ Zero false positives in regression
- ✅ Sub-60 second full validation
- ✅ Sub-5 second smoke test
- ✅ 100% milestone completion

## Documentation

- `MILESTONE_1_COMPLETE.md` - Validation framework
- `MILESTONE_2_COMPLETE.md` - Golden references
- `MILESTONE_3_COMPLETE.md` - Performance baselines
- `VALIDATION_FRAMEWORK_COMPLETE.md` - Full documentation

## License

Part of RawrXD v15.0 - see main LICENSE file.

---

## Legacy: Marketplace Installer Tests

The following tests are for the MASM64 Extension Marketplace Installer:

### Unit Tests (11 tests)
1. **ParseVsixHeader_ValidFile** - Tests parsing valid VSIX package headers
2. **ParseVsixHeader_InvalidFile** - Tests error handling for invalid files
3. **ParseManifest_ValidJson** - Tests parsing valid package.json manifests
4. **ParseManifest_InvalidJson** - Tests error handling for malformed JSON
5. **ResolveDependencies_None** - Tests extensions with no dependencies
6. **ResolveDependencies_Single** - Tests single dependency resolution
7. **ExtractFiles_Valid** - Tests file extraction from VSIX packages
8. **GenerateNativeEntryPoint** - Tests MASM64 code generation
9. **RegisterExtension** - Tests registry operations
10. **InstallExtension_Complete** - Tests complete installation flow
11. **InstallExtension_AlreadyInstalled** - Tests duplicate installation handling

### Integration Tests (1 test)
12. **Integration_FullPipeline** - Tests complete end-to-end installation pipeline

### Stress Tests (1 test)
13. **Stress_MultipleInstalls** - Tests installing 10 extensions sequentially

### Building and Running

#### Option 1: Batch Script (Windows)
```batch
build_tests.bat
```

#### Option 2: Node.js Runner (Recommended)
```bash
# Install dependencies
npm install

# Run all tests
node run_tests.js

# Build only
node run_tests.js --build-only

# Clean artifacts
node run_tests.js --clean
```

#### Option 3: Manual Build
```batch
REM Assemble
ml64.exe /c /Zi tests\test_marketplace_installer.asm

REM Link
link.exe /OUT:tests\test_marketplace_installer.exe ^
    tests\test_marketplace_installer.obj ^
    src\agentic\marketplace_installer.obj ^
    kernel32.lib user32.lib msvcrt.lib

REM Run
tests\test_marketplace_installer.exe
```

## Test Structure

```
tests/
├── test_marketplace_installer.asm  # Main test suite
├── fixtures/                       # Test fixtures
│   └── test-extension.vsix        # Mock VSIX package
├── output/                         # Test output directory
└── test-report.json               # Generated test report
```

## Test Fixtures

The test suite automatically creates mock VSIX packages with:
- Valid VSIX signature
- Sample package.json manifest
- Mock extension files

## Expected Output

```
========================================
Test Suite: Marketplace Installer Test Suite
========================================

[TEST] Starting: ParseVsixHeader_ValidFile
[PASS] ParseVsixHeader_ValidFile (12.34ms)

[TEST] Starting: ParseVsixHeader_InvalidFile
[PASS] ParseVsixHeader_InvalidFile (5.67ms)

...

========================================
Total: 13 | Passed: 13 | Failed: 0
========================================
```

## Test Framework Functions

### Test_InitSuite
Initializes test suite with name and allocates result storage.

### Test_Run
Executes a single test function and records results.

### Test_AssertEqual
Asserts two values are equal.

### Test_AssertNotNull
Asserts a pointer is not null.

### Test_AssertTrue
Asserts a condition is true.

### Test_FinalizeSuite
Prints summary and returns exit code.

## Adding New Tests

1. Create test function following naming convention:
```asm
Test_YourTestName proc frame uses rbx
    ; Setup
    ; Execute
    ; Assert
    mov eax, TEST_PASS  ; or TEST_FAIL
    ret
Test_YourTestName endp
```

2. Add to Test_RunAll:
```asm
lea rcx, szTestName
lea rdx, Test_YourTestName
call Test_Run
```

3. Add test name string:
```asm
szTestName db 'YourTestName',0
```

## Continuous Integration

### GitHub Actions Example
```yaml
name: Test Marketplace Installer

on: [push, pull_request]

jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup MASM
        run: |
          # Setup Visual Studio tools
      - name: Run Tests
        run: node run_tests.js
```

## Troubleshooting

### Build Errors
- Ensure Visual Studio 2022 is installed
- Check ml64.exe and link.exe are in PATH
- Verify Windows SDK is installed

### Test Failures
- Check test fixtures exist in `tests/fixtures/`
- Ensure write permissions for `tests/output/`
- Review test output for specific error messages

### Missing Dependencies
```bash
npm install
```

## Performance Benchmarks

Expected execution times (on typical hardware):
- Unit tests: ~100-200ms total
- Integration test: ~500ms
- Stress test: ~2-5 seconds

## Code Coverage

The test suite covers:
- ✅ VSIX parsing (header, manifest, files)
- ✅ Dependency resolution
- ✅ File extraction and decompression
- ✅ Native code generation
- ✅ Registry operations
- ✅ Error handling
- ✅ Edge cases (duplicates, invalid input)

## License

MIT License - See LICENSE file for details
