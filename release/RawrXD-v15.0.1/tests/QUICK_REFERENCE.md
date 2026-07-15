# RawrXD Validation Framework - Quick Reference

## 🚀 One-Liners

```bash
# Build and test everything (Windows)
.\build_and_test.bat

# Build and test everything (Unix/Make)
make ci

# Run all tests (parallel - fastest)
python run_parallel.py

# Run with live dashboard
python dashboard_server.py &
python run_parallel.py
```

## 📋 Common Tasks

### Build
| Task | Windows | Unix |
|------|---------|------|
| Build all | `.\build_and_test.bat` | `make build` |
| Build category | `gcc -O2 -o test.exe test.c -lm` | `make test-cpu` |
| Clean | `rm *.exe` | `make clean` |

### Test
| Task | Command |
|------|---------|
| All tests | `python run_all.py --all` |
| Parallel | `python run_parallel.py --workers 4` |
| Category | `.\run_validation.bat kernels` |
| Specific | `python run_parallel.py --category cpu` |

### Categories
```bash
# Available categories
cpu, tokenizer, gguf, kernels, sampler, integration, regression, performance, stress

# Example: Run only kernel tests
.\run_validation.bat kernels
```

### Development
| Task | Command |
|------|---------|
| Watch mode | `python watch_and_test.py` |
| Dashboard | `python dashboard_server.py --port 8080` |
| Coverage | `python analyze_coverage.py` |
| Compare | `python compare_results.py` |

## 📊 Interpreting Results

### Success
```
Total Tests:  16
Passed:       16
Failed:       0
[OK] All tests passed
```

### Failure
```
Total Tests:  16
Passed:       15
Failed:       1
[FAIL] Some tests failed
```

### Performance Baselines
| Test | Target | Good | Bad |
|------|--------|------|-----|
| Matmul 128³ | <1000ms | <500ms | >1500ms |
| Softmax 1024 | <100ms | <50ms | >150ms |
| RMSNorm 4096 | <60ms | <30ms | >90ms |

## 🔧 Troubleshooting

### "No tests found"
```bash
# Check executables exist
dir cpu\test_*.exe

# Rebuild
.\build_and_test.bat
```

### "Reference data not found"
```bash
# Generate references
cd ..\reference
.\generate_reference.exe
```

### Slow performance
```bash
# Use parallel runner
python run_parallel.py --workers 8

# Skip stress tests
python run_all.py --unit --regression --performance
```

## 📁 File Locations

```
tests/
├── run_validation.bat      # Main runner
├── run_parallel.py          # Parallel runner
├── run_all.py              # Unified runner
├── dashboard_server.py      # Web dashboard
├── cpu/                    # CPU kernel tests
├── kernels/                # Core kernel tests
├── regression/             # Golden reference tests
├── performance/            # Benchmark tests
├── stress/                 # Stress tests
└── reports/                # Generated reports
```

## 🔗 Useful Links

- Dashboard: http://localhost:8080 (when running)
- Reports: `tests/reports/latest.html`
- Coverage: `tests/reports/coverage_report.json`

## 💡 Pro Tips

1. **Fast feedback**: Use `python run_parallel.py` for ~200ms execution
2. **Continuous testing**: Use `python watch_and_test.py` while coding
3. **Before commit**: Run `.\build_and_test.bat` to ensure everything works
4. **Performance tracking**: Use `python compare_results.py` to detect regressions
5. **CI/CD**: Use `make ci` for clean, build, test, report pipeline

## 🆘 Emergency Commands

```bash
# Everything broken? Start fresh:
make distclean
.\build_and_test.bat

# Just need a quick sanity check?
.\run_validation.bat cpu tokenizer

# Full validation with reports?
make ci
```
