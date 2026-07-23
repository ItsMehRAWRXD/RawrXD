# Sovereign Substrate - Build System Guide

## Quick Start

```bash
# Configure build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build everything
make -j$(nproc)

# Run tests
make test

# Run demo
./demo/demo_sovereign_substrate
```

## Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `RAWR_BUILD_TESTS` | ON | Build test suite |
| `RAWR_BUILD_DEMO` | ON | Build demo application |
| `RAWR_BUILD_SHARED` | OFF | Build shared library (default: static) |
| `RAWR_ENABLE_ASAN` | OFF | Enable AddressSanitizer |
| `RAWR_ENABLE_TSAN` | OFF | Enable ThreadSanitizer |
| `RAWR_ENABLE_COVERAGE` | OFF | Enable code coverage |

## Feature Toggles

| Option | Default | Description |
|--------|---------|-------------|
| `RAWR_INTENT_GUARDAILS` | ON | Enable intent guardrails |
| `RAWR_PATCH_FIREWALL` | ON | Enable patch firewall |
| `RAWR_SECURITY_HARDENING` | ON | Enable security hardening |
| `RAWR_MODEL_ADAPTER` | ON | Enable model adapter |
| `RAWR_PERSISTENCE` | ON | Enable persistence layer |
| `RAWR_TELEMETRY` | ON | Enable telemetry |

## Platform-Specific Instructions

### Windows (Visual Studio)

```bash
# Configure with Visual Studio generator
cmake .. -G "Visual Studio 17 2022" -A x64

# Build
cmake --build . --config Release

# Or open RawrXD.sln in Visual Studio
```

### Windows (Ninja)

```bash
# Configure with Ninja
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release

# Build
ninja
```

### Linux/macOS

```bash
# Configure
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
make -j$(nproc)

# Install (optional)
sudo make install
```

## Build Targets

| Target | Description |
|--------|-------------|
| `sovereign` | Main library (static/shared) |
| `demo_sovereign_substrate` | Demo application |
| `test_intent_guardrails` | Intent guardrails tests |
| `test_sovereign_puppeteer` | Puppeteer tests |
| `test_agent_kernel` | Agent kernel tests |
| `test_repository_memory` | Repository memory tests |
| `test_security_hardening` | Security tests |
| `test_model_adapter` | Model adapter tests |
| `test_persistence` | Persistence tests |
| `test_tool_system` | Tool system tests |
| `test_sovereign_substrate_e2e` | End-to-end tests |
| `test_summary` | Run all tests |

## Example Build Session

```bash
# 1. Create build directory
mkdir build && cd build

# 2. Configure with all features
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DRAWR_BUILD_TESTS=ON \
    -DRAWR_BUILD_DEMO=ON \
    -DRAWR_SECURITY_HARDENING=ON \
    -DRAWR_MODEL_ADAPTER=ON

# 3. Build everything
cmake --build . --parallel 8

# 4. Run tests
ctest --output-on-failure

# 5. Run demo
./demo/demo_sovereign_substrate
```

## Troubleshooting

### Missing Dependencies

The Sovereign Substrate has minimal external dependencies:
- C++17/20 compiler
- CMake 3.16+
- Platform libraries (automatically linked)

### Windows SDK Issues

If you encounter Windows SDK errors, ensure:
1. Windows SDK 10.0.22621.0 or later is installed
2. Visual Studio 2022 with C++ workload is installed
3. Running from Developer Command Prompt

### Link Errors

If you see linker errors:
```bash
# Clean build
rm -rf build
mkdir build && cd build

# Reconfigure
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build with verbose output
cmake --build . --verbose
```

### Test Failures

If tests fail:
```bash
# Run specific test with output
./tests/test_security_hardening

# Run with GDB (Linux)
gdb ./tests/test_agent_kernel
```

## Installation

```bash
# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .

# Install
sudo cmake --install .

# Or specify prefix
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/rawrxd
sudo cmake --install .
```

## Packaging

```bash
# Create package
cpack -G TGZ  # Linux
cpack -G ZIP  # Windows
```

## Development Build

For development with debug symbols:

```bash
mkdir build-debug && cd build-debug
cmake .. -DCMAKE_BUILD_TYPE=Debug -DRAWR_ENABLE_ASAN=ON
cmake --build .
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Build and Test

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Configure
        run: cmake -B build -DCMAKE_BUILD_TYPE=Release
      
      - name: Build
        run: cmake --build build --parallel
      
      - name: Test
        run: ctest --test-dir build --output-on-failure
```

## Performance Build

For maximum performance:

```bash
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_FLAGS="-O3 -march=native -DNDEBUG" \
    -DRAWR_BUILD_TESTS=OFF \
    -DRAWR_BUILD_DEMO=OFF

cmake --build . --parallel
```

## Cross-Compilation

### Windows to Linux (WSL)

```bash
# In WSL
mkdir build-wsl && cd build-wsl
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

### Linux to Windows (MinGW)

```bash
mkdir build-mingw && cd build-mingw
cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=../cmake/mingw-toolchain.cmake \
    -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

## Verification

After building, verify the installation:

```bash
# Check library
ls -la libsovereign.a  # or .lib/.dll

# Check demo
./demo/demo_sovereign_substrate --version

# Run quick test
./tests/test_security_hardening
```

## Build Statistics

| Component | Lines | Compile Time | Binary Size |
|-----------|-------|--------------|-------------|
| Intent Guardrails | ~3,500 | ~30s | ~500KB |
| Sovereign Puppeteer | ~2,970 | ~25s | ~400KB |
| Agent Kernel | ~4,500 | ~40s | ~600KB |
| Repository Memory | ~1,500 | ~15s | ~300KB |
| Control Plane | ~1,200 | ~20s | ~350KB |
| Security Hardening | ~1,700 | ~25s | ~450KB |
| Model Adapter | ~1,200 | ~20s | ~350KB |
| Tool System | ~1,500 | ~20s | ~400KB |
| **Total** | **~20,500** | **~3m** | **~3.5MB** |

## Next Steps

After building:
1. Run the demo: `./demo/demo_sovereign_substrate`
2. Explore the test suite: `ctest -N`
3. Read the architecture docs in `docs/`
4. Start integrating with your project

---

**The Sovereign Substrate is ready to build!**
