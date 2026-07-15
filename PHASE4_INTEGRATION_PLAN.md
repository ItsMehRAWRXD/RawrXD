# Phase 4: Full Integration Testing Plan

## Overview

Phase 4 focuses on end-to-end integration testing of the unified architecture with real legacy implementations.

## Current Status

✅ **Phase 3 Complete**: Adapters connected to real legacy code
- LegacyCoreAdapter.cpp delegates to AgenticEngine
- LegacyInferenceAdapter.cpp uses GGMLBackend
- Both compile successfully

## Phase 4 Goals

1. **Link Integration Test** with real legacy implementations
2. **Verify End-to-End Functionality** through adapters
3. **Performance Baseline** measurement
4. **Error Handling** validation

## Test Components

### 1. Agentic Integration Test

**File**: `test_phase4_agentic.cpp`

**Tests**:
- AgenticEngine initialization through Core interface
- File operations (read/write/list) via adapter
- Search operations (grep) via adapter
- Command execution via adapter
- Safety validation via adapter
- Chat/Inference via adapter

**Dependencies**:
- `src/agentic_engine.cpp` (real implementation)
- `src/agentic/LegacyCoreAdapter.cpp` (adapter)
- `src/agentic/Core.h` (unified interface)

### 2. Inference Integration Test

**File**: `test_phase4_inference.cpp`

**Tests**:
- GGMLBackend initialization
- Model loading (if available)
- Tokenization
- Generation (if model available)
- Performance metrics

**Dependencies**:
- `src/inference/GGMLBackend.cpp` (real implementation)
- `src/inference/LegacyInferenceAdapter.cpp` (adapter)
- `src/inference/InferenceEngine.h` (unified interface)

### 3. Combined Integration Test

**File**: `test_phase4_combined.cpp`

**Tests**:
- Agentic + Inference working together
- End-to-end task execution
- Error propagation
- Resource cleanup

## Build Configuration

### Compiler Flags
```bash
-std=c++17
-I./src
-I./include
-O2  # Optimization for performance baseline
```

### Link Requirements
```bash
# Core dependencies
src/agentic_engine.cpp
src/agentic_file_operations.cpp
src/agentic_command_executor.cpp

# Inference dependencies  
src/inference/GGMLBackend.cpp
src/ggml/ggml.c
src/gguf/gguf.cpp

# Adapter files
src/agentic/LegacyCoreAdapter.cpp
src/inference/LegacyInferenceAdapter.cpp
```

## Test Execution Plan

### Step 1: Compile Test Files
```bash
# Compile agentic test
g++ -std=c++17 -c test_phase4_agentic.cpp -I./src -o test_phase4_agentic.o

# Compile inference test
g++ -std=c++17 -c test_phase4_inference.cpp -I./src -o test_phase4_inference.o

# Compile combined test
g++ -std=c++17 -c test_phase4_combined.cpp -I./src -o test_phase4_combined.o
```

### Step 2: Link Executables
```bash
# Link agentic test
g++ test_phase4_agentic.o src/agentic/LegacyCoreAdapter.o \
    src/agentic_engine.o [other deps...] \
    -o test_phase4_agentic.exe

# Link inference test
g++ test_phase4_inference.o src/inference/LegacyInferenceAdapter.o \
    src/inference/GGMLBackend.o [other deps...] \
    -o test_phase4_inference.exe
```

### Step 3: Run Tests
```bash
./test_phase4_agentic.exe
./test_phase4_inference.exe
./test_phase4_combined.exe
```

## Success Criteria

| Test | Criteria |
|------|----------|
| Agentic | All file/search/command operations work through adapter |
| Inference | Model loading/tokenization works through adapter |
| Combined | End-to-end task execution succeeds |
| Performance | Within 10% of direct legacy calls |
| Memory | No leaks detected |

## Evidence Collection

- Compilation logs (no errors)
- Test execution output (all pass)
- Performance metrics (baseline)
- Memory usage reports

## Next Steps After Phase 4

1. **Phase 5**: Production hardening
2. **Phase 6**: Gradual migration of existing code
3. **Phase 7**: Legacy code archival
4. **Phase 8**: Full removal of legacy paths

---

Ready to begin Phase 4 implementation.
