# RawrXD Architecture Migration Guide
## From Fragmented to Coherent

**Date:** 2026-07-08  
**Version:** 15.0.0

---

## Overview

This guide documents the migration from the fragmented, duplicate-heavy codebase to the unified 5-layer architecture.

---

## Quick Reference: Old → New

### Inference Engine Migration

| Old Header | New Header | Status |
|------------|------------|--------|
| `cpu_inference_engine.h` | `inference/InferenceEngine.h` | ✅ Unified |
| `cpu_inference_engine_Clean.h` | `inference/InferenceEngine.h` | ❌ Delete |
| `cpu_inference_engine_fixed.cpp` | `inference/InferenceEngine.cpp` | ❌ Delete |
| `cpu_inference_engine_init_fix.cpp` | `inference/InferenceEngine.cpp` | ❌ Delete |
| `cpu_inference_engine_production.cpp` | `inference/InferenceEngine.cpp` | ❌ Delete |
| `cpu_inference_engine_real.cpp` | `inference/InferenceEngine.cpp` | ❌ Delete |

### Agentic Core Migration

| Old Header | New Header | Status |
|------------|------------|--------|
| `agentic_engine.h` | `agentic/Core.h` | ✅ Unified |
| `agentic_core.h` | `agentic/Core.h` | ❌ Delete |
| `agentic_core_win32.h` | `agentic/PlatformWin32.h` | ❌ Delete |
| `agentic_executor.h` | `agentic/Core.h` | ❌ Delete |
| `agentic_bridge.cpp` | `agentic/Bridge.cpp` | ❌ Delete |

---

## Code Migration Examples

### Example 1: Inference Engine Usage

**Before (Fragmented):**
```cpp
// Which one to include? All have different APIs!
#include "cpu_inference_engine.h"
// or
#include "cpu_inference_engine_Clean.h"
// or
#include "cpu_inference_engine_real.h"

// Different initialization patterns
CPUInferenceEngine* engine = new CPUInferenceEngine();
engine->Initialize(config);  // May or may not exist
engine->LoadModel(path);     // Different return types

// Inconsistent method names
engine->generate(prompt);      // Some versions
engine->Generate(prompt);    // Other versions
engine->infer(prompt);       // Yet others
```

**After (Unified):**
```cpp
#include "inference/InferenceEngine.h"

using namespace RawrXD::Inference;

// Single, clear API
auto engine = InferenceEngine::Create(config);
if (!engine->LoadModel(path)) {
    // Handle error
}

// Consistent naming
auto result = engine->Generate(prompt, params);
if (result.success) {
    std::cout << result.text << std::endl;
}
```

### Example 2: Agentic Core Usage

**Before (Fragmented):**
```cpp
// Multiple competing implementations
#include "agentic_engine.h"
AgenticEngine* agent = new AgenticEngine();

// or
#include "agentic_core.h"
AgenticCore* agent = new AgenticCore();

// or
#include "agentic_executor.h"
AgenticExecutor* agent = new AgenticExecutor();

// Inconsistent task submission
agent->SubmitTask(task);           // Some versions
agent->Execute(task);              // Other versions
agent->RunTask(task);              // Yet others
```

**After (Unified):**
```cpp
#include "agentic/Core.h"

using namespace RawrXD::Agentic;

// Single, clear API
auto core = Core::Create(config);
if (!core->Initialize()) {
    // Handle error
}

// Consistent task submission
auto future = core->SubmitTask(task);
auto result = future.get();

// Or synchronous
auto result = core->ExecuteSync(task);
```

### Example 3: Task Creation

**Before (Inconsistent):**
```cpp
// Different task structures in different files
struct AgentTask {
    std::string command;
    std::string args;
    int priority;
};

struct TaskInfo {
    std::string type;
    std::string instruction;
    std::function<void()> callback;
};

struct WorkItem {
    int id;
    std::string name;
    std::vector<std::string> params;
};
```

**After (Unified):**
```cpp
#include "agentic/Core.h"

using namespace RawrXD::Agentic;

// Single Task structure
task.type = TaskType::File;
task.instruction = "Read configuration";
task.priority = TaskPriority::Normal;
task.fileParams.operation = "read";
task.fileParams.path = "config.json";

// Or use convenience methods
std::string content = core->ReadFile("config.json");
```

---

## Build System Migration

### CMakeLists.txt Changes

**Before (Fragmented):**
```cmake
# Multiple build scripts doing similar things
add_executable(RawrXD 
    cpu_inference_engine.cpp          # Which one?
    cpu_inference_engine_fixed.cpp    # All of them?
    agentic_engine.cpp
    agentic_core.cpp                  # Duplicate
    agentic_executor.cpp              # Duplicate
    # ... 50 more files
)
```

**After (Unified):**
```cmake
# Layer 0: HAL
add_library(rxd_hal STATIC
    src/hal/memory.cpp
    src/hal/simd.cpp
)

# Layer 1: GGML
add_library(rxd_ggml STATIC
    src/ggml/ggml.c
    src/ggml/backend.cpp
)
target_link_libraries(rxd_ggml PUBLIC rxd_hal)

# Layer 2: Inference
add_library(rxd_inference STATIC
    src/inference/InferenceEngine.cpp
    src/inference/ModelLoader.cpp
    src/inference/Tokenizer.cpp
    src/inference/Sampler.cpp
)
target_link_libraries(rxd_inference PUBLIC rxd_ggml)

# Layer 3: Agentic
add_library(rxd_agentic STATIC
    src/agentic/Core.cpp
    src/agentic/TaskScheduler.cpp
    src/agentic/ToolRegistry.cpp
    src/agentic/HistoryRecorder.cpp
    src/agentic/PolicyEngine.cpp
)
target_link_libraries(rxd_agentic PUBLIC rxd_inference)

# Layer 4: Executables
add_executable(RawrXD-Win32IDE src/ui/win32/MainWindow.cpp)
target_link_libraries(RawrXD-Win32IDE PRIVATE rxd_agentic)
```

---

## Directory Structure Migration

### Before (Chaotic)
```
src/
├── cpu_inference_engine.h              # 15+ versions
├── cpu_inference_engine.cpp
├── cpu_inference_engine_Clean.h
├── cpu_inference_engine_Clean.cpp
├── cpu_inference_engine_fixed.cpp
├── cpu_inference_engine_init_fix.cpp
├── cpu_inference_engine_production.cpp
├── cpu_inference_engine_real.cpp
├── agentic_engine.h                    # 12+ versions
├── agentic_engine.cpp
├── agentic_core.h
├── agentic_core.cpp
├── agentic_core_win32.h
├── agentic_executor.h
├── agentic_executor.cpp
├── agentic_bridge.cpp
├── ExecutionScheduler.h                # 8+ versions
├── ExecutionScheduler.cpp
├── ExecutionScheduler_v2.h
├── ExecutionScheduler_v2.cpp
├── ExecutionScheduler_PATCH_PLAN.md
└── ... (thousands of files)
```

### After (Organized)
```
src/
├── hal/                                # Layer 0
│   ├── memory.cpp
│   ├── simd.cpp
│   └── thread_primitives.cpp
├── ggml/                               # Layer 1
│   ├── ggml.c
│   ├── backend.cpp
│   └── rxd_extensions.cpp
├── inference/                          # Layer 2
│   ├── InferenceEngine.h               # ✅ Unified
│   ├── InferenceEngine.cpp
│   ├── ModelLoader.cpp
│   ├── Tokenizer.cpp
│   └── Sampler.cpp
├── agentic/                            # Layer 3
│   ├── Core.h                          # ✅ Unified
│   ├── Core.cpp
│   ├── TaskScheduler.cpp
│   ├── ToolRegistry.cpp
│   ├── HistoryRecorder.cpp
│   └── PolicyEngine.cpp
├── ui/                                 # Layer 4a
│   ├── win32/
│   ├── cli/
│   └── common/
└── server/                             # Layer 4b
    ├── HttpServer.cpp
    └── ApiHandlers.cpp
```

---

## Step-by-Step Migration Process

### Phase 1: Preparation (Day 1)

1. **Backup current code**
   ```bash
   git checkout -b coherence-migration
   mkdir .migration-backup
   cp -r src/* .migration-backup/
   ```

2. **Run architecture enforcement script**
   ```bash
   python tools/architecture_enforcement.py
   # Review violations report
   ```

3. **Identify all duplicate implementations**
   ```bash
   # Use the script output to find duplicates
   cat architecture_report.txt | grep "Duplicate"
   ```

### Phase 2: Create Unified Headers (Day 2-3)

1. **Create unified InferenceEngine.h**
   - Review all CPUInferenceEngine implementations
   - Extract common functionality
   - Design clean, consistent API
   - Place in `src/inference/InferenceEngine.h`

2. **Create unified Core.h**
   - Review all AgenticEngine implementations
   - Extract common functionality
   - Design clean, consistent API
   - Place in `src/agentic/Core.h`

### Phase 3: Implement Unified Classes (Day 4-7)

1. **Implement InferenceEngine.cpp**
   - Merge best features from all versions
   - Ensure all tests pass
   - Document any behavioral changes

2. **Implement Core.cpp**
   - Merge best features from all versions
   - Ensure all tests pass
   - Document any behavioral changes

### Phase 4: Update Callers (Day 8-10)

1. **Update all files using old headers**
   ```bash
   # Find all files including old headers
   grep -r "cpu_inference_engine" src/ --include="*.cpp" --include="*.h"
   grep -r "agentic_engine" src/ --include="*.cpp" --include="*.h"
   ```

2. **Replace includes and update code**
   ```cpp
   // Old
   #include "cpu_inference_engine.h"
   CPUInferenceEngine* engine = ...;
   
   // New
   #include "inference/InferenceEngine.h"
   auto engine = RawrXD::Inference::InferenceEngine::Create();
   ```

### Phase 5: Delete Old Files (Day 11)

1. **Remove duplicate implementations**
   ```bash
   git rm src/cpu_inference_engine_Clean.h
   git rm src/cpu_inference_engine_Clean.cpp
   git rm src/cpu_inference_engine_fixed.cpp
   git rm src/cpu_inference_engine_init_fix.cpp
   git rm src/cpu_inference_engine_production.cpp
   git rm src/cpu_inference_engine_real.cpp
   git rm src/agentic_core.h
   git rm src/agentic_core.cpp
   git rm src/agentic_core_win32.h
   git rm src/agentic_executor.h
   git rm src/agentic_executor.cpp
   git rm src/agentic_bridge.cpp
   ```

### Phase 6: Verify (Day 12)

1. **Run full build**
   ```bash
   mkdir build && cd build
   cmake ..
   cmake --build . --parallel
   ```

2. **Run all tests**
   ```bash
   ctest --output-on-failure
   ```

3. **Run architecture enforcement**
   ```bash
   python tools/architecture_enforcement.py
   # Should show 0 violations
   ```

---

## Common Migration Issues

### Issue 1: Different Method Signatures

**Problem:** Old implementations have different signatures
```cpp
// Version A
bool LoadModel(std::string path);

// Version B
int LoadModel(const char* path, int flags);

// Version C
void LoadModel(std::string path, bool validate);
```

**Solution:** Choose most flexible signature
```cpp
// Unified
bool LoadModel(const std::string& path);
bool LoadModel(const std::string& path, const LoadOptions& options);
```

### Issue 2: Different Return Types

**Problem:** Same method, different returns
```cpp
// Version A
std::string Generate(const std::string& prompt);

// Version B
int Generate(const std::string& prompt, std::string& output);

// Version C
struct Result { std::string text; bool success; };
Result Generate(const std::string& prompt);
```

**Solution:** Use result structure
```cpp
struct GenerationResult {
    bool success;
    std::string text;
    std::string errorMessage;
    // ... metrics
};
GenerationResult Generate(const std::string& prompt, const Params& params);
```

### Issue 3: Different State Management

**Problem:** Some versions use singleton, others don't
```cpp
// Version A (singleton)
class CPUInferenceEngine {
    static CPUInferenceEngine* GetInstance();
};

// Version B (unique_ptr)
std::unique_ptr<CPUInferenceEngine> CreateEngine();

// Version C (raw pointer)
CPUInferenceEngine* NewEngine();
```

**Solution:** Use factory pattern
```cpp
class InferenceEngine {
public:
    static std::unique_ptr<InferenceEngine> Create(const Config& config);
    // No singleton - explicit ownership
};
```

---

## Verification Checklist

- [ ] All old headers removed
- [ ] All code uses new unified headers
- [ ] Build succeeds with no warnings
- [ ] All tests pass
- [ ] Architecture enforcement shows 0 violations
- [ ] No duplicate implementations remain
- [ ] Documentation updated
- [ ] Migration guide followed

---

## Rollback Plan

If issues arise:

1. **Immediate rollback:**
   ```bash
   git checkout main
   ```

2. **Selective rollback:**
   ```bash
   git checkout coherence-migration -- src/inference/InferenceEngine.cpp
   ```

3. **Restore from backup:**
   ```bash
   cp -r .migration-backup/* src/
   ```

---

## Summary

This migration consolidates:
- **15+ CPUInferenceEngine implementations** → **1 unified InferenceEngine**
- **12+ AgenticEngine implementations** → **1 unified Core**
- **50+ build scripts** → **1 CMakeLists.txt**
- **Chaos** → **Coherence**

**Estimated effort:** 2 weeks  
**Expected outcome:** Maintainable, coherent architecture
