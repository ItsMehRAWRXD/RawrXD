# Phase 2: Adapter Layer Implementation Plan

**Date:** 2026-07-08  
**Status:** 🚧 PLANNING  
**Goal:** Create adapter layer for gradual migration from legacy code to new unified APIs

---

## Overview

Phase 1 gave us compiling headers and stub implementations. Phase 2 will create an **adapter layer** that:

1. Wraps existing working code behind the new unified interfaces
2. Allows gradual migration without breaking existing functionality
3. Provides a bridge between old and new implementations

---

## Adapter Pattern

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Code                         │
│                      (Uses new API)                         │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                  Unified Interface                          │
│              (Core.h / InferenceEngine.h)                   │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                  Adapter Layer                              │
│         (Wraps legacy code, implements new interface)       │
└───────────────────────┬─────────────────────────────────────┘
                        │
            ┌───────────┴───────────┐
            ▼                       ▼
┌─────────────────────┐   ┌─────────────────────┐
│   Legacy Code        │   │   New Code          │
│   (Still works)      │   │   (Gradually        │
│                      │   │    replaces legacy) │
└─────────────────────┘   └─────────────────────┘
```

---

## Phase 2 Tasks

### Task 1: LegacyCoreAdapter

**File:** `src/agentic/LegacyCoreAdapter.h` and `.cpp`

**Purpose:** Implement the `Core` interface by delegating to existing working agentic code.

**Implementation Strategy:**
```cpp
class LegacyCoreAdapter : public Core {
public:
    // Constructor takes existing agentic components
    LegacyCoreAdapter(ExistingAgenticEngine* engine);
    
    // Implement Core interface by delegating
    bool Initialize() override { 
        return m_legacyEngine->Initialize(); 
    }
    
    std::future<TaskResult> SubmitTask(const Task& task) override {
        // Convert Task to legacy format
        // Submit to legacy engine
        // Convert result back
    }
    
    // ... other methods
    
private:
    ExistingAgenticEngine* m_legacyEngine;
};
```

**Acceptance Criteria:**
- [ ] Implements all `Core` interface methods
- [ ] Compiles without errors
- [ ] Can be instantiated with existing agentic engine
- [ ] Basic task execution works

---

### Task 2: LegacyInferenceAdapter

**File:** `src/inference/LegacyInferenceAdapter.h` and `.cpp`

**Purpose:** Implement the `InferenceEngine` interface by delegating to existing working inference code.

**Implementation Strategy:**
```cpp
class LegacyInferenceAdapter : public InferenceEngine {
public:
    // Constructor takes existing inference engine
    LegacyInferenceAdapter(ExistingCPUInference* engine);
    
    // Implement InferenceEngine interface
    bool LoadModel(const std::string& path) override {
        return m_legacyEngine->LoadModel(path);
    }
    
    GenerationResult Generate(const std::string& prompt, 
                               const GenerationParams& params) override {
        // Convert params to legacy format
        // Call legacy generate
        // Convert result back
    }
    
    // ... other methods
    
private:
    ExistingCPUInference* m_legacyEngine;
};
```

**Acceptance Criteria:**
- [ ] Implements all `InferenceEngine` interface methods
- [ ] Compiles without errors
- [ ] Can load and run models through legacy code
- [ ] Performance matches direct legacy usage

---

### Task 3: Factory Integration

**File:** Modify `src/agentic/Core.cpp` and `src/inference/InferenceEngine.cpp`

**Purpose:** Add factory methods that create adapter instances.

**Implementation:**
```cpp
// In Core.cpp
std::unique_ptr<Core> Core::CreateLegacyAdapter(ExistingAgenticEngine* engine) {
    return std::make_unique<LegacyCoreAdapter>(engine);
}

// In InferenceEngine.cpp
std::unique_ptr<InferenceEngine> InferenceEngine::CreateLegacyAdapter(
    ExistingCPUInference* engine) {
    return std::make_unique<LegacyInferenceAdapter>(engine);
}
```

**Acceptance Criteria:**
- [ ] Factory methods added to headers
- [ ] Factory methods implemented
- [ ] Can create adapters from existing code
- [ ] No memory leaks

---

### Task 4: Migration Helper

**File:** `tools/migrate_to_unified_api.py`

**Purpose:** Automated tool to help migrate existing code to new API.

**Features:**
- Find all usages of legacy agentic/inference APIs
- Generate migration patches
- Report migration progress
- Identify blocking issues

**Usage:**
```bash
python tools/migrate_to_unified_api.py --scan src/
python tools/migrate_to_unified_api.py --generate-patch src/some_file.cpp
```

**Acceptance Criteria:**
- [ ] Scans codebase for legacy API usage
- [ ] Generates accurate migration patches
- [ ] Reports statistics on migration progress
- [ ] Handles edge cases gracefully

---

## Migration Strategy

### Step 1: Identify Legacy Code
Find all files using:
- `AgenticEngine` (old name)
- `CPUInferenceEngine` (old name)
- Direct GGML calls outside Layer 1

### Step 2: Create Adapters
Build adapters that wrap existing code without modifying it.

### Step 3: Migrate Callers
Update callers to use new unified API through adapters.

### Step 4: Replace Implementations
Gradually replace adapter internals with new implementations.

### Step 5: Remove Adapters
Once all code uses new implementations, remove adapters.

---

## Timeline

| Task | Estimate | Priority |
|------|----------|----------|
| LegacyCoreAdapter | 4-6 hours | High |
| LegacyInferenceAdapter | 4-6 hours | High |
| Factory Integration | 2 hours | Medium |
| Migration Helper | 4-8 hours | Low |
| **Total Phase 2** | **14-22 hours** | |

---

## Success Criteria

Phase 2 is complete when:

1. ✅ Adapters compile and work with existing code
2. ✅ At least one subsystem migrated to use new API
3. ✅ No regression in functionality
4. ✅ Migration path documented
5. ✅ Performance within 5% of legacy

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Legacy code too tightly coupled | Create smaller, focused adapters |
| Performance regression | Benchmark before/after, optimize hot paths |
| Breaking changes | Maintain backward compatibility layer |
| Migration takes too long | Prioritize critical paths, defer edge cases |

---

## Next Steps

1. **Start Task 1:** Create LegacyCoreAdapter
2. **Identify existing code:** Find working agentic/inference implementations
3. **Build first adapter:** Wrap simplest subsystem first
4. **Test thoroughly:** Ensure no regressions
5. **Document:** Update migration guide

---

**Ready to start Phase 2?** 🚀
