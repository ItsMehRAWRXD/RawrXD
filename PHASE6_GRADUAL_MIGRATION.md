# Phase 6: Gradual Migration

## Overview

Phase 6 focuses on gradually migrating existing code from legacy interfaces to the new unified Core and InferenceEngine interfaces. This follows the strangler pattern - incrementally replacing legacy usage while maintaining backward compatibility.

## Current Status

✅ **Phases 0-5 Complete**:
- Phase 0: Inventory (51,172 files analyzed)
- Phase 1: Unified Headers (Core.h, InferenceEngine.h)
- Phase 2: Adapter Layer (LegacyCoreAdapter, LegacyInferenceAdapter)
- Phase 3: Connected to Legacy (AgenticEngine, GGMLBackend)
- Phase 4: Integration Testing (verified compilation and linking)
- Phase 5: Production Hardening (ErrorHandling, Logger, Config)

## Phase 6 Goals

1. **Identify Migration Candidates**
   - Find all usages of legacy AgenticEngine
   - Find all usages of legacy CPUInferenceEngine
   - Prioritize by usage frequency and complexity

2. **Create Migration Guides**
   - Document API mappings
   - Provide code transformation examples
   - Create automated migration scripts

3. **Execute Migration**
   - Start with low-risk components
   - Migrate incrementally
   - Maintain backward compatibility

4. **Validate Migration**
   - Ensure functionality preserved
   - Performance benchmarks
   - Regression testing

## Migration Strategy

### Priority Levels

| Priority | Component | Reason |
|----------|-----------|--------|
| P0 | Test files | Low risk, high coverage |
| P1 | Utility functions | Simple mappings |
| P2 | CLI tools | Isolated, easy to test |
| P3 | IDE integration | Complex but well-defined |
| P4 | Core engine | High risk, last to migrate |

### Migration Pattern

```cpp
// BEFORE: Legacy usage
AgenticEngine engine;
engine.initialize();
std::string result = engine.grepFiles("pattern", ".");

// AFTER: Unified interface
auto core = RawrXD::Agentic::Core::Create();
core->Initialize();
RawrXD::Agentic::Task task;
task.type = RawrXD::Agentic::TaskType::Search;
task.searchParams.query = "pattern";
auto future = core->SubmitTask(task);
auto result = future.get();
```

## Migration Guide

### AgenticEngine → Core Migration

| Legacy Method | New API | Notes |
|---------------|---------|-------|
| `initialize()` | `Core::Create()` + `Initialize()` | Use factory pattern |
| `grepFiles()` | `SubmitTask(TaskType::Search)` | Async by default |
| `readFile()` | `SubmitTask(TaskType::File)` | Use fileParams |
| `writeFile()` | `SubmitTask(TaskType::File)` | Use fileParams |
| `listDir()` | `SubmitTask(TaskType::File)` | Use fileParams |
| `executeCommand()` | `SubmitTask(TaskType::Terminal)` | Use terminalParams |
| `chat()` | `SubmitTask(TaskType::Inference)` | Use inferenceParams |
| `isCommandSafe()` | `GetPolicies().ValidateTask()` | Policy engine |

### CPUInferenceEngine → InferenceEngine Migration

| Legacy Method | New API | Notes |
|---------------|---------|-------|
| `GetSharedInstance()` | `InferenceEngine::Create()` | Factory pattern |
| `LoadModel()` | `LoadModel()` | Same signature |
| `Generate()` | `Generate()` | Same signature |
| `Tokenize()` | `Tokenize()` | Same signature |
| `IsModelLoaded()` | `IsModelLoaded()` | Same signature |

## Implementation Plan

### Step 1: Create Migration Scripts
- [ ] Python script to identify legacy usages
- [ ] Automated code transformation tool
- [ ] API compatibility checker

### Step 2: Migrate Test Files
- [ ] Update test_agentic.cpp
- [ ] Update test_inference.cpp
- [ ] Update integration tests

### Step 3: Migrate Utilities
- [ ] Update file operation utilities
- [ ] Update search utilities
- [ ] Update command execution utilities

### Step 4: Migrate CLI Tools
- [ ] Update CLI main functions
- [ ] Update command handlers
- [ ] Update configuration loading

### Step 5: Migrate IDE Integration
- [ ] Update IDE agent bridge
- [ ] Update chat interface
- [ ] Update tool registry integration

### Step 6: Migrate Core Engine
- [ ] Update main entry points
- [ ] Update initialization sequences
- [ ] Final cleanup

## Validation Strategy

### Functional Testing
- All existing tests must pass
- New tests for unified interfaces
- Integration tests for mixed usage

### Performance Testing
- Benchmark before/after migration
- Ensure no regression
- Measure adapter overhead

### Regression Testing
- Full test suite execution
- Manual testing of critical paths
- Long-running stability tests

## Evidence Collection

- Migration logs
- Before/after code comparisons
- Performance benchmarks
- Test results

## Success Criteria

| Criterion | Target | Measurement |
|-----------|--------|-------------|
| Files Migrated | 100% | Count of legacy usages |
| Test Pass Rate | 100% | All tests pass |
| Performance | ±5% | No significant regression |
| Code Coverage | ≥90% | Unified interface usage |

## Next Steps

1. Create migration identification script
2. Start with test file migration
3. Document API mappings
4. Execute incremental migration
5. Validate and benchmark

---

**Phase 6 Status**: Ready to begin gradual migration.
