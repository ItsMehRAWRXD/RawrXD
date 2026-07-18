# Build Recovery Plan - Phase 1: Restore Build Health

## Current State (2026-07-16)

**Target**: RawrEngine  
**Status**: ❌ Build Failing  
**Blocking Issues**: 4 categories

## Critical Errors

### 1. Missing Header File
```
tier1_handlers_stubs.cpp(6): fatal error C1083: 
Cannot open include file: '../core/command_dispatch.h'
```
**Fix**: Create missing header or fix include path

### 2. Template Instantiation Error
```
gpudispatchgate_stubs.cpp(29): error C2946: 
explicit instantiation; 'RawrXD::GPUDispatchGate' is not a template-class specialization
```
**Fix**: Remove invalid template instantiation syntax

### 3. Container Iteration Error
```
subsystem_registry.cpp(22): error C2039: 
'rbegin': is not a member of 'std::unordered_map'
```
**Fix**: `std::unordered_map` doesn't support reverse iteration - use forward iteration

### 4. Duplicate Function Definitions
```
command_handlers.cpp(1131): error C2084: 
function 'RawrXD::handleVSCodeExtList' already has a body
```
**Fix**: Remove duplicate function implementations

## Recovery Steps

### Step 1: Fix subsystem_registry.cpp
- Replace `rbegin()`/`rend()` with `begin()`/`end()`
- Or use proper reverse iteration technique

### Step 2: Fix command_handlers.cpp
- Identify and remove duplicate function definitions
- Likely copy-paste error or merge conflict

### Step 3: Fix gpudispatchgate_stubs.cpp
- Remove invalid template instantiation
- Check if class is actually a template

### Step 4: Fix tier1_handlers_stubs.cpp
- Create missing `command_dispatch.h` header
- Or correct the include path

## Verification

After each fix:
```bash
cmake --build build-ninja --target RawrEngine 2>&1 | grep -E "(error|warning|FAILED)"
```

## Success Criteria

- [ ] Zero compile errors
- [ ] Zero linker errors (LNK2001/LNK2019/LNK1120)
- [ ] RawrEngine binary produced
- [ ] Binary runs without crashing

## Phase 9 Integration (After Build Health)

Once build is stable:
1. Integrate health_checks.cpp
2. Integrate prometheus_metrics.cpp
3. Integrate log_aggregation.cpp
4. Integrate distributed_tracing.cpp
5. Integrate config_management.cpp

Each with full compile → link → test → verify cycle.
