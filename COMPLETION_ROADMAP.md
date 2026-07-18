# RawrXD Completion Roadmap
## From Infrastructure to Autonomy

**Date:** 2026-07-17  
**Current State:** Infrastructure Complete → Integration Required  
**Next Milestone:** VAL-012 (Autonomous Loop Closure)

---

## Executive Summary

RawrXD has **4,076 C++ files** and **1.67M lines of code** across infrastructure, agents, planners, and memory systems. The project has achieved **implementation breadth** but lacks **integration depth**.

**The Problem:** Components exist in isolation. The autonomy loop is not closed.

**The Solution:** Stop adding subsystems. Start connecting existing ones.

---

## Current State (Evidence-Based)

### What Exists (D/C Level)

| Component | Files | Status | Evidence |
|-----------|-------|--------|----------|
| Core IDE | 1,200+ | ✅ Built | Executables exist |
| Build System | 89 CMake | ✅ Working | 324 binaries |
| Inference | 800+ | ⚠️ Partial | GGUF pipeline |
| Planner | PlanOrchestrator | ✅ Source | Simulated LLM |
| Executor | AgenticExecutor | ✅ Source | Methods exist |
| Memory | AgenticMemorySystem | ✅ Source | Storage works |
| Recovery | ErrorRecoverySystem | ✅ Source | Framework only |
| Tests | 414 files | ✅ Present | No auto-selection |

### What's Missing (Integration)

```
Planner → Executor     ❌ Not connected
Executor → Build       ❌ Not connected
Build → Test Selection ❌ Not connected
Test → Repair          ❌ Not connected
Repair → Memory        ❌ Not connected
```

---

## The Finish Line

### Definition of "Done"

A single autonomous task executes end-to-end:

```
User: "Fix the off-by-one error"
    ↓
Planner creates plan
    ↓
Executor locates code
    ↓
Changes made
    ↓
Build triggered
    ↓
Tests selected & run
    ↓
Success reported
```

**Evidence Required:**
- `goal.txt` - Input
- `plan.json` - Generated plan
- `changes.patch` - Code modifications
- `build.log` - Build output
- `test.log` - Test results
- `completion.json` - Final report

---

## Implementation Plan

### Phase 1: Integration Sprint (4 Weeks)

#### Week 1: Planner → Executor Bridge
**Deliverable:** `PlannerExecutorBridge` compiles and runs

**Files:**
- `src/integration/planner_executor_bridge.h`
- `src/integration/planner_executor_bridge.cpp`
- `tests/integration/val_012_autonomous_loop.cpp`

**Success:**
```cpp
PlannerExecutorBridge bridge(
    &planner, &executor, &errorRecovery, &memory);
auto result = bridge.executeGoal("Fix tokenizer");
// result.trace saved to evidence/
```

#### Week 2: Build Integration
**Deliverable:** File changes trigger builds

**Integration Point:**
```cpp
class BuildTrigger {
    BuildResult onFilesModified(const std::vector<FileChange>& changes);
};
```

**Success:**
- Modify file → Build runs automatically
- Build output captured in trace

#### Week 3: Test Selection
**Deliverable:** Tests selected based on changes

**Integration Point:**
```cpp
class TestSelector {
    std::vector<Test> selectTests(const BuildResult& build);
};
```

**Success:**
- Changed files → Relevant tests identified
- Tests execute
- Results captured

#### Week 4: Failure Recovery
**Deliverable:** Automatic repair attempts

**Integration Point:**
```cpp
class FailureRepair {
    RepairAttempt repair(const TestFailure& failure);
};
```

**Success:**
- Test fails → Repair attempted
- Fix applied → Rebuild triggered
- Outcome recorded

---

## Validation Entries

### VAL-012: Autonomous Loop Closure

**Status:** In Progress

**Evidence:**
- [x] Source exists (`src/integration/`)
- [x] Compiles (when built)
- [ ] Executes (pending)
- [ ] Proven (pending)

**Promotion Criteria:**
```
✓ Bridge instantiates
✓ Goal received
✓ Plan generated
✓ Steps execute
✓ Evidence captured
✓ Trace saved
```

### VAL-013: Build Integration

**Status:** Not Started

**Promotion Criteria:**
```
✓ File change detected
✓ Build triggered automatically
✓ Output captured
✓ Exit code propagated
```

### VAL-014: Test Selection

**Status:** Not Started

**Promotion Criteria:**
```
✓ Code-to-test mapping exists
✓ Changed files → test selection
✓ Tests execute
✓ Results captured
```

### VAL-015: Failure Recovery

**Status:** Not Started

**Promotion Criteria:**
```
✓ Failure classified
✓ Repair template selected
✓ Fix applied
✓ Rebuild triggered
✓ Success verified
```

---

## Stop Doing / Start Doing

### Stop Doing (Subsystem Freeze)

- ❌ Adding new agent roles
- ❌ Adding new memory types
- ❌ Adding new planner features
- ❌ Adding new build targets
- ❌ Adding new test frameworks
- ❌ Adding new inference kernels
- ❌ Adding new GPU backends

### Start Doing (Integration Focus)

- ✅ Connect Planner to Executor
- ✅ Trigger builds on changes
- ✅ Select tests automatically
- ✅ Attempt repairs
- ✅ Record outcomes
- ✅ Close the loop

---

## Evidence Collection

Every integration point produces:

```
evidence/
└── val-012/
    ├── goal.txt           # Input
    ├── plan.json          # Generated plan
    ├── trace.json         # Execution trace
    ├── build.log          # Build output
    ├── test.log           # Test results
    └── completion.json    # Final report
```

---

## Success Metrics

### Week 1
- [ ] `PlannerExecutorBridge` compiles
- [ ] Bridge instantiates without errors
- [ ] Goal flows through to execution
- [ ] Evidence saved to disk

### Week 2
- [ ] File changes trigger builds
- [ ] Build output captured
- [ ] No manual intervention required

### Week 3
- [ ] Tests selected based on changes
- [ ] Relevant tests identified correctly
- [ ] Test results captured

### Week 4
- [ ] Test failures trigger repair
- [ ] Repair attempted automatically
- [ ] Outcome recorded in memory

### Final Milestone
- [ ] One complete autonomous task
- [ ] Evidence chain complete
- [ ] No human intervention
- [ ] Success or graceful failure

---

## Risk Mitigation

### Risk: Integration harder than expected
**Mitigation:** Focus on minimal viable connections first

### Risk: Components don't fit together
**Mitigation:** Create adapter layer, don't modify components

### Risk: Build system too complex
**Mitigation:** Use existing CMake targets, don't add new ones

### Risk: Tests don't map to changes
**Mitigation:** Start with file-name-based matching

---

## Conclusion

**RawrXD has the pieces. The work remaining is integration, not implementation.**

**The finish line:** One autonomous task, end-to-end, with evidence.

**Not the finish line:** Another 100k lines of infrastructure.

**Next action:** Implement `PlannerExecutorBridge` and run VAL-012.

---

*Roadmap created based on audit evidence showing infrastructure complete but autonomy loop open.*
