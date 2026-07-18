# RawrXD Integration Validation Plan
## From Infrastructure to Autonomy

**Date:** 2026-07-17  
**Status:** Infrastructure Complete → Integration Required  
**Goal:** Prove autonomous workflow with existing components

---

## The Realization

RawrXD has accumulated **systems**, but the product requirement is a **closed workflow**.

### Current State (Evidence-Based)

| Area | Infrastructure | Integration | Proof |
|------|---------------|-------------|-------|
| Codebase | 4,076 C++ files, 1.67M LOC | ❌ | ❌ |
| Build System | 324 executables, 89 CMake files | ✅ | ✅ |
| Inference | GGUF pipeline, kernels | ⚠️ | ❌ |
| Agent Components | Planner, Executor, Memory | ❌ | ❌ |
| Autonomous Loop | Components exist | ❌ | ❌ |

**Conclusion:** The last 20% (integration) defines the product.

---

## Validation Strategy: Freeze & Integrate

### Phase 1: Component Freeze (Immediate)

**Rule:** No new subsystems. Only integration code.

**Existing Components to Connect:**

```
PlanOrchestrator (src/plan_orchestrator.cpp)
    ↓ CONNECT
AgenticExecutor (src/agentic_executor.cpp)
    ↓ CONNECT
BuildTaskProvider (src/build_system/)
    ↓ CONNECT
TestRunner (tests/)
    ↓ CONNECT
ErrorRecoverySystem (src/error_recovery_system.cpp)
    ↓ CONNECT
AgenticMemorySystem (src/agentic_memory_system.cpp)
```

---

## VAL-012: Autonomous Bug Fix (Target Milestone)

### Scope

**Goal:** Fix a real bug in RawrXD autonomously.

**Input:**
```
"Fix the off-by-one error in the tokenizer"
```

**Required Evidence Chain:**

```
1. GOAL_RECEIVED
   └── goal.txt
       "Fix the off-by-one error in the tokenizer"

2. PLAN_GENERATED
   └── plan.json
       {
         "steps": [
           "Locate tokenizer source",
           "Identify off-by-one pattern",
           "Generate fix",
           "Build",
           "Run tokenizer tests",
           "Verify fix"
         ]
       }

3. CODE_LOCATED
   └── search_results.json
       {
         "files": ["src/tokenizer.cpp"],
         "symbols": ["Tokenize", "BPEMerge"],
         "lines": [45, 128]
       }

4. CHANGES_MADE
   └── changes.patch
       --- a/src/tokenizer.cpp
       +++ b/src/tokenizer.cpp
       @@ -45,7 +45,7 @@
       -  for (int i = 0; i <= len; i++)
       +  for (int i = 0; i < len; i++)

5. BUILD_EXECUTED
   └── build.log
       [cmake] Success
       [ninja] Success
       Exit code: 0

6. TESTS_RUN
   └── test.log
       Tests: 47
       Passed: 47
       Failed: 0

7. COMPLETION_REPORT
   └── completion.json
       {
         "success": true,
         "files_modified": 1,
         "tests_passed": 47,
         "execution_time_ms": 45000
       }
```

---

## Integration Points to Implement

### Point 1: Planner → Executor

**Current Gap:**
```cpp
// PlanOrchestrator creates plan
// AgenticExecutor executes tasks
// NO CONNECTION between them
```

**Integration Code Needed:**
```cpp
// src/integration/planner_executor_bridge.cpp

class PlannerExecutorBridge {
public:
    AutonomousExecutionResult executePlan(const Plan& plan) {
        for (const auto& step : plan.steps) {
            auto result = executor_.execute(step);
            if (!result.success) {
                auto repair = errorRecovery_.attemptRepair(result);
                if (!repair.success) {
                    memory_.recordFailure(plan, step, result);
                    return failure(result);
                }
            }
            memory_.recordProgress(plan, step, result);
        }
        return success(plan);
    }
};
```

**Evidence Required:**
- [ ] Bridge compiles
- [ ] Bridge executes
- [ ] Plan flows from Planner to Executor
- [ ] Results flow back

---

### Point 2: Executor → Build System

**Current Gap:**
```cpp
// AgenticExecutor modifies files
// BuildTaskProvider builds
// NO AUTOMATIC TRIGGER
```

**Integration Code Needed:**
```cpp
// src/integration/build_trigger.cpp

class BuildTrigger {
public:
    BuildResult onFilesModified(const std::vector<FileChange>& changes) {
        auto affectedTargets = buildGraph_.getAffectedTargets(changes);
        return buildTaskProvider_.build(affectedTargets);
    }
};
```

**Evidence Required:**
- [ ] File changes trigger build
- [ ] Build output captured
- [ ] Exit code propagated

---

### Point 3: Build → Test Selection

**Current Gap:**
```cpp
// Build succeeds
// Tests exist (414 files)
// NO AUTOMATIC SELECTION
```

**Integration Code Needed:**
```cpp
// src/integration/test_selector.cpp

class TestSelector {
public:
    std::vector<Test> selectTests(const BuildResult& build) {
        auto changedFiles = build.getChangedFiles();
        auto affectedTests = codeToTestMap_.findTests(changedFiles);
        return affectedTests.empty() 
            ? runAllTests() 
            : affectedTests;
    }
};
```

**Evidence Required:**
- [ ] Code-to-test mapping exists
- [ ] Changed files → test selection
- [ ] Tests execute
- [ ] Results captured

---

### Point 4: Test Failure → Repair

**Current Gap:**
```cpp
// Tests fail
// ErrorRecoverySystem exists
// NO AUTOMATIC REPAIR ATTEMPT
```

**Integration Code Needed:**
```cpp
// src/integration/failure_repair.cpp

class FailureRepair {
public:
    RepairAttempt repair(const TestFailure& failure) {
        auto pattern = failureAnalyzer_.classify(failure);
        auto fix = repairTemplates_.getFix(pattern);
        if (fix) {
            return applyFix(fix, failure);
        }
        return cannotRepair(failure);
    }
};
```

**Evidence Required:**
- [ ] Failure classification works
- [ ] Repair templates exist
- [ ] Fix applied automatically
- [ ] Rebuild triggered

---

### Point 5: Repair → Memory

**Current Gap:**
```cpp
// Repair attempted
// AgenticMemorySystem exists
// NO LEARNING LOOP
```

**Integration Code Needed:**
```cpp
// src/integration/learning_loop.cpp

class LearningLoop {
public:
    void recordRepair(const RepairAttempt& repair, bool success) {
        MemoryEntry entry;
        entry.type = MemoryType::Procedure;
        entry.content = repair.toJson();
        entry.metadata = success ? "successful" : "failed";
        memorySystem_.storeMemory(entry);
    }
};
```

**Evidence Required:**
- [ ] Repair stored in memory
- [ ] Retrieved on similar failures
- [ ] Improves over time

---

## Implementation Priority

### Week 1: Bridge Planner → Executor
**Goal:** Close the first gap.

**Deliverable:**
```
Input: "Fix tokenizer"
Output: plan.json + execution trace
```

### Week 2: Connect Build & Test
**Goal:** Changes trigger build and test.

**Deliverable:**
```
File change → Build → Test selection → Test execution
```

### Week 3: Add Failure Recovery
**Goal:** Handle at least one failure type.

**Deliverable:**
```
Test failure → Analysis → Repair attempt → Rebuild
```

### Week 4: Close Memory Loop
**Goal:** Learn from repairs.

**Deliverable:**
```
Repair → Store → Retrieve on similar failure
```

---

## Success Criteria

### Minimum Viable Autonomy

```
✅ One complete autonomous task
✅ Evidence chain captured
✅ No human intervention required
✅ Success or graceful failure reported
```

### Full VAL-012 Completion

```
✅ Goal received
✅ Plan generated
✅ Files located
✅ Changes made
✅ Build succeeded
✅ Tests passed
✅ Memory updated
✅ Report generated
```

---

## Stop Doing / Start Doing

### Stop Doing
- [ ] Adding new agent roles
- [ ] Adding new memory types
- [ ] Adding new planner features
- [ ] Adding new build targets
- [ ] Adding new test frameworks

### Start Doing
- [ ] Connecting Planner to Executor
- [ ] Triggering builds on changes
- [ ] Selecting tests automatically
- [ ] Attempting repairs
- [ ] Recording outcomes

---

## Evidence Collection

Every integration point must produce:

```
integration_point/
├── source/           # Integration code
├── build.log        # Compilation evidence
├── execution.log    # Runtime evidence
├── test.log         # Validation evidence
└── trace.json       # Complete execution trace
```

---

## Conclusion

RawrXD has the components. The work remaining is **integration, not implementation**.

**The finish line:** One autonomous task, end-to-end, with evidence.

**Not the finish line:** Another 100k lines of infrastructure.

---

*Plan created based on audit evidence showing infrastructure complete but autonomy loop open.*
