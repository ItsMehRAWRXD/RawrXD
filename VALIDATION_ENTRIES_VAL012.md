# VAL-012 Validation Entries
## Vertical Slice: Autonomous Loop Closure

**Date:** 2026-07-17  
**Status:** Implementation Complete → Validation Required  
**Approach:** Vertical Slice (not horizontal integration)

---

## Philosophy

Instead of integrating all components horizontally (Planner → Executor → Build → Test → Repair → Memory), we implement a **vertical slice**:

```
Goal
 ↓
Plan
 ↓
Change
 ↓
Build
 ↓
Test
 ↓
Report
```

This proves the concept with minimal complexity before expanding.

---

## VAL-012A: Goal → Plan → Change

**Status:** D → C (In Progress)

**Scope:** First vertical slice milestone

**Evidence Required:**
```
evidence/val-012a/
├── goal.json
├── plan.json
├── changes.json
└── completion.json
```

**Promotion Criteria:**

### D → C (Compile)
- [x] Source exists (`src/val012/`)
- [ ] Compiles without errors
- [ ] Links with existing components
- [ ] Test executable builds

### C → B (Unit Test)
- [ ] Controller instantiates
- [ ] Goal received
- [ ] Plan generated
- [ ] Changes applied
- [ ] Evidence saved

### B → A (Runtime Validation)
- [ ] Real goal processed
- [ ] Deterministic plan produced
- [ ] File changes applied
- [ ] Trace captured
- [ ] Completion.json valid

**Success Criteria:**
```
Input:  "Add --version command"
Output: goal.json + plan.json + changes.json + completion.json
```

---

## VAL-012B: Change → Build

**Status:** Not Started

**Scope:** Add build integration

**Evidence Required:**
```
evidence/val-012b/
├── goal.json
├── plan.json
├── changes.json
├── build.log
├── build.json
└── completion.json
```

**Promotion Criteria:**

### D → C
- [ ] BuildTrigger class exists
- [ ] Compiles

### C → B
- [ ] File changes trigger build
- [ ] Build output captured

### B → A
- [ ] Real build executed
- [ ] Exit code captured
- [ ] Duration measured

**Success Criteria:**
```
File change → cmake --build → build.log
```

---

## VAL-012C: Build → Test

**Status:** Not Started

**Scope:** Add test execution

**Evidence Required:**
```
evidence/val-012c/
├── goal.json
├── plan.json
├── changes.json
├── build.log
├── test.log
├── test.json
└── completion.json
```

**Promotion Criteria:**

### D → C
- [ ] TestRunner class exists
- [ ] Compiles

### C → B
- [ ] Tests execute
- [ ] Results captured

### B → A
- [ ] Real tests run
- [ ] Pass/fail counted
- [ ] Duration measured

**Success Criteria:**
```
Build success → Tests run → test.log
```

---

## VAL-012D: Full Loop

**Status:** Not Started

**Scope:** Complete vertical slice

**Evidence Required:**
```
evidence/val-012/
├── input/
│   └── goal.txt
├── planning/
│   └── plan.json
├── execution/
│   ├── changes.json
│   └── changes.patch
├── validation/
│   ├── build.log
│   ├── build.json
│   ├── test.log
│   └── test.json
├── telemetry/
│   └── events.json
├── completion.json
└── manifest.json
```

**Promotion Criteria:**

### D → C
- [ ] All components compile
- [ ] Controller links

### C → B
- [ ] Mock goal flows through
- [ ] All phases execute
- [ ] Evidence generated

### B → A
- [ ] Real goal processed
- [ ] Files modified
- [ ] Build executed
- [ ] Tests run
- [ ] Completion reported
- [ ] Trace archived

**Success Criteria:**
```
"Add --version command"
  ↓
Plan generated
  ↓
Files modified
  ↓
Build succeeded
  ↓
Tests passed
  ↓
completion.json
```

---

## VAL-015: Test Selection (Moved Up)

**Status:** E → D (Design Complete)

**Priority:** High (moved alongside VAL-012)

**Rationale:** A self-completing IDE without validation is dangerous.

**First Implementation:**
```cpp
class TestSelector {
public:
    std::vector<Test> select(const std::vector<FileChange>& changes) {
        // V1: Filename heuristic
        // "tokenizer.cpp" → "tokenizer_test.cpp"
        
        // V2: Include graph
        // V3: Symbol graph
        // V4: ML-based
    }
};
```

**Evidence:**
```
changes.json
  ↓
test_selection.json
  ↓
selected_tests.json
```

---

## VAL-023: Execution Trace

**Status:** D (Source exists)

**New Validation Entry**

**Purpose:** Every autonomous operation produces reproducible artifact.

**Schema:**
```json
{
  "run_id": "uuid",
  "commit_hash": "abc123",
  "binary_hash": "sha256...",
  "hardware": "x86_64-windows-msvc",
  "goal": {...},
  "plan": {...},
  "changes": [...],
  "build": {...},
  "tests": [...],
  "events": [...],
  "completion": {...}
}
```

**Promotion Criteria:**

### D → C
- [x] Trace schema defined
- [x] Trace writer exists

### C → B
- [ ] Trace compiles
- [ ] Unit test validates serialization

### B → A
- [ ] Real task produces trace
- [ ] Trace validates against schema
- [ ] Trace is reproducible

---

## Revised Completion Order

```
1. VAL-012A
   Goal → Plan → Change
   |
   v
2. VAL-012B
   Change → Build
   |
   v
3. VAL-012C
   Build → Test
   |
   v
4. VAL-023
   Execution Trace
   |
   v
5. VAL-012D
   Full Loop
   |
   v
6. VAL-015
   Test Selection
   |
   v
7. VAL-016
   Repair Loop
   |
   v
8. VAL-017
   Memory Learning
```

---

## Evidence Structure

### Per-Run Evidence

```
evidence/
└── val-012-{timestamp}-{run-id}/
    |
    ├── manifest.json          # Run metadata
    |
    ├── input/
    │   └── goal.json          # User input
    |
    ├── planning/
    │   └── plan.json          # Generated plan
    |
    ├── execution/
    │   ├── changes.json       # Change list
    │   └── changes.patch      # Actual diff
    |
    ├── validation/
    │   ├── build.log          # Raw build output
    │   ├── build.json         # Structured build result
    │   ├── test.log           # Raw test output
    │   └── test.json          # Structured test result
    |
    ├── telemetry/
    │   └── events.json        # State transitions
    |
    └── completion.json        # Final report
```

### Manifest Format

```json
{
  "run_id": "uuid",
  "commit_hash": "54b1d50d5",
  "binary_sha256": "sha256...",
  "source_hash": "sha256...",
  "timestamp": "2026-07-17T18:00:00Z",
  "hardware": "x86_64-windows-msvc",
  "files": [
    "goal.json",
    "plan.json",
    "changes.json",
    "build.log",
    "build.json",
    "test.log",
    "test.json",
    "completion.json",
    "events.json"
  ]
}
```

---

## Success Definition

### VAL-012 Complete When:

```
✓ One autonomous task executes end-to-end
✓ Evidence chain is complete
✓ Trace is reproducible
✓ No human intervention required
✓ Success or graceful failure reported
```

### Not Required for VAL-012:

```
✗ Perfect AI reasoning
✗ Arbitrary task handling
✗ Complex repair strategies
✗ Learning from history
✗ Multi-agent coordination
```

---

## Next Actions

1. **Compile VAL-012A**
   ```
   cd src/val012
   cmake --build .
   ```

2. **Run Test**
   ```
   ./val012_test
   ```

3. **Verify Evidence**
   ```
   ls evidence/val-012-*/
   cat evidence/val-012-*/completion.json
   ```

4. **Promote to A**
   - Real goal processed
   - Trace captured
   - Completion valid

---

*Validation entries track vertical slice progress toward autonomous loop closure.*
