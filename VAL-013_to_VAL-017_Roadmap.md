# VAL-013 to VAL-017: Autonomous Engineering Roadmap

## Overview

Following the successful completion of **VAL-012** (first closed-loop autonomous task), this document outlines the recommended progression toward comprehensive autonomous engineering capabilities.

---

## Completed: VAL-012 ✅

**Achievement:** System-level proof that the autonomous workflow can execute successfully under the demonstrated scenario.

**Evidence:** Complete artifact package with goal → plan → execute → build → test → evidence chain.

---

## Recommended Next Steps (Revised Priority)

### VAL-014: Real Toolchain Integration ⭐ HIGHEST PRIORITY
**Priority:** 1 (Immediate)

**Goal:** Replace simulated build/test with actual compiler/test runner invocation.

**Why First:**
Your infrastructure already invokes a real compiler. Leveraging the existing build system provides **much stronger evidence** than additional simulated scenarios.

**Scenario:**
```
Goal: "Fix tokenizer off-by-one error"
Execution:
  1. Modify src/tokenizer.cpp
  2. Invoke: cmake --build build --target RawrEngine
  3. Invoke: ctest -R tokenizer
  4. Capture actual build/test output
```

**Success Criteria:**
- [ ] Real source edits applied
- [ ] Real compiler invoked (not simulated)
- [ ] Real linker invoked
- [ ] Real test runner invoked
- [ ] Actual exit codes captured
- [ ] Compiler diagnostics preserved
- [ ] Reproducible evidence package

**Evidence Required:**
- Compiler version and flags
- Build duration
- Linker output
- Test output with pass/fail counts
- Exit codes (build, test)
- Binary SHA-256 for reproducibility

**Validation Mode:** `regression`

---

### VAL-013: Multi-File Changes
**Priority:** 2 (After VAL-014)

**Goal:** Demonstrate planning and execution across multiple translation units.

**Scenario:**
```
Goal: "Refactor logging system to use structured JSON"
Files affected:
  - src/logging/Logger.hpp (interface change)
  - src/logging/Logger.cpp (implementation)
  - src/core/Diagnostics.cpp (call site updates)
  - tests/logging/test_logger.cpp (test updates)
```

**Success Criteria:**
- [ ] Plan identifies all dependent files
- [ ] Changes applied consistently across files
- [ ] Build succeeds after multi-file modification
- [ ] Tests pass for all affected components

**Evidence Required:**
- Dependency graph showing file relationships
- Cross-file change consistency check
- Build log showing all files compiled

---

### VAL-014: Real Toolchain Integration
**Priority:** 2 (Near-term)

**Goal:** Replace simulated build/test with actual compiler/test runner invocation.

**Scenario:**
```
Goal: "Fix tokenizer off-by-one error"
Execution:
  1. Modify src/tokenizer.cpp
  2. Invoke: cmake --build build --target RawrEngine
  3. Invoke: ctest -R tokenizer
  4. Capture actual build/test output
```

**Success Criteria:**
- [ ] Real compiler invoked (not simulated)
- [ ] Actual build output captured
- [ ] Real test runner invoked
- [ ] Exit codes verified
- [ ] Duration metrics captured

**Evidence Required:**
- Compiler version and flags
- Build duration
- Test output with pass/fail counts
- Binary SHA-256 for reproducibility

---

### VAL-015: Intelligent Test Selection
**Priority:** 3 (Performance optimization)

**Goal:** Use changed files/symbols to select only relevant tests.

**Scenario:**
```
Goal: "Optimize matrix multiplication kernel"
Changed: src/kernels/matmul.cpp
Analysis:
  - Affects: test_matmul, test_inference, test_benchmark
  - Does NOT affect: test_tokenizer, test_parser
Selection:
  - Run: test_matmul, test_inference
  - Skip: test_tokenizer, test_parser
```

**Success Criteria:**
- [ ] Symbol dependency analysis implemented
- [ ] Test selection precision > 90%
- [ ] Test selection recall = 100% (no relevant tests skipped)
- [ ] Time saved vs. full suite measured

**Evidence Required:**
- Dependency analysis output
- Selected vs. skipped test lists
- Precision/recall metrics
- Time comparison (selected vs. full)

---

### VAL-016: Autonomous Repair (Major Capability Jump)
**Priority:** 4 (Largest capability gain)

**Goal:** Demonstrate recovery from build/test failures without human intervention.

**Scenario:**
```
Goal: "Add bounds checking to tokenizer"
Attempt 1:
  - Modify src/tokenizer.cpp
  - Build: FAIL (undefined reference to std::clamp)
  
Diagnosis:
  - Missing #include <algorithm>
  
Repair:
  - Add missing include
  
Attempt 2:
  - Build: SUCCESS
  - Test: FAIL (bounds off by one)
  
Diagnosis:
  - Condition should be >= not >
  
Repair:
  - Fix condition
  
Attempt 3:
  - Build: SUCCESS
  - Test: SUCCESS
  - Evidence: Complete
```

**Success Criteria:**
- [ ] Build failure detected and diagnosed
- [ ] Repair proposed and applied
- [ ] Rebuild attempted
- [ ] Test failure detected and diagnosed
- [ ] Repair proposed and applied
- [ ] Final verification passes

**Evidence Required:**
- Failure detection log
- Diagnosis output
- Repair proposal (diff)
- Retry loop evidence
- Final success confirmation

**Why This Matters:**
VAL-016 demonstrates **recovery**, not just successful execution. This is the core capability that distinguishes autonomous engineering from simple automation.

---

### VAL-017: Multi-Agent Debate
**Priority:** 5 (Advanced coordination)

**Goal:** Multiple agents propose competing solutions with evaluation and selection.

**Scenario:**
```
Goal: "Optimize memory allocation strategy"
Agent A Proposal:
  - Approach: Pool allocator
  - Estimated benefit: 15% faster
  - Risk: Fragmentation

Agent B Proposal:
  - Approach: Arena allocator
  - Estimated benefit: 20% faster
  - Risk: Lifetime complexity

Evaluation:
  - Both approaches prototyped
  - Benchmarked against baseline
  - Agent B selected (higher benefit)

Execution:
  - Implement arena allocator
  - Verify benchmarks
```

**Success Criteria:**
- [ ] Multiple agents generate proposals
- [ ] Evaluation criteria defined
- [ ] Prototypes executed
- [ ] Selection rationale captured
- [ ] Final implementation verified

**Evidence Required:**
- Multiple proposal diffs
- Evaluation scores
- Benchmark results
- Selection rationale
- Final implementation

---

## Summary Progression

```
VAL-012 ✅  Single-file change, simulated build/test
    |
    v
VAL-013     Multi-file changes, dependency awareness
    |
    v
VAL-014     Real toolchain integration
    |
    v
VAL-015     Intelligent test selection (performance)
    |
    v
VAL-016 🎯  Autonomous repair (MAJOR CAPABILITY)
    |
    v
VAL-017     Multi-agent debate (coordination)
```

**Key Insight:**
The largest capability jump is **VAL-016** (autonomous repair). Prior validations (013-015) build the infrastructure needed for reliable repair loops. VAL-017 adds coordination sophistication.

**Recommended Focus:**
1. Complete VAL-013 (multi-file) for realistic scenarios
2. Complete VAL-014 (real toolchain) for trustworthy evidence
3. **Prioritize VAL-016** (autonomous repair) for core capability demonstration
4. VAL-015 and VAL-017 can proceed in parallel

---

## Evidence Quality Evolution

| Validation | Evidence Quality | Reproducibility |
|------------|------------------|-----------------|
| VAL-012 | Integration validation | Manual verification |
| VAL-013 | Multi-file tracking | Git + build logs |
| VAL-014 | Real toolchain | Compiler version + flags |
| VAL-015 | Performance metrics | Duration + selection criteria |
| VAL-016 | Recovery traces | Failure → diagnosis → repair loop |
| VAL-017 | Decision rationale | Multiple proposals + evaluation |

---

## Success Metrics

**VAL-012 → VAL-016 Progression:**
- **From:** Single scenario, simulated execution
- **To:** Multiple scenarios, real execution, autonomous recovery

**Confidence Increase:**
- VAL-012: "System can execute a workflow"
- VAL-016: "System can recover from failures and complete tasks autonomously"

**Engineering Value:**
- VAL-012: Proof of concept
- VAL-016: Production-ready autonomous capability

---

*Document Version: 1.0*  
*Date: 2026-07-17*  
*Status: Roadmap defined, awaiting implementation*
