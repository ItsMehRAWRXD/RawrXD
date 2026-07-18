# VAL-012: Autonomous Task Closure

## Validation Record

**Date:** 2026-07-17  
**Status:** 🔄 IN PROGRESS  
**Severity:** Critical Path Blocker  
**Component:** Planner → Executor → Build → Test Loop  
**Scope:** First closed-loop autonomous task with evidence trace

---

## Validation Purpose

VAL-012 is the first **system-level proof** that demonstrates:

```
User Goal → Plan → Execution → Build → Test → Evidence
```

This is not about adding more infrastructure. It is about proving that
existing infrastructure can complete a closed loop.

---

## Current State Snapshot

| Layer | Status | Evidence |
|-------|--------|----------|
| Repository scale | ✅ Proven | 197/197 tensors validated |
| Build infrastructure | ✅ Proven | RawrEngine.exe produces |
| Kernel/runtime pieces | ⚠️ Partially proven | L4.1 pending |
| IDE/editor foundations | ✅ Proven | UI components functional |
| LSP bridge contracts | ✅ Proven | VAL-011 complete |
| Planner implementation | ⚠️ Exists, not autonomous | Plan generation works |
| Executor implementation | ⚠️ Exists, not workflow-connected | Task dispatch works |
| Memory system | ⚠️ Exists, not learning loop | Storage works |
| **Autonomous IDE** | ❌ **Not yet proven** | **VAL-012 target** |

---

## The Control Plane Gap

The remaining work is not a discovery problem. The missing piece is the
**control plane** that connects:

```
Planner ──► Executor ──► Tools ──► Build ──► Test ──► Memory
   ▲                                              │
   └──────────────── Feedback Loop ◄───────────────┘
```

---

## VAL-012 Acceptance Gate

### Required Artifact Structure

```
validation/
└── val-012/
    ├── input/
    │   └── goal.txt              # User goal specification
    │
    ├── planning/
    │   └── plan.json             # Generated plan with tasks
    │
    ├── execution/
    │   ├── trace.json            # Action-by-action execution log
    │   └── changes.patch         # Actual file modifications
    │
    ├── build/
    │   └── build.log             # Build output with success/failure
    │
    ├── testing/
    │   └── test.log              # Test results
    │
    └── result/
        └── completion.json       # Final validation result
```

### completion.json Schema

```json
{
  "validation_id": "VAL-012",
  "goal": "Fix tokenizer off-by-one error",
  "planned": true,
  "files_modified": 1,
  "build_success": true,
  "tests_passed": true,
  "memory_updated": true,
  "evidence_complete": true,
  "status": "COMPLETE"
}
```

---

## Execution Chain

### Phase 1: Planner → Executor Bridge
**Target:** Goal string → Plan object → Executable tasks

**Evidence Required:**
- `planning/plan.json` exists
- Plan contains >= 1 task
- Tasks reference existing tools

### Phase 2: Executor → Existing Tools
**Constraint:** Do not create new tools. Wire existing:
- File operations (read/write/modify)
- Search (grep/semantic)
- Compiler invocation
- Test runner
- Diagnostics capture

**Evidence Required:**
- `execution/trace.json` shows tool invocations
- Each action has start/completed timestamps
- Failures recorded with context

### Phase 3: Evidence Recorder
**Requirement:** Every action emits structured events:

```json
{
  "event_type": "ActionStarted|ActionCompleted|ArtifactProduced|FailureDetected|RecoveryAttempted",
  "timestamp": "2026-07-17T12:00:00Z",
  "action_id": "uuid",
  "tool": "file_modify",
  "inputs": {},
  "outputs": {},
  "duration_ms": 150
}
```

**Purpose:** Turn debugging the autonomous system into debugging a normal pipeline.

### Phase 4: Build/Test Loop
**Initial Rule:** Changed file extension → known test group

**Evidence Required:**
- `build/build.log` shows success/failure
- `testing/test.log` shows pass/fail counts

### Phase 5: Memory Update
**Storage:** Only problem → action → result

**Evidence Required:**
- Memory entry created with task outcome
- Retrievable for future similar tasks

---

## What VAL-012 Does NOT Include

| Out of Scope | Rationale |
|--------------|-----------|
| Perfect planning | Deterministic first, optimize later |
| Broad code understanding | Narrow task, focused scope |
| Autonomous repair of every failure | Log failures, defer recovery |
| Multi-agent debate | Single executor, single task |
| Complex dependency analysis | Extension → test group mapping |
| Abstract memory types | Simple key-value proven first |

---

## Infrastructure vs Autonomous Capability

### Current Classification (Stricter)

```
PlanOrchestrator:
    Infrastructure capability: ✅ yes
    Autonomous capability: ⏳ pending

AgenticExecutor:
    Infrastructure capability: ✅ yes
    Autonomous capability: ⏳ pending

AgenticMemorySystem:
    Infrastructure capability: ✅ yes
    Autonomous capability: ⏳ pending
```

### Product Promise

**Not:** "Contains agent classes"

**Is:** "Can complete engineering tasks"

---

## Recommended Execution Order

### Step 1: Planner → Executor Bridge
**Highest leverage.** Connect goal to executable plan.

### Step 2: Executor → Tool Wiring
Use existing tools. No new tool creation.

### Step 3: Evidence Recorder
Structured logging for every transition.

### Step 4: Build/Test Integration
Extension-based test group selection.

### Step 5: Memory Integration
Simple problem/action/result storage.

---

## Success Criteria

```
User Goal
   |
   v
Planner ──► Plan Generated ──► planning/plan.json ✅
   |
   v
Executor ──► Tasks Executed ──► execution/trace.json ✅
   |
   v
File Modified ──► changes.patch ✅
   |
   v
Build ──► build.log shows success ✅
   |
   v
Test ──► test.log shows pass ✅
   |
   v
Memory ──► result/completion.json ✅
```

**Result:** First autonomous task with artifacts proving every transition.

---

## Sign-off

| Role | Name | Date | Status |
|------|------|------|--------|
| Specification | GitHub Copilot | 2026-07-17 | ✅ Defined |
| Implementation | - | - | 🔄 In Progress |
| Validation | - | - | ⏳ Pending |

---

## Next Milestone

After VAL-012 completes:

```
VAL-012: First Autonomous Task (Narrow)
        |
        v
VAL-013: Multi-Task Sequences
        |
        v
VAL-014: Failure Recovery Patterns
        |
        v
VAL-015: Full IDE Autonomy
```
