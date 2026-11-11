# AGENT_RELIABILITY_GAP_MATRIX — Upper-Tier §6 / Batch 20

**Audit:** `UPPER_TIER_MASTER_001_BATCH_20_AUDIT`  
**Scope:** `F:\rawrxd` (read-only)  
**Date:** 2026-11-11  

```
CERTIFIED=0
PROMOTE=0
UPPER_TIER=0
TIP_CLIMB=HOLD
STUB_ACCEPTANCE=FORBIDDEN
SOURCE_WIRED != RUNTIME_REACHED
NOT_RUN != PASS
BATCH_20_MILESTONE=NOT_ACCEPTED
```

## Framing

| Field | Value |
| --- | --- |
| §6 | Agentic reliability (target ≥99% critical-workflow pass rate; prior estimate 48%) |
| Batch 20 workstreams | Tool dispatch, autonomous edits, build/test loop, rollback, cancellation |
| Required milestone | **Agent loop accepted** |
| Prereq | Batch 17 native build unblocked — **G1 FAIL** (no linked Native exe under `build_win32ide\Release`) |

Controlling blocker evidence: `F:\rawrxd\evidence\AGENT_RUNTIME_VALIDATION_001\DISPOSITION.json`.

## Gap matrix

| Dimension | Source wired | Runtime reached | Runtime pass | Disposition |
| --- | --- | --- | --- | --- |
| Tool dispatch fallthrough | Yes (IdeSsot path) | Unknown | No | SOURCE_WIRED_PARTIAL |
| Cancel / stale callback | Yes | Yes (prior candidates) | No | RUNTIME_PASS=0 |
| Atomic edit / rollback | Partial | Unknown | No | MULTI_FILE_TX not product-wired |
| Duplicate tool exec | Yes (per-turn guard) | Partial | No | EXACTLY_ONCE=NOT_VERIFIED |
| Infinite loop bounds | Partial / fragmented | Unknown | No | No product SSOT bounded loop |
| Task-success rates | No suite sealed | Fixture-only | No | Rates unmeasured |

### 1. Tool dispatch fallthrough

**What exists:** `Win32IDE::dispatchAgentTool` → `IdeSsot::DispatchTool` → `ToolCallBridge::ExecuteToolCall`; unknown tools fail closed; `canonicalize_tool_name` maps Cursor/legacy aliases; adversarial probe 13/13 on security gate (`AGENT_TOOLS_ROUTE_WIRE_001`).

**Gaps:** Product Native IDE E2E for unsupported-command non-fallthrough **NOT_RUN** (G1 blocks). `AgenticBridge::StartAgentLoop` only re-chats the same prompt — not a tool dispatch loop. Parallel registries remain outside the IDE SSOT claim.

### 2. Cancel / stale callback

**What exists:** `AgenticLoopBridge` cancel + single-completion fence + reader join before handle dispose; GhostText generation/request_id stale fencing; inference generation atomics.

**Gaps / evidence against PASS:**
- `BATCH1_CANCEL_RECOVERY_001`: `RUNTIME_PASS=0` (crash before Stop/Request B); Gates 04–08 FAIL.
- `F_GHOSTTEXT_CANCEL_ROUTING_CLOSURE_001`: `CANCELLATION=FAIL`, `STALE_FENCING=NOT_VERIFIED`.

### 3. Atomic edit / rollback

**What exists:** `tool_core::write_atomic` (temp + `ReplaceFileW`); `AgentEditHistory` byte restore + `Win32IDE_AgentHistory` snapshot/record path used from AgentCommands.

**Gaps:** `rawr_core` `edit_files` still trunc-writes in place (non-atomic). `multi_file_transaction` **not** in primary `F:\rawrxd\CMakeLists.txt`. Preserve-user / concurrent-agent conflict detection unproven. AF05 still ❌ in `FEATURE_GAP_REGISTER.md` (acceptance lag).

### 4. Duplicate tool exec

**What exists:** `ToolCallExactlyOnceGuard` inside `ExecuteToolCall`; AgentCommands `AGENT_DISPATCH_BUSY` when loop bridge owns dispatch.

**Gaps:** `CHAT_EXACTLY_ONCE_001` → `EXACTLY_ONCE=NOT_VERIFIED`. Per-turn ID dedupe ≠ cross-retry idempotency. Non-SSOT retry stacks may bypass the guard.

### 5. Infinite loop bounds

**What exists:** Scattered caps (`AgenticLoopBridge` maxRetries=2, chat session maxToolIterations=10, react_tool_loop=15, agent_loop.hpp=100). `BoundedAgentLoop.h` (maxSteps=8) is header-only / **not CMake-linked**.

**Gaps:** No single product bounded agent-loop SSOT. `StartAgentLoop(maxIterations)` bounds a non-tool loop. Unified token/time budgets for agent turns unproven.

### 6. Task-success rates

**What exists:** Fixture-level `AGENT_E2E_001` `CANDIDATE_PASS` / `NOT_CERTIFIED`; GUI soak packets; hidden-gap notes that fault injection is often ABSENT.

**Gaps:** No sealed critical-workflow reliability suite; no held-out repo success-rate measurement; **99% target unmeasured** (`NOT_RUN != PASS`). Tracker estimates unchanged pending new runtime acceptance.

## Rollup

- Dimensions audited: **6**
- Dimensions with runtime pass: **0**
- Batch 20 “Agent loop accepted”: **false**
- §6 99% target met: **false**

### Next gates (ordered)

1. Batch 17 G1 — linked `RawrXD-Win32IDE-Native.exe` (exit 0, size + SHA-256).
2. On that SHA: IdeSsot unknown-tool + alias dispatch (prove no fallthrough).
3. Cancel → stale-callback suite (agent + GhostText + chat) `RUNTIME_PASS`.
4. Atomic single-file + multi-file rollback fault injection (zero data-loss).
5. Exactly-once under retry/stress on product SSOT path.
6. Product bounded agent loop SSOT (replace chat-only `StartAgentLoop`).
7. Define and run critical-workflow reliability suite; record measured rates only (do not invent 99%).

## Key path index

| Role | Path |
| --- | --- |
| IDE tool SSOT | `src\win32app\Win32IDE_AgentToolSsot.cpp` |
| Dispatch choke | `src\agentic\IdeToolDispatchSsot.hpp` |
| Exactly-once | `src\agentic\ToolCallExactlyOnceGuard.hpp` |
| Atomic write | `src\agentic\tool_core.hpp` |
| Undo restore | `src\agentic\AgentEditHistory.h`, `src\win32app\Win32IDE_AgentHistory.cpp` |
| Cancel bridge | `src\win32app\Win32IDE_AgenticLoopBridge.cpp` |
| Weak loop | `src\win32app\Win32IDE_AgenticBridge.cpp` (`StartAgentLoop`) |
| Tracker | `evidence\UPPER_TIER_MASTER_001\TRACKER.json` |

Companion machine-readable matrix: `AGENT_RELIABILITY_GAP_MATRIX.json`.
