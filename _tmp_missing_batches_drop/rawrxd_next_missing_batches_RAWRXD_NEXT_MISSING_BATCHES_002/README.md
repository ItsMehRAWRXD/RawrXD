# RAWRXD_NEXT_MISSING_BATCHES_002

Dependency-free C++20 / PowerShell source drop for the next RawrXD closure sequence.

This drop intentionally **does not re-implement** the preceding `RAWRXD_NEXT_CLOSURE_BATCHES_001` work you supplied (`MODEL_IDENTITY`, `AUTOCLOSURE_TOOL_AUTHORITY`, `MOE_SOFTMAX_WEIGHT`).

## Batches in this drop

### 1. `RAWRXD_GPT_OSS_SPECIAL_GRAPH_001`
### 2. `RAWRXD_LAGUNA_SPECIAL_GRAPH_001`
### 3. `RAWRXD_DEEPSEEK4_SPECIAL_GRAPH_001`

Files:

- `src/deep2/special_graph/FleetSpecialGraph.hpp/.cpp`
- `src/deep2/special_graph/FleetSpecialGraphExecutor.hpp/.cpp`

What it closes:

- native graph IR for embedding → attention/MLA → MoE → residual → final norm → LM head → logits;
- family-specific graph construction;
- deterministic node ordering and validation;
- executable node dispatcher with a fail-closed first-error boundary;
- per-family receipts proving every planned graph node reached its backend callback and final logits.

Current RawrXD fleet-contract values used without invention:

- GPT-OSS: 36 layers, 128 routed experts, top-4, 131072 context;
- Laguna S 2.1: 48 layers, 256 routed experts, top-10, 1 shared expert, 8 KV heads, head dim 128, 1048576 context;
- DeepSeek V4 Flash: 1000000 context and MLA graph family; layer/expert geometry is **not guessed**. It must come from admitted runtime metadata. Missing geometry fails closed.

The executor callback is the intended seam to the existing Deep2 CPU/Vulkan graph operations. The source-only selftest uses a callback that records execution; it is **not** a shipping-GPU inference claim.

---

### 4. `RAWRXD_DUAL_GPU_INDEPENDENT_AGENT_001`

Files:

- `src/agentic/DualGpuIndependentAgentScheduler.hpp/.cpp`

What it closes:

- explicit primary/secondary GPU binding;
- independent model contexts;
- optional strict requirement that the two agents use distinct devices;
- one shared Tool Authority cookie/identity;
- bounded cross-agent message queue;
- clean secondary-GPU-unavailable behavior;
- receipt fields for context/device independence and actual run/message counts.

Integration seam:

- bind the context factory to Deep2 context creation with explicit Vulkan device ordinal;
- pass the canonical `AgentToolRegistry`/Tool Authority identity in `sharedToolAuthority`;
- do not share KV/context pointers between agents.

---

### 5. `RAWRXD_HEXMAG_RESIDENCY_E2E_001`

Files:

- `src/core/HexMagResidencyAuthority.hpp/.cpp`

What it closes:

- real prefetch accounting;
- LRU trim/eviction;
- reload after eviction;
- reload byte accounting;
- stale-residency detection;
- fail-closed callback failures;
- E2E receipt requires at least one successful prefetch, eviction and reload with non-zero reload bytes.

Integration seam:

Bind the four callbacks to the existing Deep2 `ElasticResidencyManager` / weight-residency authority. HexMag itself does not acquire a parallel storage implementation.

---

### 6. `RAWRXD_SCREENPILOT_TOOL_AUTHORITY_001`

Files:

- `src/screenpilot/ScreenPilotToolAuthorityBridge.hpp/.cpp`

What it closes:

- ScreenPilot tool requests enter the canonical `AgentToolRegistry::invoke()` path;
- every dispatch is marked `AgentToolSurface::LocalServer`;
- server-derived permission masks are enforced at each tool call;
- approval-required permissions call the ScreenPilot approval callback;
- cancellation is propagated into `ToolContext`;
- workspace-only requests reject resolved path escapes;
- direct bypass attempts force the receipt to FAIL.

This is designed for the existing `RawrXD_SP_AuthorityV2` / LocalServer agent coordinator rather than creating a second browser-only executor.

---

### 7. `RAWRXD_MULTI_AGENT_MERGE_AUTHORITY_001`

Files:

- `src/agentic/MultiAgentMergeAuthority.hpp/.cpp`

What it closes:

- source read goes through canonical Tool Authority;
- source write goes through canonical Tool Authority;
- optimistic base-content fingerprint rejects stale edits;
- deterministic non-overlapping line merge;
- overlapping independent-agent edits become an explicit conflict and **do not write**;
- no direct filesystem I/O in the merge coordinator;
- conflict and stale-base counters are receipt-visible.

This gives the R9700 writer / 7800 XT reviewer path a concrete merge authority instead of allowing either agent to overwrite the other's work directly.

---

### 8. `RAWRXD_CLEAN_CLONE_RELEASE_001`

File:

- `scripts/certify_clean_clone_release.ps1`

What it does:

1. fresh single-branch clone;
2. captures exact 40-character HEAD;
3. strict x64 CMake configure with stub fallbacks disabled;
4. builds `RawrXD-Win32IDE`;
5. requires a non-empty shipping EXE;
6. runs CTest when available;
7. performs a candidate-only source stub scan;
8. rejects explicit synthetic-receipt mechanisms;
9. emits a fail-closed release receipt.

This script has **not** been executed in the Linux source-validation container because PowerShell/MSVC are unavailable there. Do not mark this gate PASS until it runs on the Windows clean-clone lane.

---

## Known-open-gap guard

`scripts/audit_known_open_gaps.ps1` checks the older audited Layer-0 providers that have appeared as stubs/constant-success implementations in repository authority:

- ProductionProfiler
- NVMeStream
- BP16Streamer
- CompressedKVCache
- MARSController

The guard exists so a stale copy of those providers cannot be silently ignored during final closure. It does **not** overwrite a newer local implementation. If your local tree already closed them, the guard should stop matching them; if not, they remain a separate source batch rather than being falsely certified here.

## Apply

```powershell
Expand-Archive `
  .\rawrxd_next_missing_batches_RAWRXD_NEXT_MISSING_BATCHES_002.zip `
  -DestinationPath F:\~dev\next_missing_batches `
  -Force

Set-Location F:\~dev\next_missing_batches\rawrxd_next_missing_batches_RAWRXD_NEXT_MISSING_BATCHES_002

.\apply_rawrxd_next_missing_batches.ps1 `
  -RepoRoot "F:\~dev\rawrxd" `
  -PatchStrictCMake
```

Then build the actual shipping target:

```powershell
cmake --build `
  F:\~dev\rawrxd\win32ide_strict\build_v4 `
  --config Release `
  --target RawrXD-Win32IDE
```

Run the known-open-gap guard:

```powershell
.\scripts\audit_known_open_gaps.ps1 -RepoRoot "F:\~dev\rawrxd"
```

## Source-only validation performed

The standalone package was configured and compiled as C++20, then six tests ran via CTest:

```text
100% tests passed, 0 tests failed out of 6
```

See `SOURCE_VALIDATION.txt` for the complete receipts.

Important distinction:

```text
SOURCE_LAYER_COMPILE=PASS
SOURCE_SELFTESTS=PASS
PATCHED_WINDOWS_SHIPPING_BUILD=NOT_RUN_IN_CONTAINER
REAL_MODEL_GPU_SPECIAL_GRAPH=NOT_RUN_IN_CONTAINER
REAL_DUAL_GPU_AGENT_CONTEXTS=NOT_RUN_IN_CONTAINER
REAL_HEXMAG_RESIDENCY_CALLBACKS=NOT_RUN_IN_CONTAINER
REAL_SCREENPILOT_LOCALSERVER_PATH=NOT_RUN_IN_CONTAINER
CLEAN_CLONE_RELEASE_GATE=NOT_RUN_IN_CONTAINER
```

Those remaining receipt lines must come from the integrated Windows product path, not from these standalone tests.
