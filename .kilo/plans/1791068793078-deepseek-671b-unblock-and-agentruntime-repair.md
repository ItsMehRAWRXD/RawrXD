# DeepSeek 671B Unblock, then AgentRuntime Repair

## Objective

Load and run `DeepSeek-R1-Q4_K_M` (671B, Q4_K_M, 11/11 shards, 376.65 GB) on the
deep2 streamer, then restore autonomous agentic execution via a repaired
`AgentRuntime`.

Scope decision: both goals, sequenced. Justification — `AgentRuntime::CallModel`
must parse tool calls from real model output; over a streamer that emits zero
tokens the agentic layer is inert. The 671B load is the dependency.

---

## Measured starting state

From `deep2_streamer_cert.exe` run against 635 logical models (2026-10-04):

```ini
DeepSeek-R1-Q4_K_M   shards 11/11 COMPLETE   376.65 GB   arch=deepseek2
  load=FAIL  stage=20  MODEL_ADMISSION_REJECTED
  message=2 required tensor role(s) absent; first: attn_k_b
```

The engine's own tensor scan, same run, printed:

```ini
blk.0.attn_kv_b.weight shape=[512,32768] type=12 bytes=9437184
MLA_METADATA arch=deepseek2 layout=unknown numHeads=128 kvLoraRank=512
```

**The contradiction that defines the defect:** Deep2Engine's tensor scan sees
`attn_kv_b`; the `ModelMetadata` handed to `ModelRegistry` does not. The fused
layout is already accepted by the admission grammar:

```cpp
ModelRegistry.cpp:700   constexpr RoleRule kMlaFusedKvUpRole[] = {{"attn_kv_b","attn_kv_b",true}};
ModelRegistry.cpp:845   const bool kvFusedOk = roleSatisfied(md, kMlaFusedKvUpRole[0]);
ModelRegistry.cpp:776   roleSatisfied -> (perLayer ? layersWithRole(md,rule) > 0 : tensorExists)
```

So this is **not** a missing-layout-grammar defect. It is a metadata-population
or tensor-enumeration defect. Which one is not yet established — do not assume.

---

## Phase 0 — Retract three wrong claims made this session

Record these before proceeding; two were asserted then disproven by source reading.

```ini
RETRACTED  "GGUFAdapter K-quant block_bytes wrong blocks the deep2 stream"
           Real defect (all six K-quants understated), but deep2 has its own
           reader at src/deep2/GGUFLoader.hpp:537. Unproven on the stream path.
RETRACTED  "thread_local scratch aliasing is a live defect"
           Already fixed; pattern survives only in
           Deep2Engine_GpuForward.cpp.pre_gpu_finite_prefix_diag.bak:91
RETRACTED  "missing-kernel fallback fails open"
           Refuted — GetDequant is null-checked in the weight-fetch path
```

## Phase 1 — Instrument, do not guess

**Single most important step.** `ModelMetadata` is never printed at rejection.
Add a fail-loud diagnostic at the rejection site (`ModelRegistry.cpp:1045`) that
emits per-role evidence rather than a verdict:

```cpp
for each evaluated role:
    stem, roleSatisfied, tensorExists(md,stem), layersWithRole(md,rule),
    layers_seen, shards_seen, tensors_total
```

Also print the raw `md` tensor-name count and first/last stem for the rejected
model.

Run: `deep2_streamer_cert.exe` against
`F:\OllamaModels\DeepSeek-R1-Q4_K_M-COMPLETE\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf`

## Phase 2 — Fix, chosen by what Phase 1 measures

Do not pre-commit to a branch.

```ini
FORK A  shards_seen < 11, layers_seen < 61
        -> metadata built from a shard subset. Fix enumeration over all shards.
           Risk: cost grows with shard count; consider lazily querying stems.

FORK B  shards_seen == 11, layers_seen == 61, layersWithRole("attn_kv_b") == 0
        -> stem/name mismatch. Fix the role table or the stem extraction.
           Check blk.N prefix stripping and any ".weight" suffix handling.

FORK C  tensors_total == 0 or near 0
        -> metadata never populated for sharded models. Fix population.
```

Acceptance: the 671B model passes `countMissingRequiredTensors` with
`missing == 0`, and admission no longer rejects on `attn_k_b`.

## Phase 3 — MLA CPU path (hard prerequisite, large)

Passing admission is necessary but not sufficient. Measured on a model that
*did* pass admission:

```ini
admission OK arch=deepseek2 family=MLA moe=1 mla=1
SUSPENDED arch=deepseek2 reason=MLA_CPU_PATH_ABSENT vulkan=0
   -- suspended BEFORE mapping; nothing read or allocated
```

MLA exists only on the Vulkan/GPU branch. The 671B is MoE + MLA. Without a CPU
MLA path, or without a working GPU residency path, the model cannot run at all.
Decide explicitly: CPU MLA, or GPU MLA + residency. This is the largest piece of
work in the plan and cannot be skipped.

## Phase 4 — Quant decode correctness (independent of 1-3)

Affects the models that *do* load. Keep separate from admission.

```ini
P4a  GGUFAdapter::ComputeTensorSize understates all six K-quant block_bytes:
       Q2_K 67/84, Q3_K 44/110, Q4_K 132/144,
       Q5_K 164/176, Q6_K 194/210, Q8_K 258/260
     First establish whether the deep2 stream path calls this function at all.
     If not, it is a canonical-path defect and a separate ticket.

P4b  Q5_0 / type 6 decode emits -nan (gemma3-1b). Sizing at GGUFAdapter.cpp:365
     computes 22 and is CORRECT, so this is a decode fault. Six divergent Q5_0
     implementations exist; gguf_adapter.hpp:54 declares BlockQ5_0 = 4 while
     GGML type is 6, so any table indexed by that enum reads the wrong row.

P4c  Symptom evidence to reproduce against:
       llama3.2-3b-Q2_K  attn_v=Q3_K  V_PROJ ABSMAX=1.4861e+07  POISON
       gemma3-1b-Q2_K    attn_v=Q5_0  forward failed: LinearW non-finite, idx=1/256
       llama-80B Q4_K    reached forward, then LinearW non-finite at prefill token 0
```

Note V_PROJ is the first-bad stage while K_PROJ is good, in every measured case.

## Phase 5 — AgentRuntime repair

`AgentRuntime.cpp` does not exist in the tree. Before adopting it, note the
repo already has **two** tool registries; `ToolDispatcher` would be a third.

Defects to fix, all source-verified:

```ini
A1  CallModel is a stub returning a hardcoded "Task analysis complete".
    IsTaskComplete substring-matches "complete", so the stub's own text ends
    the run on turn 1. The agent never calls a model or a tool. This violates
    CLAIM_AGENTIC_REQUIRES_REAL_MODEL_TOOL_LOOP=1 in AGENTS.md and cannot ship.
    -> wire to Deep2Engine::generateStream (40+ existing call sites to copy from)

A2  AuthorizeCall auto-approves PermissionLevel::APPROVAL_REQUIRED. This
    regresses RAWRXD_GIT_SAFETY_AUTHORITY_001, which took four ledger entries
    to reach a state where an out-of-scope staged path is refused.
    -> route all mutation through GitSafetyAuthority; remove auto-approve

A3  ExecuteInternal holds registryMutex_ across entry.handler(call), arbitrary
    user code. Non-recursive mutex -> deadlock if a handler re-enters the
    dispatcher; blocks Register/Unregister/HasTool for the handler's duration.
    -> look up the entry under lock, release, then invoke the handler

A4  WaitForExecutionSlot busy-spins sleep_for(10ms) while <condition_variable>
    is included but unused. Replace with the CV that was evidently intended.

A5  CompactContext erases `toRemove` from resultHistory without checking its
    length: erase(begin, begin+toRemove) overruns when
    resultHistory.size() < toRemove. It also claims "Summarize older results"
    but only erases. GetAgentTrace pairs toolHistory[i]/resultHistory[i] by
    index, so any desync corrupts the trace.

A6  ExecuteAsync captures [&call, &run] by reference into std::async; `run` is
    owned by activeRuns_ map. Safe only if the map is not mutated concurrently.
    -> take runId and re-resolve, or document the invariant

A7  PauseAgent / ResumeAgent are TODO stubs returning false; checkpoint
    round-trip loses budgets, toolHistory, resultHistory, modelResponses.
    LoadCheckpoint yields a run reporting IDLE with zero budget.
    -> either implement or remove the surface

A8  StartAgent calls run->Start() (which calls resourceBudget.Start()) BEFORE
    assigning defaultToolBudget_/turnBudget_/resourceBudget_. Timing state is
    started against default-constructed values then overwritten.

A9  GetAgentState returns FAILED for an unknown runId, conflating not-found
    with failure.

A10 Missing includes for what it uses: <future>, <optional>, <memory>,
    <chrono>, <mutex>, <vector>, <string>. Does not compile standalone.
```

## Validation

```ini
V1  Phase 1 diagnostic prints layers_seen=61, shards_seen=11 for the 671B model
V2  countMissingRequiredTensors == 0 for the 671B model
V3  admission no longer emits MissingRequiredTensor field=attn_k_b
V4  MLA path chosen (CPU or GPU) and the model maps; residency_ratio > 0
V5  forwardTokenAllLayers completes; DECODE_ONE > 0; stream_callbacks > 0;
    tokens > 0   (AGENTS.md DROW condition for the streamer)
V6  tokenizer parity checked before forward: emit count vs roundtrip_exact
V7  AgentRuntime: a run executes a real tool and records a non-empty result
    with outputCount > 0; CallModel is proven non-stub by a test that fails when
    the stub text is restored
```

Never promote PARTIAL to PASS. A stage that never ran is not a pass.

## Risks

```ini
R1  Phase 2 fork is undetermined. Any fix written before Phase 1 is a guess.
R2  MLA CPU path is substantial work; schedule it, do not assume Phase 1
    unblocks the model.
R3  Quant decode defects (P4) may independently prevent correct output even
    after the model loads. Load success != correctness.
R4  Adopting ToolDispatcher without A2 regresses a certified gate.
R5  VSCode history is capped at 50 entries/file, so revision counts are
    saturated and cannot rank churn. Two DeepSeek-relevant stale-artifact leads
    exist (D:-era test_gguf_tensor_bounds.cpp with 24 revisions, not in the
    current tree; and the gguf_loader.cpp "Undo Accept Diff" snapshot).
```

## Out of scope

```ini
- MiniMax-M2.7 (UnknownArchitecture), qwen3next/qwen35 (ssmStateSize false
  rejection), gptoss/deepseek4/qwen4exp (ffn_down_exps MoE shape),
  laguna (head geometry). All measured, all separate tickets.
- 531 of 635 logical models report MISSING_PAYLOAD — a corpus problem, not code.
- Beaconism: burr.txt (2025-11-13 transcript) and src/deep2/Beaconism.hpp define
  two incompatible architectures under one name. Unresolved and separate.
```