# FULL IDE COMPLETION LEDGER — RawrXD / Deep2

**Authoritative state ledger.** Every row records the honest status with its evidence.
A gate is PASS only when every acceptance requirement is satisfied by executable,
reproducible evidence (source alone, compiles, finite logits, or commit messages do not
count). Historical reports are treated as claims until reproduced against current source.

- Repo: `F:\rawrxd` · Branch: `local-30b-backend`
- Baseline commit when this ledger was opened: `d09d513a2d` (+ uncommitted D2 work)
- Maintained by: orchestrating agent (this session); parallel worker: Gates 16–18 audit.

## Gate status

| Gate | Scope | Status | Evidence / notes |
| --- | --- | --- | --- |
| 1 | Quantization parity | **PASS** | `evidence/BUILD_PROVENANCE_2026-10-13.md`; tools rebuilt from committed sources re-verified (`build_deep2_parity_trace.bat`, exit 0). |
| 2 | Primitive implementation provenance | **OPEN** | Registry consistency receipt (`gate2_registry_cert.json`, `tools/gate2_manifest_consistency.ps1`); full primitive-by-primitive provenance audit not yet produced. |
| 3 | GGUF tensor geometry | **PASS** | Prior certification at HEAD; universal_gguf type-table fix committed. |
| 4 | Native CPU/GPU dispatch certification | **PASS** | `GATE4_CERTIFICATION_2026-10-13.md`; per-config audit logs in `gate4_ci/`; dispatcher-ledger mismatch fixed (465→310 true call count, commit `854ed56b78`). |
| 5 | Independent multi-position reference parity | **PARTIAL** | 129/129 positions compared against the independent llama.cpp clone: 116/129 argmax exact (GPU), worst cos 0.9964745, worst max abs 1.168507, all 13 disagreements inside the measured error band (top-2 flips). Token-level greedy agreement on the production stream: 127/128. Strict 129/129 token-for-token parity NOT met → stays PARTIAL until certified. |
| 6 | KV-cache, state, context correctness | **PASS (bounded)** | `GATE6_KVCACHE_CONTEXT.md`; KV rounding-on-write matches reference bit-exactly (F16 rounding of V); causal KV verified over 129 positions by the Gate 5 teacher-forced comparison. |
| 7 | Architecture execution | **PASS (dense)** | llama/tinyllama family executes native; MLA/MoE/SSM/hybrid partial (see S-items). |
| 8 | Native GPU, quantization, ROM streaming | **PARTIAL** | Native Vulkan dispatch PASS (Gate 4); ROM streamer + expert caching not certified end-to-end. |
| 9 | Agentic IDE end-to-end tool execution | **PARTIAL** | Agentic loop harness exists (`tools/deep2_agentic_loop.cpp`, `deep2_plan.cpp`); full IDE tool-execution chain not certified. |
| 10 | Concurrent multi-GPU orchestration and tensor parallelism | **NOT STARTED** | Diagnostic Vulkan F32 GEMV and explicit padded-view path pass 98-shape CPU/single-GPU parity with zero tails. Across pad multiples 1/4/8/16, 16-F32 stride is fastest in the tested sweep; at local width 2049 it is 2.86× faster on R9700 and 3.29× on RX 7800 XT versus contiguous rows. A strict single-R9700 TinyLlama smoke preserves the four-token stream with zero CPU GEMVs. These are kernel-layout/runtime compatibility results, not model-level tensor parallelism. A real two-device layer-parallel smoke dispatched 4,302 GPU GEMVs with no CPU fallback but disagreed with the R9700-only greedy stream after token 1 (1/4 agreement), and layer-completion counters were zero. Gate acceptance still requires matrix sharding, explicit offsets, synchronized cross-device transfers, full-logit parity, no CPU fallback, and allocation high-water. See `evidence/TP_UNEVEN_STRIDE_LAYOUT_CERT_2026-10-19.md`, `evidence/TP_UNEVEN_SHARD_BACKEND_AUDIT_2026-10-19.md`, and `evidence/TP_UNEVEN_MULTI_GPU_LAYER_SMOKE_2026-10-19.receipt.txt`. |
| 11 | DeepSeek 671B native execution | **NOT STARTED** | Blocked on model availability (no 671B GGUF on disk) + memory budget. |
| 12 | Performance certification (150 TPS) | **OPEN** | See below — measured, not met. |
| 13 | Million-token context | **NOT STARTED** | Blocked on KV budget/streaming design. |
| 14 | ROM reconstruction integrity | **NOT STARTED** | No reproduction harness executed yet. |
| 15 | Piranha/HexMag multi-agent scalability | **NOT STARTED** | Coordination layer unreviewed this session. |
| 16 | Native compiler/linker/builder/debugger/test execution | **PARTIAL** | Independent audit found IDE sources compile, but the final link is blocked by the installed Qt VS2019 library / VS2022 compiler ABI mismatch; no fresh linked runtime proof. See `evidence/RAWRXD_LOCAL_GITHUB_ARTIFACT_AUDIT_2026-10-19.md`. |
| 17 | Complete IDE feature integration | **PARTIAL** | Independent audit found partial UI/tool integration evidence; the final File New assertion and fresh-binary end-to-end workflow remain unverified. See `evidence/RAWRXD_LOCAL_GITHUB_ARTIFACT_AUDIT_2026-10-19.md`. |
| 18 | Security, tool authorization, receipts | **OPEN** | Independent audit did not establish authenticated tool execution with end-to-end permission and receipt-integrity proof. See `evidence/RAWRXD_LOCAL_GITHUB_ARTIFACT_AUDIT_2026-10-19.md`. |
| 19 | Endurance, cancellation, crash/device-loss recovery | **NOT STARTED** | — |
| 20 | Clean-checkout production release certification | **NOT STARTED** | Depends on all above. |

## D1 / D2 engineering items (inference-owned)

| Item | Scope | Status | Evidence |
| --- | --- | --- | --- |
| **D2** | Dependency-correct GPU submission batching | **PASS** | Historical integrated receipt remains preserved. Fresh exact-base revalidation on D1 commit `74fafe2584`: R9700, TinyLlama Q4_K_M, same binary and 135-token prompt; all 135×32,000 full-logit rows matched bit-for-bit, CPU fallback 0/0, submissions and waits 21,080→12,170 (−42.27%). One matched pair measured prefill 31,142.0→29,746.5 ms (4.335→4.538 tok/s); the decode probe was one token and does not establish sustained decode speed. Receipt: `F:/rawrxd/.worktrees/codex-d2-revalidate-74fafe/evidence/D2_REVALIDATION_74FAFE_20261019/receipt.md`. Session-3 is a separate workload (8,835→5,139, −41.8%). |
| **D1** | Multi-token batched prefill | **PARTIAL on local-30b-backend; PASS on isolated TinyLlama replay** | `Executor::PrefillBatch` and `Deep2Engine::prefillBatched` are present. Isolated commit `74fafe2584` passed the 1/2/8/32/128 TinyLlama/R9700 matrix with bit-exact full logits, committed K/V rows, state, continuation, and zero CPU fallback. This verifier is not integrated into current `local-30b-backend`; retain PARTIAL there until the tested delta is reviewed and replayed on the target branch. Receipt: `F:/rawrxd/.worktrees/codex-d1-replay-338c7d/evidence/D1_REPLAY_1977E_20261019/receipt.md`. Other model families and Q4_K fused LM-head remain unverified. |

## Performance (Gate 12 / S10) — measured receipt

Model: tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf (SHA-256 `9fecc3b3…d76a0`, 668,788,096 B),
device: AMD Radeon AI PRO R9700 (Vulkan), 8 prompt tokens, 128 generated tokens.

| Metric | Serial | Batched (D2) | Warm |
| --- | --- | --- | --- |
| Decode TPS | 4.220 | **4.405** | 4.449 |
| Steady decode TPS | 4.219 | 4.404 | 4.448 |
| Prefill TPS | 2.115 | 3.580 | 4.579 |
| Submits/position | 155 | 90.1 | 89.0 |
| GPU share of measured window | — | **85.2%** | 85.2% |

- GPU time is now measured independently of host waits (device timestamp queries;
  `kernel_ms` is a host-wait alias and is documented as such).
- **150 TPS floor: NOT met.** Measured limit = 4.405 decode TPS (2.9% of floor).
  Blocker: kernel dispatch geometry (one invocation per output row) — 85% of the
  decode window is real device time; submission overhead is only ~15%.
- S07 speculative decode: acceptance measured at **0.9333** on a copy workload
  (56/60 accepted) and **0.0000** on a ramp prompt; **zero speedup** because the
  target model still runs one forward per position → S07 stays OPEN pending batched
  verification (the D1 follow-on).

## Verified checks performed this session

1. Toolchain rebuilt from the committed sources (parity + bench + strata harnesses, exit 0).
2. Batched vs serial full-logit parity: bit-identical 135/135 (two independent controls).
3. Stream determinism: identical 128-token streams across cold, warm, and unbatched runs.
4. Independent llama.cpp check over the generated stream: 127/128 tokens exact.
5. `cpu_calls=0`, `fallback=<none>`, nonfinite logits = 0, `descriptor_sets_in_flight=0`
   after every measured run; VRAM peak 600.8 MB, RAM peak 1,018.9 MB.
6. Space recovery on F:: 2.53 GB reclaimed after verifying committed summaries;
  `build_gate4`/`parity_out` preserved because a concurrent agent was writing them.

## Known defects / unfinished (do not clear by gate passage)

- `kernel_ms` aliasing host wait (now documented; `gpu_ms` added as the device metric).
- Prefill is one forward per token (D1 open).
- Per-row kernel dispatch geometry caps throughput at ~4.4 TPS (Gate 12 blocker).
- Speculative verification is serial (S07 speedup unrealized).
- Multi-GPU concurrent execution and tensor parallelism uncertified (Gate 10); DeepSeek 671B untested (Gate 11).
- Concurrency hazard observed: another agent editing this checkout mid-session produced
  interleaved saves in `runtime_graph_executor.cpp`; the merged state was verified by
  rebuild + re-run, but the workstreams should use separate worktrees.

## Next dependencies (in order)

1. Commit + push the D2 work and this ledger.
2. D1 batched prefill (inference-owned) — parity + causal KV evidence required.
3. Batched speculative verification (unlocks S07 speedup measurement).
4. Kernel dispatch geometry (tiled matmul) — the Gate 12 blocker.
5. Gates 16–18 audit results → IDE feature completion → 19/20.

## Session-3 addendum (autonomous completion agent, 2026-10-13 late)

Integration branch HEAD is now 2f795322c4 (the D1/D2 work landed on
local-30b-backend):

| Item | Status | Evidence |
| ---- | ------ | -------- |
| D1 — batched multi-token prefill | **PASS (bit-exact)** | Executor::PrefillBatch; full-logit BIT_EXACT vs serial — tinyllama 32000 logits max_abs=0, DeepSeek-V2-Lite MoE/MLA 102400 logits max_abs=0; decode streams identical |
| D2 — GPU submission batching | **PASS (measured)** | submits/waits 8835→5139 (-41.8%; 158→92/token); decode TPS 1.50→3.53 (tinyllama Q4_K_M); batch-replay UAF fixed; identical outputs |

Performance honesty note: 3.53 tok/s is the certified native decode rate — the 150 TPS
floor remains OPEN and unattained on this hardware/loop.

### Gate 16 (native toolchain + IDE build) — PARTIAL, compile repaired, link blocked

- **FIXED** the audit's gate-blocking Win32IDE.cpp C2679: a namespace collision — the
  members were declared against unqualified IGGUFLoader/GGUFMetadata/TensorInfo
  while the real interface is RawrXD::IGGUFLoader (src/RawrXD_Interfaces.h); both
  loaders derive from it. Plus rchitecture_type is a std::string (to_string
  removed) and missing <commdlg.h>/<shellapi.h> in the sidebar/commands TU.
  **All 16 RawrXD-Win32IDE sources now compile clean** (VS2022 + Qt 6.7.3 headers +
  Vulkan SDK). Commit 5808c3bdf.
- **FIXED** Deep2::MedusaDecoder (engine linked it with header-only declarations):
  full declared surface implemented in src/deep2/engine_subsystems.cpp — head
  registration, F32 projectHead mat-vec that fails closed on quantized heads, top-k
  candidate extraction, prefix-correct tree verification, repeated-rejection
  auto-disable. Engine unresolved externals 266 → 221.
- **BLOCKED (genuine)**: Win32IDE LINK. The only Qt on this box is
  C:\Qt\6.7.3\msvc2019_64; only VS2022 is installed. Prebuilt Qt libs cannot link
  VS2022 objects (v142 vs v143 ABI). Certification needs a VS2019 toolchain or an
  msvc2022_64 Qt build — do not mark Gate 16/17 PASS from the compile result alone.

### Defects carried forward

- Engine link: 221 unresolved externals remain (KVCache, MARS, MoE*, Warmup,
  RouterPrefetchTelemetry, QuantKernelRegistry, ReverseHotpatchEngine, PlasmaGovernor,
  Chamber, Sovereign, Deep2Device_*, OllamaBlobParser, GetBlockGeometryForType).
- Qt ABI blocker (above).
- Gate 5 stays PARTIAL (bounded-error certification, not exact parity) per the program
  standard; S07 and S12 stay OPEN until measured acceptance and 150 TPS pass.
