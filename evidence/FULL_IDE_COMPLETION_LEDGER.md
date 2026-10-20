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
| 9 | Agentic IDE end-to-end tool execution | **PARTIAL** | 2026-10-20: the active Deep2 loop, shared ToolCallBridge/SelfRepairLoop, direct `rawr tools run`, `rawr run` prompt path, and Project Wizard callbacks now read and bind the workspace MOTD per turn; the bridge revokes turns on scope exit and rejects policy replacement before subsequent tools. Offline checks and targeted builds pass (see `evidence/MOTD_AUTHORIZATION_SOURCE_BUILD_2026-10-20.md`). `rawr run` still has no model-to-tool dispatch loop; HexMag/SubAgent dispatch is not proven on the shared gate, and full IDE E2E/token-survival is unverified. |
| 10 | Concurrent multi-GPU orchestration and tensor parallelism | **NOT STARTED** | Diagnostic Vulkan F32 GEMV and explicit padded-view path pass 98-shape CPU/single-GPU parity with zero tails. Across pad multiples 1/4/8/16, 16-F32 stride is fastest in the tested sweep; at local width 2049 it is 2.86× faster on R9700 and 3.29× on RX 7800 XT versus contiguous rows. A strict single-R9700 TinyLlama smoke preserves the four-token stream with zero CPU GEMVs. These are kernel-layout/runtime compatibility results, not model-level tensor parallelism. A real two-device layer-parallel smoke dispatched 4,302 GPU GEMVs with no CPU fallback but disagreed with the R9700-only greedy stream after token 1 (1/4 agreement), and layer-completion counters were zero. Gate acceptance still requires matrix sharding, explicit offsets, synchronized cross-device transfers, full-logit parity, no CPU fallback, and allocation high-water. See `evidence/TP_UNEVEN_STRIDE_LAYOUT_CERT_2026-10-19.md`, `evidence/TP_UNEVEN_SHARD_BACKEND_AUDIT_2026-10-19.md`, and `evidence/TP_UNEVEN_MULTI_GPU_LAYER_SMOKE_2026-10-19.receipt.txt`. |
| 11 | DeepSeek 671B native execution | **NOT STARTED** | Blocked on model availability (no 671B GGUF on disk) + memory budget. |
| 12 | Performance certification (150 TPS) | **OPEN** | See below — measured, not met. |
| 13 | Million-token context | **NOT STARTED** | Blocked on KV budget/streaming design. |
| 14 | ROM reconstruction integrity | **NOT STARTED** | No reproduction harness executed yet. |
| 15 | Piranha/HexMag multi-agent scalability | **NOT STARTED** | Coordination layer unreviewed this session. |
| 16 | Native compiler/linker/builder/debugger/test execution | **PARTIAL** | Independent audit found IDE sources compile, but the final link is blocked by the installed Qt VS2019 library / VS2022 compiler ABI mismatch; no fresh linked runtime proof. See `evidence/RAWRXD_LOCAL_GITHUB_ARTIFACT_AUDIT_2026-10-19.md`. |
| 17 | Complete IDE feature integration | **PARTIAL** | Independent audit found partial UI/tool integration evidence; the final File New assertion and fresh-binary end-to-end workflow remain unverified. See `evidence/RAWRXD_LOCAL_GITHUB_ARTIFACT_AUDIT_2026-10-19.md`. |
| 18 | Security, tool authorization, receipts | **OPEN** | The MOTD guard now binds ACK to session/turn and current policy SHA-256 in covered paths; offline adversarial tests pass. `/api/tool` is explicitly disabled in the active APIServer dispatcher and the API translation unit compiles, but there is no active HTTP listener/runtime proof. HexMag/SubAgent and other OS-side-effect call sites are not all routed through a shared dispatcher; receipts are local hashes/logs, not signed/non-repudiable attestations. See `evidence/MOTD_AUTHORIZATION_SOURCE_BUILD_2026-10-20.md` and `evidence/RAWRXD_LOCAL_GITHUB_ARTIFACT_AUDIT_2026-10-19.md`. |
| 19 | Endurance, cancellation, crash/device-loss recovery | **NOT STARTED** | — |
| 20 | Clean-checkout production release certification | **NOT STARTED** | Depends on all above. |

## D1 / D2 engineering items (inference-owned)

| Item | Scope | Status | Evidence |
| --- | --- | --- | --- |
| **D2** | Dependency-correct GPU submission batching | **PASS** | Historical integrated receipt remains preserved. Fresh exact-base revalidation on D1 commit `74fafe2584`: R9700, TinyLlama Q4_K_M, same binary and 135-token prompt; all 135×32,000 full-logit rows matched bit-for-bit, CPU fallback 0/0, submissions and waits 21,080→12,170 (−42.27%). One matched pair measured prefill 31,142.0→29,746.5 ms (4.335→4.538 tok/s); the decode probe was one token and does not establish sustained decode speed. Receipt: `evidence/D2_REVALIDATION_74FAFE_20261019/receipt.md`. Session-3 is a separate workload (8,835→5,139, −41.8%). |
| **D1** | Multi-token batched prefill | **PASS (TinyLlama current branch)** | Current `Deep2Engine::prefillBatched` now passes serial/batched causal KV and full-logit parity on TinyLlama at prompt lengths 1/2/8/30/32/128; H11 chunks 1/2/16/128 are byte-exact with `max_abs_overall=0` and no nonfinite values. Receipt: `evidence/H11_D1_CORRECTION_RECEIPT_20261020.md`; raw logs are committed beside it. The batched attention reducer is reference-backed for correctness; performance-specific batching remains separate. Other model families and Q4_K fused LM-head remain unverified. |

## Authorized large-model phase (2026-10-20)

The controlled D2 135-token capture was verified before resuming GPU work. The first current-source Nemotron 30B Q4_K_M run completed 128 generated positions on the R9700 with finite logits, zero CPU calls, zero fallback, GPU completion, and a real stream. It measured 3.557 decode TPS, 35,699.5 ms decode wall time, 1,010.0 MB device high-water, and 24,267.1 MB host-RAM peak. This is a scoped native execution PASS, not independent llama.cpp logit parity, multi-GPU certification, or a 150 TPS result. Receipt: `F:/rawrxd/evidence/LARGE_MODEL_CERT_20261020/nemotron30b_q4_current_20261020T1408/receipt.md`.

The separate `nemotron-bolt.gguf` NVFP4 probe produced finite logits but 400 CPU calls because the active top-level `QuantDot` wrapper has no integrated type-40 dispatch. Its evidence is retained under `F:/rawrxd/evidence/LARGE_MODEL_SMOKE_20261020/nemotron30b_probe_20261020T1351/`; this remains an open implementation blocker before certifying NVFP4 models.

The NVFP4 shader source now compiles to a verified 5,268-byte SPIR-V artifact,
but the active top-level dispatcher still rejects quant-dot kind 7. The shader
compile is recorded separately; runtime wiring and parity remain open:
`F:/rawrxd/evidence/LARGE_MODEL_CERT_20261020/nvfp4_shader_compile_20261020T1510/receipt.md`.

The first available Qwen-sized candidate was also probed before moving to a
larger model. The local `qwen3.8:27b` Ollama blob is a Qwen3.5 hybrid export,
not a 32B/40B dense model. It ingested and bound 673 operations, then failed
at position 0 with `residualadd: addend 'attn_proj' missing`; no logits or TPS
are claimed. The active universal graph does not yet emit the gated
`attn_qkv`/`attn_gate` hybrid mixer. Receipt:
`F:/rawrxd/evidence/LARGE_MODEL_SMOKE_20261020/qwen38_27b_probe_20261020T1418/receipt.md`.

As a bounded substitute, the local `deepseek-r1:32b` blob (DeepSeek R1
Distill Qwen 32B, GGUF `qwen2`) completed a two-token native R9700 smoke with
finite logits, zero CPU calls, zero fallback, and a real stream (`7596 287`).
Decode measured 0.175 TPS after a 78.9 s bind; this is a correctness/smoke
PASS only. Receipt:
`F:/rawrxd/evidence/LARGE_MODEL_CERT_20261020/deepseek_r1_32b_qwen2_current_20261020T1430/receipt.md`.

GPT-OSS 120B is present locally as a 65.37 GB GGUF, but the host has 64 GiB
RAM and the current runtime materializes weights in host memory. Its preflight
is therefore blocked before launch; the 120B receipt records the measured
budget and the required ROM/streaming prerequisite:
`F:/rawrxd/evidence/LARGE_MODEL_SMOKE_20261020/gpt_oss_120b_preflight_20261020T1430/receipt.md`.

The independent ROM manifest path is healthy across the available large-model
inventory: 417/417 Nemotron Q4 tensors, 771/771 DeepSeek 32B tensors, 687/687
GPT-OSS 120B tensors, 843/843 NVFP4 Nemotron-Bolt tensors, 807/807 Qwen3-Next
80B tensors, 1,328/1,328 DeepSeek-V4 Flash tensors, and 814/814 Laguna
tensors bound with zero dtype or range errors. GPT-OSS is therefore available
to the ROM layer even though the current host-materializing forward executable
cannot safely launch it. Suite receipt:
`F:/rawrxd/evidence/LARGE_MODEL_CERT_20261020/rom_manifest_suite_20261020T1440/receipt.md`.

The native `rawr` CLI remains an integration blocker: its model registry sees
only 16 workspace fixtures, the configured localhost:8080 inference endpoint
is not listening, and `rawr doctor` fails only on that reachability check. The
Ollama inventory and native large-model receipts therefore cannot yet be
selected through the shipped CLI. Receipt:
`F:/rawrxd/evidence/LARGE_MODEL_SMOKE_20261020/rawr_cli_backend_20261020T1520/receipt.md`.

The CMake route-menu target itself is now reproducibly green: Python generated
the Local GGUF, Local Ollama, and Cloud Kilo descriptors with exit code 0.
This is generation evidence only; Gate 17 remains PARTIAL until the linked IDE
binary and live discovery are verified. Receipt:
`F:/rawrxd/evidence/IDE_ROUTE_MENU_GENERATION_20261020.md`.

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
- S07 controlled native measurement (2026-10-20): code accepted 15/164 proposed (9.1%) and prose accepted 0/32; both emitted 128 tokens with exact greedy stream agreement and zero nonfinite logits. Speculative decode was slower (code 55,418.4 ms vs 28,105.5 ms serial; prose 34,434.6 ms vs 28,938.8 ms), and GPU-call counts increased. S07 remains OPEN. Receipt: `evidence/S07_SPEC_MEASUREMENT_RECEIPT_20261020.md`.

## Verified checks performed this session

1. Toolchain rebuilt from the committed sources (parity + bench + strata harnesses, exit 0).
2. Batched vs serial full-logit parity: bit-identical 135/135 (two independent controls).
3. Stream determinism: identical 128-token streams across cold, warm, and unbatched runs.
4. Independent llama.cpp check over the generated stream: 127/128 tokens exact.
5. `cpu_calls=0`, `fallback=<none>`, nonfinite logits = 0, `descriptor_sets_in_flight=0`
   after every measured run; VRAM peak 600.8 MB, RAM peak 1,018.9 MB.
6. Space recovery on F:: 2.53 GB reclaimed after verifying committed summaries;
  `build_gate4`/`parity_out` preserved because a concurrent agent was writing them.
7. 2026-10-20 MOTD authorization: `RawrXD-CLI-V2` and `deep2_agentic_loop` rebuilt with VS2022; standalone state-machine/ToolCallBridge adversarial test exited 0; loop `--motd-selftest` exited 0; `rawr tools run read_motd` returned the policy digest; a workspace without the policy was denied with exit 3. The disabled API route translation unit compiled, but the API server has no active listener and is not runtime-certified. Detailed commands and surfaces: `evidence/MOTD_AUTHORIZATION_SOURCE_BUILD_2026-10-20.md`.

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

Native IDE route integration was rebuilt from the current working tree with exit code 0; the generated route header and linked executable hashes are recorded in vidence/IDE_NATIVE_ROUTE_BUILD_20261020.md. This is a build receipt only; live UI smoke, Ollama discovery, and source-delta publication remain open.

The native IDE route source is now published in commit cf32e9554d63021bcf8d613e6b832c98da0512ec. A post-commit route-generator build and native IDE link both exited 0; hashes and scope are recorded in vidence/IDE_NATIVE_ROUTE_SOURCE_CERT_20261020.md. Gate 17 remains PARTIAL pending live UI and end-to-end model-response smoke.

The committed native route was exercised against Ollama at 127.0.0.1:11434: the catalog exposed 41 models, and qwen2.5-coder:1.5b-base returned a non-empty bounded response. The Nemotron 3-nano 4B probe completed with an empty response despite eval tokens, so model-specific response behavior remains open. Receipts: vidence/LARGE_MODEL_SMOKE_20261020/ollama_route_qwen15b_20261020T1424/receipt.md and vidence/LARGE_MODEL_SMOKE_20261020/ollama_route_nemotron4b_20261020T142342/receipt.md.

A current-tree H11 replay against TinyLlama failed closed at lk.0.attn_output.weight: all chunks 1/2/16/128 produced non-finite output (48/2048 bad, first index 3), with zero dispatch/submit/fence counters. This is a regression/blocker against the isolated D1 receipt and remains open. Receipt: vidence/LARGE_MODEL_SMOKE_20261020/h11_current_tree_tinyllama_20261020T1425/receipt.md.

Post-route regression: the native IDE target still builds, but the default Release build is blocked by legacy MASM awrxd_hexmag_repeat (LNK1181), CTest has 14 entries with missing executables, and the H11 current-tree replay fails closed on non-finite lk.0.attn_output.weight. Detailed battery receipt: vidence/IDE_REGRESSION_BATTERY_20261020.md.

## H11 geometry and batched prefill correction — 2026-10-20

The current-tree H11 failure was reproduced and repaired against TinyLlama 1.1B Q4_K_M. The loader now reports the actual GGUF geometry before execution (`layers=22 hidden=2048 heads=32 kv_heads=4 head_dim=64`); the prior 4096/32-head fallback is rejected by the parity harness. The layer-0 nonfinite output came from the batched GQA mapping sending query heads 4..31 past the four-head KV view. The mapping now uses `query_head / (numHeads / numKVHeads)` and bounds the grouped index.

The D1 reference path also now publishes post-final-norm hidden states, embeds each causal chunk immediately before its layer-major pass, and uses the production `AttentionWithCache` reducer after staged KV writes. This preserves the batched layer boundary while keeping the numerical comparison on the same dot-product, softmax, and weighted-accumulation implementation as serial inference. The standalone batched scorer remains corrected but is not used for the correctness receipt until a separate performance comparison is made.

Controlled H11 receipts (TinyLlama, FP32 KV, one worker, zero nonfinite values):

- 1-token control: `evidence/H11_GQA_HIDDENOUT_FIX_20261020.log` — PASS.
- 2-token prompt: `evidence/H11_TWO_TOKEN_ATTENTION_REFERENCE_20261020.log` — P1/P2/P3/P4 PASS, `kv_byte_exact=1`, `max_abs_overall=0`.
- 8-token prompt: `evidence/H11_8TOKEN_ATTENTION_REFERENCE_20261020.log` — P1/P2/P3/P4 PASS, `kv_byte_exact=1`, `max_abs_overall=0`.
- 32-token prompt: `evidence/H11_32TOKEN_ATTENTION_REFERENCE_20261020.log` — P1/P2/P3/P4 PASS, `kv_byte_exact=1`, `max_abs_overall=0`.
- 128-token prompt: `evidence/H11_128TOKEN_ATTENTION_REFERENCE_20261020.log` — P1/P2/P3/P4 PASS, `kv_byte_exact=1`, `max_abs_overall=0`.
- 30-token default prompt: `evidence/H11_FULL_PROMPT_ATTENTION_REFERENCE_20261020.log` — P1/P2/P3/P4 PASS, `kv_byte_exact=1`, `max_abs_overall=0`.

The final H11 build exited 0. The Release parity executable SHA-256 is `FB575E317D12ACED4FB6602ED8A06666E91E3935391A3113D3F4E48BC10B9A8E`. These receipts close the H11/D1 correctness milestone for this model and workload. They do not close D2 performance, S07, S12, Gate 5, or multi-GPU certification; dispatch accounting remains zero because Vulkan note hooks are not wired.


## S07 controlled native measurement — 2026-10-20

The isolated R9700/TinyLlama `deep2_spec_bench` run completed with exit code 0. The benchmark’s correctness verdict was `PASS` for both code and prose streams, but S07 certification remains **OPEN** because speculative execution did not reduce target work or wall time.

- Code: 128 emitted, 164 proposed, 15 accepted (9.1%); decode 28,105.5 ms serial vs 55,418.4 ms speculative; 36,098 vs 62,801 GPU calls.
- Prose: 128 emitted, 32 proposed, 0 accepted (0.0%); decode 28,938.8 ms serial vs 34,434.6 ms speculative; 47,208 vs 52,872 GPU calls.
- Combined: 15 accepted of 256 emitted and 196 proposed; both streams were 128/128 identical and all logits were finite.
- No Vulkan validation-layer, alignment, or runtime error/warning messages appeared in the captured log.

Receipt: `evidence/S07_SPEC_MEASUREMENT_RECEIPT_20261020.md`; raw run: `evidence/S07_SPEC_RUN_20261020/`.

## S07 adaptive verifier and draft-policy measurement — 2026-10-20

The verifier now records sequence-level batches, evaluated positions, serial KV repairs, and adaptive fallbacks. The default fail-safe disables speculation after two consecutive zero-accept rounds. On the same 128-token TinyLlama/R9700 workload, the repeat drafter measured code 0.95x and prose 1.04x serial speed; prompt lookup raised acceptance to 45.7%/70.0% but measured 0.78x/0.94x. All streams remained 128/128 identical with zero nonfinite logits and zero CPU calls.

This is an optimization and diagnostic improvement, not an S07 pass. The verifier still runs attention/norm/KV stages token-minor inside each PrefillBatch and performs serial KV repair after partial rejection. Receipt: evidence/S07_ADAPTIVE_POLICY_RECEIPT_20261020.md.


## S07 Q4_K/Q6_K fused LM-head integration — 2026-10-20

The real TinyLlama output head is Q6_K (`output.weight dims=[2048,32000]`). The fused verifier now passes the GGUF type, uses the correct vocabulary dimension, discovers the shader from packaged or source-tree paths, and reconstructs the serial path's interleaved Q8_K activations. A fresh four-token differential witness measured max_abs `4.76837158e-06`, exact greedy stream agreement, finite logits, and zero CPU calls.

The rebuilt 128-token R9700 run stayed exact and GPU-only: code 4.54 -> 4.33 TPS (0.95x), prose 4.50 -> 4.27 TPS (0.95x), with 3/12 and 0/8 drafts accepted; GPU calls increased from 36,098 to 37,742 (code) and 47,208 to 48,614 (prose). S07 acceleration remains OPEN.

The per-op trace shows approximately 195 ms/token in `FlushDotBatch` versus approximately 14.4 ms in the LM head, so the next performance work targets submission/fence amortization rather than draft policy alone. Receipts: `evidence/S07_Q6_FUSED_RECEIPT_20261020.md`, `evidence/S07_Q6_FUSED_VALIDATE_4_RUN6_20261020/`, `evidence/S07_Q6_FUSED_128_BOTH_RUN2_20261020/`, and `evidence/S07_Q6_TIMING_4_20261020/`.


## Q6 row-4 shared-tile and command-reuse route — 2026-10-20

The guarded `DEEP2_QUANT_ROW_TILE=4` + `DEEP2_QUANT_Q6_SHARED_TILE=1` + `DEEP2_QUANT_REUSE_COMMANDS=1` route reached 31.02 TPS code / 29.07 TPS prose over a controlled 128-token TinyLlama run, with exact streams, finite logits, and zero CPU calls. After rebuilding both SPIR-V artifacts with `scripts/compile_quant_row4_shaders.ps1` and rebuilding Release, the route revalidated at 31.15 TPS serial / 29.89 TPS speculative for 128 code tokens, again exact, finite, and CPU-call free. The four-token 44.41 TPS probe is exploratory and not a sustained claim. The subgroup-vector Q6 candidate failed differential validation (max_abs 20.4811039) and remains rejected. S12 remains FAIL at 150 TPS; S07 remains OPEN. Receipt: `evidence/S12_Q6_HOT_ROUTE_RECEIPT_20261020.md`.

## Q6 row-8 dispatch-correctness candidate — 2026-10-20

A guarded `DEEP2_QUANT_ROW_TILE=8` Q6 shared-tile route was added alongside row-4. The shader uses eight 32-lane cohorts and loads all 54 aligned Q6 words per cohort; command-replay dispatch now uses `QuantDotRowsPerWorkgroup()` so the row-8 path does not launch redundant empty groups. Release build and all four SPIR-V variants compile with exit code 0. The corrected 128-token TinyLlama code/prose run is finite, exact, and GPU-only (`evidence/S07_Q6_ROW8_128_BOTH_R4_20261020/`), but measures 31.55/30.36 TPS code and 29.47/27.83 TPS prose (serial/speculative), so no 40 TPS claim is made. S07 remains OPEN and S12 remains FAIL at 150 TPS. Receipt: `evidence/S07_Q6_ROW8_NEMOTRON_RECEIPT_20261020.md`.

## Native Nemotron 30B smoke — 2026-10-20

The native row-8/Q6/reuse route loaded `nemotron-3.5-lightning-30b-Q4_K_M.gguf` (Nemotron-H MoE, 53 layers, hidden 2688, context 1048576) and completed an 8-token GPU serial run with finite logits and zero CPU calls. Decode was 275.7 ms for 8 tokens (~29.02 TPS); the recurrent SSM graph correctly disables speculative rollback. This is a loadability/correctness smoke, not sustained 30B performance certification. Receipt: `evidence/NEMOTRON30B_ROW8_8TOK_20261020/SPEC_BENCH_RECEIPT.txt`.
## Native DeepSeek R1 32B smoke — 2026-10-20

The universal loader identified `deepseek-r1_32b.gguf` as Qwen2 (64 layers, hidden 5120, 40 heads, vocab 152064, context 131072) and Vulkan initialized on the R9700. The process terminated after pipeline initialization before a forward receipt, finite-logit result, or clean exit was recorded on repeated 8-token and 1-token attempts. This model is NOT CERTIFIED for native forward execution; preserved logs and the blocker analysis are in `evidence/DEEPSEEK32B_NATIVE_BLOCKER_20261020.md`.