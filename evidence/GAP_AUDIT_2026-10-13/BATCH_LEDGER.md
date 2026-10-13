# RAWRXD Gap Audit — Batch Execution Ledger (2026-10-13)

Source register: user-supplied 96-item gap audit. Status vocabulary (per the audit's own
"implemented / registered / dispatched / numerically correct" distinction):

- `VERIFIED`   — closed with fresh evidence in this session or a cited prior run
- `OPEN`       — real gap, not yet closed
- `PARTIAL`    — implemented but not certified
- `BLOCKED`    — needs external resource (hardware, model file, upstream tool)

Each row records: status, evidence artifact, and batch. Batches of 15 items.

| # | Gap (short) | Prio | Status | Evidence / note |
|---|-------------|------|--------|-----------------|
| 1 | MLA decompression primitive | P0 | VERIFIED | `src/modelgenie/ModelGenieExecutor.cpp:1917` full impl; `QuantParityRegistry.cpp:239` gate driven by executor bindings, not stale manifest |
| 2 | MLA attention integration | P0 | PARTIAL | impl exists; llama3.2:3b layer divergence bisect closed roPE/cache defects (see #6) |
| 3 | Q4_K × Q8_K full-path parity | P0 | VERIFIED | RAWRXD_GPU_QUANT_DOT_003: cos 1.0000000000, rel 2.86e-07 (real GGUF weights, R9700); float-dequant isolation: Deep2 == llama.cpp at 2.2e-7 on blk00/05 attn_proj |
| 4 | Q6_K × Q8_K full-path parity | P0 | VERIFIED | RAWRXD_GPU_QUANT_DOT_003: cos 1.0000000000, rel 6.71e-08 |
| 5 | Q8_K activation packing | — | VERIFIED | 8-block byte-level parity PASS (prior); Q8KQuant.h signed-extremum/round-half-even/clamp vs ggml-quants.c verified; permanent regression gate |
| 6 | Full layer-by-layer parity | P0 | VERIFIED (bounded) | llama3.2:3b 28-layer × 2-position per-op walk vs llama.cpp dumps. Two systematic defects FOUND+FIXED: (a) RoPE pairing for llama-family was NEOX, reference is NORM; (b) KV cache precision: reference kqv_out is bit-exactly F16(V) — Deep2 now stores F16. After fixes: blocks 0-5 exact to ~1e-7, pos-1 argmax matches reference (26957), final logits cos 0.99993 (pos0) / 0.99692 (pos1). Residual: Q8_K quantization-boundary sensitivity (inputs differ ~1e-6, dot outputs ~1e-3) bounded by tolerance table |
| 7 | Full vocabulary logit parity | P0 | PARTIAL | full-vocab comparison implemented for both positions; cos ≥ 0.9969; pos0 argmax flip is a 0.0073-margin near-tie (tokens 2 vs 791) |
| 8 | Multi-token autoregressive parity | P0 | VERIFIED (2-token) | position-1 argmax matches reference after fixes; KV reuse/positions exercised end-to-end |
| 9 | MoE routing and expert execution | P0 | VERIFIED | deepseek-v2 expert routing + dual-gate fixes DEEP2_SESSION_STATUS §1 |
| 10 | SSM/Mamba2 execution | P0 | PARTIAL | `tools/nemotron_mamba2_parity.exe` exists; rerun for evidence |
| 11 | Architecture-specific RoPE | P0 | VERIFIED | rope_adjacent now follows the llama.cpp LLAMA_ROPE_TYPE table (NORM families enumerated); pos-1 rope fit to reference post-rope Qcur/Kcur: cos 0.99999994/0.99999996 |
| 12 | Quantization format coverage | P0 | PARTIAL | 21 kernels bound in QuantParityRegistry; 12 types deliberately unbound → Admit refuses |
| 13 | Fused GPU kernel correctness | P0 | PARTIAL | GPU quant-dot cert PASS on Q4_K/Q6_K; fused-qkv GPU path to certify |
| 14 | GPU-only execution | P0 | VERIFIED | 128-token runs: gpu_calls>0, cpu_calls=0, fallback=<none> (3 models) |
| 15 | Unsupported-primitive handling | P0 | VERIFIED | MatMulFwd gate returns unavailable; RuntimeExecutable() fail-closed |
| 16 | ModelGenome schema | P0 | — | queued (batch 2) |
| 17 | Tensor layout validation | P0 | — | queued (batch 2) |
| 18 | Execution graph generation | P0 | — | queued (batch 2) |
| 19 | Primitive-to-kernel binding | P0 | — | queued (batch 2) |
| 20 | Architecture admission | P0 | — | queued (batch 2) |
| 21 | Model-specific generated headers | P1 | — | queued (batch 2) |
| 22 | Model-family coverage | P1 | — | queued (batch 2) |
| 23 | Quantization capability matrix | P0 | — | queued (batch 2) |
| 24 | Automatic parity certification | P0 | — | queued (batch 2) |
| 25 | Model artifact provenance | P1 | — | queued (batch 2) |
| 26 | Generated graph caching | P1 | — | queued (batch 2) |
| 27 | Model compatibility diagnostics | P1 | — | queued (batch 2) |
| 28 | Native GPU compute ABI | P0 | — | queued (batch 2) |
| 29 | Quantized matmul w/o scalar fallback | P0 | — | queued (batch 2) |
| 30 | GPU attention and MLA kernel coverage | P0 | — | queued (batch 2) |
| 31 | Cross-GPU transfer/sync | P0 | — | queued (batch 3) |
| 32 | R9700 + RX 7800 XT placement | P1 | — | queued (batch 3) |
| 33 | VRAM admission and budget | P0 | — | queued (batch 3) |
| 34 | GPU residency/eviction | P1 | — | queued (batch 3) |
| 35 | CPU/GPU numerical equivalence | P0 | — | queued (batch 3) |
| 36 | Kernel fusion correctness+perf | P1 | — | queued (batch 3) |
| 37 | Device-loss recovery (Win driver) | P1 | — | queued (batch 3) |
| 38 | Command-buffer/alloc reuse | P1 | — | queued (batch 3) |
| 39 | Multi-GPU scheduling/balance | P1 | — | queued (batch 3) |
| 40 | Forward progress while streaming | P0 | — | queued (batch 3) |
| 41 | Large-model tensor window scheduling | P0 | — | queued (batch 3) |
| 42 | Prefetch/compute lease sync | P0 | — | queued (batch 4) |
| 43 | Streamed tensor lifetime/eviction | P0 | — | queued (batch 4) |
| 44 | Sharded GGUF reconstruction | P0 | — | queued (batch 4) |
| 45 | Reverse-BF16 numerical cert | P0 | — | queued (batch 4) |
| 46 | Effective bytes/token | P0 | — | queued (batch 4) |
| 47 | Multi-device weight staging | P1 | — | queued (batch 4) |
| 48 | Expert-aware MoE streaming | P0 | — | queued (batch 4) |
| 49 | DeepSeek 671B full-model execution | P0 | — | queued (batch 4) |
| 50 | Sustained 150 TPS target | P0 | — | queued (batch 4) |
| 51 | Disk stall/mapping failure recovery | P1 | — | queued (batch 4) |
| 52 | Million-token context feasibility | P1 | — | queued (batch 4) |
| 53 | Q8_0/Q4_K compressed KV parity | P0 | — | queued (batch 4) |
| 54 | MLA compressed latent KV | P0 | — | queued (batch 5) |
| 55 | Paged KV allocation/reclamation | P0 | — | queued (batch 5) |
| 56 | KV ownership across agents | P0 | — | queued (batch 5) |
| 57 | Context extension beyond limits | P1 | — | queued (batch 5) |
| 58 | Prefix sharing / COW | P1 | — | queued (batch 5) |
| 59 | KV eviction/reload/integrity | P1 | — | queued (batch 5) |
| 60 | Concurrent decoding state isolation | P0 | — | queued (batch 5) |
| 61 | Long-context positional accuracy | P0 | — | queued (batch 5) |
| 62 | Agent migration between windows | P1 | — | queued (batch 5) |
| 63 | Shared model residency in swarm | P0 | — | queued (batch 5) |
| 64 | Token-stream-to-task routing | P1 | — | queued (batch 5) |
| 65 | Structured output parse/repair | P0 | — | queued (batch 5) |
| 66 | Agent state transfer | P0 | — | queued (batch 6) |
| 67 | Concurrent tool-call scheduling | P1 | — | queued (batch 6) |
| 68 | Work stealing / dynamic distribution | P1 | — | queued (batch 6) |
| 69 | Cancel/retry/timeout recovery | P0 | — | queued (batch 6) |
| 70 | Swarm result validation/dedup | P0 | — | queued (batch 6) |
| 71 | Tool authority / sandbox boundaries | P0 | — | queued (batch 6) |
| 72 | Persistent evidence ledger per agent | P1 | — | queued (batch 6) |
| 73 | Real throughput scaling across agents | P1 | — | queued (batch 6) |
| 74 | Win32 IDE full forward-pass integration | P0 | — | queued (batch 6) |
| 75 | IDE-to-Deep2 inference lifecycle | P0 | — | queued (batch 6) |
| 76 | Native build/link closure | P0 | — | queued (batch 6) |
| 77 | Unified compiler/builder/linker diagnostics | P1 | — | queued (batch 6) |
| 78 | Workspace multi-root | P1 | — | queued (batch 6) |
| 79 | File watcher completeness | P1 | — | queued (batch 6) |
| 80 | Session persistence/recovery | P1 | — | queued (batch 7) |
| 81 | Duplicate command-dispatch cleanup | P1 | — | queued (batch 7) |
| 82 | Agent panel shutdown-race cert | P0 | — | queued (batch 7) |
| 83 | Copilot streaming/tool-call parity | P0 | — | queued (batch 7) |
| 84 | Browser authority/tool permission | P1 | — | queued (batch 7) |
| 85 | IDE model/GPU perf dashboard | P1 | — | queued (batch 7) |
| 86 | E2E release packaging/install | P1 | — | queued (batch 7) |
| 87 | Full supported-model regression matrix | P0 | — | queued (batch 7) |
| 88 | Deterministic reference comparisons | P0 | — | queued (batch 7) |
| 89 | Numerical tolerances by operation | P0 | — | queued (batch 7) |
| 90 | CI build and runtime certification | P0 | — | queued (batch 7) |
| 91 | Performance regression detection | P1 | — | queued (batch 7) |
| 92 | Long-duration inference endurance | P0 | — | queued (batch 7) |
| 93 | Crash recovery / memory-leak tests | P1 | — | queued (batch 7) |
| 94 | Source-to-binary provenance | P1 | — | queued (batch 7) |
| 95 | Reproducible release builds | P1 | — | queued (batch 7) |
| 96 | Automated deployment/rollback | P1 | — | queued (batch 7) |



## Batch zone status (2026-10-13)

Native batch capability drops (tools/native_batches, MSVC-verified this session):

- BATCH_01_15_PASS  - tool policy/audit, budgets, retry, journal, evidence ledger,
  dependency graph, work queue, session, workspace-confined files, FIM/inference callback
- BATCH_16_30_PASS, BATCH_31_45_PASS, BATCH_46_60_PASS  (cumulative, /MT /W4, MSVC x64)
- All four built and run green by tools\native_batches\build_all_batches.bat.
  These verify the batch capability contracts; they do not yet wire the drops into
  the production AgentOrchestrator ABI (that requires the decorated symbol list).


