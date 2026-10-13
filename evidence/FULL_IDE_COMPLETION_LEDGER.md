# RawrXD / Deep2 — Full IDE Completion Ledger

**Started:** 2026-10-13 (autonomous completion directive) · **Repo:** `F:\rawrxd` · **Branch:** `local-30b-backend`
**Rule applied:** a gate PASSES only on reproducible executable evidence; planning, source existence, compile-only, and simulated output do not count. Everything unmet is reported BLOCKED/PARTIAL/FAIL with its blocker.

## 1. Strata integration program (S01–S12) — executed this session

Full matrix with commands, logs and measurements: `evidence/STRATA_S01_S12_GATE_MATRIX_2026-10-13.md`.

| Gate | Status | One-line evidence |
|------|--------|-------------------|
| S01 | PASS | 28,677 timestamped expert placement/eviction records, 1,221 attributed evictions |
| S02 | PASS | VRAM hit rate 0.8165–0.8714 measured; 2,831 real evictions at 4 GiB cap; budget respected |
| S03 | PARTIAL | 1,580 prefetch uploads, 0 stale reads, no speedup (synchronous upload path) |
| S04 | PASS | 7.76 GB H2D + 0.23 GB D2H measured; 17.53/22.70 GB/s staging |
| S05 | PARTIAL | CPU/R9700/7800 XT routing token-identical; concurrent multi-GPU not implemented |
| S06 | PASS | INT8 KV 24/24 token-identical vs FP32; 71.88% savings; 1M-row store PASS |
| S07 | BLOCKED | Verification machinery real, parity exact; 0.57–0.72× throughput (no batched prefill) |
| S08 | FAIL (improvement) | Hotness eviction 0.7774 hit/1.06 TPS vs LRU 0.8165/1.27 — LRU retained |
| S09 | PARTIAL | No deadlocks; 158–292 submits/token, wait≈kernel (dense path unbatted) |
| S10 | PASS | TTFT/prefill/decode/aggregate TPS + JSON receipts on every run |
| S11 | PARTIAL | KV store certified to 1M tokens; model-level 4K+ BLOCKED (no batched prefill) |
| S12 | FAIL | 3.84–4.35 TPS measured vs 150 floor; blockers measured and recorded |

## 2. Existing 20-gate program — reconciled against repository evidence

State taken from `evidence/GAP_AUDIT_2026-10-13/` and this session's re-verification; historical reports treated as evidence only where reproducible at current HEAD.

| Gate | Area | Status at 2026-10-13 | Basis |
|------|------|----------------------|-------|
| 1 | Build integrity | PARTIAL | `tools\build_deep2_parity_trace.bat` and `tools\build_deep2_strata_bench.bat` build+run; full root CMake build not verified |
| 2 | Quantization registry | PASS (scope-limited) | 22 kernels registered; end-to-end family coverage not certified (GAP_AUDIT gate2) |
| 3 | GGUF geometry | PASS | tensor geometry re-verified (GAP_AUDIT gate3) |
| 4 | GPU dispatch | PASS | this session: 2,635 GPU calls / 0 CPU / 0 fallback on tinyllama Q4_K_M; bit-identical GENSTREAM after rebuild; 7800 XT pin PASS |
| 5 | Numerical parity | PASS (stated tolerance) | CPU-vs-GPU argmax agreement; **reference (llama.cpp) full-logit parity still OPEN** — first-divergence tooling exists |
| 6 | KV/context correctness | PASS (FP32/F16 path) | incremental vs full recomputation verified; governor rejection verified (GAP_AUDIT gate6) |
| 7 | Architecture execution (dense/MLA/MoE/SSM/hybrid) | PARTIAL | dense + MoE execute on GPU with zero fallback (this session); MLA runs (DeepSeek-V2-Lite) but SSM/Mamba2 and hybrid paths unverified at HEAD |
| 8 | Native GPU/quantization/ROM streaming | PARTIAL | quantized kernels + VRAM weight cache real; ROM/reverse-BF16 streaming unverified |
| 9 | Agentic IDE end-to-end | PARTIAL | prior agentic logs exist; not re-verified this session |
| 10 | Multi-GPU orchestration | PARTIAL | per-device routing verified (S05); concurrent execution not implemented |
| 11 | DeepSeek 671B execution | NOT STARTED | no 671B weights on disk |
| 12 | Performance certification (150 TPS) | FAIL | S12 measurements above |
| 13 | Million-token context | PARTIAL | KV subsystem certified (S11); model-level blocked |
| 14 | ROM reconstruction integrity | NOT VERIFIED | no reproducible run at HEAD |
| 15 | Piranha/HexMag swarm | NOT VERIFIED | prior logs only |
| 16 | Compiler/linker/debugger/terminal | NOT VERIFIED | prior logs only; stale paths reported by GAP_AUDIT |
| 17 | IDE feature integration | PARTIAL | many handlers exist; dead/unverified actions not audited this session |
| 18 | Security/tool authorization | NOT VERIFIED | prior logs only |
| 19 | Endurance/recovery | NOT VERIFIED | prior logs only |
| 20 | Release certification | BLOCKED | depends on 1–19 |

## 3. Defects discovered this session (tracked until closed)

- D1 Per-token executor: no batched multi-token prefill → blocks S07 speedup, S11 model-level long context, and is the main S12 throughput blocker.
- D2 One submit + one fence wait per dense dot (158–292/token; wait_ms ≈ kernel_ms). MoE expert dots are batched; dense projections are not.
- D3 Concurrent multi-GPU execution not implemented (single device context per process).
- D4 Root `build.bat` / several Deep2 scripts contain obsolete VS/drive paths (GAP_AUDIT); `deep2_cert` and `rawr_cli` are not root CMake targets.
- D5 `MedusaDecoder.cpp` missing → `d2.exe` does not link (273 unresolved externals); speculative telemetry shows 0 acceptance, 34.54 vs 53.07 TPS (slower).
- D6 CompressedKVCache legacy ABI (header without implementation) superseded by the new `StrataInt8KVCache.hpp`; legacy declarations should be retired to avoid duplicate-truth.
- D7 SDK header layout: `timestampValidBits` is on `VkQueueFamilyProperties` in Vulkan SDK 1.4.357.0 (worked around in `EnsureQuantTimestampPool`).
- D8 `RR_WEIGHT_CACHE_POLICY=hotness` measured worse than LRU on DeepSeek-V2-Lite routing; kept as opt-in, default LRU.
- D9 Build-tree contention: concurrent sessions and CCleaner intermittently lock `tools\*.exe`/obj targets (LNK1104); retry builds rather than assuming failure.

## 3. D1 / D2 execution — 2026-10-13 (verified)

### D2 — dependency-correct GPU submission batching: **VERIFIED**

A/B on tinyllama Q4_K_M, R9700, identical workload (prefill 32 / generate 24), batching default-on vs `DEEP2_NO_DOT_BATCH=1`:

| Config | submits | waits | kernel_ms | decode TPS | TOKSTREAM |
|--------|---------|-------|-----------|------------|-----------|
| batching ON (default) | 5,139 | 5,139 | 13,635.5 | **3.53** | identical |
| batching OFF | 8,835 | 8,835 | 38,147.4 | 1.50 | identical |

**41.8% fewer submissions and fences, 2.35× decode throughput, zero numerical change.** Receipts: `strata_bench_d2_batch_on.json`, `strata_bench_d2_batch_off.json`.

### D1 — multi-token batched prefill: **VERIFIED (correctness) / per-architecture speedup**

New `Executor::PrefillBatch(tokens, startPos)` (`runtime_graph_executor.cpp`): op-major/token-minor; each Linear op queues one dot per token into one submission (chunked at `QuantDot::BatchCapacity()`=32 dots); attention/MoE/SSM/norms run per token in causal order via the same kernels as `ExecuteToken`. Opt-in; serial path untouched.

| Model | Prefill TPS serial → batched | Full-logit parity | Decode stream |
|-------|------------------------------|-------------------|---------------|
| tinyllama Q4_K_M (dense) | 1.95 → **3.53 (1.85×)** | **BIT_EXACT** (32,000 logits, max_abs=0, cos=1.0) | identical |
| DeepSeek-V2-Lite Q4_K_M (MoE/MLA) | 0.53 → 0.55 (neutral) | **BIT_EXACT** (102,400 logits, max_abs=0, cos=1.0) | identical |

MoE neutrality explained: its decode cost is the per-token expert compute (18 expert dots/token/block), which this change does not batch across tokens; projection submissions were not the bottleneck there. Cross-token expert batching is tracked as **D10**.

### Defects found and fixed during D1

- **D11 (fixed):** batch CPU-replay invoked a capture-by-reference `CpuDot` lambda after its stack frame returned (use-after-return, access violation on any EndBatch failure). All queued closures now capture by value (`runtime_graph_executor.cpp`: OpLinear k-quant path, MoE up/gate/down banks).
- **D12 (fixed):** `kQuantBatchMaxSets=32` device ring capacity was not exposed; a 48-dot prefill batch failed closed and (via D11) crashed. `QuantDot::BatchCapacity()` added; `PrefillBatch` chunks at the capacity.
- **D9 (standing):** concurrent sessions/CCleaner intermittently lock build outputs (LNK1104); retry.

## 4. Gates 16–18 read-only audit (independent worker, 2026-10-13)

- **Gate 16 — FAIL:** advertised native compiler/linker sources absent; `rawrxd.exe`, `rawrxd_compiler_qt`, MASM suite excluded from CMake; `MedusaDecoder.cpp` missing (d2.exe will not link); `Win32IDE-Native` fails to compile at `Win32IDE.cpp:5247-5248` (C2679); no build+link+run exit codes on record.
- **Gate 17 — NOT VERIFIED:** Qt IDE surfaces excluded ("Qt6 not found"); native IDE unbuilding; `RawrXD-IDE` CMake target behind `if(FALSE)`; pervasive `placeholder`/`TODO` markers; the lone smoke test drives dead `.obj`s; no end-to-end launch→edit→build→run session.
- **Gate 18 — PARTIAL:** `ToolAuthority`/`PermissionGate` in `src/agentic/AgentMode.{h,cpp}` is real and enforced by the live `rawr` CLI (`rawrxd_cli_v2.cpp:307-309`); verifiable execution receipts exist only as orphaned scaffolding in `tools/native_batches/*` (no CMake target, no `ExecutionReceipt` symbol under `src/`); live evidence is log/JSON-only; the E2E evidence path references the non-existent `build_gate4`.

Ownership assigned to the IDE worker; inference-owned files (D1 executor, D2 Vulkan/quant-dot) are off-limits to that worker.

## 5. Session commits

- `ce8ee05cd4` fix(deep2): remove duplicate ssmConvState/MLA declarations (C2365) — pushed
- Strata program commit (this session's source + evidence): see `git log` after commit of this ledger

## 5. Next dependencies (in order)

1. D1 follow-up (D10): cross-token expert batching inside OpMoEExecute for MoE prefill speedup (parity gate: BIT_EXACT vs serial).
2. D2 follow-up: extend same-submission grouping beyond q/k/v (dense FFN up/gate pairs, output projections) and measure submits/token.
3. Gate 5 closure: full-logit llama.cpp reference parity at many positions.
4. D3 concurrent multi-GPU scheduling for Gate 10.
5. Gates 16–18 per the audit above (IDE worker scope).
6. Gate 11 (DeepSeek 671B) needs weights not present on disk; Gate 15/17/19/20 depend on 11–14.
