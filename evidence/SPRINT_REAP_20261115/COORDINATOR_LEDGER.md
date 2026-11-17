# RawrXD 90-Move Recovery Sprint — Coordinator Ledger

- Sprint start (UTC): 2026-11-15T01:40Z
- Baseline commit: `5ed2096bb9` (branch `evidence/reap-multi-model-20261113`)
- Worktrees: `F:\rawrxd\.kilo\worktrees\sprint-w{1..5}` (branches `sprint/w{1..5}`)
- Integration owner: W6, branch `sprint/integration-20261115`, main tree `F:\rawrxd`
- Authoritative disposition until proven otherwise: `PROMOTE=0 · CERTIFIED=0/128 · RELEASE=HELD`

## Worker status

| Worker | Scope | Moves | Task ID | State |
|--------|-------|-------|---------|-------|
| W1 | Reference oracle + numerical trace | 1–23 | ses_e23220689ffePUo5gTS9eBYeZs | RUNNING |
| W2 | Quantized kernels + CPU perf | 24–26, 31–40, 45 | ses_e2321ffa1ffeeY0DO466rUj5Dk | RUNNING |
| W3 | Tokenizer + coherent generation | 28–30, 41–44 | ses_e2321f46effe49Rg2V0gsVm5Ry | RUNNING |
| W4 | Vulkan GPU + CSPD | 46–60 | ses_e2321e6cbffeoeO7hvafJ4Qmx4 | RUNNING |
| W5 | REAP + streaming + large models | 61–75 | ses_e2321d2b3ffe8QgLBnpfqu31Oa | RUNNING |
| W6 | Integration + regression + certification | 76–90 | ses_e2321c42affe14nhuFsIZVjZ5c | RUNNING |

## Batch gate state

| Batch | Moves | Gate | State |
|-------|-------|------|-------|
| 1 — Source integrity, reference oracle, first divergence | 1–15 | First divergence localized with exact-SHA and tensor-error receipts, or documented instrumentation blocker | PENDING |
| 2 — Numerical correctness and tokenizer repair | 16–30 | Earliest proven defect repaired without introducing an earlier divergence; tolerances reported | PENDING |
| 3 — CPU performance and native coherent generation | 31–45 | Coherent native generation demonstrated; CPU decode TPS measured after verified optimization | PENDING |
| 4 — Vulkan GPU inference and CSPD integration | 46–60 | Actual GPU kernels execute, outputs within declared tolerance, CSPD measured on/off | PENDING |
| 5 — REAP, synthetic weights, streaming, large models | 61–75 | Each tested model has explicit PASS/FAIL/PARTIAL/NOT_RUN with hashes and native-path evidence | PENDING |
| 6 — Integration, regression, certification evidence | 76–90 | Reproducible integrated build, exact-SHA evidence matrix, honest release decision | PENDING |

## Move ledger

Status values: DONE (real evidence) · PARTIAL · FAILED · BLOCKED · NOT_RUN · IN_PROGRESS

### Batch 1 — Source integrity, reference oracle, first divergence (W1)
| # | Move | Status | Evidence |
|---|------|--------|----------|
| 1 | Verify source SHA + reconcile CSPD commit history | IN_PROGRESS | W1 |
| 2 | SHA-256 of deep2_bench_tps.exe | IN_PROGRESS | W1 |
| 3 | SHA-256 llama3.2-3B Q2_K model | IN_PROGRESS | W1 |
| 4 | Preserve working tree (CSPD shaders, src/deepx) | IN_PROGRESS | W1 + W6 |
| 5 | Six isolated worktrees verified | DONE | coordinator (created at 5ed2096bb9) |
| 6 | Reproduce 0.466 tok/s CPU baseline | IN_PROGRESS | W1 |
| 7 | Prompt token-ID parity Deep2 vs llama.cpp | IN_PROGRESS | W1/W3 |
| 8 | Inspect llama.cpp tensor-export hooks | IN_PROGRESS | W1 |
| 9 | Per-layer residual-state export | IN_PROGRESS | W1 |
| 10 | Attention norm + Q/K/V export | IN_PROGRESS | W1 |
| 11 | Attention out/proj/residual export | IN_PROGRESS | W1 |
| 12 | FFN norm/output/final residual export | IN_PROGRESS | W1 |
| 13 | Align tensor names/shapes/layouts | IN_PROGRESS | W1 |
| 14 | Automated per-layer comparison | IN_PROGRESS | W1 |
| 15 | FIRST divergent layer + operator recorded | IN_PROGRESS | W1 |

### Batch 2 — Numerical correctness and tokenizer repair (W1/W2/W3)
| # | Move | Status | Evidence |
|---|------|--------|----------|
| 16 | Inspect divergent operator inputs/outputs | IN_PROGRESS | W1 |
| 17 | Element-wise layout comparison | IN_PROGRESS | W1 |
| 18 | RoPE freq/scaling/position indexing | IN_PROGRESS | W1 |
| 19 | Q/K/V weights, biases, dims | IN_PROGRESS | W1 |
| 20 | GQA head→KV-head mapping | IN_PROGRESS | W1 |
| 21 | Attention scaling + masking | IN_PROGRESS | W1 |
| 22 | ATTN_PRE_O_0 / ATTN_OUT_0 amplification | IN_PROGRESS | W1 |
| 23 | Output projection vs reference | IN_PROGRESS | W1 |
| 24 | Q4_0 quant matvec verification | IN_PROGRESS | W2 |
| 25 | Q2_K / Q4_K verification | IN_PROGRESS | W2 |
| 26 | Q6_K unpack + accumulation | IN_PROGRESS | W2 |
| 27 | FFN norm, gate, down projection | IN_PROGRESS | W1/W2 |
| 28 | Tokenizer vocab IDs + special-token metadata | IN_PROGRESS | W3 |
| 29 | Unknown-token fallback repair (only if proven wrong) | IN_PROGRESS | W3 |
| 30 | Rebuild + rerun first-token/multi-token parity | IN_PROGRESS | W3 |

### Batch 3 — CPU performance and coherent generation (W2/W3)
| # | Move | Status | Evidence |
|---|------|--------|----------|
| 31 | OpLinear per-layer timing instrumentation | IN_PROGRESS | W2 |
| 32 | DequantCached hit/miss counters | IN_PROGRESS | W2 |
| 33 | Dequantizations per generated token | IN_PROGRESS | W2 |
| 34 | Repeated decode allocations | IN_PROGRESS | W2 |
| 35 | Scalar quantized dot-product profile | IN_PROGRESS | W2 |
| 36 | Cached dequant validity across positions | IN_PROGRESS | W2 |
| 37 | Repair confirmed cache invalidation / redundant work | IN_PROGRESS | W2 |
| 38 | SIMD vs scalar reference | IN_PROGRESS | W2 |
| 39 | CPU threading + sync overhead | IN_PROGRESS | W2 |
| 40 | Prefill vs decode benchmark split | IN_PROGRESS | W2 |
| 41 | Decode via BPETokenizer::Decode | IN_PROGRESS | W3 |
| 42 | Readable text + special-token handling | IN_PROGRESS | W3 |
| 43 | Deterministic multi-token generation | IN_PROGRESS | W3 |
| 44 | Cancellation + resource cleanup | IN_PROGRESS | W3 |
| 45 | CPU TPS / latency / correctness record | IN_PROGRESS | W2 |

### Batch 4 — Vulkan GPU and CSPD (W4)
| # | Move | Status | Evidence |
|---|------|--------|----------|
| 46 | R9700 device selection + driver info + Code43 | IN_PROGRESS | W4 |
| 47 | Shader binaries + pipeline creation | IN_PROGRESS | W4 |
| 48 | GPU buffer allocation/alignment/descriptors | IN_PROGRESS | W4 |
| 49 | CPU→GPU upload correctness | IN_PROGRESS | W4 |
| 50 | Quantized GEMV GPU dispatch | IN_PROGRESS | W4 |
| 51 | GPU GEMV vs CPU oracle | IN_PROGRESS | W4 |
| 52 | Vulkan sync + memory barriers | IN_PROGRESS | W4 |
| 53 | Attention GPU dispatch + correctness | IN_PROGRESS | W4 |
| 54 | Compile/validate both CSPD Split-KV shaders | IN_PROGRESS | W4 |
| 55 | Repair B33 head-dimension support | IN_PROGRESS | W4 |
| 56 | B34 reduction + scratch-buffer layout | IN_PROGRESS | W4 |
| 57 | Wire DEEP2_CSPD=1 into real decode path | IN_PROGRESS | W4 |
| 58 | CSPD vs validated attention output | IN_PROGRESS | W4 |
| 59 | CSPD on/off at 4K/16K/32K/64K | IN_PROGRESS | W4 |
| 60 | GPU calls, numerical errors, TPS, memory | IN_PROGRESS | W4 |

### Batch 5 — REAP, synthetic weights, streaming, large models (W5)
| # | Move | Status | Evidence |
|---|------|--------|----------|
| 61 | REAP implementation + variant inventory | IN_PROGRESS | W5 |
| 62 | Historical synthetic-weight source recovery | IN_PROGRESS | W5 |
| 63 | Braided streaming/loading + reconstruction location | IN_PROGRESS | W5 |
| 64 | REAP metadata + tensor shapes + mappings | IN_PROGRESS | W5 |
| 65 | Compressed-weight reconstruction vs reference | IN_PROGRESS | W5 |
| 66 | REAP16 / 59 / 81 / 199 independent tests | IN_PROGRESS | W5 |
| 67 | Compressed GLM-4.7 355B-A32B identity | IN_PROGRESS | W5 |
| 68 | Native load of representative REAP model | IN_PROGRESS | W5 |
| 69 | Async streaming + prefetch ordering | IN_PROGRESS | W5 |
| 70 | GPU residency / offload / NVMe accounting | IN_PROGRESS | W5 |
| 71 | Loader cancellation + partial-read recovery | IN_PROGRESS | W5 |
| 72 | Large-model loader deadlock reproduce/diagnose | IN_PROGRESS | W5 |
| 73 | Qwen3-Next 80B load + arch compatibility | IN_PROGRESS | W5 |
| 74 | GPT-OSS 120B + sharded models | IN_PROGRESS | W5 |
| 75 | Model-by-model load/inference/correctness/perf | IN_PROGRESS | W5 |

### Batch 6 — Integration, regression, certification (W6)
| # | Move | Status | Evidence |
|---|------|--------|----------|
| 76 | Integrate into one controlled branch | IN_PROGRESS | W6 |
| 77 | Resolve conflicts without discarding experiments | IN_PROGRESS | W6 |
| 78 | Clean native CLI build | IN_PROGRESS | W6 |
| 79 | Full numerical regression suite | IN_PROGRESS | W6 |
| 80 | Revalidate tokenizer + coherent generation | IN_PROGRESS | W6 |
| 81 | Revalidate CPU/GPU parity on integrated SHA | IN_PROGRESS | W6 |
| 82 | Prefill + decode benchmarks | IN_PROGRESS | W6 |
| 83 | Streaming, cancellation, cleanup regressions | IN_PROGRESS | W6 |
| 84 | Healthy proxy unaffected | IN_PROGRESS | W6 |
| 85 | Supported archs + quantization formats | IN_PROGRESS | W6 |
| 86 | Leaks, deadlocks, GPU validation errors | IN_PROGRESS | W6 |
| 87 | Source/exe/shader/model hashes | IN_PROGRESS | W6 |
| 88 | Map evidence to 128 certification gates | IN_PROGRESS | W6 |
| 89 | Commit verified increments (no push) | IN_PROGRESS | W6 |
| 90 | Final PASS/PARTIAL/FAIL disposition | IN_PROGRESS | W6 |

## Coordinator notes

- Subagent default model `kilo/stealth/space-bunny-alpha` is missing from the catalog; workers were dispatched with `Glyph Cluster` (kilo) as an explicit fallback.
- `F:` free space at sprint start: 37.8 GB. No model copies or conversions are permitted.
- Sealed evidence is not modified. `PROMOTE` stays 0; `RELEASE` stays HELD unless real evidence legitimately changes it.