# Deep2 Certification Plan — Tasks 06 through 15

**Status**: ACTIVE — Production gate execution sequence  
**Authority**: RawrXD Deep2 production certification pipeline  
**Philosophy**: Fail-closed, NOT_RUN ≠ PASS, evidence over claims

---

## Task Overview

| Task ID | Code | Title | Target |
|---------|------|-------|--------|
| 06 | DEEP2_SPEC_FUSED_RUNTIME_001 | Certify fused speculative LM-head runtime | Verify DispatchGemvQ4KBatch reached by real speculative path |
| 07 | DEEP2_SPEC_ACCELERATION_001 | Achieve speculative speedup > 1.0× | TinyLlama/Qwen2.5-Coder benchmarks with >1.0× speedup |
| 08 | DEEP2_GPU_DECODE_ROOFLINE_001 | Profile and optimize GPU decode bottlenecks | Roofline analysis, optimize largest bottleneck |
| 09 | DEEP2_GGUF_LIFECYCLE_001 | Certify production GGUF lifecycle | Load/generate/cancel/unload/reload/corrupted handling |
| 10 | DEEP2_MULTIGPU_RESILIENCE_001 | Certify multi-GPU scheduling and resilience | R9700-only, dual-GPU, device-loss, recovery |
| 11 | DEEP2_CONTEXT_SCALING_001 | Certify long-context KV correctness | 4K→32K→128K→512K→1M progression |
| 12 | RAWR_AUTONOMOUS_REPAIR_E2E_001 | Independent autonomous repair challenge | Undisclosed defect → inspection → edit → build → test → verify |
| 13 | HEXMAG_PARALLEL_WORKTREE_001 | Certify HexMag parallel swarm execution | Concurrent agents, worktrees, deps, conflicts, merge |
| 14 | RAWR_FULL_RECOVERY_001 | Certify crash recovery and fault injection | Terminate processes, verify durable resume, no duplicates |
| 15 | RAWR_PRODUCTION_CERT_001 | Independent production release certification | Clean rebuild, all gates, perf numbers, signed manifest |

---

## Common Infrastructure

### Build System
- Direct MSVC compilation via batch scripts (same pattern as `deep2_spec_bench`, `deep2_context_scaling`)
- Dependencies: Vulkan SDK 1.4.357.0, ggml (built from `F:\rawrxd\3rdparty\ggml`)
- Output: `F:\rawrxd\tools\<task>.exe`
- Evidence: `F:\rawrxd\evidence\<task>\`

### Test Patterns (from existing certifications)
1. **Real model only** — `--model <gguf>` required, refuses without
2. **Fail-closed gates** — PASS/FAIL/NOT_RUN, never "passed with caveats"
3. **Per-workload reporting** — Code/prose split for speculative
4. **JSON receipts** — Machine-readable + human-readable evidence
5. **Provenance tracking** — Model SHA256, GGUF metadata, git commit

### Required GGUF Models
- **TinyLlama-1.1B** (code/prose workloads, small enough for rapid iteration)
- **Qwen2.5-Coder-7B** (code workload, representative)
- **Nemotron 30B** (existing baseline, for regression)
- **Any GGUF with 128K+ context** (for context scaling)

---

## Task 06: DEEP2_SPEC_FUSED_RUNTIME_001
**Certify fused speculative LM-head runtime**

### Objective
Verify that `DispatchGemvQ4KBatch` is reached by the real speculative verification path, with correct per-position logits and measured launch reduction.

### Gates
| Gate | Description | Pass Criteria |
|------|-------------|---------------|
| G1 | Path reachability | `DispatchGemvQ4KBatch` called ≥1 per verify round |
| G2 | Logit correctness | Speculative logits match serial at every position (cosine ≥ 0.999) |
| G3 | Launch reduction | Batched verify issues ≤ 1.16× launches vs 1.55× serial per round (EXL3 reference) |
| G4 | Finite logits | Zero non-finite across full vocab on both arms |

### Implementation
- Extend `deep2_spec_bench.cpp` with GPU dispatch tracing
- Add `DispatchGemvQ4KBatch` call counter in `vulkan_compute.cpp`
- Compare batched vs serial logit vectors per position
- Report launch counts per round

### Evidence
- `evidence/deep2_spec_fused_runtime/DISPATCH_TRACE.json`
- `evidence/deep2_spec_fused_runtime/LOGIT_PARITY.json`

---

## Task 07: DEEP2_SPEC_ACCELERATION_001
**Achieve speculative speedup above 1.0×**

### Objective
Benchmark TinyLlama (code/prose) and Qwen2.5-Coder with identical prompts. Demonstrate reproducible >1.0× speedup on at least one workload and safe serial fallback elsewhere.

### Gates
| Gate | Description | Pass Criteria |
|------|-------------|---------------|
| G1 | Speedup > 1.0× | At least one workload shows speculative TPS / serial TPS > 1.0 |
| G2 | Parity | Token stream identical to serial greedy (Task 06 G2) |
| G3 | Safe fallback | Adaptive disable triggers on persistent rejection |
| G4 | Reproducibility | 3 consecutive runs within ±5% TPS variance |

### Implementation
- Use `deep2_spec_bench.cpp` as base
- Add automated multi-run harness
- Test workloads: code (Python functions), prose (narrative)
- Models: TinyLlama-1.1B, Qwen2.5-Coder-7B
- Config: gamma=4, ngram=3, prompt-lookup draft

### Evidence
- `evidence/deep2_spec_acceleration/SPEEDUP_REPORT.json`
- `evidence/deep2_spec_acceleration/PARITY_VERIFICATION.txt`

---

## Task 08: DEEP2_GPU_DECODE_ROOFLINE_001
**Profile and optimize GPU decode bottlenecks**

### Objective
Measure kernel execution, launch overhead, memory bandwidth, synchronization, KV reads, and LM-head costs. Optimize the largest measured bottleneck.

### Gates
| Gate | Description | Pass Criteria |
|------|-------------|---------------|
| G1 | Kernel timing | All major kernels timed (GEMV, attention, RMSNorm, LM-head) |
| G2 | Memory bandwidth | Achieved bandwidth reported vs theoretical peak |
| G3 | Launch overhead | Vulkan dispatch latency measured and reported |
| G4 | Bottleneck ID | Largest time consumer identified with % of decode step |
| G5 | Optimization | One optimization applied with measurable improvement |

### Implementation
- New tool: `deep2_gpu_decode_roofline.cpp`
- Use Vulkan timestamp queries for kernel timing
- Measure: `DispatchGemvQ4KBatch`, `DispatchGemvQ4KBatch8Row`, attention, KV cache reads
- Profile 100 decode steps, report median/mean/p99
- Apply optimization to largest bottleneck, re-measure

### Evidence
- `evidence/deep2_gpu_decode_roofline/ROOFLINE_PROFILE.json`
- `evidence/deep2_gpu_decode_roofline/OPTIMIZATION_REPORT.md`

---

## Task 09: DEEP2_GGUF_LIFECYCLE_001
**Certify production GGUF lifecycle**

### Objective
Test load → generate → cancel → unload → reload → corrupted GGUF handling with memory accounting and fail-closed architecture dispatch.

### Gates
| Gate | Description | Pass Criteria |
|------|-------------|---------------|
| G1 | Load | Model loads, weights mapped, KV cache allocated |
| G2 | Generate | Produces tokens, streaming callback works |
| G3 | Cancel | Mid-generation cancel stops cleanly, no leak |
| G4 | Unload | All allocations freed, VRAM/host memory returned |
| G5 | Reload | Second load works identically to first |
| G6 | Corrupted GGUF | Truncated/malformed file rejected at load, no crash |
| G7 | Memory accounting | All allocations tracked, zero leaks after full cycle |

### Implementation
- New tool: `deep2_gguf_lifecycle.cpp`
- Use `Deep2Engine` directly (loadModel, generateStream, unloadModel, switchModel)
- Inject cancellation via callback return false
- Corrupt test: truncate GGUF, flip magic bytes, invalid metadata
- Memory tracking: `GGUFLoader::FreeTensorData`, `alignedAlloc`/`alignedFree` counters

### Evidence
- `evidence/deep2_gguf_lifecycle/LIFECYCLE_RECEIPT.json`
- `evidence/deep2_gguf_lifecycle/MEMORY_ACCOUNTING.csv`

---

## Task 10: DEEP2_MULTIGPU_RESILIENCE_001
**Certify multi-GPU scheduling and resilience**

### Objective
Validate R9700-only operation, dual-GPU residency when available, device-loss handling, and safe recovery without corrupted output or memory leaks.

### Gates
| Gate | Description | Pass Criteria |
|------|-------------|---------------|
| G1 | R9700-only | Full model runs on single R9700 (32GB), no OOM |
| G2 | Dual-GPU residency | Weights split across GPUs per layer plan, both utilized |
| G3 | Device loss | Simulated GPU removal (queue timeout) → recovery without corrupt output |
| G4 | Rebind | Dropped blocks re-uploaded to surviving GPU, generation continues |
| G5 | No leaks | VRAM/host memory stable after recovery cycle |

### Implementation
- New tool: `deep2_multigpu_resilience.cpp`
- Use `DualGPUBackend`, `DualGPUHook`, `Deep2MultiGpuLayerPlan`
- Single GPU: force all layers to GPU 0 via layer plan
- Dual GPU: alternate layers (odd→GPU0, even→GPU1)
- Device loss: kill worker thread, trigger `DropAllOnGPU`, `RebindBlock`
- Measure: generation continues, logits valid, no memory growth

### Evidence
- `evidence/deep2_multigpu_resilience/RESILIENCE_RECEIPT.json`
- `evidence/deep2_multigpu_resilience/DEVICE_LOSS_RECOVERY.log`

---

## Task 11: DEEP2_CONTEXT_SCALING_001
**Certify long-context KV correctness**

### Objective
Progress through 4K, 32K, 128K, 512K, and 1M where supported. Verify KV contents, memory residency, position handling, and measured decode scaling.

### Gates (from existing `deep2_context_scaling.cpp`)
| Gate | Description | Pass Criteria |
|------|-------------|---------------|
| C1 | Geometry | KV blocks report ≥ N allocated rows after N positions |
| C2 | Write coverage | Zero leading all-zero rows |
| C3 | Row content | Sampled K/V rows finite and non-constant |
| C4 | Position sanity | Causal ordering preserved |
| C5 | Residency | Leases held, resident bytes consistent |
| C6 | Scaling | Tokens/sec recorded, decode steps don't regress |

### Implementation
- Already implemented in `deep2_context_scaling.cpp`
- Run with `--lengths 4096,32768,131072,524288,1048576`
- Use model with 1M context (Nemotron 30B declares 1M)
- Report decode TPS at each length

### Evidence
- `evidence/deep2_context_scaling/CONTEXT_SCALING_RECEIPT.txt` (exists)
- `evidence/deep2_context_scaling/CONTEXT_SCALING_RECEIPT.json` (to add)

---

## Task 12: RAWR_AUTONOMOUS_REPAIR_E2E_001
**Independent autonomous repair challenge**

### Objective
Give Deep2 an undisclosed repository defect. Require genuine model-driven inspection, editing, build, testing, self-correction, and independent final verification.

### Gates
| Gate | Description | Pass Criteria |
|------|-------------|---------------|
| G1 | Defect injection | Realistic bug inserted (not trivial, not obvious) |
| G2 | Autonomous detection | System identifies defect without human hints |
| G3 | Repair | Valid fix applied, builds, tests pass |
| G4 | Self-correction | If first fix fails, system iterates |
| G5 | Independent verification | External test confirms fix, no regression |

### Implementation
- Orchestration script: `certify_autonomous_repair.ps1`
- Defect types: off-by-one in KV indexing, quantization dispatch bug, memory leak
- Use agentic loop (existing `deep2_agentic_loop.cpp`)
- Verification: independent test harness runs after repair

### Evidence
- `evidence/rawr_autonomous_repair/DEFECT_DESCRIPTION.md`
- `evidence/rawr_autonomous_repair/REPAIR_LOG.json`
- `evidence/rawr_autonomous_repair/VERIFICATION_RECEIPT.txt`

---

## Task 13: HEXMAG_PARALLEL_WORKTREE_001
**Certify HexMag parallel swarm execution**

### Objective
Run concurrent agents in isolated worktrees with task ownership, dependency scheduling, conflict resolution, and safe merge certification.

### Gates
| Gate | Description | Pass Criteria |
|------|-------------|---------------|
| G1 | Worktree isolation | Each agent in own git worktree, no cross-contamination |
| G2 | Task ownership | Clear assignment, no duplicate work |
| G3 | Dependency scheduling | Dependent tasks wait for prerequisites |
| G4 | Conflict resolution | Merge conflicts detected and resolved automatically |
| G5 | Safe merge | Merged result passes all tests, no regressions |

### Implementation
- Use `.kilo/worktrees/` infrastructure (already exists)
- Agent manager: `agent_manager` tool with sections
- Task graph: YAML/JSON defining dependencies
- Conflict resolution: 3-way merge + semantic check
- Merge certification: full test suite on merged result

### Evidence
- `evidence/hexmag_parallel_swarm/SWARM_RECEIPT.json`
- `evidence/hexmag_parallel_swarm/MERGE_CERTIFICATION.log`

---

## Task 14: RAWR_FULL_RECOVERY_001
**Certify crash recovery and fault injection**

### Objective
Terminate inference, worker, build, and coordinator processes at controlled points. Verify durable resume, no duplicate committed actions, and accurate recovery receipts.

### Gates
| Gate | Description | Pass Criteria |
|------|-------------|---------------|
| G1 | Inference crash | Kill during decode → resume from last checkpoint |
| G2 | Worker crash | Kill agent → task reassigned, no duplicate work |
| G3 | Build crash | Kill compilation → resume from last successful object |
| G4 | Coordinator crash | Kill orchestrator → state recovered from journal |
| G5 | No duplicates | Zero duplicate committed actions across all scenarios |
| G6 | Receipts | Every recovery produces signed receipt |

### Implementation
- New tool: `deep2_fault_injection.cpp` + `certify_recovery.ps1`
- Checkpoint system: `Deep2Engine` state serialization
- Kill points: prefill end, mid-decode, post-token, during GPU dispatch
- Recovery: load checkpoint, verify KV cache consistency
- Journal: append-only operation log for coordinator

### Evidence
- `evidence/rawr_full_recovery/FAULT_INJECTION_REPORT.json`
- `evidence/rawr_full_recovery/RECOVERY_RECEIPTS/`

---

## Task 15: RAWR_PRODUCTION_CERT_001
**Independent production release certification**

### Objective
Rebuild from clean source, run all regression/endurance/security gates, reproduce performance numbers, verify offline operation, and produce a signed or hash-verified release manifest.

### Gates
| Gate | Description | Pass Criteria |
|------|-------------|---------------|
| G1 | Clean rebuild | Fresh clone → configure → build → all targets succeed |
| G2 | Regression gates | All existing certifications (01-14) PASS |
| G3 | Endurance | 1000 token generation on 3 models, zero crashes |
| G4 | Security | No hardcoded secrets, fail-closed on malformed input |
| G5 | Performance | Reproduce baseline TPS within ±5% |
| G6 | Offline | Full operation without network (local GGUF only) |
| G7 | Signed manifest | SHA256 of all artifacts, GPG-signed or hash-verified |

### Implementation
- Orchestration script: `certify_production_release.ps1`
- Clean build in temp directory
- Run all certification tools in sequence
- Performance: compare against frozen baselines
- Manifest: JSON with all artifact hashes, git commit, timestamp

### Evidence
- `evidence/rawr_production_cert/PRODUCTION_MANIFEST.json`
- `evidence/rawr_production_cert/REGRESSION_SUMMARY.md`
- `evidence/rawr_production_cert/PERFORMANCE_REPRODUCTION.csv`
- `evidence/rawr_production_cert/RELEASE_ATTESTATION.sig`

---

## Execution Order

```
Phase 1 (GPU Path Certification):
  06 → 07 → 08

Phase 2 (Lifecycle & Resilience):
  09 → 10

Phase 3 (Context & Autonomous):
  11 → 12

Phase 4 (Swarm & Recovery):
  13 → 14

Phase 5 (Release):
  15
```

**Dependencies**: 
- 06 requires working speculative verifier (exists)
- 07 requires 06 PASS
- 08 independent but benefits from 06/07
- 09 independent (uses Deep2Engine directly)
- 10 requires DualGPUBackend (exists)
- 11 already implemented (needs JSON receipt)
- 12-14 require orchestration infrastructure
- 15 requires all prior tasks PASS

---

## Sign-off

Each task produces:
1. **Executable** — `F:\rawrxd\tools\<task>.exe`
2. **Build script** — `F:\rawrxd\tools\build_<task>.bat`
3. **Evidence directory** — `F:\rawrxd\evidence\<task>\`
4. **Receipt** — `RECEIPT.txt` + `receipt.json`
5. **Verdict** — PASS/FAIL in receipt and exit code

**Final deliverable**: `RAWR_PRODUCTION_CERT_001` manifest with all 10 task receipts embedded.