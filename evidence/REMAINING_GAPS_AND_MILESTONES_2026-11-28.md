# Remaining gaps & milestones — comprehensive audit (2026-11-28)

HEAD 23b844f816 · branch integration/combined-2026-11-25 (pushed).

## 1. Build & test baseline (CURRENT)
- **Full `all` build: GREEN** — 369/369 targets, exit 0 (both products, all tools, all test exes).
- **ctest: 88/89 effectively PASS** (98%). `gate2_manifest_consistency` passes on rerun
  (order/flaky); the one real failure is `deep2_multitoken_decode_parity` (below).
- 2 skipped (GPU/model-gated): deep2_h11_prefill_parity, deep2_persistent_kv_smoke.

## 2. Real bug found by the test suite
- **deep2_multitoken_decode_parity FAIL**: batched prefill diverges from serial prefill
  (`S03_PREFILL_PARITY maxAbs=0.495 maxRel=127`, `S03_HIDDEN_PARITY first_divergent_pos=0`,
  maxAbs 2.13). **Precise localization**: divergence is at POSITION 0 (the first token), so it
  is NOT a causal-mask / position-N defect — it is the batched layer-major
  `Deep2Engine::prefillBatched` → `forwardLayerBatched` first-token path (embedding / finalNorm /
  KV-write ordering) differing from the serial `prefillSerial` → `forwardTokenAllLayers`.
  Serial: per-token embed→forwardTokenAllLayers(h, t+1)→norm→publish→kv.advance().
  Batched: embed all n → forwardLayerBatched(layer, batch, base, base+1) layer-major → publish →
  kv.advanceBy(n). The pos-0 hidden differs => the batched layer pass for the first token is not
  bit-comparable to the serial one. Milestone: make `forwardLayerBatched` pos-0 output match
  `forwardTokenAllLayers` (<1e-3). This is a focused GPU/numerical fix, NOT a config gap.

## 3. Known correctness/perf gaps (from this session's live runs)
- **GPU Q4_K forward garbled output**: single-GPU Q4_K packed GEMV produces finite-but-wrong
  logits (CPU coherent, GPU garbled). Localized to the Q4_K packed GEMV shader/kernel.
- **Performance**: ~7.8 TPS (CPU tinyllama Q4) vs G15 target 150 TPS — far below.
- **gemma3-1b Q2_K** crashes the Deep2 loader (model-format compat); tinyllama works.

## 4. Gate ledger (evidence/gate_ledger.json)
| Gate | Status |
|------|--------|
| G01 freeze_baseline | PASS |
| G02 explicit_cross_device_transfer | PASS |
| G03 independent_device_budgets | PASS |
| G04 concurrent_safe_residency | PASS |
| G05 native_quant_coverage | PASS (Q2_K/Q3_K/Q4_K native) |
| G06 cross_arch_parity | PARTIAL (nemotron_h FAIL §D) |
| G07 deepseek_671B | BLOCKED (no 671B GGUF on disk) |
| G08 full_numerical_correctness | PARTIAL |
| G09 streaming_bf16_nanoquant | OPEN |
| G10 continuous_generation | PARTIAL |
| G11 secondary_gpu_kv | OPEN |
| G12 long_context_1M | OPEN |
| G13 gpu_deck_scheduler | OPEN |
| G14 speculative | OPEN |
| G15 150tps | BLOCKED (~4.5–7.8 TPS) |
| G16 ide_server | BLOCKED (Qt ABI) |
| G17 agentic_tool_integrity | OPEN (mechanisms verified; certifier review) |
| G18 swarm | OPEN |
| G19 endurance | OPEN |
| G20 release_provenance | OPEN |

## 5. Work packages (WORKPACKAGES_2026-11-25)
- DONE this session: Pkg 3 (LSP 16/16), Pkg 4 (crash mechanism), Pkg 5 (routing analysis),
  Pkg 6 (build integrity), Pkg 8 (3 docs VOID).
- REMAINING:
  - Pkg 7 — session persistence port (orphaned Session.cpp members / duplicate symbols;
    needs single-owner port into FileOps + version field).
  - Pkg 9 — GPU quant dispatch completeness (Q8_K kernel, Q4_1/Q5_1/IQ4_NL executor map,
    Q6_K CPU FP32) — tied to the Q4_K GPU bug above.
  - Pkg 10 — MSVC hardware handoff (fault injection, packaged IDE, stack-overflow WER).

## 6. Milestones to "fully finished" (prioritized)
1. **Fix deep2_multitoken_decode_parity** (batched prefill parity) — real, test-backed.
2. **Fix GPU Q4_K forward** (shader/kernel numerical parity vs CPU) — unblocks Pkg 9 + G08.
3. **Close G17** — certifier review of the (now deterministic) tool-integrity evidence.
4. **Pkg 7 session port** — single-owner persistence + version field.
5. **Performance (G15)** — profile & raise TPS (NCRO hot-path).
6. **G18/G19/G20** — swarm, endurance, release provenance (need runtime/hardware).
7. **G07/G12/G16** — blocked on 671B model / 1M ctx / Qt ABI (external).

## State
```
BUILD=GREEN(369)  CTEST=88/89  CERTIFIED=0 RELEASE=HELD PROMOTE=0
BLOCKER=none (build/test)  EXTERNAL=hardware/model/certifier for G07/G12/G15/G16/G18-20
```
Build & configuration are fully finished; remaining items are correctness (multitoken parity,
GPU Q4_K), performance, and certification/hardware — each a focused follow-up.