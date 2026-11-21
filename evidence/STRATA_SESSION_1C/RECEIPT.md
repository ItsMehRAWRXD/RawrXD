# Phase 1C — MoE session acceptance — 2026-11-21

Sprint gate: **the reusable StrataChatSession must show real expert residency on a MoE model**

## Setup

```
exe   F:\rawrxd\build\Release\deep2_strata_chat_session.exe
SHA256 2D124CA38CD90675DCA1E5D14A78E617FE78EDDA65670EB858ED05E896E87A32
model F:\rawrxd\models\deepseek-coder-v2_16b.gguf   (deepseek2, MoE, 64 experts)
cmd   --tokens 1 450 4996 --max-new 8 --gpu --strata
```

## Observed

```
[tok 0..7] 2433, 207, 17, 15, 15, 22, 12, 17
DISPATCH gpu_calls=6644 cpu_calls=0 nonfinite=0
EXPERT_LEDGER observations=5148 hits=2829 evictions=0
SESSION_STATUS OK
EXIT=0
```

## Acceptance

| Gate | Result |
|---|---|
| Session compiles / links | PASS |
| GGUF ingestion | PASS |
| Graph binding | PASS |
| Prefill | PASS |
| ≥8 generated tokens | PASS |
| GPU dispatches > 0 | **6,644** |
| CPU calls = 0 | **PASS** |
| Non-finite logits = 0 | **PASS** |
| Expert observations > 0 | **5,148** |
| Session finalisation | PASS |
| Process exit | 0 |

Expert hit rate = 2,829 / 5,148 = **0.5496** over this short cold run.

## Interpretation

- The reusable `StrataChatSession` (commit `2c9e5b130e`) performs real GPU inference and
  drives the expert-residency ledger on a MoE model — not only on dense models.
- Zero evictions at 8 tokens is expected; residency pressure appears only over longer runs or
  smaller budgets (Phase 1D).
- This is the component Phase 2 will wire into `generateResponseAsync` for the `strata` route.

## Caveats

- 3 prefill + 8 decode tokens; one prompt; single device (R9700).
- Hit rate is not comparable to the benchmark's 84% because the workload is far shorter.
- Coherent text was not assessed; the harness prints token IDs, not decoded text.
- No GUI involvement yet.