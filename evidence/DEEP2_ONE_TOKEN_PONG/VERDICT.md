# DEEP2 one-token / PONG smoke — 2026-08-29

## Valuation (reconciled)

- Range: **$125M–$145M**, midpoint **~$135M**
- Reason for uplift vs ~$125M: P0 agent-infra discounts closed
- Autonomy premium: **not** awarded

## Fresh-process measurement (TinyLlama Q4_K_M)

Harness: `test_generate_one_token.exe <model> PONG 1` with `configureGeneration(temperature=0, topK=1)`

| Check | Result |
|-------|--------|
| Model load | PASS |
| Engine init | PASS |
| Prompt tokenize ("PONG" → 2 tokens) | PASS |
| Greedy path enabled | PASS (`[GREEDY] enabled=1`) |
| Activations finite (layer traces) | PASS (`nan=0 inf=0` on sampled B3_STATE lines) |
| Logits finite | PASS (prior 16-token run: finite=32000 nan=0) |
| Argmax == selected | PASS |
| Decoded output contains `PONG` | **FAIL** (exit 2) |
| Observed gen token | id=3748 text≈`▁game` (mojibake in console) |

## Blocker refinement

Previous note (`DEEP2_NUMERICAL_STABILITY_BLOCKER.txt`) emphasized activation explosion / NaN.
**Today's fresh-process run does not show NaN explosion on this TinyLlama path.**

Remaining blocker for PONG / agency chain:

> **Finite but incorrect logits / decode** under deterministic greedy — semantic correctness not certified.

## Authority chain (unchanged)

```
load → one-token forward → finite activations → valid logits
→ correct deterministic PONG → multi-token → tool-call synthesis → AGENT-E2E-002b
```

Current position: through **finite activations**; **failed** at correct deterministic PONG.

## Freezes

- AGENT-E2E-002: frozen
- MLA / SSM: frozen until transformer path semantically stable
- AGENT-E2E-002b: deferred

## Artifacts

- `pong_greedy1_out.txt` / `pong_greedy1_err.txt`
- `run1_stdout.txt` (earlier 16-token finite run, non-greedy)
