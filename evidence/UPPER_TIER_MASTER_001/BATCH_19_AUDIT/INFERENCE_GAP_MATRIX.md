# INFERENCE_GAP_MATRIX — Upper-Tier Batch 19

**Audit:** `UPPER_TIER_MASTER_001_BATCH_19_AUDIT`  
**Scope:** `F:\rawrxd` (read-only Deep2 sources/evidence)  
**Date:** 2026-11-11  

```
CERTIFIED=0
PROMOTE=0
UPPER_TIER=0
TIP_CLIMB=HOLD
STUB_ACCEPTANCE=FORBIDDEN
SOURCE_WIRED != RUNTIME_REACHED != CERTIFIED
NOT_RUN != PASS
IN_PROGRESS != PASS
FAIL != PASS
BATCH_19_MILESTONE=NOT_ACCEPTED
WIN32IDE_EDITED=0
BATCH17_BUILD_TOUCHED=0
SEALED_RECEIPTS_REWRITTEN=0
```

## Framing

| Field | Value |
| --- | --- |
| Focus | Deep2 attention / token / single / multi / numerical |
| Authority batch | `DEEP2_NATIVE_CORRECTNESS_BATCH_001` (N01–N05) |
| Historical preserve | `AGGREGATE_DECODE_DEEP2_RUNTIME_001` (cite only; not rewritten) |
| Prior Ollama E2E | `AGGREGATE_DECODE_E2E_001` (separate path) |
| P13 | OPEN — Deep2 correctness+performance |
| P14 | OPEN — STRATA readiness audit |

Tracker estimates **unchanged** this audit: engineering 82 / release 58 / AI-IDE 69 / traditional 63. Milestone completion estimate 84 cited only; not raised.

## N01–N05 / P13–P14 matrix

| ID | Name | Source wired | Runtime reached | Runtime pass | Disposition |
| --- | --- | --- | --- | --- | --- |
| N01 | Clean tip rebuild (single+multi) | Yes | Yes | Receipt PASS cited; CERTIFIED=0 | SOURCE_WIRED; RUNTIME_REACHED; not certified |
| N02 | Numerical (attn/NaN + token/logit) | Yes | Yes | Receipt PASS cited; oracle≠promote | SOURCE_WIRED; RUNTIME_REACHED; CERTIFIED=0 |
| N03 | Session isolation | Yes | Yes | **No** (`SESSION_ISOLATION_PASS=0`) | RUNTIME_REACHED; FAIL; RECEIPT absent |
| N04 | Concurrency architecture | Partial (mutex serialize) | No N04 receipt | No | TRUE_PARALLEL=NOT_RUN |
| N05 | E2E stress acceptance | No harness dir | No | No | NOT_RUN |
| P13 | Deep2 correctness+performance | N01–N05 ladder | Partial | No | Remains OPEN |
| P14 | STRATA readiness | Outside N0x | Not Batch19 closure | No | Remains OPEN |

## Aggregate decode (historical cite)

- `AGGREGATE_DECODE_DEEP2_RUNTIME_001`: `deep2_runtime_reached=1`, HTTP fallback 0, stub tokens 0; single TPS ≈0.28; multi TPS ≈0.19; **CERTIFIED=0**.
- Multi is mutex-serialized (`decode_mu_` in `AggregateDecodeDeep2Backend.cpp`); `CONCURRENT=1` ≠ true parallel.
- `MILESTONE_ACK`: do not relabel as full certification; next_batch N01–N05; NOT_VERIFIED includes session isolation, thread-safe shared engine, sustained throughput.

## N01 (cite sealed receipt)

Sealed `N01_CLEAN_TIP_REBUILD/RECEIPT.json` status=PASS, CERTIFIED=0, PROMOTE=0: tip lib rebuild + aggregate single/multi smokes BACKEND=DEEP2, GENERATED_TOKENS 8/12, TPS 0.280010 / 0.179261. Preserves historical AGGREGATE_DECODE baseline without overwrite. `win32ide_untouched=1`.

## N02 (cite sealed receipt)

Sealed `N02_NUMERICAL_CORRECTNESS/RECEIPT.json` status=PASS, CERTIFIED=0: ATTN_FINITE_VALID=1 / ATTN_NAN_REJECTED=1; geometry headDim=64 qHeads=32 kvHeads=4; PREFILL_PARITY_MAX_REL=0; TOKEN_ID_MATCH=1. Explicitly not an external oracle promotion. Tip lib advanced vs N01 sealed hash — N01 smokes remain sealed to N01 HASHES.

## N03 (blocker)

Plan status IN_PROGRESS; **no RECEIPT.json**.

- Build: `BUILD_LOG2.txt` → `N03_BUILD_EXIT=0`.
- Run: `RUN.txt` → `KV_PTR … DISTINCT=1`, `CANCEL_ISOLATED=1`, but `OUTPUTS_OK=0`, `TOKENS_B=` empty, peer engine `B3_ABORT … 0xC0000005` / FORWARD_FAULT.
- Terminal lines: `SESSION_ISOLATION_PASS=0` / `CERTIFIED=0` / `PROMOTE=0`.

**Verdict:** RUNTIME_REACHED with **FAIL**. Do not invent PASS.

## N04 / N05

- N04 directory absent. Shared-engine path still mutex-serialized; optional_next on aggregate disposition remains open.
- N05 directory absent. Short smokes (8/12 tokens) are baseline-only ≠ stress acceptance. `SUSTAINED_THROUGHPUT` still NOT_VERIFIED on milestone ack.

## P13 / P14 mapping

- **P13** owns Batch 19 Deep2 correctness+performance. N01/N02 receipt PASSes are candidate evidence only and **do not close P13**. N03 FAIL + N04/N05 OPEN keep P13 OPEN.
- **P14** STRATA readiness is adjacent dual-engine/IDE readiness; Deep2 N0x does not close it. STRATA pilot laws elsewhere remain `STRATA_GPU_PASS != IDE_E2E_PASS`.

## Controlling blockers

1. **N03_SESSION_ISOLATION_FAIL** — concurrent dual-engine AV / empty TOKENS_B → PASS=0.
2. **N04_TRUE_PARALLEL_OPEN** — mutex multi ≠ MT-safe shared engine.
3. **N05_E2E_STRESS_OPEN** — no stress receipt.
4. **P13_STILL_OPEN** / **P14_STILL_OPEN**.
5. Batch17 G1 native IDE rebuild noted as out-of-scope (not fought); this audit path is headless Deep2.

## Rollup

- Receipt PASS cited: N01, N02 (CERTIFIED=0).
- Runtime reached: N01, N02, N03, historical AGGREGATE_DECODE.
- Runtime pass this audit: **0** (N03 FAIL; N04/N05 NOT_RUN; N01/N02 ≠ certification).
- Batch 19 milestone: **NOT_ACCEPTED**.
- Next executable gate: clear N03 dual-engine concurrent fault and seal RECEIPT without inventing PASS; then N04; then N05. Keep `CERTIFIED=0` `PROMOTE=0`.

Authority JSON: `INFERENCE_GAP_MATRIX.json`.
