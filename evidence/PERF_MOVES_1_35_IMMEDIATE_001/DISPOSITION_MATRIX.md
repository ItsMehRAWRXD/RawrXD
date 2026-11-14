# PERF Moves 1–35 — Immediate Disposition Matrix

```text
PACK=PERF_MOVES_1_35_IMMEDIATE_001
AUTHORITY=evidence/RAWRXD_PERFORMANCE_001/PERF_COMPLETION_CONTRACT.md §§1–35
ASOF_LOCAL=2026-11-14T08:55:00-05:00
PROMOTE=0 CERTIFIED=0 TIP_CLIMB=HOLD
GATE_STOP=1 NEXT_SPEND=NONE LOCKED=1
INVENT_PASS=0 NOT_RUN!=PASS CROSS_SHA_CREDIT=0
```

Honest statuses: `SEALED` | `INSTALLED` | `OPEN` | `BLOCKED_BY_GATE_STOP` | `N/A`.

**SSOT supremacy for coverage/epoch:** `PERF_PROGRAM_COMPLETE_002.txt` + `COVERAGE_EPOCH_0/AUTHORITY.txt` + `ENDURANCE_EPOCH_0/RECEIPT.txt` supersede stale `COVERAGE_MATRIX_001/INDEX.txt` (claims OPEN / MEASURED_UNIQUE=0 / LIVE_MEASURE_AUTHORIZED=1). Do not invent fresh MEASURED from INDEX; do not erase sealed exhaustion.

§36 Scoreboard Scheduler Law = **OUT OF SCOPE** (pointer only).

---

## Summary table

| Move# | Status | Note |
|------:|--------|------|
| 1 | SEALED | Sealed authority + TIP_CLIMB=HOLD; 5.904 historical-only. `GATE.txt` + §1. |
| 2 | SEALED | Purity profile sealed. `PERF_WITNESS_PURITY.txt` / `PERF_PASS_PROFILE_001.txt`. |
| 3 | INSTALLED | Authority artifact set present; contract §3 scripts on disk. |
| 4 | SEALED | Finite rainbow 18 (3×3×2); RNG=0. `RAINBOW_TABLE_001/` + §4. |
| 5 | INSTALLED | Coverage law in force; new live coverage spend blocked by GATE_STOP. |
| 6 | INSTALLED | Epoch law (EPOCH_SIZE=18); accounting closed via EPOCH_0. |
| 7 | SEALED | Phase A closed: env match / wall fail. `CHAMPION_ENV_BYTEWISE_REPRO_001/GATE.txt`. |
| 8 | SEALED | Exit = FAIL_WALL_REPRO → 5.904=HISTORICAL_ONLY; baseline path taken. |
| 9 | SEALED | SEARCH_BASELINE_TPS=4.329 installed + repeatable. `SEARCH_BASELINE_001.txt`. |
| 10 | SEALED | 18 unique configs enumerated. `COVERAGE_MATRIX_001/COVERAGE_MANIFEST.json`. |
| 11 | SEALED | First measurement epoch complete MEASURED_UNIQUE=18. `COVERAGE_EPOCH_0/AUTHORITY.txt`. |
| 12 | SEALED | Classification applied in epoch receipts (winner rank-only). |
| 13 | SEALED | Rank → WINNER_CONFIG_ID=QB64_QA32_QKV64 (coverage rank only). |
| 14 | SEALED | Endurance 5/5; RETAIN_BASELINE (min 3.238 < 4.329). `ENDURANCE_EPOCH_0/RECEIPT.txt`. |
| 15 | SEALED | Promotion law applied: PROMOTE=0 / PROMOTION=NONE. |
| 16 | INSTALLED | Attribution-only law; used historically (e.g. QKV readback path). |
| 17 | BLOCKED_BY_GATE_STOP | Further QKV_READBACK cut optimization spend forbidden (NO_REOPEN + NEXT_SPEND=NONE). |
| 18 | SEALED | NO_REOPEN=QB_KERNEL\|KVA\|LOGITS\|SX\|5.904 live in `GATE.txt`. |
| 19 | INSTALLED | No directional climb; TIP_CLIMB=HOLD. `TIP_CLIMB_001_HOLD.txt`. |
| 20 | INSTALLED | Tip bot 256-climb disabled. Invoke-PerfTipBot not authorized. |
| 21 | INSTALLED | Ordinal≠unique coverage law; finite 18 respected in completion seal. |
| 22 | SEALED | Epoch completion receipt present. `PERF_PROGRAM_COMPLETE_002.txt` + EPOCH_0. |
| 23 | SEALED | Matrix tree + EPOCH0 receipts; **INDEX.txt stale** — authority = AUTHORITY/COMPLETE_002. |
| 24 | INSTALLED | Preservation law; EPOCH0 receipts retained (no overwrite this pack). |
| 25 | INSTALLED | Manifest truth / `_` separator law remains sealed inference constraint. |
| 26 | INSTALLED | PRODUCT_PATH=1 required for promote; held. |
| 27 | INSTALLED | PARITY=1 required; endurance PARITY_ALL=1 recorded; no promote. |
| 28 | OPEN | STABLE_PRODUCT_WALL=0 / no promotable wall above 4.329. Climb to close = BLOCKED_BY_GATE_STOP. |
| 29 | SEALED | Valid terminal path: SEARCH_COMPLETE=1 BASELINE_RETAINED=1 PROMOTION=NONE. `PERF_PROGRAM_COMPLETE_002.txt`. |
| 30 | SEALED | TARGET_TPS_8=UNMET; CURRENT_SEARCH_SPACE=EXHAUSTED (honest). |
| 31 | BLOCKED_BY_GATE_STOP | New search-space requires separate measured-owner justification; GATE_STOP forbids spend. |
| 32 | INSTALLED | Failure-handling law; no new candidate crash work this pack. |
| 33 | BLOCKED_BY_GATE_STOP | Autonomous coverage loop would require live measure spend → STOP. Disposition-only legal. |
| 34 | SEALED | Required final authority block emitted in `PERF_PROGRAM_COMPLETE_002.txt`. |
| 35 | INSTALLED | Governing principle obeyed under STOP: no wander / no reopen / no invented PASS. |

---

## GATE_STOP ledger

### Remains BLOCKED_BY_GATE_STOP (not legally actionable as PERF spend)

- Any tip climb / rainbow live search / new SX candidate measure
- Reopen QB_KERNEL | KVA | LOGITS | SX | historical 5.904 chase
- Further QKV_READBACK cut optimization (§17)
- New search-space introduction (§31)
- Agent autonomous coverage loop requiring live witnesses (§33)
- Closing STABLE_PRODUCT_WALL via new endurance/climb (§28 actionable only after GATE_STOP lifts)

### Legally actionable under STOP (this pack / parallel)

- Disposition documentation (this matrix) — **DONE**
- Verify SEARCH_BASELINE_001 still installed at 4.329 — **DONE** (file read; no re-run)
- Epoch coverage accounting without new spend — **DONE** (AUTHORITY/COMPLETE_002 vs stale INDEX)
- Parallel product lane: CLI coherent decode on sealed SHA `0E53D810…` — `CLI_COHERENCE_UNK_001` (**ROOT_CAUSE sealed; Vulkan COHERENCE FAIL; same-SHA host A/B coherent; PROMOTE=0**)
- REAP/Laguna LAYER_NAN@L40 / attn_gate — **LEFT OPEN** → `REAP_STRATA_FAIR_H2H_001`

---

## Stale-artifact honesty

| Artifact | Claim | Superseding authority |
|----------|-------|------------------------|
| `COVERAGE_MATRIX_001/INDEX.txt` | OPEN / MEASURED_UNIQUE=0 / LIVE_MEASURE_AUTHORIZED=1 | `COVERAGE_EPOCH_0/AUTHORITY.txt` + `PERF_PROGRAM_COMPLETE_002.txt` + `ENDURANCE_EPOCH_0/RECEIPT.txt` |
| Historical 5.904 | champion wall | HISTORICAL_ONLY; NO_REOPEN |
| `rawr.exe` TPS | product CLI smoke only | NON_AUTHORITY for PERF wall (`GATE.txt`) |

Do not “fix” INDEX in this pack as a PERF reopen; note only.

---

## Parallel product lane (≠ PERF climb)

```text
CLI_INFERENCE_SMOKE_001 = PARTIAL (TOK=8 COHERENCE=FAIL Vulkan)
CLI_COHERENCE_UNK_001   = ROOT_CAUSE_SEALED
  Vulkan: nonfinite GPU hidden → zero logits → id=0 <unk>
  Same-SHA host A/B (RAWRXD_GPU_FWD=0): STDOUT="Yes, 2 + 2 =" COHERENCE=PASS (diagnostic only)
EXE_SHA256=0E53D810712979A8ECB0853DA50BD1CABEC84015F183BC43B00B101EBEAEF5D0
CROSS_SHA_CREDIT=0
PROMOTE=0
```

---

## Next legal owner

```text
NEXT_LEGAL_OWNER=GPU resident forward nonfinite on TinyLlama Vulkan/MULTIGPU
  (CLI_COHERENCE_UNK_001; SAME_SHA 0E53D810… until rebuild starts NEW smoke)
ALT_IF_CLI_BLOCKED=REAP_STRATA_FAIR_H2H_001 (Laguna LAYER_NAN@L40 / attn_gate apply)
PERF_CLIMB_OWNER=NONE (GATE_STOP=1 NEXT_SPEND=NONE)
PROMOTE=0 TIP_CLIMB=HOLD
```
