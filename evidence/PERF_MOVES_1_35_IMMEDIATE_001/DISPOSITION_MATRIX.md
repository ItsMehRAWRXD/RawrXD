# PERF Moves 1–35 — Disposition Matrix

```text
PACK=PERF_MOVES_1_35_IMMEDIATE_001
AUTHORITY=RAWRXD_PERFORMANCE_001/PERF_COMPLETION_CONTRACT.md
ASOF=2026-11-14
PROMOTE=0
TIP_CLIMB=HOLD
GATE_STOP=1
NEXT_SPEND=NONE
INVENT_PASS=0
```

Law: `NOT_RUN != PASS`. Status values: **SEALED** | **INSTALLED** | **OPEN** | **BLOCKED_BY_GATE_STOP** | **N/A**.

Supremacy: `GATE.txt` `GATE_STOP=1` / `NEXT_SPEND=NONE` blocks new rainbow live measure / tip climb / QB|KVA|LOGITS|SX|5.904 reopen even where coverage artifacts still say `LIVE_MEASURE_AUTHORIZED=1`.

| Move | Section | Status | Evidence pointer |
|-----:|---------|--------|------------------|
| 1 | Current Sealed Authority | SEALED | `PERF_PASS_PROFILE_001.txt`, `PERF_WITNESS_PURITY.txt`, `TIP_CLIMB_001_HOLD.txt` — TIP_CLIMB=HOLD; 5.904 historical |
| 2 | Purity Contract | SEALED | `PERF_WITNESS_PURITY.txt` CHRONO=LUKEWARM; FORCED_OFF/ON profile sealed |
| 3 | Existing Authorities and Artifacts | SEALED | Contract §3 list present under `RAWRXD_PERFORMANCE_001/` + scripts/ |
| 4 | Rainbow Search Authority | SEALED | `RAINBOW_TABLE_001/INDEX.txt` ENUMERATOR_AUTHORITY=SEALED; FINITE_PASS_SIZE=18; LIVE_MEASURE_AUTHORIZED=0 |
| 5 | Coverage Law | INSTALLED | `COVERAGE_MATRIX_001/` UNIQUE_CONFIG_COUNT=18 DUPLICATE=0; MEASURED_UNIQUE=0 |
| 6 | Epoch Law | INSTALLED | `COVERAGE_MATRIX_001/EPOCH0*` present; epoch accounting artifacts exist; no new epoch spend this pack |
| 7 | Phase A — Reproduce Historical Champion | SEALED | `CHAMPION_ENV_BYTEWISE_REPRO_001/GATE.txt` PHASE_A_CLOSED=1 BYTEWISE_ENV_MATCH=1 |
| 8 | Champion Reproduction Exit | SEALED | Exit **B Historical-only**: FAIL_WALL_REPRO; 5.904=HISTORICAL_ONLY / NO_REOPEN |
| 9 | Establish the Search Baseline | INSTALLED | `SEARCH_BASELINE_001.txt` INSTALLED_SEARCH_BASELINE_TPS=4.329 SEALED |
| 10 | Phase B — Enumerate 18 Unique | SEALED | `RAINBOW_TABLE_001` + `COVERAGE_MANIFEST.json` UNIQUE=18 |
| 11 | Phase C — First Measurement Epoch | BLOCKED_BY_GATE_STOP | MEASURED_UNIQUE=0; GATE_STOP forbids new candidate measures (`NEXT_SPEND=NONE`) |
| 12 | Candidate Classification | BLOCKED_BY_GATE_STOP | Depends on §11 measures; not inventable |
| 13 | Ranking Law | BLOCKED_BY_GATE_STOP | No measured epoch ranking under STOP |
| 14 | Phase D — Winner Endurance | BLOCKED_BY_GATE_STOP | No winner; endurance forbidden until post-STOP |
| 15 | Promotion Law | SEALED | `PERF_PROMOTION_LAW_001.txt` + SEARCH_BASELINE PROMOTE_ONLY_IF; PROMOTE=0 held |
| 16 | Attribution-Only Law | SEALED | `QKV_READBACK_CUT_001_ACCEPT.txt` STATUS=CUT_MISS WALL_PROMOTE=0 |
| 17 | QKV Readback Cut Contract | SEALED | Cut miss sealed; NO_REOPEN with KVA family under GATE |
| 18 | No-Reopen Law | SEALED | `GATE.txt` NO_REOPEN=QB_KERNEL\|KVA\|LOGITS\|SX\|5.904 |
| 19 | No Directional Climb | SEALED | `TIP_CLIMB_001_HOLD.txt` TIP_CLIMB=HOLD; LIVE_TIP_CLIMB=HOLD |
| 20 | Tip Bot Law | SEALED | INVOKE_PERF_TIP_BOT=0; MAX_ITERATIONS_256=NOT_AUTHORIZED |
| 21 | Rainbow Cursor Law | SEALED | `RAINBOW_CURSOR.json` present; live advance blocked (LIVE_MEASURE_AUTHORIZED=0 + GATE_STOP) |
| 22 | Epoch Completion Receipt | OPEN | Epoch0 not complete (MEASURED_UNIQUE=0); receipt not earned — ≠ PASS |
| 23 | Coverage Matrix | INSTALLED | Matrix OPEN for fill but spend frozen; accounting OK under STOP |
| 24 | Evidence Preservation | SEALED | Existing seals retained; this pack additive only |
| 25 | Manifest Truth Law | SEALED | Generators + PASS_MANIFEST paths under purity; no invented manifests this pack |
| 26 | Product-Path Requirement | OPEN | PERF wall product-path held; parallel CLI lane PARTIAL (`CLI_INFERENCE_SMOKE_001` TOK=8 COHERENCE=FAIL) — ≠ PERF PASS |
| 27 | Parity Requirement | SEALED | Champion receipt PARITY=1 (env); epoch candidate parity N/A until §11 |
| 28 | Stable Wall Requirement | OPEN | Installed baseline 4.329; STABLE_FLOOR_ABOVE_4.329 not proven; GATE NEXT_SPEND=NONE supersedes champion NEXT_SPEND note for climb |
| 29 | Final Completion Conditions | OPEN | Coverage incomplete + GATE_STOP → final completion NOT met; ≠ PASS |
| 30 | Target TPS | OPEN | Target climb blocked; historical 5.904 NO_REOPEN; baseline compare=4.329 only |
| 31 | New Search-Space Law | SEALED | Finite 18; RNG_USED=0; no new space invented |
| 32 | Failure Handling | SEALED | FAIL_WALL_REPRO + CUT_MISS handled as sealed negatives; no reopen |
| 33 | Agent Behavior | SEALED | This pack: disposition + verify only; no tip climb; PROMOTE=0 |
| 34 | Required Final Output | OPEN | Final promotable output not produced (GATE_STOP + incomplete epoch) |
| 35 | Governing Principle | SEALED | Coverage + epoch + measured authority + fail-closed promote — principle held; execution frozen at STOP |

## Blocked vs actionable

| Class | Moves | Action |
|-------|-------|--------|
| SEALED / INSTALLED under STOP | 1–10, 15–21, 23–25, 27, 31–33, 35 | No further PERF spend; preserve |
| BLOCKED_BY_GATE_STOP | 11–14 | Wait for GATE_STOP lift; do not invent measures |
| OPEN (honest incomplete) | 22, 26, 28–30, 34 | Not closable by documentation alone |
| Legal parallel (≠ PERF climb) | — | CLI unk coherence on SHA `0E53D810…` → `CLI_COHERENCE_UNK_001` |
| Out of scope | #36 | Scoreboard pointer only |

## Verify (no new climb)

```text
GATE_STOP=1                                    # GATE.txt
INSTALLED_SEARCH_BASELINE_TPS=4.329            # SEARCH_BASELINE_001.txt + CHAMPION GATE
CHAMPION_REPRODUCTION=FAIL_WALL_REPRO          # CHAMPION_ENV_BYTEWISE_REPRO_001
UNIQUE_CONFIG_COUNT=18 MEASURED_UNIQUE=0       # COVERAGE_MATRIX_001
RAINBOW LIVE_MEASURE_AUTHORIZED=0              # RAINBOW_TABLE_001
TIP_CLIMB=HOLD                                 # TIP_CLIMB_001_HOLD.txt
PROMOTE=0
```

## Parallel product lane (pointer only)

```text
CLI_INFERENCE_SMOKE_001=PARTIAL
EXE_SHA256=0E53D810712979A8ECB0853DA50BD1CABEC84015F183BC43B00B101EBEAEF5D0
STDOUT=<unk>×8 COHERENCE=FAIL
NEXT_OWNER=CLI_COHERENCE_UNK_001 (same SHA; CROSS_SHA_CREDIT=0)
```

REAP/Laguna LAYER_NAN@L40 left OPEN — see `REAP_STRATA_*` / enterprise RELATED; not closed by this pack.
