# A7 — Open gaps vs Top-25 criteria (fail-closed)

```
ASOF_LOCAL=2026-11-13T21:32:00-05:00
WORKSTREAM=A7_COMPETITIVE_BENCH_OPEN_GAPS
PROMOTE=0 · CERTIFIED=0 · TIP_CLIMB=HOLD · COMPETITIVE_PASS=0
INVENT_PASS=0 · INVENT_PEER_SCORE=0 · NOT_RUN!=PASS
PARENT_PCT_WRITE=0 · LIVE=FORBIDDEN · CANON=FORBIDDEN
CANON_OVERALL=48 = min(CLI67,GUI48)
SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS
```

**Authority (read-only cites):**  
`../JOINT_STATUS_LIVE.txt` · `../BOARD_SINGLE_WRITER.txt` · `../VALUATION_CLI.txt` ·  
`../GUI_TOP25_VALUATION_001/gpu/VALUATION_GUI_REMEASURE_TIP6754_GATE_075.txt` ·  
`../../COMPETITIVE_BENCH_001/STATUS.txt` · peer product cells remain `NOT_RUN` (`MATRIX.md`)

**Bar:** Top-25 parity cell = **100**.  
**Maturity delta** = `100 − CONTROLLING_%` (or disposition gap when no controlling %).  
EXE_COL / UNMERGED proposals are **not** controlling. Do not invent scores.

---

## 1. Controlling rollup (sealed — do not invent)

| Lane | SCORE_PCT | SUM / basis | Auth seal | COMPLETE |
|------|----------:|-------------|-----------|----------|
| CLI | **67** | 811 / 12 | `../CLI_TOP25_VALUATION_001/runs/R46_COMBINED_MERGE_SEAL.txt` | 0 |
| GUI | **48** | 585 / 12 | `../GUI_TOP25_VALUATION_001/gpu/GPU_RESIDENT_DECODE_NO_HOST_FALLBACK_074.txt` + tip6754 remeasure | 0 |
| OVERALL | **48** | min(67,48) | `../BOARD_SINGLE_WRITER.txt` | JOINT=0 |

CLI tip SHA `15A119D1…` · GUI tip bind `6754616E…` · GUI absorb074 `0B6229F2…`

---

## 2. Focus-axis open-gap matrix (CLI × GUI)

Focus requested: **local inference · agent edit/build/test · LSP · packaging**.  
Related open axes (DAP / Clean-VM) listed where they bound maturity.

| Focus axis | CLI controlling | GUI controlling | Open gap (fail-closed) | Seal cites | Maturity Δ |
|------------|----------------:|----------------:|------------------------|------------|-----------:|
| **Local inference (dense/MF)** | CAT7=**90** (gemma MATCH residual) | Cat6 absorb=**85** (3/4 MF; gemma FAIL_CLOSED) | Tip bind `6754616E` still `TIP6754_LINEAGE_GPU_RESIDENT=0` / `TIP_TOKEN_SURVIVED=0`; absorb ≠ tip lineage | CLI: `CAT7_DENSE_MATCH_CLOSED.txt` · GUI: `GPU_RESIDENT_DECODE_NO_HOST_FALLBACK_074.txt` · `TIP6754_LINEAGE_GPU_RESIDENT_FAIL_CLOSED_075.txt` · MF `MULTI_FAMILY_ABSORB074_*` | Tip lineage **OPEN** (GPU_RESIDENT=0 on tip); absorb Cat6 Δ=**15**; CLI CAT7 Δ=**10** |
| **Local inference (MoE/SSM)** | CAT8=**58** | (GUI MoE not separately scored on controlling 12-cat; MF gemma open) | MoE/SSM/coherence OPEN; MiniMax REAP exclusive HOLD | `R46_COMBINED_MERGE_SEAL.txt` · `../../COMPETITIVE_BENCH_001/STATUS.txt` | CLI Δ=**42** |
| **Agent edit / build / test** | CAT4=**85**; A4 llama32 `EDIT_BUILD_TEST_PASS=1` on tip CLI SHA but `MODEL_SELECTED_TOOL=0` / tip `FORCE_TOOL` ABSENT | Cat11=**25** controlling; HWND EBT **NOT_RUN**; EXE_COL 075b/075c Cat11=45 UNMERGED | M3 incomplete: tip FORCE_TOOL not bound; GUI tip HWND agentic EBT NOT_RUN; `FILES_READ/PATCH` cycle ≠ full agentic product on GUI tip | CLI: `A4_CLI_EDIT_BUILD_TEST_LLAMA32_*/run.meta.txt` · `m3_cli_ebt_*` · GUI: `A4_GUI_EDIT_BUILD_TEST_*/SEAL_PROPOSE.txt` · `MILESTONE_PRIORITY_LOCK.txt` M3 | GUI Cat11 Δ=**75**; CLI CAT4 Δ=**15** (tip FORCE_TOOL residual) |
| **LSP** | (no separate CLI LSP cat; DAP_CLI related) | Cat10=**20** controlling; EXE_COL 075c Cat10=**40** RUNTIME_REACHED **UNMERGED** | Controlling holds 20; composite merge **N** (cross-SHA blend REJECT) | `ABSORB075c_NOFORCE_CAT10_LSP_SEAL.txt` · `board_receipts/BR_CAT10_075c_COMPOSITE_MERGE_001.txt` · tip6754 remeasure Cat10=20 | Controlling Δ=**80**; EXE_COL candidate Δ=**60** (not merged) |
| **Packaging / offline install** | CAT1=**65** · CAT3=**60** · CAT12=**80** | Cat8=**30** controlling; EXE_COL 075c Cat8=45 UNMERGED | M4 host zip **SEALED**; `CLEAN_VM=0 NOT_RUN`; MSI/NSIS/winget **ABSENT**; `M4_PCT_RAISE=0` | `ENTERPRISE_COMPLETION_PROGRAM_001/A6_OFFLINE_INSTALLER_M4_001.txt` · `OFFLINE_INSTALLER_M4_001/SEAL.txt` · JOINT `M4_*` | GUI Cat8 Δ=**70**; CLI CAT1 Δ=**35** / CAT3 Δ=**40** |
| **Debugger / DAP** (agentic adjacent) | CAT6=**15** `DAP_CLI=ABSENT` | Cat4=**35** controlling; Wire077 Cat4=55 CANDIDATE UNMERGED | CLI DAP absent; GUI BP_STEP_VARS / journal OPEN on controlling | `R46_COMBINED_MERGE_SEAL.txt` · `DAP_WIRE_STUB_REPLACE_077.txt` · tip6754 remeasure | CLI Δ=**85**; GUI Cat4 Δ=**65** |

---

## 3. Full controlling category snapshot (citation only)

### CLI — R46 (`VALUATION_CLI.txt`)

| # | Category | % | Open residual | Δ |
|---|----------|--:|---------------|--:|
| 1 | Install | 65 | Clean-VM ABSENT | 35 |
| 2 | Install docs | 85 | CLEAN_VM ABSENT only | 15 |
| 3 | Distribution | 60 | NOT_PUBLISHED | 40 |
| 4 | Agentic CLI | 85 | tip FORCE_TOOL ABSENT; slash/history | 15 |
| 5 | Terminal / ConPTY | 85 | flaky + Terminal-Bench NOT_IN_TREE | 15 |
| 6 | Debugger | **15** | DAP_CLI=ABSENT | **85** |
| 7 | Dense GPU | 90 | multi-family gemma MATCH | 10 |
| 8 | MoE GPU | 58 | SSM + coherence + MiniMax | 42 |
| 9 | REAP | 45 | TOK=0 | 55 |
|10 | Recovery | 75 | reject-100 polish | 25 |
|11 | Competitive | 68 | broader MATCH/TPS; peer IDE NOT_RUN | 32 |
|12 | Offline | 80 | CLEAN_VM | 20 |

### GUI — tip6754 + absorb074 controlling (`VALUATION_GUI_REMEASURE_TIP6754_GATE_075.txt`)

| # | Category | % | Open residual | Δ |
|---|----------|--:|---------------|--:|
| 1 | Shell HWND | 55 | tip/absorb surfaces | 45 |
| 2 | Editor | 60 | nongpu prior | 40 |
| 3 | Terminal/ConPTY | 55 | product gate open | 45 |
| 4 | DAP | 35 | BP_STEP_VARS=NOT_RUN_NO_JOURNAL | 65 |
| 5 | Agentic chat | 55 | absorb GEN SEH=0 | 45 |
| 6 | Local GPU | 85 | tip lineage GPU_RESIDENT=0; gemma FAIL_CLOSED on MF | 15 |
| 7 | Streaming | 55 | prior | 45 |
| 8 | Packaging | **30** | NOT_PUBLISHED; CLEAN_VM NOT_RUN | **70** |
| 9 | Offline autonomy | 55 | local MF HOST_DECODE=0 | 45 |
|10 | LSP | **20** | HOLD on controlling; 075c=40 EXE_COL UNMERGED | **80** |
|11 | Agentic edit | **25** | HWND EBT NOT_RUN | **75** |
|12 | Four-panel | 55 | weak_cats HWND | 45 |

---

## 4. Competitive peer bench (no invented peer wins)

| Item | Disposition | Cite |
|------|-------------|------|
| 25×12 product matrix scaffold | RawrXD 12 SEAL_CITED; peers 288 NOT_RUN | `MATRIX.md` · `COUNTS.txt` |
| Suite matrix | COMPETITIVE_PASS=0; IDE --help TIMEOUT; coding autofix NOT_RUN; external IDE/Terminal-Bench NOT_IN_TREE | `../../COMPETITIVE_BENCH_001/SUITE_MATRIX.md` |
| Tip CLI vulkan 15A119 R38 | PASS_RUNTIME GEN=4; COMPETITIVE_PASS=0; MATCH=0 | `../../COMPETITIVE_BENCH_001/STATUS.txt` |

---

## 5. Top 5 blockers (ranked by maturity delta)

Controlling scores only. EXE_COL ≠ raise.

| Rank | Blocker | Lane | Controlling | Δ vs Top25 bar | Why it bounds maturity | Seal / receipt |
|-----:|---------|------|-------------|----------------:|------------------------|----------------|
| **1** | DAP / debugger absent | CLI CAT6 | **15** | **85** | Largest sealed Δ; agent debug surface ABSENT on tip CLI | `R46_COMBINED_MERGE_SEAL.txt` · `VALUATION_CLI.txt` |
| **2** | LSP weak on controlling GUI | GUI Cat10 | **20** | **80** | OVERALL lane is GUI; 075c Cat10=40 remains UNMERGED (cross-SHA REJECT) | tip6754 remeasure · `ABSORB075c_NOFORCE_CAT10_LSP_SEAL.txt` · `BR_CAT10_075c_COMPOSITE_MERGE_001.txt` |
| **3** | Agentic edit/build/test on GUI tip | GUI Cat11 | **25** | **75** | HWND EBT NOT_RUN on `6754616E`; M3 incomplete | `A4_GUI_EDIT_BUILD_TEST_*/SEAL_PROPOSE.txt` · `MILESTONE_PRIORITY_LOCK.txt` |
| **4** | Packaging / Clean-VM | GUI Cat8 (+ CLI install/dist) | **30** (GUI) | **70** | M4 host sealed but CLEAN_VM NOT_RUN, MSI/channels ABSENT, M4_PCT_RAISE=0 | `A6_OFFLINE_INSTALLER_M4_001.txt` · JOINT `M4_CLEAN_VM=0` |
| **5** | Tip-bound local inference lineage | GUI tip SHA | GPU_RESIDENT=**0** / TOK_SURVIVED tip=**0** | **OPEN** (tip ≠ absorb Cat6=85) | Authority lane `OVERALL_AUTHORITY_LANE=GUI_TIP_ABSORB`; tip lineage fail-closed holds tip climb | `TIP6754_LINEAGE_GPU_RESIDENT_FAIL_CLOSED_075.txt` · `GPU_RESIDENT_DECODE_NO_HOST_FALLBACK_074.txt` |

Honorable (next deltas, not top-5): GUI Cat4 DAP=35 Δ65 · CLI REAP CAT9=45 Δ55 · CLI MoE CAT8=58 Δ42 · CLI Dist CAT3=60 Δ40.

---

## 6. Explicit non-claims

- No PARENT / LIVE / CANON PCT write this pack.
- No peer IDE scores invented (`PEER_NOT_RUN=288`).
- SEAL_CITED ≠ competitive win vs Top-25 IDEs (`COMPETITIVE_PASS=0`).
- UNMERGED EXE_COL (Cat4 Wire077, Cat8/10/11 075b/075c, GUI=50 proposal) ≠ CONTROLLING_%.
- `PROMOTE=0` · `TIP_CLIMB=HOLD` · `JOINT_COMPLETE=0`.

## 7. Pointers

| Artifact | Path |
|----------|------|
| This matrix | `OPEN_GAPS_MATRIX.md` |
| Product×task scaffold | `MATRIX.md` |
| RawrXD seal index | `RAWRXD_SEAL_INDEX.txt` |
| Competitive bench status | `../../COMPETITIVE_BENCH_001/STATUS.txt` |
| Board lock | `../BOARD_SINGLE_WRITER.txt` |

END
