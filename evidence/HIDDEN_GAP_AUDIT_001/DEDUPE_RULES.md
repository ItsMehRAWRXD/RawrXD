# DEDUPE_RULES — master register merge prep

```
ASOF_UTC=2026-11-09T12:40:00Z
MOTD_ACK=1
LANE=HIDDEN_GAP_AUDIT_001
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
CONTROLLING_TIP=CC79
A4F_IMMUTABLE=1
NO_ARITHMETIC_78_PLUS_120_PLUS_45=1
INVENT_CONFIRMED_DEFECT=0
NO_CROSS_SHA_PASS_INHERITANCE=1
ENGINEERING_MATURITY_ESTIMATE=82_PERCENT_UNCHANGED
```

## Purpose

Rules for later merge into `MASTER_HIDDEN_GAP_REGISTER.md` (and any `MASTER_DEFECT_REGISTER.md`).
These rules **deduplicate** overlapping inventories. They do **not** authorize promotion, certification, or tip moves.

## Forbidden arithmetic

```
FORBIDDEN: blocker_count = 78 + 120 + 45
FORBIDDEN: blocker_count = Finish25_remain + H_CONFIRMED + Issue57_open
FORBIDDEN: maturity_delta from inventory cardinality
```

H01–H120 are **investigation targets**, not 120 defects.
The prior ~78-item acceptance register is a **starting ledger**, not an additive term.
Issue #57’s 45 gates are an **acceptance inventory**, overlapping both.

Only after identity-merge may a **set** of unique requirement IDs be counted — and only **CONFIRMED** (evidence-backed failures) enter the blocker set used for repair priority.

## Status promotion law

| From | To CONFIRMED | Allowed? |
|------|--------------|----------|
| INVESTIGATE | CONFIRMED | Only with SHA-specific FAIL / sealed negative receipt |
| UNVERIFIED | CONFIRMED | Only if missing required behavior is proven **broken** (not merely NOT_RUN) |
| UNVERIFIED | stays UNVERIFIED | Default when required and NOT_RUN |
| N_A_OUT_OF_SCOPE | CONFIRMED daily-driver | **Forbidden** until spec change + owner authorization |
| PASS on SHA_A | PASS on SHA_B | **Forbidden** (no cross-SHA inheritance) |

```
NOT_RUN ≠ FAIL ≠ CONFIRMED
OPEN_PR ≠ CONFIRMED
SOURCE_WIRED ≠ RUNTIME_PASS
PR_ACCEPTANCE_PARTIAL ≠ PRODUCT_PASS
```

## Identity keys (merge on these, not titles alone)

When two rows describe the same requirement, keep **one** master row with `aliases[]`:

1. `subsystem` + `observable_behavior` + `acceptance_proof_type`
2. Prefer stable IDs: `Hxx`, Finish-25 `Txx`, Issue #57 `A|B|C##`, Issue #49 receipt key, PR gate name
3. Record `evidence_paths[]` and `sha_scope` (CC79 / INTEG004 / PR78 tip / …)
4. If statuses disagree: take the **fail-closed** status (CONFIRMED > UNVERIFIED > INVESTIGATE for attention; never upgrade to PASS)

## Deduplicate vs Finish-25

| Finish-25 / oneshot | Typical H / GitHub overlap | Merge rule |
|---------------------|----------------------------|------------|
| Historical 19/25 | Prior authority only | Do **not** treat remaining 6 as additive to H-register; keep as Finish-25 residual set |
| Current oneshot 4/25 (T10, T16_EXT, T17, T20) | EXT/Terminal/Chat/Recovery | PASS on named tip ≠ CC79 product-final; annotate `sha_scope`; do not clear H43–H56 / H118 |
| T10 recovery | H69, H101 | T10 PASS ≠ AgentSession restore (PR78) PASS — keep H69 UNVERIFIED until PR78 restore E2E |
| T24 packaging PARTIAL | H98–H100, H105 | Single packaging row; status from SHA-specific package receipt |
| T25 / CERTIFIED=0 | H106, H120 | Certification held; H106 stays INVESTIGATE until a wrongful multi-SHA cert is evidenced **or** single-SHA cert completes |

Authority files:

- `FULL_FEATURE_ONESHOT_001\FINISH25_MATRIX.md`
- `POST_E59D_CANDIDATE_001\` historical Finish-25 seals
- Slim `A4F083DF…` daily-driver — **immutable**; EXT may be OUT_OF_SCOPE there without clearing full-feature H rows

## Deduplicate vs oneshot / INTEG gates

| Oneshot / INTEG signal | Merge rule |
|------------------------|------------|
| INTEG004 Problems PASS (`47451F24…`) | Candidate-only; **≠** CC79; **≠** PRODUCT_PASS; do not close H36-class rows on CC79 |
| CC79 Problems FAIL / Build 3014 exit=-1 | Belongs to compiler/Problems band (H27–H42 / Track C); do **not** auto-CONFIRM AgentSession H65 |
| Autonomous coding=NOT_RUN | Maps to **H120** (+ #49); status UNVERIFIED until E2E receipt |
| Deep2 PARTIAL / Ollama NOT_RUN | Maps to H73–H90; do not invent CONFIRMED numerical FAILs |
| MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED | Maps to H118 / #49; UNVERIFIED, not CONFIRMED simultaneous failure |

## Deduplicate vs PR acceptance receipts

Receipts under `evidence\PR7*_ACCEPTANCE_001\` (present: PR77, PR78, PR79):

| Receipt | Consumes / aliases | Merge rule |
|---------|--------------------|------------|
| `PR77_ACCEPTANCE_001` | Four-panel, ConPTY, Output, Problems, inference UI marshal | MERGE_READY=0 until SHA-built; CONFLICTING ≠ product CONFIRMED defect |
| `PR78_ACCEPTANCE_001` | H57–H72 AgentSession band (esp. H61–H72 Track D) | All runtime gates NOT_RUN → UNVERIFIED/INVESTIGATE only |
| `PR79_ACCEPTANCE_001` | H43–H56 ExtensionHost; H95–H96 | SOURCE_WIRED ≠ EXT PASS |
| PR #75 (no local `PR75_ACCEPTANCE_001` yet) | Compiler/linker; H41–H42; #57 B06–B12 | 37 local claimed ≠ 16 linker executed; Windows PE daily-driver in-scope; ELF/Mach-O/Android out-of-scope per below |
| PR #76 | Deep2 consolidation; H73–H90 | HELD/CONFLICTING; DO NOT MERGE; CI empty-runner ≠ kernel CONFIRMED |

```
PR_OPEN + CONFLICTING = integration_blocker_state
PR_OPEN + CONFLICTING ≠ Hxx CONFIRMED
MERGE_READY=0 until receipt EXE_SHA256 + measured gates
```

If a PR receipt later records FAIL on a named gate, upgrade the **aliased H row** to CONFIRMED with that receipt path — once.

## Deduplicate vs Issues #49 / #50 / #57

### Issue #49 (product-final)

- Single decisive E2E scenario; maps primarily to **H120** plus supporting H61–H90 keys listed in `HIDDEN_GAPS_H61_H120.md`
- Closing #49 on one EXE SHA is the maturity milestone; inventory counts do not move 82%

### Issue #50 (ladder)

- Layers 0–10 are **sequencing**, not +11 blockers
- Provider 32/32 isolated PASS ≠ Layer 0 integration seal ≠ Deep2 L1
- Alias ladder layers to existing H/PR gates; do not append 11 new CONFIRMED rows

### Issue #57 (45 gates)

Split on merge:

| #57 group | Daily-driver merge | Enterprise / N_A |
|-----------|--------------------|------------------|
| A Native IDE (01–15) | In-scope UNVERIFIED/INVESTIGATE; alias to H13–H56, H107–H111, H120 | — |
| B Compiler (01–12 PE/COFF/MASM/NASM/Windows) | In-scope; alias PR75 / H41–H42 | — |
| B13 ELF/Linux | — | **N_A_OUT_OF_SCOPE** daily-driver |
| B14 Mach-O/macOS/iOS | — | **N_A_OUT_OF_SCOPE** daily-driver |
| B15 Android | — | **N_A_OUT_OF_SCOPE** daily-driver |
| C GPU single-device oracles / GGUF / NaN / packaging | In-scope UNVERIFIED/INVESTIGATE; alias H73–H90, H98–H106 | — |
| C08–C09 dual/multi-GPU | — | **N_A_OUT_OF_SCOPE** daily-driver (alias H82/H83) |

Justification: Windows MSVC/Ninja/Vulkan daily-driver + Issue #49 R9700 local path does not require independent ELF/Mach-O/Android toolchains or dual-GPU partitioning to be CONFIRMED blockers. Enterprise closure may still track those gates without inflating daily-driver blocker cardinality.

## Master row schema (required fields)

```
id                # canonical (prefer Hxx or Txx or I57-Xxx)
aliases           # [Finish25, PR gate, Issue receipt key, 78-register id]
status            # CONFIRMED|UNVERIFIED|INVESTIGATE|N_A_OUT_OF_SCOPE|DUPLICATE_OF
duplicate_of      # if DUPLICATE_OF
sha_scope         # exact EXE SHA or NOT_BOUND
evidence_paths    # existing receipts only
pr_refs           # #75-#79 as applicable
issue_refs        # #49/#50/#57
blocker_eligible  # 1 only if status==CONFIRMED AND daily-driver in-scope
```

## Blocker set definition (post-merge)

```
DAILY_DRIVER_CONFIRMED_BLOCKERS =
  { rows | status==CONFIRMED
         AND blocker_eligible==1
         AND N_A_OUT_OF_SCOPE==0
         AND evidence_paths non-empty
         AND sha_scope bound }
```

Track D result to seed merge: **CONFIRMED_BLOCKERS_H61_H120 = 0**.

UNVERIFIED rows (e.g. H120, H64, H69, H73–H75, H107–H109) are **acceptance gaps**, not yet CONFIRMED defects — they still drive execution order toward Issue #49 without being counted as proven bugs.

## Non-claims

- Do not change ENGINEERING_MATURITY_ESTIMATE (82%) from dedupe alone
- Do not set PRODUCT_PASS / CERTIFIED / PROMOTE from register merge
- Do not overwrite frozen A4F package or sealed Finish-25 historical seals
- Do not treat GitHub code-search misses as local evidence absence

## Apply order (when master merge runs)

1. Ingest Track B GitHub inventory + Track D `HIDDEN_GAPS_H61_H120.md` + Track C H01–H60 (when present)
2. Ingest Finish-25 + oneshot + INTEG004 + `PR7*_ACCEPTANCE_001`
3. Identity-merge aliases; apply N_A carve-outs
4. Emit unique requirement set + `DAILY_DRIVER_CONFIRMED_BLOCKERS`
5. Leave INVESTIGATE/UNVERIFIED visible; never drop #49 H120 until product-final PASSes on one SHA

```
MERGE_RULES=DRAFTED
ARITHMETIC_78_120_45=FORBIDDEN
CONFIRMED_ONLY_BLOCKERS=1
PROMOTE=0
CERTIFIED=0
```
