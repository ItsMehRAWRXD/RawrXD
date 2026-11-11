# BLOCKER_DEPENDENCY_ORDER — confirmed daily-driver only

```
ASOF_UTC=2026-11-09T15:00:00Z
MOTD_ACK=1
LANE=F:\rawrxd\evidence\RELEASE_FREEZE_001
SOURCE_AUDIT=HIDDEN_GAP_AUDIT_001 (SEALED_REFERENCE)
SOURCE_RUNTIME=CC79_RUNTIME_001
ENGINEERING_MATURITY=82%_UNCHANGED
PROMOTE=0
CERTIFIED=0
BLOCKER_LIST_ORDERED=1
INVESTIGATION_NE_CONFIRMED=1
NO_CROSS_SHA_PASS=1
A4F_IMMUTABLE=1
```

## Inclusion law

Only evidence-backed **CONFIRMED** daily-driver blockers from sealed audit + **live** CC79 runtime gaps that block REQUIRED (R1/R2).

```
INVESTIGATE ≠ ordered blocker
UNVERIFIED ≠ ordered blocker
OPTIONAL deferred ≠ ordered blocker
CONFIRMED_PRIOR included only if it still blocks REQUIRED on candidate
H22 mitigated on F5F4807E → verify-only until SHA replaced
```

## Seed reconcile (high-signal)

| ID | Seed note | Order decision |
|----|-----------|----------------|
| H01/H21 | Core-DPI link | **In** — but **surgical DPI into lifecycle**, not naive full-Core link (Core duplicates WindowProc/createWindow/onSize with linked lifecycle → rebuild thrash) |
| H57 | AgentSession Native | **In** — blocks R1.AGENT_TOOL + Issue #49 |
| H43/H51 | ExtHost cleanup | **In** — H51 FORCE_KILL SHA-scoped; must re-prove on candidate |
| H42 | native-linker | **In** — blocks R1.BUILD / I49 build-failure recovery |
| H22 | Output | **Mitigated** on tip_cc79_integ_002 `F5F4807E…` (`OUTPUT_HWND=PASS`, EXE hash verified). Keep as **re-verify on any replacement SHA**; not first repair while tip EXE retained |
| H27 | VS_UNICODE prior on CC79 | **In as PRIOR** — scrub on candidate so Problems stay stable |

Live CC79 gaps (fail-closed):

| Gap | Evidence | Order decision |
|-----|----------|----------------|
| `EXACTLY_ONCE=NOT_VERIFIED` | BUTTON_PROBE_MULTI_RESPONSE_RECONCILE | **In** — blocks R1.MODEL trust |
| `TERMINAL_PANEL_E2E=PARTIAL` | CC79 SCOREBOARD / FOUR_PANEL | **In** — blocks full IDE_TERMINAL / agent shell |
| Four-panel / Debug | User brief cited PARTIAL/BLOCKED; CC79 SCOREBOARD 14:52Z claims PASS on `F5F4807E…` | **Fail-closed**: treat as **SHA-scoped measurement, not product-final**; re-verify on candidate; do not invent new PASS |
| Issue #49 | NOT_RUN / NOT_DEMONSTRATED | **In** as terminal milestone (not a code blocker — gated after workflow unlock) |

---

## Ordered blockers (what unblocks integrated workflow first)

Priority = dependency order for **one candidate**. Symptoms under a parent are not separate first repairs.

| Pri | Blocker | Evidence class | Unlocks first |
|-----|---------|----------------|---------------|
| B0 | **One release-freeze candidate worktree/EXE** absorbing tip_cc79_integ_002 lessons; A4F untouched | Process | All later gates |
| B1 | **H22 Output re-verify** on candidate (PASS only if measured on that SHA). Tip `F5F4807E…` already PASS — inherit bytes only if candidate **is** that EXE; else repair/reprove | OUTPUT_GATE | R1.OUTPUT / compile-nav |
| B1 | **H27 VS_UNICODE / Problems env scrub** on candidate | CONFIRMED_PRIOR CC79 | R1.PROBLEMS |
| B1 | **TERMINAL_PANEL_E2E** leave PARTIAL | CC79 live | Shell/agent terminal leg |
| B2 | **EXACTLY_ONCE** chat dispatch correlation (input→dispatch id→backend→response→transcript) | NOT_VERIFIED reconcile | R1.MODEL |
| B2 | **H57 AgentSession on Native/Ext product path** (link **and** call-site bind; library-only ≠ RUNTIME_REACHED) | CONFIRMED audit | R1.AGENT_TOOL / cancel / Issue #49 |
| B2 | **H21 DPI surgical** in linked lifecycle (not full H01 Core TU dump) | CONFIRMED H21; H01 folded | Stable UI under DPI change |
| B3 | **H42 (+H41) native-linker execution** on candidate — adapter PASS ≠ native complete | CONFIRMED | R1.BUILD / I49 recovery |
| B3 | **H43/H51 ExtHost cleanup** FORCE_KILL=0 on **candidate SHA** | CONFIRMED SHA-scoped 47451; no inherit | R1.EXT_SHUTDOWN / R1.EXIT |
| B4 | **Four-panel + Debug re-verify** on candidate SHA | CC79 SHA-scoped claims | Conjunction input to R1 repeat |
| B5 | **Issue #49 product-final E2E** on that SHA | REQUIRED decisive | Maturity reassess only if PASS |
| B6 | **R3 package / clean-machine / rollback** | NOT_RUN | Delivery seal |

Supporting CONFIRMED (fold into B0–B3; do not solo-chase):

| ID | Fold into |
|----|-----------|
| H02 duplicate Problems/dispatch | B1 Problems path ownership |
| H03 stub replacing production | B2/B5 stub gates (`STUB_*=0`) |
| H04 feature flag EXT default OFF | B0 candidate CMake (`RAWRXD_NATIVE_IDE_EXT` as needed) |
| H56 test-ext PASS / real FAIL | B3/B5 real matrix only |

---

## Explicitly excluded from this ordered list

- All Track D **INVESTIGATE** / **UNVERIFIED** unless a REQUIRED gate fails and root-causes there
- H08/H27 **as new discoveries** (PRIOR only; H27 kept above solely for Problems stability)
- Full H01 Core.cpp link-in (duplicate symbols with lifecycle — theater risk)
- H87 GPU device-loss specialty
- Parallel tip remesure campaigns
- Any arithmetic inventing “18%” or summing 78+120+45

---

## First repair set (step 3 seed)

Smallest set unlocking workflow toward Issue #49:

1. Create `release/freeze-001` candidate worktree (B0)
2. H57 Native/Ext bind path (B2) — without thrashing full rebuild until bind compiles clean
3. EXACTLY_ONCE dispatch guard / correlation hooks (B2)
4. H21 DPI case in lifecycle (B2 surgical)
5. H27 Problems scrub if candidate env still polluted (B1)
6. Build **once** when that set is coherent → record full SHA
7. Then H42 / H51 / terminal / four-panel re-verify → Issue #49

```
BLOCKER_LIST_ORDERED=B0>B1_OUTPUT_PROBLEMS_TERMINAL>B2_EXACTLY_ONCE_H57_H21>B3_H42_H51>B4_FOUR_PANEL_REVERIFY>B5_ISSUE49>B6_PACKAGE
H22_ON_F5F4807E=MITIGATED_VERIFY_ONLY
PROMOTE=0
NEXT_ACTION=CANDIDATE_WORKTREE + SMALLEST_B2_REPAIRS
```
