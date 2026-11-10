# Release scope freeze — Windows daily-driver IDE

```text
ASOF_UTC=2026-11-09T14:50:00Z
ENGINEERING_MATURITY_ESTIMATE=82%
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
TIP_MOVE_AUTHORIZED=0
CONTROLLING_TIP=CC79
CONTROLLING_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
A4F_IMMUTABLE=1
NO_CROSS_SHA_PASS_INHERITANCE=1
AUDIT_ENTRIES_NE_COMPLETION_SCORE=1
PERCENTAGE_NOT_WEIGHTED=1
```

**100% means:** every gate in this freeze PASSes on one final release executable SHA.  
**Promotion and certification** remain separately controlled (`PROMOTE` / `CERTIFIED`) and are **not** implied by maturity estimate changes.

Investigation targets (H-register, GitHub checklists) are **not** defects until evidenced. They do not divide into the remaining 18%.

---

## 1. Required for this release (must have working user flow + test)

| Area | Acceptance (user-visible or dependency) |
|------|-------------------------------------------|
| Editor / workspace | Open → edit → save → reopen without data loss |
| Build | Compile → link → run; concurrent stdout/stderr; timeout/cancel |
| Output | Build/terminal/debug routing into correct pane |
| Problems | Populate from real diagnostics; click → **actual** file/line/caret (B12) |
| Chat / local model | Stream → Stop → Clear → next-request recovery; backend failure visible |
| Agent tools | Authorized edit → durable file change → cancel/rollback path |
| Terminal / PowerShell panel | Enter command → listing/output in **that** pane; chat transcript untouched |
| Extension host | Discover/load/activate/execute; unload/quit **without** FORCE_KILL |
| Debugger (release-min) | Launch, breakpoint hit, step/continue/stop via IDE UI (not headless-only) |
| Four-panel | Chat + Terminal + Output + Debug simultaneous without stale HWND interference |
| Cancellation / recovery | Request A → Stop → Request B; no hung children; session recoverable |
| Persistence | Session/workspace state survives restart for required surfaces |
| Packaging | Deterministic Windows package; clean-machine launch; rollback |
| Exit | Clean process/thread/handle teardown |

**Integrated workflow gate (single SHA):**  
`open/edit/save → compile/link/run → Output + Problems navigation → model response → agent tool action → cancel/recovery → session persistence → extension shutdown → clean exit`  
+ repeated-use and failure-recovery checks.

---

## 2. Optional (explicitly deferred unless pulled in)

| Item | Decision |
|------|----------|
| Multi-platform native compilers (ELF/Mach-O/Android) | **OPTIONAL** — defer |
| Issue #57 500-cell feature matrix / extreme concurrency / 1M context | **OPTIONAL** — defer unless product-final contract mandates |
| ROCm `gfx1201` | **OPTIONAL** — Vulkan-only release may exclude with explicit note |
| Marketplace / unfinished security fiction stubs | **OPTIONAL** — defer |
| GhostText / native browser / full LSP productization | **OPTIONAL** unless already required by a Required row’s dependency |
| Certification ladder Layers 2–8 full seal | **SEPARATE** from daily-driver release freeze; track under Issue #50 |

---

## 3. Hidden dependencies of required features (keep in scope)

| Dependency | Why |
|------------|-----|
| `VS_UNICODE_OUTPUT` scrub / compiler env isolation | Required for Problems populate |
| JobObject / process-tree kill on cancel | Required for Terminal/Build cancellation |
| Problems aggregator ↔ ListView ↔ `navigateToFileLine`/`openDocumentPath` | Required for B12 |
| Extension IPC handshake + cleanup | Required for extension shutdown |
| Output tab producer wiring (not blank-tab selection alone) | Required for Output/PS panel routing |
| ConPTY terminal manager | Dependency of Terminal; **≠** PowerShell panel acceptance alone |

---

## 4. Candidate policy (anti-thrash)

```text
ONE_WORKING_BRANCH=1
ONE_ACCEPTANCE_BUILD_AT_A_TIME=1
NO_PARALLEL_REBUILD_TRACKS_FOR_SAME_GATE=1
PRIOR_SHA_RECEIPTS_HISTORICAL_ONLY=1
```

Measured identities (do not invent PASS across them):

| Role | SHA-256 | Path |
|------|---------|------|
| CONTROLLING | `CC79F6CD…` | tip_final_integ_002 |
| tip_004 historical Phase A | `27E2263E…` | tip_final_integ_004 — B02 FAIL sealed |
| INTEG_006 partial | `B50A2AB1…` | tip_final_integ_006 — Chat/Term/Problems populate; B12 not caret-proved |
| B02 remediation | `2CCAE57A…` | tip_b02_remediation_001 — Terminal PASS; Chat/B12 FAIL; other gates NOT_RUN |

**Next acceptance candidate:** merge smallest repair set into **one** branch → **one** rebuild → new SHA → full Required workflow on that SHA only.

---

## 5. Explicit non-goals for this freeze

- Chasing all 117 register rows individually  
- Raising maturity % for isolated subsystem PASS  
- Tip-move / PROMOTE / CERTIFIED without Issue #49–class integrated evidence + authorization  
- Treating `--term-smoke` as PowerShell panel `ls` PASS  
- Treating `POSTED_NM_DBLCLK` as B12 caret PASS  
