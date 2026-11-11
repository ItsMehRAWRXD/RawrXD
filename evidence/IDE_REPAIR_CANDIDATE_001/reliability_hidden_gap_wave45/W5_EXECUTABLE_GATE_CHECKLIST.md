# W5 Executable Gate Checklist — 94→97 (planning weight only)

```text
BAND=94->97
MILESTONE=FULL_FEATURE_HIDDEN_GAP_REGRESSION
WEIGHT=+3_PLANNING_ONLY
MATURITY_EARNED=0
PROMOTE=0
I57_AUTO_DEFECTS=0
I57_OBLIGATIONS=45
SHA_RULE=same post-Wave1 candidate as W4
```

## Law for Issue #57

From issue body + `ISSUE57_GATES_OBLIGATIONS.csv` + ladder §3:

- 45 items are **open acceptance obligations**, not 45 accomplished fixes and **not** 45 defects.
- `auto_defect=0` for every row.
- Local `yes_related` / `partial_related` ≠ PASS.
- Open defects only with **repro + owner + same-SHA FAIL receipt**.

## A) Confirmed blockers vs obligations (fail-closed)

| Class | Count rule | What belongs here |
|-------|------------|-------------------|
| CONFIRMED_BLOCKER | Same-SHA FAIL receipt on **controlling repair candidate** | Only after executable FAIL. Inventory does **not** invent these from the 45. |
| OBLIGATION_ONLY | All 45 Issue #57 gates until PASS sealed | See CSV companion + crosswalk below. |
| HISTORICAL_CONFIRMED | Prior SHA FAIL (CC79/47451/RC4) | Re-queue as **re-prove obligations** on new SHA — do not bulk-defect. |

### Historical confirmed (re-prove; not auto-defect on new SHA)

| HistID | Prior SHA | Failure | Maps W5 / I57 | Owner |
|--------|-----------|---------|---------------|-------|
| H-C1 | CC79… | Problems UI empty / items=0 | A09/A10 adjacent; Finish25 Problems; four-panel | WS12 Problems |
| H-C2 | 47451… | EXT_CLEANUP FORCE_KILL=1 | W4-EXT-02; A09 cleanup | WS20 |
| H-C3 | CC79… | Debugger UI E2E FAIL | **A14** obligation | WS14 / Debugger |
| H-C4 | CC79… | Four-panel integrated OPEN | Surface regression | WS10–14 |
| H-RC4-G03 | 78E187… | Agent orchestration FAIL (READ/CU) | Wave1 (not W5 primary) | WS04–08 |
| H-RC4-G10 | 78E187… | Extensions NOT_RUN | W4-EXT | WS20 |
| H-RC4-G12 | 78E187… | Reliability NOT_RUN | W4-REC | WS23 |

```text
NEW_CONFIRMED_FROM_I57_BULK=0
HISTORICAL_CONFIRMED_REPROVE=7_ROWS_ABOVE
```

## B) Issue #57 → executable W5 gates (owners)

Status for every ID starts as **OBLIGATION_ONLY**. `local_receipt` copied from CSV.

### Section A — Native IDE E2E (owners: IDE / build / surfaces)

| ID | Obligation (abbrev) | Owner | Executable proof shape | Class | Notes |
|----|---------------------|-------|------------------------|-------|-------|
| A01 | GHA runner_id=0 fixed; Linux+Windows green | WS01 / CI | Successful Actions run IDs archived | OBLIGATION_ONLY | Fail run `#40089650136` = infrastructure obligation |
| A02 | Per-file SHA-256 inventory JSON | WS01 | Inventory JSON on audited commit | OBLIGATION_ONLY | yes_related ≠ PASS |
| A03 | CMake literal-source admission | WS01 / CMake | Admission report + missing-path disposition | OBLIGATION_ONLY | |
| A04 | No-external-deps / Qt quarantine | WS01 | Strict scan receipt | OBLIGATION_ONLY | partial_related |
| A05 | Feature→TU/call-site manifest | WS01 | Frozen manifest file | OBLIGATION_ONLY | |
| A06 | Clean-checkout Win32 IDE no-Qt rebuild | WS01 / Build | Clean tree build log + EXE SHA | OBLIGATION_ONLY | |
| A07 | Rebuild rawr.exe + agent same checkout | WS01 / Agent | Same-checkout SHA set | OBLIGATION_ONLY | |
| A08 | Save/close/reopen file SHA-256 | WS13 Editor | Launch→edit→save→reopen hash compare | OBLIGATION_ONLY | RC4 G04 NOT_RUN |
| A09 | Terminal start/output/exit/cancel/cleanup | WS10 | Term smoke + cancel/cleanup markers | OBLIGATION_ONLY | RC4 G05 NOT_RUN; overlaps W4-CAN |
| A10 | PowerShell panel lifecycle | WS10 | PS panel start/output/restart | OBLIGATION_ONLY | |
| A11 | LSP handshake/diagnostics/completion | WS13 / LSP | JSON-RPC session receipt | OBLIGATION_ONLY | partial_related |
| A12 | GhostText accept/cancel + real adapter | WS13 / GhostText | Display+accept+cancel receipt | OBLIGATION_ONLY | yes_related |
| A13 | Native browser isolation/lifecycle | WS14 Browser | Render + origin isolation receipt | OBLIGATION_ONLY | no receipt |
| A14 | Debugger BP/step/watch on real debuggee | WS14 Debugger | Live debuggee UI receipt | OBLIGATION_ONLY | Hist H-C3 re-prove |
| A15 | Agent edit→build→test→snapshot rollback | WS19 / WS07 / WS11 | Full IDE-driven workflow on same SHA | OBLIGATION_ONLY | Wave2 primary; related 35C22 ≠ this SHA |

### Section B — Slingshot / compiler / cross-platform

| ID | Obligation | Owner | Class | Scope note |
|----|------------|-------|-------|------------|
| B01–B05 | Slingshot braid/guard/POC/reconcile | Slingshot / Deep2 | OBLIGATION_ONLY | No sealed recovery; not daily-driver first |
| B06 | Compiler/linker inventory | Compiler lane | OBLIGATION_ONLY | yes_related |
| B07–B12 | Native C/C++/MASM/NASM/link/execute | Compiler / Linker | OBLIGATION_ONLY | B10 historically banner-only — obligation, not bulk defect |
| B13–B15 | ELF / Mach-O / Android contracts | Cross-platform | OBLIGATION_ONLY | OUT_OF_SCOPE for Win daily-driver min; still #57 obligations, not auto-defects |

### Section C — GPU / TPS / matrix / release

| ID | Obligation | Owner | Class | Notes |
|----|------------|-------|-------|-------|
| C01–C05 | Baseline / FFN / GEMV / fences / lane restore | Deep2 / GPU (WS16–17) | OBLIGATION_ONLY | related≠PASS |
| C06–C09 | R9700 / RX7800 / dual TPS + attribution | Perf / #48 | OBLIGATION_ONLY | Hardware runners |
| C10–C11 | GGUF matrix / Nemotron SSM parity | Model loader / SSM | OBLIGATION_ONLY | |
| C12 | Real-model 150+ TPS if attainable | Perf | OBLIGATION_ONLY | No synthetic TPS; absence ≠ defect |
| C13 | Identical A/B conditions | Perf | OBLIGATION_ONLY | |
| C14 | 25×20=500 cell matrix real evidence | Full-feature / Finish25 | OBLIGATION_ONLY | Do not prefill cert |
| C15 | Signed package + crash/offline/release | WS24 Packaging | OBLIGATION_ONLY | RC4 portable integrity partial only |

## C) Full-feature / hidden-gap / regression executable slice (post-Wave1)

| RegID | Proof | Owner | Depends | Class |
|-------|-------|-------|---------|-------|
| W5-REG-01 | Four-panel Ext+Chat+Term+Output alive | WS10–14 + WS20 | W4-EXT-01 | OBLIGATION_ONLY (hist H-C4) |
| W5-REG-02 | Problems HWND + click-to-line on fixture | WS12 | Build diagnostics | OBLIGATION_ONLY (hist H-C1) |
| W5-REG-03 | Finish-25 recount on same SHA (no invent) | WS25 / Full-feature | REG-01/02 | OBLIGATION_ONLY |
| W5-REG-04 | Hidden-gap: open CONFIRMED only from new FAIL receipts | Audit owner | REG runs | Process gate |
| W5-REG-05 | I57 daily-driver subset A08–A15 + A09/A10 exercised | IDE surfaces + Agent | Wave1+2 | OBLIGATION_ONLY |
| W5-REG-06 | Re-measure RC4 PASS axes on new SHA (G02/G07/G09/G11/G13/G14) | WS23 / Cert | Identity pin | OBLIGATION_ONLY |

```text
W5_PRIMARY_AFTER_W1= W5-REG-01..06 then I57 A-gates as scheduled
W5_DOES_NOT= mark all 45 FAIL | raise maturity | promote
```
