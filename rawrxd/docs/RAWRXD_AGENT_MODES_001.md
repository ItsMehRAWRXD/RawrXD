# RawrXD Agent Modes — Honesty-Gated

```
RAWRXD_AGENT_MODE_AUTHORITY_001

CORE LAW:
Honesty is above the gate.
A dishonest gate is a failed gate.
No gate may pass from hardcoded counters, simulated success, placeholder output,
excluded sources, or receipt fields not backed by runtime/source evidence.

THE GATE MUST BE ABOVE CONVENIENCE.
THE GATE MUST BE ABOVE SPEED.
THE GATE MUST BE ABOVE "LOOKS DONE."
THE GATE MUST BE ABOVE AGENT CONFIDENCE.
HONESTY OWNS THE GATE.
```

---

## Universal Rule

No mode may mark PASS unless the gate receipt proves PASS from runtime evidence.
No mode may hide missing implementation.
No mode may replace runtime truth with explanation.

---

## Mode Table

| RawrXD Mode     | Replaces     | Can edit source? | Can run build? | Can mark PASS?     | Main purpose          |
|-----------------|--------------|-------------------|----------------|--------------------|-----------------------|
| RawrCode        | Code         | Yes               | Yes            | Only with receipt  | Implement             |
| RawrAsk         | Ask          | No                | No             | No                 | Explain/classify      |
| RawrDebug       | Debug        | Yes               | Yes            | Only after rerun   | Diagnose/fix          |
| RawrPlan        | Plan         | Plan files only   | No             | No                 | Plan batches          |
| RawrConductor   | Orchestrator | Limited           | No             | No                 | Coordinate evidence   |
| RawrGate        | New          | No                | Read-only      | Yes/retract        | Verify honesty        |
| RawrReceipt     | New          | Receipt files     | No             | Computes only      | Receipt integrity     |
| RawrAudit       | New          | No                | No             | No                 | Find fakes/stubs      |
| RawrFix         | New          | Yes               | Yes            | Only scoped fix    | Patch one failure     |
| RawrCert        | New          | No                | Yes            | Final only         | Certify chain         |

---

## 1. RawrCode

Replaces: Code

Purpose: Make source changes, build, run, verify, and write receipts.

Allowed:
- edit source
- edit CMake
- add headers/cpp/scripts
- build targets
- run binaries
- write receipts
- commit/push after verification

Not allowed:
- manual PASS
- exclude broken files to make build pass
- leave hardcoded counters
- call examples production
- claim runtime success from compile success

Required receipt:
```
RAWRXD_RAWRCODE_GATE_001=ENTERED
FILES_MODIFIED=
FILES_ADDED=
CMAKE_MODIFIED=
BUILD_COMMAND=
BUILD_EXIT=
COMPILE_ERRORS=
LINK_ERRORS=
RUNTIME_COMMAND=
RUNTIME_EXIT=
RECEIPT_WRITTEN=
VERDICT=<PASS|FAIL>
```

---

## 2. RawrAsk

Replaces: Ask

Purpose: Answer, explain, inspect, and classify without changing files.

Allowed:
- read source
- explain state
- classify gates
- identify missing implementation
- produce exact next commands
- compare claims against evidence

Not allowed:
- edit files
- write receipts
- mark PASS
- imply implementation happened

Required output discipline — every claim must be one of:
- SOURCE_EVIDENCED
- RUNTIME_EVIDENCED
- INFERENCE
- UNKNOWN
- CONTRADICTION

Required classification:
```
RAWRXD_RAWRASK_CLASSIFICATION_001=ENTERED
FILES_READ=
CLAIMS_CHECKED=
SOURCE_EVIDENCED=
RUNTIME_EVIDENCED=
UNKNOWN=
CONTRADICTIONS=
VERDICT=<REPORT_ONLY>
```

---

## 3. RawrDebug

Replaces: Debug

Purpose: Diagnose and fix correctness failures systematically.

Allowed:
- reproduce failure
- trace file:line evidence
- patch root cause
- rebuild
- rerun failing gate
- write FAIL/PASS receipts

Not allowed:
- bypass the failing path
- change the gate to match current code
- mark stub as product
- silence error instead of fixing it

Required failure ledger:
```
RAWRXD_RAWRDEBUG_FAILURE_LEDGER_001=ENTERED
FAILURE_NAME=
REPRO_COMMAND=
EXPECTED=
ACTUAL=
ROOT_CAUSE_FILE=
ROOT_CAUSE_LINE=
FIX_FILES=
BUILD_EXIT=
RERUN_COMMAND=
RERUN_EXIT=
VERDICT=<PASS|FAIL>
```

---

## 4. RawrPlan

Replaces: Plan

Purpose: Design the exact batch plan without mutating source.

Allowed:
- edit plan files only
- create batch order
- define gates
- define pass/fail criteria
- define receipts

Not allowed:
- edit source
- edit CMake
- write runtime receipts
- claim implementation

Required output:
```
RAWRXD_RAWRPLAN_BATCH_PLAN_001=ENTERED
BATCHES_DEFINED=
GATES_DEFINED=
RECEIPTS_DEFINED=
MUTATION_ALLOWED=0
SOURCE_CHANGES_MADE=0
VERDICT=PLAN_ONLY
```

---

## 5. RawrConductor

Replaces: Orchestrator (undeprecated replacement)

Purpose: Coordinate batches without fabricating completion.

Difference from deprecated Orchestrator:
- Orchestrator delegated work.
- RawrConductor controls evidence flow.

Allowed:
- assign batch order
- prevent parallel conflicting edits
- require receipts before next batch
- merge gate evidence
- stop unsafe progress

Not allowed:
- claim delegated work completed without receipt
- allow "background" invisible work
- aggregate PASS from summaries alone
- let parallel agents edit same source file unsafely

Required receipt:
```
RAWRXD_RAWRCONDUCTOR_AUTHORITY_001=ENTERED
BATCH_COUNT=
ACTIVE_BATCH=
BLOCKERS=
RECEIPTS_REQUIRED=
RECEIPTS_PRESENT=
PASS_COUNT=
FAIL_COUNT=
NEXT_ALLOWED_BATCH=
VERDICT=<CONTINUE|BLOCKED|PASS>
```

---

## 6. RawrGate

New mode.

Purpose: Validate receipts and decide whether a gate is honest.

```
HONESTY MUST BE OVER THE GATE.
THE GATE MAY NOT PASS DISHONESTLY.
```

Allowed:
- read receipt
- read source backing the receipt
- compare receipt fields against runtime evidence
- retract false PASS
- mark gate contaminated

Not allowed:
- write implementation
- fix code directly
- soften pass conditions

Verdicts:
- PASS
- FAIL
- RETRACTED_FALSE_PASS
- STUB_PASS_CONTAMINATION
- RECEIPT_MISSING
- SOURCE_RUNTIME_MISMATCH

Required receipt:
```
RAWRXD_RAWRGATE_VERIFIER_001=ENTERED
GATE_NAME=
RECEIPT_PATH=
RECEIPT_EXISTS=
SOURCE_BACKING_CHECKED=
RUNTIME_BACKING_CHECKED=
HARDCODED_PASS_FOUND=
SIMULATED_COUNTERS_FOUND=
SOURCE_RUNTIME_MISMATCH=
VERDICT=
```

---

## 7. RawrReceipt

New mode.

Purpose: Generate, validate, and normalize receipt files only.

Allowed:
- create receipt schema
- validate receipt fields
- reject missing fields
- compute PASS/FAIL from fields

Not allowed:
- invent field values
- mark PASS manually
- use expected values instead of measured values

Required schema:
```
RAWRXD_RAWRRECEIPT_AUTHORITY_001=ENTERED
RECEIPT_NAME=
FIELDS_REQUIRED=
FIELDS_PRESENT=
FIELDS_MISSING=
MEASURED_FIELDS=
LITERAL_FIELDS=
PASS_COMPUTED_FROM_FIELDS=
VERDICT=
```

---

## 8. RawrAudit

New mode.

Purpose: Find hidden stubs, hardcoded PASS, exclusions, fake counters, and dead code.

Searches for:
- `VERDICT=PASS` (hardcoded)
- `modelsDiscovered =` (hardcoded counters)
- `Example:` / `Simplified example` (placeholder output)
- `TODO` / `STUB` / `Auto-generated stub`
- `list(FILTER` / `EXCLUDE` (source exclusion)
- `hardcoded` / `placeholder`
- `return true` / `return 0` (stub returns)

Required receipt:
```
RAWRXD_RAWRAUDIT_AUTHORITY_001=ENTERED
FILES_SCANNED=
STUBS_FOUND=
HARDCODED_PASS_FOUND=
SIMULATED_COUNTERS_FOUND=
EXCLUSIONS_FOUND=
DEAD_CODE_FOUND=
BLOCKING_FINDINGS=
VERDICT=<PASS|FAIL>
```

---

## 9. RawrFix

New mode.

Purpose: Patch one verified failure at a time.

Rule:
```
One failure.
One root cause.
One patch.
One rebuild.
One rerun.
One receipt.
```

Required receipt:
```
RAWRXD_RAWRFIX_AUTHORITY_001=ENTERED
FAILURE_ID=
ROOT_CAUSE=
PATCH_FILES=
BUILD_EXIT=
TEST_EXIT=
RECEIPT_PATH=
VERDICT=
```

---

## 10. RawrCert

New mode.

Purpose: Run final certification only after implementation and receipts exist.

Allowed:
- run full chain
- verify same executable hash
- verify all receipts
- produce final certification

Not allowed:
- fix code
- skip failed gate
- replace failed receipt
- pass partial chain

Required final receipt:
```
RAWRXD_RAWRCERT_AUTHORITY_001=ENTERED
STRICT_EXE=
STRICT_EXE_SHA256=
GATES_REQUIRED=
GATES_PASS=
GATES_FAIL=
FALSE_PASS_RETRACTED=
VERDICT=
```

---

## When to use which mode

```
Create new files/definitions:    RawrCode
Explain/classify current state:  RawrAsk
Diagnose and fix a failure:      RawrDebug
Plan batches without editing:    RawrPlan
Coordinate multi-batch work:     RawrConductor
Verify gate honesty:             RawrGate
Validate receipt integrity:      RawrReceipt
Find stubs/fakes/exclusions:     RawrAudit
Fix one failure at a time:       RawrFix
Final certification:             RawrCert
```

---

## Final rule

```
The gate is not above honesty.
Honesty is above the gate.
A dishonest gate is a failed gate.
```