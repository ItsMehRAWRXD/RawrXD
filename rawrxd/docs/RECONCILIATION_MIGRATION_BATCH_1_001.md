# Reconciliation: MIGRATION_BATCH_1 (commit `ca8ff4f5b`)

**Date:** 2026-09-29
**Trigger:** Process-level contradiction review of `ca8ff4f5b`

---

## Code result vs. authority result

```
COMMIT=ca8ff4f5b
MIGRATION_BATCH_1=W8
FILES_COMMITTED=3
TARGETED_STAGING=1
W8_IMMUTABLE_API_ADOPTION=IMPLEMENTED
W8_VERDICT_DERIVATION=MEASURED
UNRELATED_FILES_STAGED=0

RAWRXD_SINGLE_WRITER_AUTHORITY_001=FAIL_RECURRING
WRITER_LEASE_IMPLEMENTED=0
WRITER_LEASE_PROVEN=0

CA8FF4F5B_CODE_REVIEW_STATE=IMPLEMENTED_UNCERTIFIED
CA8FF4F5B_PROVENANCE_STATE=UNTRUSTED_UNTIL_RECONCILED
```

A pre-commit HEAD check proves only that the local repo was at the expected
commit. It does **not** prove exclusive writer ownership throughout the batch.

```
HEAD(t-check) == expected                    [proved]
exclusive writer ownership throughout batch  [NOT proved]
```

`ca8ff4f5b` is therefore **preserved**, but it is **not certified**.

---

## Reconciliation patch: legacy mirror non-authoritative

The migration retained `w8_headless_lifecycle_receipt.txt` as a mutable
mirror. Without explicit non-authoritative markers, an external verifier
could consume the mutable mirror and silently defeat the migration.

Reconciliation enforces:

```
IMMUTABLE_RUN_RECEIPT=AUTHORITATIVE
LEGACY_W8_MIRROR=NON_AUTHORITATIVE
LEGACY_MIRROR_ALLOWED_TO_CERTIFY=0
LEGACY_MIRROR_ALLOWED_AS_RAWGATE_INPUT=0
```

The mirror now begins with a `NON_AUTHORITATIVE_MIRROR` banner and emits
these header fields:

```
AUTHORITY=NON_AUTHORITATIVE_MIRROR
DEPRECATED=1
MIRROR_FORBIDDEN_TO_CERTIFY=1
MIRROR_FORBIDDEN_AS_RAWGATE_INPUT=1
AUTHORITATIVE_ARTIFACT=<run path under receipts/W8_HEADLESS_IDLE_LIFECYCLE_001/runs/...>
```

The mirror ends with `END_NON_AUTHORITATIVE_MIRROR` so a RawrGate verifier
can grep for the banner pair and reject any line outside the run-path
artifact.

No external verifier currently consumes the mirror (verified by repo-wide
search of `w8_headless_lifecycle_receipt` and `RAWRXD_W8_LIFECYCLE_AUTHORITY_001`).
The markers are defensive against future consumers.

---

## Corrected ladder

```
ca8ff4f5b preserved (code change intact)
       ↓
RAWRXD_SINGLE_WRITER_AUTHORITY_001
       ↓
adversarial lease PASS
       ↓
reconcile/verify ca8ff4f5b under controlled state
       ↓
prove W8 immutable artifact authoritative
       ↓
MIGRATION_BATCH_2: StrictCertificationAuthority
       ↓
measured immutability regression
       ↓
RawrGate meta-verification
       ↓
W8 schema v2 + 1800s
       ↓
GPU
```

`MIGRATION_BATCH_2` does **not** start now. The freeze holds.

---

## Current authority classification

```
MIGRATION_BATCH_1=IMPLEMENTED_NOT_CERTIFIED
MIGRATION_BATCH_2=BLOCKED
NEXT_GATE=RAWRXD_SINGLE_WRITER_AUTHORITY_001

SAFE_TO_GPU=0
SAFE_TO_W8_CERTIFY=0
SAFE_TO_PROMOTE_IMMUTABILITY=0
```

A good-looking code change cannot bypass the same provenance requirements
imposed on everything else. This is the rule the migration ladder exists
to enforce, and the rule that holds here.

---

## What this reconciliation does NOT do

- Does **not** mark `RAWRXD_RECEIPT_IMMUTABILITY_AUTHORITY_001=PASS`
- Does **not** mark `W8_HEADLESS_IDLE_LIFECYCLE_001=CERTIFIED`
- Does **not** unblock GPU
- Does **not** start MIGRATION_BATCH_2
- Does **not** weaken the verdict derivation in the immutable artifact

The reconciliation only constrains the legacy mirror's authority role so
that it cannot silently defeat the migration. The next gate
(`RAWRXD_SINGLE_WRITER_AUTHORITY_001`) is unchanged.
