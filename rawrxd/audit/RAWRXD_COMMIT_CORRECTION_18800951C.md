# RAWRXD_COMMIT_CORRECTION_18800951C

Status: correction record. History is **not** rewritten; commit `18800951c` is
left intact as the historical artifact.

```ini
CORRECTION_IDENTIFIED          = YES
HISTORY_REWRITE_REQUIRED       = NO
EXPLICIT_AUTHORIZATION_TO_REWRITE = NOT_GRANTED
CORRECTION_MODE                = ADDITIVE_RECORD
APPLIES_TO_COMMIT              = 18800951c
MEASURED_ON                    = 2026-10-02
MEASURED_AGAINST_BINARY_SHA256 = E174761742EFD2EB9AC91205151AE591FB5EAFA2F1051BECE2483A594D609DE6
```

---

## 1. Why this exists

Commit `18800951c` (`RAWRXD_BEACON_RESIDENCY_001`) names four gates in its
message as certified infrastructure:

```text
RAWRXD_BEACON_RESIDENCY_BOUND_002
RAWRXD_BEACON_MODEL_SERVER_001
RAWRXD_DECODA_STREAM_001
RAWRXD_V6_KERNEL_CLOSURE_005
```

A commit message can record an observation. It is not itself a receipt. Three of
the four names have **no receipt file** in `receipts/ledger/_chain/`. A reader
citing the commit as proof of those three gates would be citing a name, not an
artifact.

## 2. Ledger census (authoritative)

```text
TOTAL_CHAIN_RECEIPTS=19
HOLDS=12
FAILS=6
RETRACTED=1
```

## 3. Named gates: what actually exists

| Name | Receipt file | Verdict |
|---|---|---|
| `V6_KERNEL_CLOSURE_005` | present | HOLDS |
| `RAWRXD_BEACON_RESIDENCY_BOUND_002` | **absent** | no receipt |
| `RAWRXD_BEACON_MODEL_SERVER_001` | **absent** | no receipt |
| `RAWRXD_DECODA_STREAM_001` | **absent** | no receipt |

## 4. Corrected evidentiary statements

### 4.1 Residency

Do **not** state "a 10.36 GB model uses 3.99 MB." State the A/B measurement:

```text
whole-file mapping -> working set 9883.91 MB
windowed mapping   -> working set    3.99 MB
max mapped view    ->              0.56 MB
```

These figures are recorded in commit `18800951c` and are **not** sealed by a
ledger receipt. Treat them as a commit-recorded measurement until the receipt
artifact exists.

### 4.2 Bits per weight

`4.1557` is a real encoding/accounting figure (`V6_TOTAL_BPW`), not today's
physical runtime bandwidth:

```text
V6_TOTAL_BPW        = 4.1557   (encoding)
Q4_K_BPW           = 4.5000
REDUCTION          = 7.65%     (design assumed ~30%)
PHYSICAL_RUNTIME_BPW = 4.5      (Q4_K; no .dcb6 sidecar exists)
```

`V6 accounting != serialized DCB6 image != runtime physical bpw`.

### 4.3 Decoda parity

Do **not** state Decoda M0–M4 parity is closed. The ledger records:

```text
V6_KERNEL_PARITY_005           = FAILS
  evidence: "NOT MEASURED. The 4021 dot calls were fed raw Q4_K weights as the
             activation tile ... REFERENCE_PARITY is still unproven."
DECODA_READY_FOR_INTEGRATION_001 = FAILS
DECODA_VS_SCALAR_001             = FAILS
DECODA_RD_FLOOR_001              = FAILS
DECODA_HEADROOM_LOCATION_001     = FAILS
DECODA_PERF_THESIS_001           = FAILS
```

Defensible: *Decoda has proven kernel execution closure over the recorded
5,632-block gate; numerical parity and integration certification remain open.*

## 5. Separate finding: dump authority claim does not reproduce

The ledger asserts `rawr dump --format json tinyllama` reports
`arch=llama tensor_count=201, read from bytes`. Executed against the freshly
linked `rawr.exe` on this source tree:

```text
COMMAND = rawr dump --format json tinyllama
EXIT    = 0
JSON    = "model_count": 206
          "models": [ ]
VERDICT = PASS
```

The targeted query returns an **empty model set** and still reports `PASS`.
Reproduced for every positional filter tested (by name and by absolute path).

Adjacent measurements from the same run:

```text
MODELS_DISCOVERED      = 206
MODELS_WITH_PATH       = 78
MODELS_WITH_UNKNOWN_PATH = 128
UNLOADABLE_COUNT       = 128
EMPTY_ROOT_RETURNS_FAIL = 0
```

Two defects:

1. **Targeted selection is non-functional.** A filter argument yields no models.
2. **The verdict cannot disagree with the result.** An empty model set is
   reported `VERDICT=PASS`, and `EMPTY_ROOT_RETURNS_FAIL=0` records that the
   gate does not fail closed on emptiness.

This is the `A_DIAGNOSTIC_THAT_CANNOT_DISAGREE_IS_NOT_A_DIAGNOSTIC` pattern.

## 6. Source-identity note

The worktree carried 301 changed paths at measurement time. Under the
stale-binary rule, the SHA-256 above binds this correction to that binary only.
A re-pin requires a clean rebuild.

## 7. Standing rule

```ini
CLAIM_HAS_RECEIPT_FILE     = YES -> may cite receipt name
CLAIM_ONLY_IN_COMMIT_MSG   = YES -> cite as commit observation
CLAIM_ONLY_IN_CHAT/HARNESS = YES -> provisional, never publish as certified
LEDGER_SAYS_FAILS          = YES -> no later conversational PASS overrides it
```