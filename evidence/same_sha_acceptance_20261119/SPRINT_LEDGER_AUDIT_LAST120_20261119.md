# Sprint ledger audit: requested last 120 completions

Source: `C:\Users\Garrett\Downloads\RawrXD_15_Minute_Sprints_Continuation.csv`.

The file contains **109 records**, not 120. Therefore the requested last-120
window is the complete file.

## Ledger state

- `108` records are `OPEN`.
- `1` record is `BLOCKED_LOCAL_CHECKOUT_UNAVAILABLE` (`S001`).
- No record is marked `PASS`, `COMPLETE`, or `CLOSED`.
- The CSV `evidence` column is blank for the sprint rows inspected.

## Reconciliation with verified work in this session

S002 through S012 now have current receipts on the pushed branch, but the CSV
still reports them as `OPEN` and does not reference those receipts:

| Sprint | Current verified receipt | Actual disposition |
|---|---|---|
| S002 | `S002_COMPARATOR_EXIT5_20261119.md` and replay JSON | Exit 5 mapped to row-count mismatch; parity not passed |
| S003 | `S003_TRACE_CSV_VALIDATION_20261119.md` | Artifact serialization defect: repeated headers |
| S004 | `S004_MAPPING_REVALIDATION_20261119.md` | Q/K/V mapping revalidated; `attn_proj` missing |
| S005 | `S005_POSITION0_REVALIDATION_20261119.md` | Bounded diagnostic pass; strict parity open |
| S006 | `S006_POSITION1_REVALIDATION_20261119.md` | Threshold crossings reproduced; cause unknown |
| S007 | `S007_POSITION2_REVALIDATION_20261119.md` | Threshold crossings reproduced; cause unknown |
| S008 | `S008_POSITIONS3_4_REVALIDATION_20261119.md` | Position-4 `up` crossing reproduced |
| S009 | `S009_AGGREGATE_FIRST_CROSSINGS_20261119.md` | Five-position map aggregated; cause unknown |
| S010 | `S010_ROW_ALIGNMENT_REVALIDATION_20261119.md` | 5-versus-3 row mismatch remains |
| S011 | `S011_FULL_LOGIT_REVALIDATION_20261119.md` | 5/5 top-1, strict full-logit parity failed |
| S012 | `S012_REFERENCE_REVALIDATION_20261119.md` | Reference artifact valid; prior GPU parity 2/3 |

The ledger is therefore stale rather than falsely reporting PASS: it leaves all
work open, but it does not record the receipts now present in the repository.
No certification status is advanced.

```ini
CSV_RECORDS=109
REQUESTED_WINDOW=120
WINDOW_COVERAGE=109_OF_120
OPEN=108
BLOCKED=1
PASS_OR_COMPLETE=0
LEDGER_RECEIPTS_RECONCILED=S002_TO_S012
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
