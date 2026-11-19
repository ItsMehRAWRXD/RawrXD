# 120-sprint ledger reconciliation

This supplemental ledger preserves the original CSV and reconciles it to
repository evidence. It does not rewrite the source CSV or promote any gate.

## S002–S012 evidence links

| Sprint | Evidence milestone | Acceptance disposition |
|---|---|---|
| S002 | `S002_COMPARATOR_EXIT5_20261119.md` | EVIDENCE_CAPTURED; exit 5 is row mismatch |
| S003 | `S003_TRACE_CSV_VALIDATION_20261119.md` | ACCEPTANCE_FAILED; repeated headers |
| S004 | `S004_MAPPING_REVALIDATION_20261119.md` | EVIDENCE_CAPTURED; mapping verified |
| S005 | `S005_POSITION0_REVALIDATION_20261119.md` | EVIDENCE_CAPTURED; bounded only |
| S006 | `S006_POSITION1_REVALIDATION_20261119.md` | EVIDENCE_CAPTURED; parity failed |
| S007 | `S007_POSITION2_REVALIDATION_20261119.md` | EVIDENCE_CAPTURED; parity failed |
| S008 | `S008_POSITIONS3_4_REVALIDATION_20261119.md` | EVIDENCE_CAPTURED; parity failed |
| S009 | `S009_AGGREGATE_FIRST_CROSSINGS_20261119.md` | EVIDENCE_CAPTURED; cause unknown |
| S010 | `S010_ROW_ALIGNMENT_REVALIDATION_20261119.md` | ACCEPTANCE_FAILED; 5-versus-3 rows |
| S011 | `S011_FULL_LOGIT_REVALIDATION_20261119.md` | ACCEPTANCE_FAILED; strict parity failed |
| S012 | `S012_REFERENCE_REVALIDATION_20261119.md` | EVIDENCE_CAPTURED; GPU parity failed |

## Added definitions S110–S120

These are definitions only. Each remains `OPEN` until executable evidence is
produced.

| Sprint | Phase | Objective | Acceptance |
|---|---|---|---|
| S110 | Release certification | Current-SHA clean checkout build | Fresh build and hash |
| S111 | Release certification | Current-SHA native bridge generation | Real tokens and terminal callback |
| S112 | Release certification | Current-SHA GUI Deep2 chat | Transcript response through native route |
| S113 | Release certification | GPU witness for GUI request | Nonzero request-attributed dispatches |
| S114 | Release certification | Cancellation and timeout lifecycle | Exactly one terminal state, no late callback |
| S115 | Release certification | Repeated model load/unload | Baseline resource reclamation |
| S116 | Release certification | Dual-GPU execution | Both devices execute verified work |
| S117 | Release certification | Long-context stability | Bounded memory and no deadlock |
| S118 | Release certification | Full-logit parity rerun | Matching rows and defined tolerance |
| S119 | Release certification | Performance baseline | Reproducible TPS and latency receipt |
| S120 | Release certification | Final release matrix | All applicable gates pass on one SHA |

```ini
DEFINED_SPRINTS=120
EVIDENCE_CAPTURED=S002,S004,S005,S006,S007,S008,S009,S012
ACCEPTANCE_FAILED=S003,S010,S011
PASS=0
OPEN_OR_BLOCKED=120
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
