# S003 trace CSV validation

Validation command: PowerShell `Import-Csv` over `trace_p0.csv`, `trace_p1.csv`,
`trace_p2.csv`, `trace_pos0.csv`, `trace_pos1.csv`, and `trace_pos2.csv`.

Expected schema has 12 columns and each position should contain 395 operation
records. Required fields checked: `position`, `block`, `op`, and `checksum`.

| File | Parsed rows | Valid operation rows | Issue |
|---|---:|---:|---|
| `trace_p0.csv` | 395 | 395 | none |
| `trace_p1.csv` | 1185 | 1185 | none |
| `trace_p2.csv` | 2370 | 2370 | none |
| `trace_pos0.csv` | 395 | 395 | none |
| `trace_pos1.csv` | 1186 | 1185 | repeated header at line 397 |
| `trace_pos2.csv` | 2372 | 2370 | repeated headers included as data |

All actual operation rows have the required fields. The `trace_pos1.csv` and
`trace_pos2.csv` artifacts are not clean CSV payloads because a header was
appended between position runs. This is a serialization/artifact defect, not a
numerical result. No kernel change was made.

```ini
S003=FAIL_CLOSED_ARTIFACT_SERIALIZATION
EXPECTED_ROWS_PER_POSITION=395
MALFORMED_OPERATION_ROWS=0
REPEATED_HEADER_ROWS=3
NUMERICAL_PARITY=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
