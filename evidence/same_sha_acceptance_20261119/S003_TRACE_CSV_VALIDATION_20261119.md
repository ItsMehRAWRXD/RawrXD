# S003 trace CSV validation

Source SHA: `01ed69b794f3ebc434e001abe1f6bc9cc67b4ca6`

Validation parsed each CSV with `csv.reader`, discarded repeated header rows, and checked numeric fields `position`, `block`, `pc`, `op`, `size`, `checksum`, and `first0`, plus nonempty operation names.

| File | Valid rows | Bad rows | Position distribution |
|---|---:|---:|---|
| `trace_p0.csv` | 395 | 0 | 0:395 |
| `trace_p1.csv` | 1,185 | 0 | 0:395, 1:790 |
| `trace_p2.csv` | 2,370 | 0 | 0:395, 1:790, 2:1,185 |
| `deep2_op_trace.csv` | 395 | 0 | 0:395 |
| `trace_pos0.csv` | 395 | 0 | 0:395 |
| `trace_pos1.csv` | 1,185 | 0 | 0:395, 1:790 |
| `trace_pos2.csv` | 2,370 | 0 | 0:395, 1:790, 2:1,185 |

Repeated header rows were present in the `trace_pos1.csv` and `trace_pos2.csv` serialization artifacts and were excluded as headers, not treated as operation records. No malformed operation rows remain after normalization.

```ini
TRACE_CSV_VALIDATION=PASS
EXPECTED_OPERATION_RECORDS_PER_POSITION=395
MALFORMED_OPERATION_ROWS=0
REFERENCE_INTERMEDIATE_TENSORS=NOT_PRESENT_IN_TRACE
FIRST_DIVERGENCE=NOT_ESTABLISHED
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
