# Operation trace CSV validation

Validated with PowerShell `Import-Csv` on the three retained traces:

| File | Rows | Required structural fields | Result |
|---|---:|---|---|
| `deep2_op_trace.csv` | 395 | `position,block,pc,op,name,weight,input,size,checksum,backend,fallback,first0` | PASS |
| `deep2_op_trace2.csv` | 395 | same header | PASS |
| `deep2_op_trace3.csv` | 395 | same header | PASS |

The records are structurally valid and contain operation identity, tensor
metadata, backend/fallback fields, and serialized payload values. They do **not**
contain `max_abs`, `rms`, or `cosine` columns; therefore this validation does
not establish numerical parity or identify a first numerical divergence.

`S003=STRUCTURAL_TRACE_VALIDATION_PASS`
`S009=FIRST_DIVERGENCE_OPEN`
`PROMOTE=0 CERTIFIED=0 RELEASE=HELD`
