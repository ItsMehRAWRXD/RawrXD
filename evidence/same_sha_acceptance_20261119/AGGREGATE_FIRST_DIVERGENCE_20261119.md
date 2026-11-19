# Aggregate first-divergence receipt

All five position artifacts contain 395 rows and 363 comparable boundaries,
using the same Q/K/V `__dup1` mapping. The comparator threshold is cosine
`0.9999`.

| Position | First reported crossing | Boundary | Cosine | Max abs | RMSE |
|---:|---|---|---:|---:|---:|
| 0 | none recorded | — | — | — | — |
| 1 | block 2, op 33 | `v_L2__dup1.bin` | 0.99987098758696 | 0.02573797106742859 | 0.007737101712146897 |
| 2 | block 2, op 34 | `attn_preproj_L2.bin` | 0.9998488579467929 | 0.014291971921920776 | 0.0026410415837960876 |
| 3 | block 1, op 27 | `ffn_down_L1.bin` | 0.999831246024968 | 0.0247052907943726 | 0.00297190383820949 |
| 4 | block 0, op 11 | `ffn_up_L0.bin` | 0.999867351438459 | 0.0204927027225494 | 0.00498403941985388 |

These are the first threshold crossings reported by the existing comparator,
not causal proof. `attn_proj` remains missing from the reference boundary set,
and output norm/logits remain unmapped. No numerical kernel change is justified
by this receipt alone.

`S009=AGGREGATED_THRESHOLD_RECEIPT_COMPLETE`
`FIRST_CAUSAL_DIVERGENCE=UNKNOWN`
`STRICT_PARITY=OPEN`
`PROMOTE=0 CERTIFIED=0 RELEASE=HELD`
