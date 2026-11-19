# S009 aggregate first-crossing receipt

Source artifacts: `first_divergence_pos0_replay.json` through
`first_divergence_pos4_replay.json`. Threshold: cosine `< 0.9999`.

| Position | CPU first crossing | CPU cosine | GPU first crossing | GPU cosine |
|---:|---|---:|---|---:|
| 0 | none | — | none | — |
| 1 | block 2 `v`, op 33 | 0.99987098758696 | block 24 `swiglu`, op 348 | 0.99987877897446 |
| 2 | block 2 `attn_out`, op 34 | 0.999848857946793 | block 2 `ffn_out`, op 41 | 0.999835404660089 |
| 3 | block 1 `ffn_out`, op 27 | 0.999831246024968 | block 1 `ffn_out`, op 27 | 0.999831348328192 |
| 4 | block 0 `up`, op 11 | 0.999867351438459 | block 0 `up`, op 11 | 0.999867351506854 |

Every position supplied 395 operation records and 363 comparable boundaries.
Position 0 had no threshold crossing. The table identifies the earliest
reported threshold crossing per backend, not a causal kernel diagnosis.

```ini
S009=AGGREGATED
POSITIONS=5
OP_RECORDS_PER_POSITION=395
COMPARABLE_PER_POSITION=363
CAUSAL_DEFECT=UNKNOWN
STRICT_PARITY=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
