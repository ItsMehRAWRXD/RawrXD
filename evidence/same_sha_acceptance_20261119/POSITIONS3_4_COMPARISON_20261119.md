# Positions 3 and 4 operation comparison

Artifacts: `first_divergence_pos3.json` and `first_divergence_pos4_rerun.json`,
backend `cpu`.

| Position | Records | Comparable | First crossing | Boundary | Cosine | Max abs | RMSE |
|---:|---:|---:|---|---|---:|---:|---:|
| 3 | 395 | 363 | block 1, op 27 | `ffn_down_L1.bin` | 0.999831246024968 | 0.0247052907943726 | 0.00297190383820949 |
| 4 | 395 | 363 | block 0, op 11 | `ffn_up_L0.bin` | 0.999867351438459 | 0.0204927027225494 | 0.00498403941985388 |

Position 4 reproduces the previously reported block-0 `up` crossing. These are
threshold crossings, not proven causal defects. No kernel changes were made.

`S008=POSITIONS3_4_COMPARISON_COMPLETE`
`STRICT_PARITY=OPEN`
`PROMOTE=0 CERTIFIED=0 RELEASE=HELD`
