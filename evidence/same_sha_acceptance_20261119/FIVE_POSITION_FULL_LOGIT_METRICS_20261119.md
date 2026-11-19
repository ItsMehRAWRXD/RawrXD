# Five-position full-vocabulary metrics

Source: `S011_five_position_metrics.json`.

- Positions: `5`
- Vocabulary: `151936`
- All logits finite: `true`
- Exact top-1 agreement: `5/5`
- Minimum cosine: `0.9980973923169006`
- Worst maximum absolute error: `0.93182373046875` at position 4

| Position | Cosine | RMS | Max abs | Top-1 | Top-10 overlap |
|---:|---:|---:|---:|---:|---:|
| 0 | 0.9999982335376357 | 0.006863673189698828 | 0.03497123718261719 | 15/15 | 10 |
| 1 | 0.9992339625483421 | 0.13317354952640778 | 0.6386623382568359 | 315/315 | 9 |
| 2 | 0.9994733061117984 | 0.1441759184828148 | 0.6710376739501953 | 279/279 | 10 |
| 3 | 0.9982453981892444 | 0.15653774951184993 | 0.7396129369735718 | 374/374 | 9 |
| 4 | 0.9980973923169006 | 0.20862476883223058 | 0.93182373046875 | 12095/12095 | 10 |

This is bounded reference evidence, not strict full-logit parity.

`S011=BOUNDED_REFERENCE_ACCEPTANCE_RECORDED`
`STRICT_PARITY=OPEN`
`PROMOTE=0 CERTIFIED=0 RELEASE=HELD`
