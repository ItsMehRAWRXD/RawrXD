# S011 five-position full-vocabulary comparison

The retained per-position GPU artifacts and llama.cpp reference artifacts have matching token counts and vocabulary lengths: five positions, 151,936 logits each.

| Position | Cosine | RMS | Max abs | GPU top-1 | Reference top-1 | Top-10 overlap |
|---:|---:|---:|---:|---:|---:|---:|
| 0 | 0.9999982335 | 0.00686367 | 0.0349712 | 15 | 15 | 10/10 |
| 1 | 0.9992339625 | 0.133174 | 0.638662 | 315 | 315 | 9/10 |
| 2 | 0.9994733061 | 0.144176 | 0.671038 | 279 | 279 | 10/10 |
| 3 | 0.9982453982 | 0.156538 | 0.739613 | 374 | 374 | 9/10 |
| 4 | 0.9980973923 | 0.208625 | 0.931824 | 12095 | 12095 | 10/10 |

Observed aggregate: all values finite, exact top-1 agreement `5/5`, minimum cosine `0.9980973923169006`, worst max error `0.93182373046875`.

This is a structurally valid full-vocabulary comparison, but not strict numerical parity. The retained per-position artifacts are valid for this report; the packed `deep2_logits.bin` remains a separate five-row versus three-row mismatch documented by S010.

```ini
POSITIONS_COMPARED=5
VOCAB=151936
ALL_FINITE=YES
TOP1=5/5
STRICT_FULL_LOGIT_PARITY=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
