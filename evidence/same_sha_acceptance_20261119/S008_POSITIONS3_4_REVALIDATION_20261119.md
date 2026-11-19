# S008 positions 3 and 4 revalidation

Both pinned comparisons exited `0`, with 395 operation records and 363
comparable boundaries per position at cosine threshold `0.9999`.

| Position | CPU first crossing | CPU cosine | GPU first crossing | GPU cosine |
|---:|---|---:|---|---:|
| 3 | block 1 `ffn_out`, op 27 | 0.9998312460249679 | block 1 `ffn_out`, op 27 | 0.9998313483281915 |
| 4 | block 0 `up`, op 11 | 0.9998673514384594 | block 0 `up`, op 11 | 0.9998673515068542 |

The previously reported position-4 block-0 `up` crossing is reproduced for
both backends. These are threshold crossings, not proof that the named
operation is the first causal defect.

```ini
S008=COMPARISON_REPRODUCED
POSITIONS=3,4
OP_RECORDS_PER_POSITION=395
COMPARABLE_PER_POSITION=363
POSITION4_BLOCK0_UP=REPRODUCED
STRICT_PARITY=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
