# S011 full-logit revalidation

Recomputed directly from the five `gpu_logits_pos<N>.bin` files and matching
`ref_logits/ref_logits_pos<N>.bin` files using float32 arrays.

```ini
POSITIONS=5
VOCAB=151936
ALL_FINITE=YES
TOP1=5/5
MIN_COSINE=0.9980978230423398
MAX_ABS=0.93182373046875
STRICT_FULL_LOGIT_PARITY=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```

Per-position top-1 agreement was `15/15`, `315/315`, `279/279`, `374/374`, and
`12095/12095`. Top-10 overlap was `10/10`, `9/10`, `10/10`, `9/10`, and
`10/10`. The full vectors remain numerically different; bounded top-1 agreement
does not establish strict parity.
