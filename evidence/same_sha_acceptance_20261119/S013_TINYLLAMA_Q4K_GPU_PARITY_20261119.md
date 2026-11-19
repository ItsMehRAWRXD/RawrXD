# S013 TinyLlama Q4_K GPU parity

The corrected exact-model reference comparison is structurally valid: three GPU logit rows and three reference rows, 32,000 values per position.

```ini
MODEL_SHA256=9FECC3B3CD76BBA89D504F29B616EEDF7DA85B96540E490CA5824D3F7D2776A0
TOKENS=1,185,42
LTT_EXIT=0
GPU_CALLS=465
CPU_CALLS=0
FINITE_LOGITS=3/3
```

| Position | Cosine | RMS | Max abs | Top-1 | Top-10 overlap |
|---:|---:|---:|---:|---|---:|
| 0 | 0.9997565478 | 0.0554083 | 0.233017 | match | 9/10 |
| 1 | 0.9973945661 | 0.1910065 | 0.942446 | match | 8/10 |
| 2 | 0.9964957435 | 0.2933762 | 1.438342 | mismatch | 9/10 |

The GPU execution and structural comparison pass, but strict quantized parity fails at position 2. The older `LTT_TINYLLAMA_REFERENCE_COMPARE_20261119.md` contains a mismatched/obsolete comparison summary (`min_cosine=0.05869`); this receipt uses the corrected exact-model artifact documented by S012.

```ini
TINYLLAMA_GPU_EXECUTION=PASS_REPORTED
Q4K_REFERENCE_ALIGNMENT=PASS
Q4K_STRICT_PARITY=FAIL
ARGMAX_EXACT=2/3
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
