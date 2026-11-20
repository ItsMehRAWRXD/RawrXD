# S013 TinyLlama Q4_K GPU parity revalidation

The recorded model and executable artifacts were rehashed before disposition.

```ini
MODEL_SHA256=9FECC3B3CD76BBA89D504F29B616EEDF7DA85B96540E490CA5824D3F7D2776A0
EXECUTABLE_SHA256=88CB2AE5D1C34C1BDAFE0B8F35C514601D22971F9648ED2912B9D2A67F2D18AC
TOKENS=1,185,42
GPU_CALLS=465
CPU_CALLS=0
FINITE_LOGITS=3/3
ARGMAX_EXACT=2/3
MIN_COSINE=0.9964957435
MAX_ABS=1.4383420944
GPU_EXECUTION=PASS_REPORTED
STRICT_Q4K_PARITY=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```

The model hash and executable hash match the retained S013 receipt. This
confirms GPU execution and zero reported CPU calls, but position 2 still has a
top-1 mismatch and strict parity remains failed.
