# S012 TinyLlama Q4_K reference revalidation

The model hash and retained reference structure were rechecked.

```ini
MODEL_SHA256=9FECC3B3CD76BBA89D504F29B616EEDF7DA85B96540E490CA5824D3F7D2776A0
REFERENCE_POSITIONS=18
REFERENCE_ROOT=evidence/QUANTIZED_PARITY_20261119/ref
SAME_SHA_PAYLOAD_ROOT=evidence/same_sha_acceptance_20261119/tinyllama_ref
TOKENS=1,185,42
POSITIONS_USED=3
VOCAB=32000
FULL_LOGIT_PAYLOADS=3
ALL_FINITE=REPORTED
STRICT_PARITY=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```

The on-disk model hash matches the retained receipt. The reference artifact is
complete for the recorded positions, but its prior comparison remains only a
diagnostic bounded result: top-1 agreement `2/3`, minimum cosine
`0.9964957435475023`, and worst max error `1.4383420944213867`.
