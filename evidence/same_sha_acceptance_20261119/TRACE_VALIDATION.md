# LTT trace validation after serialization fix

```ini
SOURCE_SHA=b5ee9dadaf
BUILD=PASS
REFERENCE_INTERMEDIATE_CAPTURE=HIDDEN_AND_LOGITS_ONLY
FIRST_DIVERGENT_OPERATION=NOT_ESTABLISHED
```

Independent prefix runs used the same model and token contexts:

```text
p0: tokens=1             exit=0 rows=395  bad_rows=0 positions=1
p1: tokens=1,185         exit=0 rows=1185 bad_rows=0 positions=2
p2: tokens=1,185,42       exit=0 rows=2370 bad_rows=0 positions=3
```

The pinned llama.cpp teacher-forced harness produced full-vocabulary logits
and hidden states for all three positions. It does not expose per-operation
intermediate tensors, so no first cross-implementation operation is claimed.
