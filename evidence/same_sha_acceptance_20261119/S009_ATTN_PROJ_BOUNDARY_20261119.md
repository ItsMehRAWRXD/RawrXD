# S009 `attn_proj` reference boundary audit

The retained llama.cpp dump contains `attn_norm_L<N>.bin`, `attn_preproj_L<N>.bin`, and `attn_resid_L<N>.bin`, but no `attn_proj_L<N>.bin` or equivalent named projection-output payload.

The operation comparator therefore records every `attn_proj` row as `REFERENCE_MISSING`; it does not silently substitute `attn_preproj` or `attn_resid`, because those are different graph boundaries.

The model tensor inventory confirms the projection weight exists as `blk.<N>.attn_output.weight`, but a weight tensor is not an intermediate activation and cannot serve as the missing reference output.

## Consequence

The missing boundary cannot be reconstructed for block 0 from the retained artifacts alone: the reference input/residual boundary is intentionally absent at the first block, and the projection output is not dumped. A new llama.cpp capture must emit the post-output-projection activation before the residual add, using a unique name such as `attn_proj_L<N>.bin` and the same token position.

```ini
ATTN_PROJ_REFERENCE_BOUNDARY=NOT_CAPTURED
ATTN_PREPROJ_IS_PROJECTION_OUTPUT=NO
ATTN_RESID_IS_PROJECTION_OUTPUT=NO
MODEL_WEIGHT_PRESENT=YES
NEW_REFERENCE_CAPTURE=REQUIRED
STRICT_PARITY=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
