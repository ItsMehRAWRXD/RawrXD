# DEEP2_QWEN36_FIRST_DIVERGENCE_LOCALIZATION_001

## Disposition

`ALIGNMENT=PASS_REPORTED` · `REFERENCE_LOGITS=AVAILABLE` · `FULL_MODEL_PARITY=FAIL` · `FIRST_DIVERGENT_LAYER=UNKNOWN` · `PROMOTE=0`

## Controlled inputs

- GGUF: `F:\OllamaModels\Qwen3.6-35B-A3B-GGUF\Qwen3.6-35B-A3B-Q4_K_M.gguf`
- GGUF SHA-256: `4AC6A06BCE551257267F49AD2226F8671A22519CCC1A4DDE9D5B433D1F2A410D`
- Input token: `9419` (`Hello`)
- Deep2 command: `deep2_bench_tps.exe --model <GGUF> --tokens "9419" --decode 1 --cpu --serial-prefill --no-batch`
- Deep2 exit: `0`
- Deep2 logits: finite
- Deep2 generated token: `151353`
- Deep2 executable SHA-256 (diagnostic final-hidden build): `46F5BFBD8E94C718CA0579585EF1F7DDC841AEAD9E377FB3897B5D8757803F43`
- Deep2 hidden-boundary capture: `deep2_hidden.*` (token embedding plus block residual vectors, blocks 0-39)
- Deep2 repeatability: 160 capture files compared across two identical runs; `MISMATCH=0`

## Native reference

- llama.cpp diagnostic: `DEEP2_QWEN36_NATIVE_LOGIT_ORACLE_001/bin/llama_dump_logits_teacher_forced.exe`
- Corrected native run: exit `0`
- Reference logits: `248320` finite values
- Reference hidden width: `2048` (queried from model metadata; diagnostic no longer assumes 3072)
- Reference argmax: token `11`
- Deep2 argmax: token `26049` in the prior aligned capture
- Final hidden comparison: Deep2 `deep2_final_hidden.f32` versus native `ref2/ref_hidden_pos0.bin`; both 2,048 finite values, max absolute error `31.819513`, RMS `2.984292`, cosine `0.089082`

The native `llama_get_embeddings_ith` result is a final model-state embedding, not the raw token-table lookup. Therefore the raw `deep2_hidden.pub.b0.resid_in.f32` versus native embedding comparison is intentionally **not** used as a first-layer verdict. A final-state diagnostic comparison against `deep2_hidden.blk39.resid2.f32` is recorded only as downstream evidence (max absolute error `35.971073`, RMS `2.712357`, cosine `0.069685`); it does not identify the earliest divergent block.

## Comparison

- Maximum absolute error: `13.899116516113281`
- Mean absolute error: `3.372328519821167`
- RMS error: `3.9510116577148438`
- Cosine similarity: `-0.06610392034053802`
- Final-logit parity: `FAIL`

## Boundary coverage

Token ID, GGUF identity, CPU mode, serial prefill, no-batch execution, and finite-output checks are aligned. Deep2 now emits compatible block-boundary captures, but the installed llama.cpp diagnostic still exports only final logits/final-state embeddings, not per-layer residuals. Therefore the earliest divergent tensor cannot be assigned from this run.

No attention, GDN, normalization, MoE, or output-projection source was modified. Existing CPU GDN intermediate parity remains valid within its tested scope.

```ini
TOKEN_ALIGNMENT=PASS
MODEL_ALIGNMENT=PASS
REFERENCE_LOGITS=AVAILABLE
FULL_MODEL_LOGIT_PARITY=FAIL
EMBEDDING_PARITY=NOT_COMPARED
LAYER_BOUNDARY_PARITY=NOT_AVAILABLE
FIRST_DIVERGENT_LAYER=UNKNOWN
DEEP2_BOUNDARY_REPEATABILITY=PASS
SOURCE_REPAIR=NOT_AUTHORIZED
PROMOTE=0
```
