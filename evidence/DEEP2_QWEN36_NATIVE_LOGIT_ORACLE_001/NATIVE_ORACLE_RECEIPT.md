# DEEP2_QWEN36_NATIVE_LOGIT_ORACLE_001

## Disposition

`NATIVE_LLAMA_SUPPORT=PASS` · `REFERENCE_LOGITS=AVAILABLE` · `FULL_MODEL_LOGIT_PARITY=FAIL` · `PROMOTE=0`

## Provenance

- Model: `F:\OllamaModels\Qwen3.6-35B-A3B-GGUF\Qwen3.6-35B-A3B-Q4_K_M.gguf`
- Model SHA-256: `4AC6A06BCE551257267F49AD2226F8671A22519CCC1A4DDE9D5B433D1F2A410D`
- Input token IDs: `9419` (`Hello`, GGUF tokenizer)
- Native diagnostic: `F:\rawrxd\evidence\DEEP2_QWEN36_NATIVE_LOGIT_ORACLE_001\bin\llama_dump_logits_teacher_forced.exe`
- Diagnostic SHA-256 (corrected hidden-width build): `6AB8E23F8C6011E902D9A09FB276336FD7CF99AE11E210BE46785D6BE734C804`
- Native package: Python `llama_cpp` 0.3.36 headers/libs
- Native run exit: `0`
- Raw run log: `oracle_run.txt`

## Reference output

- Logit file: `ref2/ref_logits_pos0.bin` (the earlier `ref/` run is retained)
- Vocabulary values: `248320`
- Finite: `true`
- Reference SHA-256: `4B32688F62F7386C704ADE146B103972E66D56AE79E714885F6050981277719A`

## Deep2 comparison

- Deep2 vector: `DEEP2_QWEN36_FULL_MODEL_PARITY_001/deep2_logits_hello/d2_logits_pos0.bin`
- Deep2 SHA-256: `2a161641a227c28bd3573a672f82b3185d86a13b09fffb9c76ded5588cc5a946`
- Compared values: `248320`
- Both vectors finite: `true`
- Maximum absolute error: `13.899116516113281`
- Mean absolute error: `3.372328519821167`
- RMS error: `3.9510116577148438`
- Cosine similarity: `-0.06610392034053802`
- Native argmax: token `11`, logit `14.928254127502441`
- Deep2 argmax: token `26049`, logit `8.954997062683105`

## Interpretation

The native llama.cpp reference path supports this model and produced a valid first-step vocabulary vector. The large, negative-cosine mismatch establishes a full-model numerical divergence before sampling. This does **not** identify the first divergent internal layer. CPU GDN intermediate parity remains valid within its existing scope; attention, normalization, routing, output projection, and configuration differences remain open.

No Deep2 source repair is authorized solely from this final-logit mismatch. The next diagnostic should capture a compatible layer-by-layer oracle or verify architecture/configuration parity before modifying kernels.

```ini
CPU_GDN_PARITY=PASS
NATIVE_LLAMA_ORACLE=PASS
REFERENCE_LOGITS=AVAILABLE
FULL_MODEL_LOGIT_PARITY=FAIL
FIRST_DIVERGENT_LAYER=UNKNOWN
VULKAN_GDN=FAIL_CLOSED
PROMOTE=0
```
