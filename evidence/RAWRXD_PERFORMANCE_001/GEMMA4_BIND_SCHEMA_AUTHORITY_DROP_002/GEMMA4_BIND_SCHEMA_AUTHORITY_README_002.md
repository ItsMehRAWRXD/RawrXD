# GEMMA4_BIND_SCHEMA_AUTHORITY_DROP_002

This drop fixes the next observed issue after Gemma4 root/layer alias binding: `BindLlamaSchema` still expects llama.cpp-style `token_embd.weight` and `blk.N.*` names. The binder already maps Gemma/HF names into Deep2 slots; the schema guard must accept those bound slots instead of re-checking only raw llama names.

## Files

- `Gemma4BindLlamaFallback.hpp` — validates modelWeights after alias binding and emits `GEMMA4_BIND_LLAMA_FALLBACK`.
- `FfnInterInferFix.hpp` — repairs `intermediateDim` from tensor-set evidence, preferring `ffn_down` input width when fused `ffn_up` is doubled.
- `DecodeBlockerAttributionWire.hpp` — explicit Reset/Emit wrappers for the decode isolation ladder.
- `GEMMA4_BIND_SCHEMA_AUTHORITY_DROP_002.patch` — surgical splice patch.

## Required order

1. Include headers.
2. During weight mapping, call root alias bind before llama-only layer logic.
3. Parse Gemma/HF layer index with `gemma4_schema::ParseLayerIndex(name)`.
4. Call layer alias bind with the parsed Gemma/HF index.
5. After weight mapping, run:
   - `ffn_inter_fix::RepairIntermediate(...)`
   - `phi3_fused_ffn::RepairModel(...)`
   - `gemma4_schema::EmitSummary(...)`
   - `gemma4_bind_fallback::TryClearBindLlamaSchemaByAliases(...)`
6. Only then run the authority ladder.

## Classification

This is source-only open/runtime compatibility. Runtime PASS remains deferred until the model emits its own receipt.
