# PHI3_GEMMA4_DECODE_NEXT_DROP_001

Source-only compatibility/attribution drop.

## Files

- `Phi3FusedFfnRuntime.hpp` — supports Phi-3 fused `ffn_up.weight` as `gate|up` without clamping the tensor rows down to the half-width.
- `Gemma4SchemaBinder.hpp` — binds Gemma/HF-style names (`model.layers.N.self_attn.q_proj.weight`, `model.layers.N.mlp.gate_proj.weight`, etc.) into Deep2's existing weight slots.
- `DecodeBlockerAttribution.hpp` — diagnostic timers for the one-by-one ignore ladder.

## Copy targets

```powershell
Copy-Item .\Phi3FusedFfnRuntime.hpp G:\~dev\rawrxd\src\deep2\Phi3FusedFfnRuntime.hpp -Force
Copy-Item .\Gemma4SchemaBinder.hpp G:\~dev\rawrxd\src\deep2\Gemma4SchemaBinder.hpp -Force
Copy-Item .\DecodeBlockerAttribution.hpp G:\~dev\rawrxd\src\deep2\DecodeBlockerAttribution.hpp -Force
```

Apply `PHI3_GEMMA4_DECODE_NEXT_DROP.patch` manually if `git apply` cannot match your locally modified tree.

## Build

```powershell
cmake --build build-fd --target deep2_streamer_parity -j 1
```

## Expected receipts

Phi-3:

```text
PHI3_FUSED_FFN_RUNTIME layers=32 repaired=32 authority=PASS
PHI3_FUSED_FFN_EXEC=1
AUTHORITY_LADDER=PASS
TOKENS_COMMITTED>=1
```

Gemma4:

```text
GEMMA4_SCHEMA_BINDER ok=1 why=GEOM_READY
BLOCKED_AT=GEOM -> CLEARED
MODEL_OPEN=PASS
```

Decode attribution:

```text
DECODE_BLOCKER_ATTRIBUTION_BEGIN=1
TOKENS_REQUESTED=20
TOKENS_COMMITTED=20
TOKENS_DECODED=20
TOKENIZER_SINGLE_CALLS=20
TOKENIZER_SEQUENCE_CALLS=0
DECODE_REPLAY_FACTOR=1.000000
DECODE_OWNER=<FORWARD|LOGITS|SAMPLE|DETOK|CALLBACK|RECEIPT|KV|OTHER>
PROMOTE=0
```
