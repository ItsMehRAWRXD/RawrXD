# PHI3_FUSED_QKV_AUTHORITY_DROP_001

Your receipt shows Phi-3 is not failing at raw GGUF open anymore. The loader sees
`blk.N.attn_qkv.weight`, then the authority ladder blocks at `attn_q`.

This drop teaches the runtime schema that Phi-3 owns Q/K/V through one fused
projection:

```text
blk.N.attn_qkv.weight = Q | K | V
blk.N.attn_output.weight = output projection
```

For the observed shape:

```text
hidden = 3072
attn_qkv rows = 9216 = 3 * hidden
schema = PHI3_FUSED_QKV_3H
```

Expected next state:

```text
PHI3_OPEN_FAILED=0
PHI3_FUSED_QKV_AUTHORITY=PASS
AUTHORITY_LADDER=PASS
PREFILL=OBSERVED
TOKENS_COMMITTED>=1
PROMOTE=0
```

Do not treat the 64-byte offset warnings as the owner unless absolute
`dataOffset + tensor.offset` proves bad. The concrete blocker is `BLOCKED_AT=attn_q`.
