# Real Qwen GDN runtime trace

Trace executable SHA-256: `49E8A39541683A6A66728C3DD4581EA884CA9B6855B9AEB79110A99D9C9A3CCE`
Trace model SHA-256: `4AC6A06BCE551257267F49AD2226F8671A22519CCC1A4DDE9D5B433D1F2A410D`
Trace log: `gdn_trace_one_token/stdout_stderr.txt`

The one-token run enabled `DEEP2_GDN_GPU_CHECK=1`, `DEEP2_GDN_DIAG=1`, and a
block-0 operand dump. The production Qwen graph admitted real GDN operations
with:

```text
qkv_width=8192 gate_width=4096 key_heads=16 value_heads=32 head_dim=128
state_size=128 groups=16 expected_state=524288
```

The trace contains `GDN_PARITY_DUMP block=0` for the GPU executor and the
CPU-pinned comparison executor. The GPU executor completed with:

```text
[gpu] gpu_calls=1301 cpu_calls=0
VERDICT=INTERNAL_DIAGNOSTIC_FAIL
```

`DEEP2_GDN_GPU_CHECK` did not report a Vulkan/reference failure, so the real
GDN dispatch and its per-block differential check completed. The remaining
first-position mismatch is downstream or in another GPU/CPU operation; this
receipt does not attribute it speculatively to GDN.

