# RAWRXD_B73_CODESTRAL_Q5K_ROUTING_001

## Status: PARTIAL — root cause found and fixed, but the model is still not correct

```ini
RAWRXD_B73_CODESTRAL_Q5K_ROUTING_001=PARTIAL
ROOT_CAUSE=ROUTING_TABLE_DISAGREEMENT (found, fixed, verified)
GENERATED_TOKENS=0 -> 8        (abort removed)
OUTPUT_CORRECTNESS=FAIL       (<unk> x8)
BACKEND_OPTIMIZATION_ALLOWED=NO
```

## The failure was misdiagnosed before this gate

The original TPS test reported `LinearW: non-finite output`. That was not the
failure. The actual boundary is a routing defect that aborts before any
arithmetic runs:

```ini
GEMV_ENTER name=blk.0.attn_v.weight type=13 rows=1024 cols=6144 packed=0
GPU_FORWARD_FAIL_STAGE=GEMV_QKV layer=0 op=qkvOverlap3
GPU_FORWARD_FAIL_STAGE=RANGE_OR_MULTIMAP
COMMITTED_FALLBACK_BLOCKED=1 STRICT_NATIVE_ABORT=1 VERDICT=FAIL stage=batch9
[PREFILL] forwardTokenAllLayers FAILED at prefill token 0
```

`packed=0` is the tell: the weight was classified as NOT a packed quant, yet the
fused QKV path then failed as though it had been.

## Root cause: three type lists disagreed by exactly one type

```ini
PackedQuant         (Deep2Engine_GpuForward.cpp)  admitted  8, 10, 11, 12, 13, 14
DispatchGemvQuant   (vulkan_compute.cpp)           admitted  8, 10, 11, 12, 14
deep2_qgemv.comp    decode branches                8, 10, 11, 12, 14
```

**Q5_K (13) was in `PackedQuant` and in neither of the other two.** It has no
kernel. The failure chain:

```text
Q5_K weight
  -> PackedQuant() returns true          (claims a native kernel exists)
  -> routed into the native packed branch
  -> DispatchGemvQuant(13, ...) returns false immediately
  -> fused QKV path treats the refusal as fatal
  -> RANGE_OR_MULTIMAP -> STRICT_NATIVE_ABORT
```

Codestral-22B exposes it because its tensors are mixed: `attn_q` and `attn_k`
are type 12, `attn_v` is type 13. llama3.2-3b never hit it because its types are
10 and 11, both fully covered.

This is why it looked like a numerical defect. It is a routing table pointing at
a kernel that does not exist.

## Fix

`PackedQuant` no longer claims Q5_K. It now lists each type with the shader
function that implements it, so the correspondence is readable at the point of
decision:

```cpp
return t == GGML_TYPE_Q8_0 ||   //  8 shader: q8_0_weight
       t == GGML_TYPE_Q2_K ||   // 10 shader: q2k_weight
       t == GGML_TYPE_Q3_K ||   // 11 shader: q3k_weight
       t == GGML_TYPE_Q4_K ||   // 12 shader: q4k_weight
       t == GGML_TYPE_Q6_K;     // 14 shader: q6k_weight
```

Q5_K now routes to the prepared-F32 path, which is correct for it. All three
lists carry a cross-reference requiring agreement before a type is added to any
one of them.

**This is a routing correction, not a workaround.** No clamp, no NaN
sanitization, no fallback kernel, no backend switch, and no arithmetic change.
Nothing is hidden, and `RAWRXD_QK_PROJECTION_PARITY_BACKEND_GATE` is not
weakened by it.

## Verified

```ini
EXE_SHA256_PRE  = 623428E7F7474BE38614811E57E1B3CFA6E383EC7759399CC3D0315C233D6378
EXE_SHA256_POST = 623428E7F7474BE38614811E57E1B3CFA6E383EC7759399CC3D0315C233D6378
BUILD_EXIT      = 0

BEFORE: generated=0  status=4 (InternalError)  RANGE_OR_MULTIMAP
AFTER : generated=8  completed=1               no RANGE_OR_MULTIMAP

Q5_K_native_attempts = 0        (correctly never attempted)
PREPARED_CACHE acquire=220 miss=11 hit=209 evict=0
                  cpuDequantCalls=11 cpuDequantBytes=2919235584
GEMV_ENTER name=blk.0.attn_v.weight type=13 packed=0  -> prepared path, correct
```

Q5_K now correctly reports `packed=0`, is prepared as F32 (11 distinct weights,
2.9 GB), and runs. The abort is gone.

## The model is still NOT correct — do not read this as Codestral working

```ini
generated text = "<unk><unk><unk><unk><unk><unk><unk><unk>"   (8 tokens, 40 chars)
GPU_FORWARD_FINITE_CHECK finite=6144 nan=0 inf=0
                    min=-1.54599e+09  max=8.16556e+08
```

Logit magnitudes of ~1e9 are the actual defect, and `nan=0 inf=0` again fails to
catch it — the same blindness that let the first Q3_K attempt produce finite
garbage. Geometry reads correctly from the GGUF (`arch=llama layers=56
hidden=6144 heads=48 kv_heads=8 vocab=32768`), so this is not a metadata problem.

A healthy model of this size does not produce ±1e9 activations. That points at
either an unquantized or mis-scaled tensor, or an F32 prepared representation
that is wrong for Q5_K specifically — Q5_K was the one type that had never
exercised the prepared path before, because it was always diverted to the native
branch and then refused.

## Next step, still narrow

The remaining question is the same one this gate set out to answer, now that the
abort no longer masks it:

```ini
FIRST_BAD_LAYER=?
FIRST_BAD_PROJECTION=?
OPERANDS_FINITE=?
OPTIMIZED_RESULT_FINITE=1        (finiteness holds; values are wrong)
SCALAR_REFERENCE=?               <- the decisive comparison, not yet performed
```

The scalar-F32 reference comparison against the prepared Q5_K path is what would
establish whether the prepared representation or the attention arithmetic is at
fault. That work is not done, and no correctness claim is made for Codestral
beyond "it no longer aborts at token 0".

```ini
B73_COMMITTED=NO
B73_PUSHED=NO
```