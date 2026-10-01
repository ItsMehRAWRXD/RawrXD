# RAWRXD_B64_NATIVE_Q2K_GEMV_001

## Verdict: PASS (revised) — the Q2_K invariant already held

```
RAWRXD_B64_NATIVE_Q2K_GEMV_001=PASS
RAWRXD_B65_NATIVE_Q3K_GEMV_001=OPEN
```

This receipt was first written as FAIL on the theory that the Q2_K native path
was unwired at four call sites. The tensor census falsified that theory.

## The falsifying evidence

```
PREPARED_CACHE acquire=1008 miss=84 hit=924 evict=0
               cpuDequantCalls=84 cpuDequantBytes=4227858432
PREPARED_PREPARE count=84  ALL type=11
```

Census of the 84 prepared tensors, by role and ggml type:

```
attn_q.weight       type=10 (Q2_K)  x28  -> NATIVE, zero dequant
attn_k.weight       type=10 (Q2_K)  x28  -> NATIVE, zero dequant
ffn_gate.weight     type=10 (Q2_K)  x28  -> NATIVE, zero dequant
ffn_up.weight       type=10 (Q2_K)  x28  -> NATIVE, zero dequant
attn_v.weight       type=11 (Q3_K)  x28  -> F32 prepared
attn_output.weight  type=11 (Q3_K)  x28  -> F32 prepared
ffn_down.weight     type=11 (Q3_K)  x28  -> F32 prepared
```

84 = 28 x 3, and the 3 are all Q3_K, not Q2_K.

`llama3.2-3b-Q2_K.gguf` is a MIXED-QUANT file. The filename describes only the
majority type. Reading per-tensor types rather than trusting the filename is what
exposed this.

## Why the flag did nothing

```
RAWRXD_Q2K_PRODUCT_DECODE unset : cpuDequantCalls=84
RAWRXD_Q2K_PRODUCT_DECODE=1     : cpuDequantCalls=84
```

Not a dispatch-closure problem. Every Q2_K tensor already reaches
`DispatchGemvQuant`. There is no Q2_K left for the flag to refuse to expand, so
the flag is a correctly-implemented no-op on this model.

## Criteria

```ini
Q2K_SHADER_MISSING=FALSE
Q2K_SHADER=deep2_qgemv.spv            (19296 bytes, compiled 2026-09-24)
Q2K_SHADER_TYPE=10_SUPPORTED          (deep2_qgemv.comp:5,60,188,217)
Q2K_PACKED_WEIGHT_SIZE=84_BYTES
Q2K_NATIVE_GEMV_CALLS=1344
Q2K_NATIVE_GEMV_FAILURES=0
Q2K_NATIVE_GEMV_PARITY=PASS            (byte-identical output, both routes)

Q2K_PRODUCT_CPU_DEQUANT_CALLS=0
Q2K_PRODUCT_F32_PREPARED_BYTES=0
Q2K_PRODUCT_ENSURE_F32_CALLS=0
Q2K_WEIGHT_USES_NEEDING_F32=0

ROOT_CAUSE_CLASS=KERNEL_ABSENT
ROOT_CAUSE_KERNEL=YES      (for Q3_K, not Q2_K)
ROOT_CAUSE_DISPATCH=NO
ROOT_CAUSE_SHADER_BUILD=NO
```

Parity method: same model, same prompt, 24 tokens, both flag states, generated
text compared as exact strings.

```
"Paris, which is also the capital of France. The city of Paris is famous for
 its beautiful gardens, beautiful parks,"
```

## Why the call-site closure was the wrong repair

Four `EnsureF32` call-site groups were flagged as bypasses: `attnNorm`/`ffnNorm`
(:433,:444), QKV (:591,:601,:606), FFN `wGate`/`wUp` (:896,:901).

None of them appear in the prepared census. The norm tensors are F32 and return
early from `EnsureF32` before any preparation. Forcing them through a GEMV
abstraction would have been wrong, exactly as suspected.

Rewiring those sites would not have changed `cpuDequantCalls`, because the
weights that actually get prepared (`attn_v`, `attn_output`, `ffn_down`) are
type 11 and reach `EnsureF32` because no native kernel exists for them.

## Provenance

```
GIT_HEAD          = 9b843bf039f917040d1c7aeae4eaa3aea090870d
EXE_SHA256_PRE    = 527719B3787651FC83ADCFF79E034349F168BFFB80898D064BFA721815C47E06
EXE_SHA256_POST   = 527719B3787651FC83ADCFF79E034349F168BFFB80898D064BFA721815C47E06
HASH_STABLE       = 1
```

## Ledger retraction

```ini
A022_STATUS=RETRACTED
A022_ORIGINAL_CLAIM=Q2K_SHADER_MISSING / Q2K route unusable
A022_ORIGINAL_LOCATION=AUDIT_LEDGER.md:26
A022_CORRECTION=Q2K_IMPLEMENTED_IN_DEEP2_QGEMV
CORRECTION_EVIDENCE=shader source + SPIR-V artifact + loader +
                    type-10 dispatch + runtime parity
A023_UNAFFECTED=1
```

A022 is retracted rather than rewritten so the incorrect historical finding and
the evidence that falsified it both remain on record.

A022 did NOT claim Q3_K lacked a kernel. That is a separate gap and is recorded
as B65, not as a correction to A022, so the two remain distinguishable.

## Related finding: dead Q3_K MASM stub

`rawrxd/src/deep2/sovereign_q3_k_gemv.asm` is 8 lines:

```asm
sovereign_q3_k_gemv_Stub PROC
    xor eax, eax
    ret
sovereign_q3_k_gemv_Stub ENDP
```

It is compiled into the build (`CMakeLists.txt:13253`). `gemv_q3_k_masm`
(`QuantKernelRegistry.cpp:175`) would call `Deep2_Q3_K_GEMV`, which the stub does
not export.

Checked for a live hazard: `gemv_q3_k_masm` appears ONLY at its own definition
site. It is never registered in the GEMV kernel table, and `Deep2_Q3_K_GEMV` is
never referenced from any live path. So this is dead code, not a silent-wrong-
answer bug, and it does not explain any measured result. It should be removed or
implemented; leaving a stub named like a real kernel in the build is a trap for
the next reader.

## B65, not started

```ini
RAWRXD_B65_NATIVE_Q3K_GEMV_001=OPEN

Q3K_BLOCK_ELEMENTS=256            (GGUFLoader.hpp:533)
Q3K_BLOCK_BYTES=110
Q3K_ABSENT_FROM_PACKEDQUANT=1     (Deep2Engine_GpuForward.cpp:83-91)
Q3K_ABSENT_FROM_DISPATCHGEMVQUANT=1 (vulkan_compute.cpp:3375 admits {8,10,12,14})
Q3K_TENSORS_PER_LAYER=3
Q3K_F32_PREPARED_BYTES=4227858432
Q3K_CPU_DEQUANT_CALLS=84

REQUIRED=bit-exact GLSL q3_K dequant + scale unpacking, compiled with
         glslangValidator, with parity measured against the CPU dequant
         reference used by PreparedWeightCache
```

Toolchain corrected: `glslangValidator.exe` IS present at
`C:\VulkanSDK\1.4.357.0\Bin\`. An earlier statement that no shader compiler was
available was wrong.

B65 is not started. Its pass criterion must be `Q3K_PARITY=PASS` before any TPS
claim, and parity requires matching the CPU reference exactly, including the
packed-fp16 scale/min unpacking.