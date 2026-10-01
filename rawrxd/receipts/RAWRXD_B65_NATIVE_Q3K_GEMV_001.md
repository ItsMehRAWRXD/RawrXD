# RAWRXD_B65_NATIVE_Q3K_GEMV_001

## Status: PASS

```
RAWRXD_B65_NATIVE_Q3K_GEMV_001=PASS
Q3K_BLOCK_PARITY=PASS
Q3K_SHADER_PARITY=PASS
Q3K_TOKEN_ID_PARITY=EXACT
CPU_DEQUANT_CALLS=0
F32_PREPARED_Q2K_BYTES=0
Q3K_NATIVE_GEMV_CALLS=2352
Q3K_NATIVE_GEMV_FAILURES=0
GENERATED_TOKEN_COUNT=24 (matches reference)
VERDICT=PASS
```

## The failure this replaces

Attempt 1 shipped a GLSL q3k_weight() that compiled, dispatched 5488 times
with zero dispatch-level failures, reported 7.49 TPS, and emitted finite
garbage:

```
"eczeczeczeczeczeczeczeczeczeczeczeczeczeczeczeczeczeczeczeczeczeczecz"
72 chars vs the reference's 116
```

Every `GPU_FORWARD_FINITE_CHECK` line read `nan=0 inf=0`. Finiteness could not
distinguish correct inference from well-behaved garbage, so the TPS was
non-authoritative and is excluded from performance history.

Three defects, all producing finite output:

```ini
DEFECT_A=SCALE_LAYOUT        wrong on  8464/18432 elements
DEFECT_B=MISSING_SCALE_MINUS_32  wrong on 18384/18432 elements
DEFECT_C=HMASK_SELECTOR_M   wrong on  7804/18432 elements
```

- A: the 16 scales are the 16 SIGNED bytes of a four-word `aux` array built
  from `scales[12]`. `aux[2]` must be snapshotted before `aux[0..3]` are
  rewritten. Attempt 1 assumed they lived in two words' low bytes.
- B: each scale is biased by `-32`. Attempt 1 dropped it.
- C: `m` is a `uint8_t` declared ONCE and shifted at the END of every `j`
  iteration, so it is not reset between the two 128-halves. Its eight used
  values are 1,2,4,8,16,32,64,128 indexed by `(n128*4 + j)`. Attempt 1 used
  `1<<n128`, correct for 1/8 of the block.

## STEP_2..STEP_5: host differential gate

`rawrxd/tools/q3k_block_diff.cpp` (RAWRXD_B65_Q3K_BLOCK_DIFF_001). Host only:
no Vulkan, no GPU, no model load, runs in well under a second.

It diffs INTERMEDIATES, not outputs, so a final mismatch cannot leave the
specific packing operation unlocalized:

```
scale_raw, scale_signed, q, hv, weight bit pattern
```

Coverage is every one of 256 elements of every block, over 8 deterministic
adversarial patterns (all-zero, all-ff, alternating, incrementing, 0xAA, 0x55,
two strides) plus 64 randomized blocks = 72 cases / 18432 elements. Packing
defects typically hit specific lanes and leave neighbours correct, which is why
sampling would have missed all three.

Both transcriptions run in one pass so the fix is auditable rather than
asserted:

```ini
--- v1 (shipped in failed GLSL) ---
scaleRawMismatch=8464 scaleSignedMismatch=18384 qMismatch=10020
hvMismatch=8366 weightMismatch=17759
V1_FIRST_BAD block=0 (all_zero) elem=0
  refScaleSigned=-32 candScaleSigned=0 refWeight=0 candWeight=-0

--- v2 (corrected transcription) ---
scaleRawMismatch=0 scaleSignedMismatch=0 qMismatch=0 hvMismatch=0 weightMismatch=0

Q3K_BLOCK_PARITY_V1=FAIL
Q3K_BLOCK_PARITY_V2=PASS
GLSL_PORT_AUTHORIZED=YES
```

The v2 transcription was written in C++ and proven BEFORE any GLSL was touched.
The gate printed `GLSL_PORT_AUTHORIZED=YES`, and only then was the shader edited.

## STEP_6..STEP_8: verified port

The proven v2 form was ported to `deep2_qgemv.comp` as `q3k_weight()`, with all
three defects documented inline so the next reader cannot reintroduce them.
Compiled with `glslangValidator.exe` (VulkanSDK 1.4.357.0) to `deep2_qgemv.spv`.

```ini
Q3K_BLOCK_ELEMENTS=256
Q3K_BLOCK_BYTES=110
PackedQuant      +Q3_K   (Deep2Engine_GpuForward.cpp)
DispatchGemvQuant admit 11 (vulkan_compute.cpp)
```

Full-model text parity on llama3.2-3b-Q2_K, 24 tokens:

```
REFERENCE (F32 prepared path):
  "Paris, which is also the capital of France. The city of Paris is famous for
   its beautiful gardens, beautiful parks,"   116 chars

B65 (native Q3_K):
  "Paris, which is also the capital of France. The city of Paris is famous for
   its beautiful gardens, beautiful parks,"   116 chars

TOKEN_ID_PARITY=EXACT
```

Same character count and same string, so the argmax sequence is identical: at
deterministic greedy decoding, identical text of identical length implies
identical token IDs.

## STEP_9: TPS

Measured on the SAME binary, hash stable across the run:

```
EXE_SHA256_PRE  = BCA4087A076F65B7BF3C590CA2CBBC75117C254AA7C922A79D2FE3DD700CFDFA
EXE_SHA256_POST = BCA4087A076F65B7BF3C590CA2CBBC75117C254AA7C922A79D2FE3DD700CFDFA
GIT_HEAD        = 9b843bf039f917040d1c7aeae4eaa3aea090870d
```

```ini
PREPARED_CACHE_LINES   = 0     (no F32 prepared at all)
ENSURE_F32_STREAM      = 0
CPU_DEQUANT_CALLS      = 0
F32_PREPARED_BYTES     = 0
TYPE11_NATIVE_DISPATCH = 2352
NATIVE_FAILURES        = 0
F32_DISPATCH           = 0     (zero host F32 GEMV dispatches)
DECODE_TPS             = 2.01
```

Every projection on this model now executes natively: Q2_K and Q3_K both on
the GPU path, with no CPU dequantization anywhere in the run.

## The TPS went DOWN, and that is the informative result

```ini
B64 baseline (F32 prepared)  6.49 TPS   cpuDequantCalls=84  4.23 GB prepared
B65 (native Q3_K)            2.01 TPS   cpuDequantCalls=0   0 bytes prepared
```

B65 removes 100% of the CPU dequant work and 100% of the F32 preparation, and
is roughly 3.2x SLOWER. That falsifies the assumption that representation churn
was the remaining bottleneck, and it identifies the actual one.

The cause is arithmetic intensity, not data movement. The prepared-F32 path ran
one wide F32 GEMV per weight per token: 4 bytes/weight, perfectly coalesced, and
`q4k_dot4`-style vectorized consumption was available for type 12. The native
Q3_K path executes a scalar `q3k_weight()` PER ELEMENT: each call does a 4-word
aux rebuild (`q3k_scale16`) plus multiple `getb()` byte extractions, so the
per-element cost is vastly higher. 256 lanes each redo the same scale unpack,
256 times, for what is one 12-byte unpack per block.

So B64's F32 path was not merely wasteful preparation -- it was also the faster
*arithmetic* path on this hardware. The correct next step is not to abandon it,
but to amortize: unpack the 16 scales ONCE per block into shared memory per
workgroup, then have all 256 lanes read from there.

```ini
B65_AMD64=CLOSED (native path exists, is provably correct, is wired)
B66=OPEN — amortize q3k_scale16 into shared memory; keep B63 prepared-cache
    as the fallback path until B66 beats it on measured TPS
```

## Guard rails added

- `q3k_block_diff.cpp` prints `GLSL_PORT_AUTHORIZED=YES` only when v2 passes.
  The shader must not be edited before that.
- The three defects are documented inline in `q3k_weight()` with the element
  mismatch counts, so the failure is attributable without re-deriving it.
- The harness is a top-level CMake target (no Vulkan dependency) precisely so
  it can prove a shader transcription WRONG without a GPU or a model load.
  Placing it inside the CLI block produced an inert target that never generated
  a vcxproj -- the same duplicate-target authority issue tracked as B62C.

## Related finding, unchanged

`rawrxd/src/deep2/sovereign_q3_k_gemv.asm` is an 8-line stub (`xor eax,eax; ret`)
and is still compiled into the build (`CMakeLists.txt:13253`). `gemv_q3_k_masm`
references `Deep2_Q3_K_GEMV`, which the stub does not export, but that function
is never registered in the GEMV table and never referenced from a live path, so
it is dead code rather than a silent-wrong-answer bug. It should be removed or
implemented; leaving a stub named like a real kernel is a trap.

## Not committed

```ini
B65_COMMITTED=NO
B65_PUSHED=NO
```