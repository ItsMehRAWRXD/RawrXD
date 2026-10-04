# RAWRXD_KERNEL_LOOM_LIVE_GEMV_BG8_001 — RECEIPT

```
RAWRXD_KERNEL_LOOM_LIVE_GEMV_BG8_001

STATUS                      = BG8_A_AND_B_PROVEN
BG8-A  single GEMV          = PASS (bit-exact, synthetic + real weight)
BG8-B  real weight capture  = PASS (bit-exact on a real GGUF tensor)
BG8-H  reverse registration= PASS (201/201 real tensors, provenance round-trip)
CHECKS_RUN                  = 72
CHECKS_PASS                 = 72
CHECKS_FAIL                 = 0
VERDICT                     = PASS
```

## BG8-B — real model weight, bit-exact

The prior receipt's honest limitation was that Q4_K blocks were
valid-by-construction. That limitation is closed.

```
BG8B_MODEL_LOADED       = G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
BG8B_TENSOR_COUNT       = 201
BG8B_TENSOR_NAME        = blk.0.attn_k.weight
BG8B_SHARD_ID           = 0
BG8B_FILE_OFFSET        = 114787712
BG8B_TOTAL_BYTES        = 294912
BG8B_TENSOR_ROWS        = 256
BG8B_TENSOR_COLS        = 2048
BG8B_SLICE_ROWS         = 32
BG8B_SLICE_BYTES        = 36864
BG8B_SLICE_FNV          = 2324084955527705980
BG8B_COMPILE_EXIT       = 0
BG8B_BINARY_DIGEST      = 2710809886908567002
BG8B_KERNEL_ENTERED     = 1
BG8B_FINITE_OUTPUT      = 1
BG8B_NONFINITE_REFERENCE= 0
BG8B_COMPARISON_COUNT   = 32
BG8B_MAX_ABS_DIFF       = 0.0        BIT-EXACT on real model bytes
BG8B_FALSIFY_MAX_ABS_DIFF = 4.94521144
```

The falsifier runs **on the same real bytes**: a one-sign change still compiles,
still runs, still finite, and diverges by 4.945. Parity is therefore known to
work on the input that actually matters, not only on synthetic input.

A near-miss worth recording: an earlier revision named a check
`BG8B_REAL_WEIGHT_PARITY` while reading `maxAbsDiff` from the *synthetic* trial
inside `certifySourceText`. The name asserted real-weight coverage the
measurement did not provide. Fixed by extracting `certifyCases()` as the single
measurement core, with `certifySourceText` (synthetic) and
`certifySourceTextOn` (real) as thin wrappers over it, so the two paths cannot
diverge. A check whose name overstates what it measured is the same defect as a
hardcoded PASS.

`PolyKernelReceipt::passed()` now also requires `caseCount > 0` and
`!invalidCase`, so a certification with zero inputs can never report PASS.

## BG8-H — the reverse layer is no longer an orphan

Measured before this work:

```
PRODUCTION_CALLERS_OUTSIDE_OWN_TU = 3   (all inside the new files)
LOADMODEL_REGISTRATIONS           = 0
```

`loadModel()` now registers real backing at the real bind site
(`Deep2Engine.cpp` `bindTensor`), after geometry is derived. The registration
logic is exercised here against the real loader:

```
BG8H_MODEL_IDENTITY        = 17210617468870487847   (from real loader facts)
BG8H_REGISTERED            = 201
BG8H_UNCLASSIFIED_ROLE     = 0                     (every real name classified)
BG8H_DIRECTORY_AFTER       = 201                   (no identity collisions)
BG8H_PROBE_NAME_LENGTH     = 19
BG8H_PROBE_LAYER_INDEX     = 0
BG8H_PROBE_ROLE            = 7                     (attn_k)
BG8H_PROBE_COLS            = 2048
BG8H_PROBE_ROWS            = 256
BG8H_NANOADDR_FORM         = CPU_AVX512            (from real CPUID)
```

`BG8H_PROVENANCE_ROUND_TRIP_EXACT` compares shardId, fileOffset, byteLength,
quantType, tensorName and cols against the loader's own `GGUFTensor`, so a
provenance field filled from the wrong tensor would fail.

`modelIdentity` hashes tensor count plus the first three tensors' names, sizes,
offsets and types — not the path string — because the same path can be replaced
with different content and identity must not survive that.

Roles are classified from the real tensor name (`attn_k`, `ffn_down_exps`,
`ssm_in`, …), and the block index is parsed from `blk.N.`. All 201 real
tinyllama tensors classified; none fell through to role 0.

A second off-by-one defect was caught here: the probe hashed
`"blk.0.attn_k.weight"` with a hand-written length of 20 when the literal is 19
characters, so the hash covered the NUL terminator and every lookup missed. The
literal is now carried in a `std::string` and its length comes from `.size()`.

## Reverse layer

```
NANOADDR_CONTAINS_PHYSICAL_ADDRESS = 0     (by construction)
C1_UNKNOWN_IDENTITY_REFUSED        = 1
C2B_BACKING_MATCHES_BINDER_PROVENANCE = 1
C3_DUAL_GPU_REQUIRED_REFUSED_WITHOUT_DEVICE = 1
C3B_SINGLE_DEVICE_STILL_REFUSES_DUAL       = 1
C3C_DUAL_DEVICE_SATISFIES_DUAL             = 1
C8_FORM_FROM_OLDER_GENERATION_IS_STALE     = 1
C5B_GPU_FORM_REFUSES_HOST_SOURCE           = 1
C10B_BROKEN_SOURCE_FAILS_TO_COMPILE        = 1
```

## Emitter scope — narrowed by measurement

| type   | maxAbsDiff vs production | disposition |
|--------|--------------------------|-------------|
| Q4_K   | **0.0** (synthetic and real) | KEPT |
| Q4_0   | 344385.565               | REMOVED |
| Q8_0   | 6978154.28               | REMOVED |
| Q6_K   | 1.17076461e+09          | REMOVED |

```
C12_TYPES_EMITTED_AND_BIT_EXACT = 1
C12_TYPES_REFUSED_WITH_REASON   = 3
C12_TYPES_EMITTED_BUT_WRONG     = 0
```

## Promotion gate

`modelResidual()` is gone. `mayWiden` accepts only `MeasuredResidual`.

```
C13B_UNMEASURED_RESIDUAL_RECOGNISED      = 1
C13C_UNMEASURED_CANNOT_WIDEN             = 1
C13D_WORSE_RESIDUAL_CANNOT_WIDEN         = 1
C13F_UNKNOWN_OWNERSHIP_FORBIDS_PROMOTION = 1
C13H_RECONSTRUCTED_WEIGHT_BREAKS_SPACELESS = 1
C13J_EXECUTABLE_HASH_TRACKS_COMPILER_FLAGS = 1
C13K_GENOME_FINGERPRINT_DISTINCT_FROM_EXECUTABLE_HASH = 1
```

## Traffic contract

```
logical_weight_bytes            = 400000000000   (400 GB, UNBOUNDED)
physical_fresh_bytes_per_token  = 8000000000     (8 GB)
sustained_bandwidth             = 1200000000000  (1.2 TB/s)
target_tps                      = 150
bandwidth_ceiling_tps           = 150            (matches target exactly)
min_traffic_collapse            = 50x
at 4 GB/token  -> ceiling 300 TPS
at 400 GB/token-> verdict 0                      (full re-read rejected)
```

## Open blockers — measured, not assumed

```
DEEP2ENGINE_COMPILABLE_IN_TREE   = 0   vulkan_compute.h:7 includes <vulkan/vulkan.h>
                                       unguarded; no Vulkan SDK present. PRE-EXISTING,
                                       not caused by this work. Blocks compiling the
                                       file the BG8-H wiring lives in.
REVERSEINTEGRATION_STUB          = 1   ReverseIntegration.hpp: attach/validate/activate
                                       all `return true`, zero callers, zero measurement
VULKAN_FORM_SOURCE_EMISSION      = UNBUILT   refuses; will not emit host text as a shader
AVX_INTRINSIC_BODY_EMITTED       = 0         portable body under an ISA name; measured
OWNERSHIP_CENSUS_FOR_THIS_PATH   = NOT_DONE  no production callsite enumerated yet
BG8-C_WINNER_PERSISTENCE         = NOT_STARTED
BG8-D_BRAIDING                   = NOT_STARTED
BG8-E_NORM_PLUS_GEMV             = NOT_STARTED
BG8-F_NORM_PLUS_QKV              = NOT_STARTED
BG8-G_PRODUCTION_SUBSTITUTION    = NOT_STARTED
TRAFFIC_CONTRACT_ON_REAL_MODEL   = NOT_STARTED  arithmetic proven; not measured on 400 GB
```

## BG8 ladder position

```
BG8-A  single GEMV .......................... PASS
BG8-B  real model weight capture ............ PASS
BG8-C  multiple generated implementations ... NOT_STARTED
BG8-D  winner persistence + replay .......... NOT_STARTED
BG8-E  adjacent GEMV + GEMV braid ........... NOT_STARTED
BG8-F  Norm + GEMV .......................... NOT_STARTED
BG8-G  Norm + QKV ........................... NOT_STARTED
BG8-H  production substitution .............. NOT_STARTED
```


## What is measured

Materialization is real end to end. Nothing is declared.

```
SOURCE_GENERATED            = 1
SOURCE_DIGEST               = 8251696207617171763   (FNV-1a 64 over emitted bytes)
SOURCE_BYTES                = 4243
COMPILE_EXIT                = 0                     (real MSVC 14.44 cl.exe)
BINARY_DIGEST               = 10195525538553487601  (FNV-1a 64 over the loaded DLL)
EXECUTION_COUNT             = 8
KERNEL_ENTERED              = 1                     (rxd_poly_gemv really called)
FINITE_OUTPUT               = 1
COMPARISON_COUNT            = 512
MAX_ABS_DIFF                = 0.0                   BIT-EXACT vs production
RMS_DIFF                    = 0.0
NONFINITE_REFERENCE         = 0
BEACON_GENERATION           = 4
HARDWARE_FINGERPRINT        = 16056160626730960708
```

Reference is `QuantKernelRegistry::GetGEMV(12)` — the production kernel, not a
local reimplementation.

## The falsification that matters

```
C11_SABOTAGED_SOURCE_DIGEST = 5156866984962076818  (differs from honest)
C11_COMPILE_EXIT            = 0                    (still compiles)
C11_KERNEL_ENTERED          = 1                    (still runs)
C11_FINITE_OUTPUT           = 1                    (still finite)
C11_MAX_ABS_DIFF            = 5.35229492           (parity DISAGREES)
HONEST_MAX_ABS_DIFF         = 0.0
```

Parity separates 0.0 from 5.35 on the same pipeline. The measurement can
disagree with the thing it measures, which is the property that makes PASS mean
anything.

## Emitter scope — narrowed by measurement

The first version emitted four quant types. The per-type differential measured
three of them to be wrong:

| type   | maxAbsDiff vs production | disposition |
|--------|--------------------------|-------------|
| Q4_K   | **0.0**                  | KEPT |
| Q4_0   | 344385.565               | REMOVED |
| Q8_0   | 6978154.28               | REMOVED |
| Q6_K   | 1.17076461e+09          | REMOVED |

```
C12_TYPES_EMITTED_AND_BIT_EXACT   = 1
C12_TYPES_REFUSED_WITH_REASON     = 3
C12_TYPES_EMITTED_BUT_WRONG       = 0
```

The three removed emitters were **deleted**, not disabled, following
`RAWRXD_B69_DEAD_Q3K_MASM_REMOVED_001`. They now refuse with the measured
reason. An emitter that exists but is wrong reads as coverage; a refusal does
not.

An earlier revision of this gate reported `48/48 PASS` while those three kernels
were wrong, because the check was `verified >= 1`. The aggregate verdict hid
three broken kernels. The check is now `wrong == 0`.

## Three real defects the gate found in code written this session

1. **Intent/graph quant mismatch was silently answered from the graph.**
   `generatePolyKernelSource` read `quantType` from the graph while the caller
   passed it in the intent, so a disagreeing pair emitted the graph's kernel.
   Found by C10. Now refused as `INTENT_GRAPH_QUANT_MISMATCH`.

2. **Q4_K layout was reconstructed, not read.** The first emitter used the
   generic ggml per-element `get_scale_min_k4()` mapping. This repo implements
   `unpack_q4_k_scales()` + 32/32 nibble grouping, which is a different layout.
   Measured divergence `maxAbsDiff = 590` on valid tensors. The emitter is now
   transcribed from `QuantKernelRegistry.cpp` and is bit-exact.

3. **Random bytes are not a valid quantized tensor.** Q4_K stores `d`/`dmin` as
   raw fp16 in its first four bytes, so random bytes decode to Inf/NaN and the
   *reference* produced non-finite values: `NONFINITE_REFERENCE=32`. That was a
   harness defect which would have made parity meaningless. `fillValidQuantizedRow`
   now writes finite fp16 scales and randomizes only payload bytes.

Two further instrument defects were found and fixed before the above could be
measured at all: the child compiler inherited no `INCLUDE`/`LIB`
(`fatal error C1034`), and the MSVC lib path was derived one directory too high
(`LNK1104: cannot open file 'LIBCMT.lib'`). Both are now discovered from the
compiler's own location and the installed SDK, and reported as
`DISCOVER_TOOLCHAIN` rather than misreported as `COMPILE`.

## Promotion gate

`modelResidual()` is gone. `mayWiden` takes only `MeasuredResidual`, which has
no field a synthetic estimate could enter through.

```
C13B_UNMEASURED_RESIDUAL_RECOGNISED      = 1   (empty residual is not "measured")
C13C_UNMEASURED_CANNOT_WIDEN             = 1
C13D_WORSE_RESIDUAL_CANNOT_WIDEN         = 1
C13E_BETTER_RESIDUAL_WIDENS              = 1
C13F_UNKNOWN_OWNERSHIP_FORBIDS_PROMOTION = 1
C13H_RECONSTRUCTED_WEIGHT_BREAKS_SPACELESS = 1
C13J_EXECUTABLE_HASH_TRACKS_COMPILER_FLAGS = 1
C13K_GENOME_FINGERPRINT_DISTINCT_FROM_EXECUTABLE_HASH = 1
```

`ExecutableIdentity::hash()` covers genome + materializer + compiler id + flags
+ target ISA + generated source hash + binary hash. Changing only the flags
changes the hash, so two different binaries from one genome are not the same
kernel.

## Traffic contract

The reversal is **logical scope > physical realization**, not "400 GB shrinks".

```
logical_weight_bytes            = 400000000000   (400 GB, UNBOUNDED)
physical_fresh_bytes_per_token  = 8000000000     (8 GB)
physical_budget_bytes_per_token = 8000000000
sustained_bandwidth             = 1200000000000  (1.2 TB/s)
target_tps                      = 150

bandwidth_ceiling_tps           = 150            (matches target exactly)
min_traffic_collapse            = 50x
logical_gt_physical             = 1
within_budget                   = 1
verdict                         = 1

at 4 GB/token  -> ceiling 300 TPS                (halving doubles it)
at 400 GB/token-> verdict 0                      (full re-read rejected)
```

Derived only; no field is assignable to a favourable value. A full re-read is
rejected at 150 TPS, which is the check that keeps the contract binding.

## Reverse layer

```
NANOADDR_CONTAINS_PHYSICAL_ADDRESS = 0     (by construction)
C1_UNKNOWN_IDENTITY_REFUSED        = 1
C2B_BACKING_MATCHES_BINDER_PROVENANCE = 1   (shard/fileOffset/bytes/quant/shape)
C3_DUAL_GPU_REQUIRED_REFUSED_WITHOUT_DEVICE = 1
C3B_SINGLE_DEVICE_STILL_REFUSES_DUAL       = 1
C3C_DUAL_DEVICE_SATISFIES_DUAL             = 1
C8_FORM_FROM_OLDER_GENERATION_IS_STALE     = 1
C5B_GPU_FORM_REFUSES_HOST_SOURCE           = 1
C10B_BROKEN_SOURCE_FAILS_TO_COMPILE        = 1
```

No device was published for the certification run, so the heartbeat reported
zero devices and every Vulkan form was unreachable. The C3B/C3C pair proves the
refusal was caused by reality rather than hard-coded: publishing a second device
changed the answer.

## Source identity

```
src/deep2/ReverseLayer.hpp        OUTSIDE->INSIDE boundary, BackingDirectory, Heartbeat
src/deep2/ReverseLayer.cpp
src/deep2/HeartbeatPublisher.cpp  INSIDE->OUTSIDE, facts only, registered devices
src/deep2/PolyKernelGenerator.hpp source emission + receipt-driven certification
src/deep2/PolyKernelGenerator.cpp
src/deep2/LoomPromotion.hpp       MeasuredResidual, mayWiden, ExecutableIdentity, TrafficContract
src/deep2/LoomPromotion.cpp
src/deep2/QuantKernelRegistry.hpp +4 lines: read-only cpuFeatures() accessor
tools/polykernel_cert.cpp         53 checks incl. 3 falsifications
tools/build_polykernel_cert.bat   assembles 7 real MASM kernels, links real registry
```

Cited prior state verified by hash, unchanged by this work:

```
rawrxd/tools/loom/KernelLoomGenerator.cpp
  CD8E07106B72BFD3774BC186C528707B8B96E7A9FEF3490312991A52B3ADAC1E
kernel_loom_gen.exe
  BFF17DCC1C99278FCDB972DBCE97BCEB581035A8D845C92CED6E7D287F88AB1B
```

`Beaconism.hpp` is a causal EVENT LOG, not a residency/hardware state beacon;
complementary, not a substitute. `ReverseIntegration.hpp` is a 10-line stub
whose `attach`/`validate`/`activate` all `return true` with zero callers — the
self-certifying shape this repo has retracted three times. Reported, not built
on.
