# RAWRXD_B66_Q3K_SHARED_UNPACK_001

## Status: PASS (correctness) — does NOT promote over B64

```ini
RAWRXD_B66_Q3K_SHARED_UNPACK_001=PASS
B66_BLOCK_PARITY=B65_EXACT
B66_TOKEN_PARITY=B65_EXACT
CPU_DEQUANT_CALLS=0
F32_PREPARED_BYTES=0
Q3K_NATIVE_GEMV_CALLS=2352
Q3K_NATIVE_GEMV_FAILURES=0

B65_BASELINE_TPS=2.01
B66_TPS=6.59
B64_FALLBACK_TPS=6.49
B66_PROMOTE_OVER_B64=NO   (6.59 vs 6.49 is within run-to-run noise)
```

## Preregistered gates, evaluated as written

```ini
B66_ACCEPT_CORRECTNESS   = exact block/token parity   -> MET
B66_ACCEPT_PERFORMANCE  = TPS > B65 (2.01)           -> MET (6.59)
B66_PROMOTE_OVER_B64    = TPS > 6.49 under identical -> NOT MET
```

The distinction matters and is deliberate. B66 is a successful optimization
experiment: 2.01 -> 6.59 TPS, a 3.28x gain, at zero CPU dequant and zero F32
preparation. It is **not** the production winner, because the prepared-F32 path
(B64) still measures marginally ahead. Routing must not change on this evidence.

## The experiment

B65 proved that eliminating CPU dequant and F32 preparation is *insufficient*.
It was ~3.2x slower than the prepared path despite doing strictly less work,
which implicated per-element metadata cost: 256 lanes each rebuilding the same
four aux words and decoding the same scale for every element.

B66 amortizes that. One lane unpacks the block's 16 decoded scales and `d` into
shared memory once per block; all 256 lanes then read from there.

```text
B65  per lane, per element:
        unpack aux -> decode scale -> extract hmask -> extract q -> weight

B66  per block, once:
        one cooperative aux unpack -> scale[16] + d in shared memory
        barrier
        256 lanes consume shared metadata
```

The quantization math is unchanged. `q3k_weight_shared()` uses the identical
index expressions as B65's `q3k_weight()`; only the source of the decoded scale
and `d` changed. That is what keeps B65 usable as a parity oracle.

## Safety guard added

The fast path maps one 256-element block onto exactly 256 lanes, which is only
valid when there is no ragged trailing block. It is therefore guarded on
`(pc.cols & 255u) == 0u`; ragged Q3_K shapes fall through to the per-element
path, which handles them correctly.

Verified that every Q3_K tensor observed takes the fast path:

```ini
Q3_K_TENSOR_GEOMETRY  rows=1024 cols=3072  x784
                      rows=3072 cols=3072  x784
                      rows=3072 cols=8192  x784
3072 % 256 = 0    8192 % 256 = 0    1024 % 256 = 0
GPU_GEMV_GEOMETRY_FAIL count = 0
```

A ragged shape would have read past the activation buffer. The guard makes that
unreachable rather than merely unlikely.

## Measured

```ini
EXE_SHA256_PRE  = 6FC1E0F4337228370FDBFD4786C50A454E4F7745A2FE109D34C710882E613672
EXE_SHA256_POST = 6FC1E0F4337228370FDBFD4786C50A454E4F7745A2FE109D34C710882E613672
GIT_HEAD        = 9b843bf039f917040d1c7aeae4eaa3aea090870d
```

```ini
MODEL          = llama3.2-3b-Q2_K.gguf
PROMPT         = "The capital of France is"
TOKENS         = 24
PREFILL_MS     = 1441.2
DECODE_MS      = 3642.1
DECODE_TPS     = 6.59
CPU_DEQUANT    = 0
PREPARED_BYTES = 0
NATIVE_CALLS   = 2352
NATIVE_FAILURES= 0
```

Token parity against the B65 oracle, both 115 characters, identical string:

```
"Paris, which is also the capital of France. The city of Paris is famous for
 its beautiful gardens, beautiful parks,"
```

## Result across the three gates

```ini
             cpuDequant   prepared    TPS     correctness
B64            84       4.23 GB     6.49    reference
B65             0       0           2.01    PROVEN (block + token)
B66             0       0           6.59    PROVEN (token parity to B65)
```

B66 closes the gap on B64's performance while keeping B65's correctness and its
zero-preparation property. It does not yet beat it. The remaining ~1.5% is
inside run-to-run noise for this workload, so the honest statement is that B64
and B66 are currently indistinguishable on speed.

## Recommended next step

Do not change routing. Measure both paths several times under identical
conditions before concluding anything from a 1.5% delta. If B66 holds equal,
prefer it: it has no host F32 residency requirement, which is a real advantage
at model sizes where the prepared representation cannot fit.

If a decisive gap is wanted, the next real lever is `q4k_dot4`-style vectorized
consumption (four contiguous elements per lane, as type 12 already uses at
`deep2_qgemv.comp`), which addresses byte-extraction count rather than unpack
count. B66 removed the unpack; it did not reduce per-element byte reads.

## Build note

The first B66 build failed on `rawrxd_math_masm.asm` (`undefined symbol :
scale_probe`), from a concurrent session's temporary instrumentation, not from
this work. Waited for that file to hold still for 60s and rebuilt clean.

```ini
B62C_RECURRENCE_COUNT>=3
DUPLICATE_CMAKE_AUTHORITY=CONFIRMED
INERT_TARGET_BLOCKS=CONFIRMED
```