# RAWRXD_B67_Q3K_DOT4_001

## Status: PASS (correctness) — does NOT beat B66

```ini
RAWRXD_B67_Q3K_DOT4_001=PASS
B67_TOKEN_PARITY=B65_EXACT
CPU_DEQUANT_CALLS=0
F32_PREPARED_BYTES=0
Q3K_NATIVE_GEMV_CALLS=2352
Q3K_NATIVE_GEMV_FAILURES=0

B65_BASELINE_TPS=2.01
B66_TPS=6.59
B67_TPS=6.37
B64_FALLBACK_TPS=6.49
PROMOTE_OVER_B66=NO
PROMOTE_OVER_B64=NO
```

## Result across all four

```ini
             cpuDequant  prepared   TPS    correctness
B64             84       4.23 GB   6.49   reference
B65              0       0         2.01   PROVEN (block + token)
B66              0       0         6.59   PROVEN (token parity to B65)
B67              0       0         6.37   PROVEN (token parity to B65)
```

B67 is correct and adds nothing. The dot4 restructuring — four contiguous
elements per lane, collapsing four scale lookups, four hmask selections and
four weight computations into one each — did not improve throughput. B66's
6.59 and B67's 6.37 are within noise of each other and of B64's 6.49.

## What this establishes

The B65 slowdown was **not** per-element metadata cost in the sense B66/B67
assumed. B66 removed the redundant aux unpack and recovered 3.28x. B67 reduced
per-element byte fetches further and recovered nothing.

That localizes the remaining cost elsewhere. The unpack was the whole problem;
everything after it is not the bottleneck. Concretely, the likely remaining
candidates are:

1. **The two barriers per block.** B66 and B67 both serialize on `barrier()`
   inside the block loop. With `blocksPerRow` = 12 for cols 3072, that is 24
   barriers per row per dispatch, each a full workgroup sync.
2. **Shared-memory broadcast contention.** All 256 lanes read `q3kScales4[lid/64*16+is]`
   — only 4 distinct addresses per instruction, so the hardware serializes
   conflicting shared reads. The unpack moved into shared memory but the
   *consumption* is still effectively a 4-way broadcast.
3. **Scalar `getb()` byte extraction.** Both paths still read weights one byte
   at a time through a `w[]` word with shift/mask. A true vectorized load would
   need the byte layout reorganized, which is a shader rewrite, not a tuning
   change.

Point 3 is the same reason `q4k_dot4` is faster for type 12: that shader loads
a **32-bit word** (`w[qsByte >> 2u]`, `deep2_qgemv.comp`) and extracts four
values from it. The Q3_K paths do four separate byte reads. That is the
structural difference left to exploit, and it requires 4-byte alignment
guarantees that the 110-byte block stride does not provide.

## Implementation notes

Branch ordering matters and was initially wrong. The B66 branch condition
(`cols % 256 == 0`) is strictly weaker than B67's (`cols % 1024 == 0`), so B66
shadowed B67 entirely until the order was swapped. The condition is now
documented in place so a future edit does not silently reintroduce it.

```ini
pc.cols % 1024 == 0  -> B67 dot4 sweep   (cols 1024/3072/8192 all qualify)
pc.cols %  256 == 0  -> B66 shared unpack
otherwise            -> B65 per-element  (correct for ragged shapes)
```

Correctness of the dot4 grouping rests on this property: within a 128-weight
half, the scale index, the shift and the hmask selector `m` depend only on
`(n128, j)`, while `l` runs 0..31 contiguously. Because `colBase` is 4-aligned,
four consecutive columns never straddle a 32-element sub-block boundary, so all
four share one scale, one shift and one `m`. Verified from the reference loop
in `dequant_q3_k` (QuantKernelRegistry.cpp:1460-1480).

`q3k_scale16()` is still called only from the cooperative unpack, never per
element, so the DEFECT A packing fix is not duplicated.

## Measured

```ini
EXE_SHA256_PRE  = D4BF8FE657CF84630DF650B79A69ED38F6D33C61B87C9015F22463B05E0B29F6
EXE_SHA256_POST = D4BF8FE657CF84630DF650B79A69ED38F6D33C61B87C9015F22463B05E0B29F6
GIT_HEAD        = 9b843bf039f917040d1c7aeae4eaa3aea090870d

MODEL=llama3.2-3b-Q2_K.gguf   PROMPT="The capital of France is"   TOKENS=24
PREFILL_MS=1451.9   DECODE_MS=3765.2   DECODE_TPS=6.37
NATIVE_CALLS=2352   NATIVE_FAILURES=0   CPU_DEQUANT_LINES=0
```

Token parity, 115 chars, identical to B66 and to the B64 reference:

```
"Paris, which is also the capital of France. The city of Paris is famous for
 its beautiful gardens, beautiful parks,"
```

## Standing conclusion

Three Q3_K native variants are now proven correct: B65 (per-element), B66
(shared unpack), B67 (dot4). All three achieve zero CPU dequantization and zero
F32 preparation. None beats the B64 prepared-F32 path's 6.49 TPS by a margin
that survives noise.

Recommendation: keep the native path (it needs no host F32 residency, which
matters at model sizes where the prepared representation cannot fit) and stop
optimizing it until the load geometry is settled. Further shader micro-tuning
is measuring inside noise.

The honest remaining lever is a real vectorized byte load, which needs the Q3_K
110-byte block layout addressed at word granularity rather than byte granularity
— a structural change to how weights are staged, not to the shader.

```ini
B67_COMMITTED=NO
B67_PUSHED=NO
```