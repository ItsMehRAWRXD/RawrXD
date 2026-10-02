# RAWRXD_Q6K_LIVE_BLOCK_TRACE_001 / RAWRXD_FP16_SUBNORMAL_001

Status: **root cause FOUND and FIXED across 7 production files. Two prior
conclusions RETRACTED.**
Date: 2026-10-01
Model: `F:/~dev/qwen2.5-coder-1.5b-base.gguf`

## First difference

```ini
RAWRXD_Q6K_LIVE_BLOCK_TRACE_001

SAME_BASE=YES
SAME_QL_BYTE=YES
SAME_QH_BYTE=YES
SAME_SCALE_BYTE=YES
SAME_D_BITS=YES
SAME_D_FP32=NO          <- before the fix
SAME_Q6_VALUE=YES
SAME_ELEMENT0_RESULT=NO
FIRST_DIFFERENCE=D_FP32
Q_MATCH=1
D_X_SCALE_MATCH=0
```

`D_BITS` agrees and `D_FP32` does not. Every quantisation field — base pointer,
`ql`, `qh`, `scales`, the `d` bit pattern, the extracted 6-bit value `q`, the
low nibble, the 2-bit field — is identical between the two paths. The
disagreement is entirely in the **fp16→fp32 conversion of the `d` super-scale**.

That is the signature the checkpoint reserved for a conversion-path defect, and
it is reached with `Q_MATCH=1`: the quant extraction is innocent.

## Root cause

`rawrxd::FP16ToFP32` (`src/gguf_loader.cpp`) normalises subnormals by shifting
the mantissa left `e` bits, then emits fp32 exponent `127 - 15 - e`.

After `e` shifts the value is `(m/1024) * 2^(-14 - e)`, so the correct exponent
field is **`127 - 14 - e`**. The committed expression was one too small, so every
fp16 subnormal decoded at **exactly half** its true value.

```ini
Q6_K_FIRST_BAD_BLOCK  = 0
Q6_K_FIRST_BAD_ELEMENT= 0
BLOCK_d_RAW           = 0x00C6      exponent field 0 -> subnormal
LOADER_VALUE          = 5.90085983e-06
TRUE_VALUE            = 1.18017197e-05
RATIO                 = 0.5
```

Exhaustive over all 65536 fp16 bit patterns:

```ini
SUBNORMALS_TESTED=2046   SUBNORMALS_WRONG=2046   WORST_REL=0.5   FRACTION_WRONG=1.0
NORMALS_TESTED=61440    NORMALS_WRONG=0         WORST_REL=0
```

The normal path was already perfect. That is why this survived review: a scale
that happens to be normal decodes correctly, so any test built from normal
scales cannot see the defect.

## It was not one copy, and the first search for it was too narrow

The trace instrumented `gguf_loader.cpp`. A census of every fp16 conversion in
the tree found **eleven implementations across seven files, in five distinct
code shapes — and five of them were wrong.**

The first census searched for the literal expression `127 - 15 - e` and found
three defective copies. That search was a *text* search for one known-bad
spelling, and it could only ever find copies written that way. Widening it to
"any routine that normalises a subnormal mantissa" found two more:

| Variant | File | Subnormals | Normals | Ratio | Disposition |
|---|---|---|---|---|---|
| V1 | `src/gguf_loader.cpp` | 2046/2046 wrong | ok | 0.5 | **fixed** |
| V2 | `src/deep2/k_quant_gemv_avx512.h` | 2046/2046 wrong | ok | 0.5 | **fixed** |
| V3 | `src/core/kquant_dequantize_q4k.cpp` | 1022/2046 wrong | ok | 1 … 2.62e5 | **fixed** |
| V5 | `src/core/dml_asm_impl.cpp` + `dml_asm_fallback.cpp` | 1022/2046 wrong | ok | 1 … 512 | **fixed** |
| V7 | `src/core/aperture_q{4,8}_0_avx512_intrinsics.cpp` | ok | **28672/61442 wrong** | — | **fixed** |
| V4 | `src/core/runtime_symbol_bridge.cpp` | ok | ok | 1 | exonerated, untouched |
| V6 | `src/core/aperture_q4_0_reference.cpp` | ok | ok | 1 | exonerated, untouched |
| V8 | `src/core/gguf_dml_bridge.cpp` | ok | ok | 1 | exonerated, untouched |
| test | `tools/q4k_gemv_parity.cpp` | 2046/2046 wrong | ok | 0.5 | fixed |
| test | `verify_registry_q4k.cpp` | 2046/2046 wrong | ok | 0.5 | fixed |
| test | `tools/q3k_block_diff.cpp` | ok | ok | 1 | exonerated, untouched |

Three distinct failure shapes, none a variant of the others:

- **V1/V2** — correct exponent off by one: `127 - 15 - e` instead of `127 - 14 - e`.
  A clean factor of 2.
- **V3/V5** — the shift count is destroyed. V3 seeds `exp = 1` and then
  *subtracts*; V5 accumulates into `exp` and then resets it with `exp = 0u`.
  Neither is a constant factor: V3's error reaches 2.6e5×, V5's 512×.
- **V7** — the subnormal path is fine and the **normal** path is broken:
  `(float)(1 << (exponent - 15))` is an *integer* shift, which is undefined
  behaviour for every exponent below 15 and cannot express a fractional power
  of two at all. 46.7% of all normal fp16 values decode wrong — every value
  below 1.0. This is a larger defect than the one the investigation was looking
  for, in a different file, on a different code path.

Repairing only the copy the trace happened to instrument would have left the
weight loader and the GEMV kernel disagreeing with each other by 2× — strictly
worse than the original state.

```ini
A_TEXT_SEARCH_FOR_ONE_KNOWN_BAD_SPELLING_ONLY_FINDS_COPIES_WRITTEN_LIKE_THAT
```

## Impact on shipped weights

```ini
TYPE     TENSORS   BLOCKS        FP16_FIELDS   SUBNORMAL   FRACTION
Q6_K     29        1685760       1685760       1684835     0.999451
Q4_K     168       4343808       8687616       49847       0.005738

TOTAL_FP16_FIELDS=10373376
WEIGHT_FIELDS_MATERIALLY_WRONG_BEFORE=1734682
WORST_SINGLE_TENSOR=token_embd.weight subnormal_fields=911614
```

**99.945% of every Q6_K super-block scale in this model was an fp16 subnormal,
and therefore every Q6_K weight the inference path materialised was being
decoded at half its true value.** This is a much larger corruption than the
Q6_K surface it was found on: the same conversion feeds Q4_K, Q5_K, Q8_0,
Q2_K and Q3_K, and 49847 Q4_K fields were equally affected.

## End-to-end consequence on real weights

The census proves the conversion is correct; the impact census proves 1.73M scale
fields were subnormal. Neither says what happened to the numbers the model
multiplies with. Decoding real rows through the production path
(`ToFloat32Rows` → `DequantQ6_K`/`DequantQ4_K`) and comparing against an
independent decode of the same bytes:

```ini
; defect present
Q6_K_ELEMENTS=9502720     Q6_K_DIFFERING=9229521   FRACTION=0.971250442
Q6_K_MAX_REL=0.5         Q6_K_COSINE=0.999745881881
Q4_K_ELEMENTS=23166976   Q4_K_DIFFERING=609489    FRACTION=0.0263085264
Q4_K_MAX_REL=1.43294334e+28   Q4_K_COSINE=0.996830029327

; defect repaired
Q6_K_DIFFERING=0   Q6_K_MAX_REL=0   Q6_K_COSINE=1.000000000000   Q6_K_VERDICT=EXACT
Q4_K_DIFFERING=0   Q4_K_MAX_REL=0   Q4_K_COSINE=1.000000000000   Q4_K_VERDICT=EXACT
```

**97.1% of decoded Q6_K weights and 2.6% of decoded Q4_K weights in this model
were wrong before the repair.** The Q4_K `max_rel` of 1.4e28 is the tell: `d`
and `dmin` are separate fp16 fields, so when one is subnormal and the other is
not they were scaled by *different* factors. That is why the corruption was not
even a uniform 2× and read as "scrambled" rather than "halved".

## The gate could not have caught this

The most consequential finding is about the certificate, not the decoder.

`real_q6k_gemv_parity.cpp` derives its verdict from three comparisons:
`rel` and `cos` compare `GemvQ6KDispatch` against `GemvQ6K`, and `refRowMax`
compares `GemvQ6KDispatch` against `gguf_loader::ToFloat32`. **All three compare
components that route through one of the two defective conversions.** With the
defect present the two paths are wrong *identically*:

```ini
; defect reinstated, gate as previously written
Q6_WORST_REL_MAX_DIFF=0        <- bit identical
Q6_WORST_COSINE=1.000000000000 <- perfect
GATE_STATUS=PASS               <- while every Q6_K weight was halved
```

The only component that disagreed was `RefDotQ6K`, the one that decodes fp16
arithmetically and shares no code with either production path — and it was a
`printf` for the first tensor, not a gate condition.

Fixed: the independent reference is now a per-tensor, per-row gate condition.

```ini
; defect reinstated, gate strengthened
Q8_TENSORS_PASS=0    Q8_TENSORS_FAIL=29
Q6_WORST_INDEPENDENT_REF_ROW=0.680264923
GATE_STATUS=FAIL

; defect repaired, gate strengthened
Q8_TENSORS_PASS=29   Q8_TENSORS_FAIL=0
Q6_WORST_REL_MAX_DIFF=0
Q6_WORST_COSINE=1.000000000000
Q6_WORST_INDEPENDENT_REF_ROW=6.62673986e-06
Q10_NEGATIVE_CONTROL=DEFECT_DETECTED
GATE_STATUS=PASS
```

Falsification was run in both directions. The repaired source was restored and
verified byte-identical (SHA256 `367D7103…3490A` loader, `EC3183E3…BBB831`
kernel) after each probe.

## Retractions

**1. `SWEEP_REL_ERROR=0.605 -> geometry/stride` is RETRACTED.**
The 0.605 was this fp16 subnormal defect, not geometry. With the conversion
repaired the sweep's independent per-row disagreement is `6.6e-06`.

**2. `Q6_K_LIVE_BLOCK_DECODE = FAIL` is RETRACTED.**
Both decoders are correct. `DIRECT_DECODE[i] == TOFLOAT32[i]` on all 13 traced
elements, field for field, including the addresses actually dereferenced.

## Four defects found in the measurement before the defect in the subject

Recording these because each one produced a confident, specific, wrong answer:

1. **The trace hook fired for element 0 of every block** (`SINK_RECORDS=29171712`
   instead of 1) and reported the *last* block decoded as a `BASE_POINTER`
   disagreement — an aliasing defect that did not exist, pointing the whole
   investigation at the wrong operator. Fixed by pinning the block.
2. **The direct-path harness omitted the half-block advance** (`ql += 64`), giving
   `FIRST_DIFFERENCE=QL_OFFSET` at exactly element 128 and nowhere earlier.
3. **The hook indexed `out[n + l + r*32]`** while `out` is a moving pointer,
   reporting `TOFLOAT_result0=0` for every element ≥128 — every input and every
   intermediate agreeing while only the result differed.
4. **`RefDotQ6K` omitted the block offset on the activation index** (`x[b*256 + …]`),
   so blocks 1..5 scored against the wrong activations. Invisible inside a
   151936-row aggregate of cancelling signs; a clean ~195% per-row disagreement
   once reported per row. This is the same defect the kernel header documents
   for its own first version.

Two further instances of the same class, in instruments written *after* the fix:

- the harness transcribed `FP16ToFP32` from the loader and therefore agreed with
  it on every subnormal, reporting `FIRST_DIFFERENCE=NONE`;
- `fp16_probe.cpp` carried its own copy and kept reporting `SUB_NORMAL_BUG_PRESENT=1`
  after the loader was repaired.

```ini
A_REFERENCE_BUILT_FROM_THE_CODE_UNDER_TEST_CANNOT_DETECT_A_DEFECT_IN_IT
A_RECORD_COUNT_THAT_IS_NOT_ONE_MEANS_YOU_OBSERVED_A_DIFFERENT_BLOCK
AN_AGGREGATE_OF_CANCELLING_SIGNS_MEASURES_ACCUMULATION_ORDER_NOT_THE_KERNEL
```

## Not claimed

- **Q4_K GPU parity was not re-run.** `tools/q4k_gemv_parity.cpp` drives the
  Vulkan shader through `VulkanCompute` and needs the full stack and a real GPU.
  Its fp16 reference copy was repaired, but its verdict is not re-certified here.
- **No token-level claim.** A generation run needs the full forward stack, which
  does not link end to end in this tree for reasons unrelated to fp16 (see the
  ledger's pre-existing link breaks). What is measured is the decoded weight
  tensor the model multiplies with, which is upstream of every token. It is
  established that 97% of Q6_K weights changed value; it is **not** established
  how the model's output text changes as a result.
- The AVX-512 Q6_K kernel remains withheld. It is not re-examined here.
- `V7`'s repair is verified by exhaustive measurement of the conversion, and the
  file compiles under `/arch:AVX512`. It is not exercised on hardware.

## A note on my own tooling

Two of the falsification probes were driven by PowerShell text round-trips
(`Get-Content -Raw` → `Set-Content`), which silently left
`src/deep2/k_quant_gemv_avx512.h` with **mixed line endings** — 170 CRLF against
359 bare LF, against a committed file that is uniformly CRLF. The code was
correct throughout and compiled cleanly, so nothing failed loudly; the diff was
merely polluted. Normalised back to CRLF.

This is the same failure class as the rest of this receipt: the edit was right,
and the tooling silently changed something the edit did not ask it to change.
Editing production files with a text round-trip rather than a targeted patch is
the mechanism, and it is worth distrusting in future falsification runs.

### Formatting normalisation, verified

Normalising by hand then hid *two further* discrepancies, neither of which the
`COMPILE=PASS` signal could see:

- one line of the subnormal branch had lost its indentation;
- the file had gained a trailing newline that `HEAD` does not have.

Both are invisible to a compile check and both corrupt forensic diff history.
Rather than assert cleanliness, the diff was measured:

```ini
CONTENT_SEMANTIC_CHANGE       = 0
LINE_ENDINGS_MIXED            = 0     all 9 files: CRLF only, 0 bare LF, no BOM
TRAILING_NEWLINE_MATCHES_HEAD = YES
WHITESPACE_ONLY_CHURN         = 0     git --numstat identical with and
                                     without --ignore-all-space, per file
COMPILE                       = PASS  5 files, /arch:AVX512 for the aperture pair
FP16_CENSUS                   = 7/7 CORRECT
Q6K_PARITY                    = PASS  29/29, independent reference active
SHA256_RECORDED               = YES   receipts/RAWRXD_FP16_SUBNORMAL_001.source_sha256.txt
```

`WHITESPACE_ONLY_CHURN = 0` is the check that actually establishes this: for each
of the nine files, `git diff --numstat` is byte-for-byte identical to
`git diff --ignore-all-space --numstat`. Any remaining line in the diff is a
content change.

```ini
rawrxd/src/gguf_loader.cpp                            110  2
rawrxd/src/deep2/k_quant_gemv_avx512.h                325  1
rawrxd/src/core/kquant_dequantize_q4k.cpp              14  1
rawrxd/src/core/dml_asm_impl.cpp                      18  3
rawrxd/src/core/dml_asm_fallback.cpp                  14  3
rawrxd/src/core/aperture_q4_0_avx512_intrinsics.cpp     2  4
rawrxd/src/core/aperture_q8_0_avx512_intrinsics.cpp     2  4
rawrxd/tools/q4k_gemv_parity.cpp                       2  1
rawrxd/verify_registry_q4k.cpp                         2  1
```

`k_quant_gemv_avx512.h` shows 325 insertions because prior sessions left
uncommitted work in that file; this tranche's contribution to it is **1 code line
and 8 comment lines**.

The formatting normalisation is **not** a separate commit. It is
indistinguishable from the correctness change at the byte level — the file now
matches HEAD's conventions, so there is no formatting-only delta left to
separate. Committing the repair on its own is the correct unit, and it has not
been made.

## Superseded evidence

Any prior parity receipt whose reference routed through one of the five
defective FP16 copies is superseded. That includes, on inspection:

- `RAWRXD_Q4K_GEMV_PARITY_001` — its `168/168` predates this repair, and
  `tools/q4k_gemv_parity.cpp` carried the V1 defect in its own reference. Not
  re-run here (GPU path); its reference copy is repaired.
- `RAWRXD_Q6K_GEMV_PARITY_001` — its `SWEEP_REL_ERROR=0.605 -> geometry`
  conclusion is retracted; the independent reference is now a gate condition.

## Reproduce

```ini
bld_q6ktrace\run_all.bat          all seven gates, in order
```

Individual gates: `run_census.bat` (conversion census, no model needed),
`run_fp16_probe.bat` (real exported routine, no model needed),
`run_trace.bat` (element trace), `run_impact.bat` (scale-field census),
`run_e2e.bat` (decoded-weight comparison), `run_sweep.bat` (Q6_K parity gate),
`run_compile_check.bat` (compile check of all seven modified files).