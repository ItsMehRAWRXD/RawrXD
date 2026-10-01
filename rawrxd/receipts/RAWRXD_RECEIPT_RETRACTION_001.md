# RAWRXD_RECEIPT_RETRACTION_001 — authority_test.receipt.txt

Status: **RETRACTED_FALSE_PASS**
Date: 2026-09-30
Target: `src/deep2/build/evidence/authority_test.receipt.txt`

## What was retracted

The file `src/deep2/build/evidence/authority_test.receipt.txt` is a 17-line static
text file checked into the tree. Every field is a literal. Nothing in it was produced by
a run recorded anywhere in the repository.

```ini
MODEL_ARCH=qwen3next
SAMPLES=384
P10_TPS=45.200000
MEDIAN_TPS=47.000000
PHYSICAL_ROOFLINE_TPS=55.000000
GPU0_FORWARDS=18432
GPU1_FORWARDS=17664
RELOAD_BYTES=0
HOST_MATERIALIZATIONS=0
HOST_TOKEN_COPIES=0
PEER_COPY_BYTES=0
PARITY_ALL=1
OUTPUT_STABLE_ALL=1
CERT=PASS
FAILURE=PASS
```

## Why it is false

**1. `FAILURE=PASS` is self-refuting.** A field named `FAILURE` reporting `PASS` is
either a mislabeled pass or a fabricated verdict. No gate produces this shape.

**2. `PARITY_ALL=1` and `OUTPUT_STABLE_ALL=1` are unbacked.** There is no recorded
oracle run, no reference output, and no diff artifact behind either claim.

**3. The claimed measurements contradict the code that would have produced them.**
At the time of this retraction the production CPU decode path is provably scalar for the
weight type in question:

- `QuantKernelRegistry.cpp` registered SIMD GEMV for `F32`, `F16`, `Q8_0`, `Q8_K` only.
  **Q4_K was scalar-only** (`:1925`).
- `gemv_q4_k_avx512` existed but its body called `gemv_q4_k_scalar` (`:1171`) and was
  never registered.
- All 21 `.asm` files under `src/deep2` are 8-line auto-generated stubs exporting
  `*_Stub`; they do not export the C symbols the wrappers call. All 7 MASM wrappers in
  `QuantKernelRegistry.cpp` (`:165,198,210,222,234,246,257`) are dead, and `:2043-2047`
  documents that they are deliberately never registered.
- `IQ*` types have **no kernel at all**: `GetGEMV` returns `nullptr` (`:2018-2022`) and
  `LinearW` throws (`:3223`).
- The thread pool is created at `Deep2Engine.cpp:860-861` and used in exactly one place,
  the MoE top-k fan-out (`:4223-4229`). `LinearW` (`:3244`) and `LinearWBatch4`
  (`:4299-4301`) are single-threaded per tensor.

A `qwen3next` run producing 384 samples, dual-GPU forward counts, and a sub-55 TPS
roofline is not reachable through that path.

**4. The repository has a fail-closed convention that this violates.** The Q5_K
registration carries an explicit in-source gate comment requiring
`Q5K_AVX2_PARITY_001` before its vector body may be registered. The same standard
applies to any `CERT=PASS`.

## Classification

```ini
RECEIPT_PROVENANCE=NONE_STATIC_LITERAL_FILE
MEASURED_VALUE_COUNT=0
HARD_CODED_VERDICT=1
SIMULATED_COUNTERS=1
CONTRADICTED_BY_SOURCE=1
SELF_REFUTING_FIELD=FAILURE=PASS
DESIGN_STATE=NOT_ASSESSED_BY_THIS_RECEIPT
```

## Rule

`P10_TPS=45.2`, `MEDIAN_TPS=47.0`, `GPU0_FORWARDS=18432`, `GPU1_FORWARDS=17664`, and
`PARITY_ALL=1` from this file **must not** appear in any summary, receipt, ledger, or
claim of Deep2 performance or parity. Quoting them is equivalent to quoting a fabricated
measurement.

The original file is retained unmodified as evidence of the false claim. It is superseded
by this record, not by deletion.

## To legitimately re-open

A replacement receipt must be produced by a committed harness, record the binary hash
and model file hash it ran against, write its output to a dated path under `audit/`, and
carry a computed verdict from a gate whose failure branch is reachable. The
`RAWRXD_Q4K_GEMV_PARITY_001` gate remains open regardless of this retraction.
