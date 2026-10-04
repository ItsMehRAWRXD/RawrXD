# RAWRXD_NQB_PRODUCTION_REOPEN_001 — 2026-10-04

Production reopen gate for nanof32braid `.nqb` containers, executed against the
only real artifact in the tree.

```ini
GATE=RAWRXD_NQB_PRODUCTION_REOPEN_001
ARTIFACT=G:\~dev\rawrxd\models\llama3.2-3b-real-f32.nqb
TARGET_FILE_SHA256=849809b0834adbad17e237e72b943d104daf7d9124f56b03294c39abd3727e8f
TOOL_BINARY_SHA256=9d827554b4a9a3f06da2943aaf89213f07714a3c2444d379b5f0d5143eb599ce
SOURCE_SET_ID=1572d8d2a99f78affcbe7f55dbae15609e6ef2d88ed469f67631c85113cb884e

ARTIFACT_VERDICT=FAIL        ARTIFACT_CHECKS_FAIL=3 of 38
NEGATIVE_CONTROLS_HAVE_POWER=1
VERDICT=FAIL  EXIT=1
```

## 1. Why a new instrument

The existing reopen probe (`tools/nqb_reopen_parity_probe.cpp`) calls
`Nanof32BraidStreamer::readAllTensors()`, which materialises every tensor
simultaneously — 12.85 GB of payloads and 6.43 GB of bfloat16 output live at
the same instant, plus a transient compressed buffer per tensor. The instrument
meant to prove the container reopens cannot run against the container that
exists. The new gate splits the claim:

```ini
PHASE 1  STRUCTURAL             bounded memory, one 8 MiB buffer
PHASE 2  READER SELF-CONSISTENCY one tensor resident at a time
PHASE 3  FALSIFICATION          green baseline, then 4 attributed controls
```

Memory is reported per phase rather than claimed globally:

```ini
PHASE1_PEAK_BUFFER_BYTES=8388608
PHASE2_READER_MATERIALIZATION_MODE=FULL_TENSOR
PHASE2_PEAK_TENSOR_BYTES=1576009728
```

## 2. What the artifact gets right

Full 12.85 GB coverage, not sampling. At 1.66 GB/s both phases run in ~130 s.

```ini
CHAIN_TENSOR_COUNT=255              HEADER_TENSOR_COUNT=255     TENSOR_COUNT_MATCH=PASS
FINAL_REVERSE_HEAD=5984856          DATA_START=5984856           FOOTER_CHAIN_REACHES_DATA_START=PASS
FOOTER_GEOMETRY_PREDICATES_HELD=PASS violations=0
ARITHMETIC_OVERFLOW_FREE=PASS        overflows=0
GAPS=0  OVERLAPS=0                   REGIONS_ABUT_WITHOUT_GAP_OR_OVERLAP=PASS
FOOTER_MAGIC_FAILURES=0  FOOTER_NAME_FAILURES=0  FOOTER_DUPLICATE_NAMES=0
FOOTER_SHAPE_FAILURES=0             FOOTER_DATA_BYTES_EQ_ELEMENTS_X4=PASS denseF32Tensors=255
PAYLOAD_BYTES_STREAMED=12850999552  PAYLOAD_BYTES_EXPECTED=12850999552  PAYLOAD_SHORT_READS=0
FINITE_VALUES=3212749888  NAN_VALUES=0  INF_VALUES=0
VOCAB_ENTRIES=128256  VOCAB_BYTES=5984600  VOCAB_STRUCTURE_VALID
READER_TENSORS_READ=255  READER_METADATA_MATCH=255  READER_BF16_HASH_MATCH=255
```

`TARGET_FILE_SHA256` is computed in the same run, so the receipt is bound to the
exact bytes it judged.

## 3. What the artifact gets wrong — exactly three fields

```ini
PARAM_COUNT_MATCH=FAIL       HEADER_PARAM_COUNT=0  CHAIN_PARAM_COUNT=3212749888
BITS_PER_WEIGHT_MATCH=FAIL   HEADER_BITS_FIELD_RAW=0  DECODED_BITS_PER_WEIGHT=0
ARCH_HEAD_DIM_MATCH=FAIL     ARCH_HEAD_DIM_STORED=64  ARCH_HEAD_DIM_DERIVED_EXPECTED=128
```

A stale header written by a converter build predating
`RAWRXD_NQBRAID_HEAD_DIM_DERIVED_001` and
`RAWRXD_GGUF_TO_NQB_CONVERTER_AUTHORITY_001`. The payload is intact and the
chain is exact; the metadata is not. The `headDim=64` defect is the one that
survives every structural check while halving `qDim`, `kvDim` and the KV cache.

`llama3.2-3b-real-q0.nqb` was walked with the same code for comparison: 255
footers, every `quantType=0` (DENSE_F32), identical geometry and identical
length, and all 255 sampled 1 MiB payload windows byte-identical to the f32
artifact. **There is no q0 artifact.** Any "q0 codec fidelity" result measured
on that file would be dense-F32 passthrough counted twice.

## 4. `bitsPerWeight`: hundredths, refuted tenths

The decode lives in one function (`decodedBitsPerWeight`). Measured over every
`.nqb` in the tree, raw field against the payload width actually present:

| file | rawBpW | quantTypes | payloadWidth | impliedBpW |
|---|---:|---:|---:|---:|
| `test_model_q0.nqb` | 160 | 0 | 4 B | 32 |
| `test_model_q1.nqb` | 160 | 1 | 2 B | 16 |
| `test_model_moe.nqb` | 160 | 1 | 2 B | 16 |
| `test_model.nqb` | 115 | 5 | braid | 1.15 |
| `m_moe_q5.nqb` | 115 | 5 | braid | 1.15 |
| `llama3.2-3b-real-f32.nqb` | 0 | 0 | 4 B | 32 |
| `llama3.2-3b-real-q0.nqb` | 320 | 0 | 4 B | 32 |

The same raw `160` appears against two different payload widths, so it carries no
information: it was a constant in the `DENSE_BF16` arm copied into the
`DENSE_F32` arm. It is wrong under hundredths **and** under tenths.

Only the braid row carries a semantically meaningful value, and it selects
hundredths: `115 hundredths == 1.15 bits/weight`, which is the number the format
is named for. Under tenths the braid's own constant would read 11.5 bpw,
contradicting `Nanof32BraidFormat.hpp` ("fixed-point: 115 = 1.15"),
`Nanof32BraidStreamer.cpp:61` (`"%u.%02u"`, `v/100`, `v%100`), and the size
arithmetic the header exists to support.

Correct values under the documented unit: F32 `3200`, BF16 `1600`. Both writers
now derive them from `sizeof()` rather than typing a literal.

## 5. Source defects fixed

```ini
BP16Streamer.hpp            Float32ToBF16Bits() extracted as THE canonical
                            conversion; bfloat16_t(float) calls it. The
                            verifier calls the same primitive instead of
                            reimplementing it, so PHASE 2 is labelled
                            READER SELF-CONSISTENCY and never an independent
                            BF16 oracle (BF16_CONVERSION_INDEPENDENT_ORACLE=
                            NOT_CLAIMED_HERE).
Nanof32BraidWriter.cpp      bitsPerWeight 160/320 -> sizeof-derived 3200/1600.
gguf_to_nqb_converter.cpp  bitsPerWeight 320 -> sizeof-derived 3200, and the
                            comment that produced 320 is corrected: it dropped a
                            factor of 100 ("32 bits is 320").
```

An intermediate repair set the writer to `320` and failed the same way
(`DECODED=3.2`). That is the second time in this session a plausible constant
was refuted by the measurement rather than by review.

## 6. Negative controls have power

```ini
BASELINE_VERDICT=PASS
NEGATIVE_CONTROLS_ADMISSIBLE=1

NC_PAYLOAD_FLIP_DETECTED=PASS        EXPECTED_CHECK=PAYLOAD_HASHES_MATCH_EXPECTED_MANIFEST
NC_FOOTER_MAGIC_ZERO_DETECTED=PASS   EXPECTED_CHECK=FOOTER_MAGIC_FAILURES_ZERO
NC_TRUNCATION_DETECTED=PASS          EXPECTED_BAIL_CLASS=STRUCTURAL_BOUNDS
NC_HEAD_DIM_CORRUPTION_DETECTED=PASS EXPECTED_CHECK=ARCH_HEAD_DIM_MATCH
NEGATIVE_CONTROLS=4/4   GATE_HAS_POWER=PASS
```

Each control is scored on the ONE predicate it is supposed to flip, and
admissibility requires a fully green baseline first. Without that gate a
permanently failing predicate makes every mutated copy look "detected" — which
is exactly what the broken `BITS_PER_WEIGHT_MATCH` was doing.

## 7. Two defects found in the measurement, not the artifact

Both produced confident wrong readings and both were caught by cross-checking
the instrument against its own input.

**Manifest hash-domain contract.** The parser read a line as `<name>\t<hash>`
while `writeManifest` emits `<reverseIndex>\t<name>\t<hash>...`. Column 0 (the
index) became the name and column 1 (the name) went to `strtoull`, which
returns 0 for `blk.1.attn_q.weight`. Every real FNV digest was compared
against 0:

```ini
PAYLOAD_HASHES_MATCH_EXPECTED_MANIFEST=FAIL compared=3 manifestEntries=3 mismatches=3
```

Three of three on the **uncorrupted** baseline is not evidence of corruption; it
is evidence the producer and verifier disagreed about the contract. The contract
is now explicit and keyed by tensor name, so traversal order is free to differ.

**Inverted condition in control scoring.** `!ctl.expectedCheck[0]` is false
whenever the expected name *is* present, so every control reported
`EXPECTED_CHECK_FAILED=0` while printing `newFailures=<the expected check>`.

## 8. Classification

```ini
NQB_PRODUCTION_REOPEN_GATE_IMPLEMENTED=1
GATE_BOUND_TOOL_SHA256=9d827554b4a9a3f06da2943aaf89213f07714a3c2444d379b5f0d5143eb599ce
GATE_BOUND_SOURCE_SET=1572d8d2a99f78affcbe7f55dbae15609e6ef2d88ed469f67631c85113cb884e
GATE_HAS_POWER=1   NEGATIVE_CONTROLS=4/4

STRUCTURAL_CHAIN_255_OF_255=PASS
PAYLOAD_FULL_COVERAGE_12850999552_BYTES=PASS
FINITE_COVERAGE_3212749888=PASS
READER_SELF_CONSISTENCY_255_OF_255=PASS

PRODUCTION_ARTIFACT_TRUSTWORTHY=0
ARTIFACT_DEFECT_HEADER_PARAM_COUNT_ZERO=1
ARTIFACT_DEFECT_HEADER_BITS_PER_WEIGHT_ZERO=1
ARTIFACT_DEFECT_ARCH_HEAD_DIM_64_VS_128=1
Q0_ARTIFACT_EXISTS=0

RAW_F32_PAYLOAD_PARITY_VS_SOURCE_GGUF=NOT_ATTEMPTED   (gate #2, needs the
                                                       GGUF dequant oracle)
READER_BF16_VS_SOURCE_GGUF=NOT_ATTEMPTED            (gate #3, self-consistency
                                                       is a strictly weaker claim)
TOKENIZER_ROUNDTRIP=NOT_ATTEMPTED                   (gate #4)
```

Phase 2's per-tensor record (`--phase2`) is the input gate #3 needs once a GGUF
source oracle exists. It already carries the BF16 truncation error against the
source F32 bytes, which reproduces the previously-recorded `0.0417309` on
`rope_freqs.weight` and `0` on `output_norm.weight` (whose values are exactly
representable).