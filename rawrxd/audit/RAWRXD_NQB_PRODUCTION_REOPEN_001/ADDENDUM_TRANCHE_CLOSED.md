# RAWRXD_NQB_PRODUCTION_REOPEN_001 — addendum: tranche closed

Items 2–6 of the NQB build order, executed and measured. Supersedes nothing in
the parent ledger; it records the state after regeneration.

## 1. Build identity was already implemented (item 1)

```ini
RAWRXD_CERT_BINARY_BUILD_IDENTITY_001 = IMPLEMENTED
cmake/rawr_build_identity.cmake       generates per-target identity headers
build/gen/rawr_build_identity_*.hpp   8 targets
converter feature markers             5, verified present in the finished EXE
```

I suspected the generated identity was stale relative to HEAD. **Measurement
refuted that**: `GIT_HEAD=b5b2796725c0630c11f50e6c83a1323dca64b59b` equals
`git rev-parse HEAD`. `TREE_DIRTY=dirty`, `SOURCE_COUNT=9`,
`BUILD_ID=4ed933e1…`, `COMPILE_TIMESTAMP=2026-10-04T23:14:58Z`. No action taken.

## 2. Two serializers existed; there is now one

The container was serialized twice: `nanof32WriteBraid()` and a hand-rolled
serializer inside `tools/gguf_to_nqb_converter.cpp` (its own `ofstream`, header
struct, `appendTensor()`, header backfill). Three different values existed for
`bitsPerWeight` on a dense-F32 file — 160, 320, 0 — and the shipped artifact
carried 0.

`Nanof32BraidStreamWriter` (new, in `Nanof32BraidWriter.{hpp,cpp}`) is now the
only place the container is serialized:

```ini
open(path, archMeta, vocab)   provisional header: every count is ZERO
appendTensor(...)             payload + footer, census accumulated from what
                              was actually emitted
finalize()                    backfills the header from that census
abort()                       deletes the partial file
```

`nanof32WriteBraid()` is now a loop over it. The converter drives it directly.
The provisional header cannot lie because it has not been told anything yet.

## 3. bpw is measured, not predicted

```cpp
bpw100 = round(payloadBytes * 800 / paramCount)   // integer, no floating point
```

Declared once as `nanof32DeriveBitsPerWeight100()` so a verifier cannot use a
different formula than the writer. Correct for mixed-codec artifacts, and a file
whose stored bpw disagrees with its payload is detectable — which is how the fake
q0 artifact would have been caught.

## 4. Transactional write, and the promote is proven

```ini
<path>.building   written
                  verdict checks run
MoveFileExW       only then renamed to <path>
```

Measured on a fixture whose verdict is FAIL:

```ini
FAILURES=1  FAIL=EMBED_ROWS_VOCAB_SIZE_DISAGREE
VERDICT=FAIL
ARTIFACT_PROMOTED=0 building_file_retained=…\smoke.nqb.building
```

No `smoke.nqb` existed. The gate refuses to make a broken container visible.

## 5. Codec identity

```ini
CODEC_COUNT_DENSE_F32=255   CODEC_COUNT_DENSE_BF16=0   … (all others 0)
REQUESTED_CODEC=DENSE_F32   RESOLVED_CODEC=DENSE_F32
CODEC_REQUEST_APPLIED=1
PHYSICAL_BITS_PER_WEIGHT=32.0000
COMPRESSION_EXPECTATION=NONE_LOSSLESS_CODEC
```

`COMPRESSION_NOT_REALISED` is armed only for lossy requests. An earlier version
fired it against every correct dense conversion — asserting that a dense-F32 file
had "failed to compress" is asserting a bug in the check, not in the file.

## 6. Regenerated artifact — ACCEPTANCE TARGET MET, VERDICT=PASS

```ini
CONVERTER   FAILURES=0  VERDICT=PASS  TRANSACTIONAL_WRITE=1
            PROMOTED_TO=G:\~dev\rawrxd\models\llama3.2-3b-real-f32.nqb

REOPEN GATE TOOL_BINARY_SHA256=7cc9898d7365dc84b0c86067ff94760e38e158b377c3561715a56890b05d3096
            SOURCE_SET_ID=b26b6a23b07bbcecf926021b6a58d96b0d6cb40f5d7d54bad997467b4935d0d9
TARGET      SHA256=068b6781e9f62d242be003e49b7975dfa34a6cae59d283ea059e9f495bef81b2
```

| field | target | measured |
|---|---:|---:|
| FILE_SIZE | 12857017048 | 12857017048 |
| DATA_START | 5984856 | 5984856 |
| HEADER_TENSOR_COUNT | 255 | 255 |
| CHAIN_TENSOR_COUNT | 255 | 255 |
| HEADER_PARAM_COUNT | 3212749888 | 3212749888 |
| CHAIN_PARAM_COUNT | 3212749888 | 3212749888 |
| HEADER_BITS_FIELD_RAW | 3200 | 3200 |
| DECODED_BITS_PER_WEIGHT | 32 | 32 |
| PHYSICAL_BITS_PER_WEIGHT | 32.00 | 32.0000 |
| ARCH_HEAD_DIM_STORED | 128 | 128 |
| CODEC DENSE_F32 | 255 | 255 |
| PAYLOAD_BYTES | 12850999552 | 12850999552 |
| PAYLOAD_SHORT_READS | 0 | 0 |
| FINITE_VALUES | 3212749888 | 3212749888 |
| NAN / INF | 0 | 0 / 0 |
| FINAL_REVERSE_HEAD | 5984856 | 5984856 |
| GAPS / OVERLAPS | 0 | 0 / 0 |
| TARGET_ARTIFACT_VERDICT | PASS | **PASS** |

```ini
ARTIFACT_CHECKS_TOTAL=38   ARTIFACT_CHECKS_FAIL=0   ARTIFACT_VERDICT=PASS
NEGATIVE_CONTROLS=4/4      NEGATIVE_CONTROLS_HAVE_POWER=1
VERDICT=PASS   EXIT=0
```

Physical geometry is byte-identical to the specimen, which is the expected
result: only the three lying header fields changed.

## 7. Forensic specimen retained and still rejected

```ini
llama3.2-3b-real-f32.STALE_HEADER_FORENSIC.nqb
  SHA256=849809b0834adbad17e237e72b943d104daf7d9124f56b03294c39abd3727e8f
  ARTIFACT_VERDICT=FAIL   EXIT=1
  FAIL PARAM_COUNT_MATCH=0 vs 3212749888
  FAIL BITS_PER_WEIGHT_MATCH=0 vs 3200
  FAIL ARCH_HEAD_DIM_MATCH=64 vs 128
```

Structurally perfect payload, semantically false metadata, permanently rejected
by the same gate that now passes the regenerated file.

## 8. Two more defects, both in the instrument

**Exit code contradicted the verdict.** The verdict was computed from the
artifact tally plus control results; the return still used the combined tally:

```ini
VERDICT=PASS
EXIT=1
```

A caller checking the exit code concludes the gate failed. Fixed; `EXIT=0` now
agrees with `VERDICT=PASS`.

**The writer's census never stored the derived value.** `finalize()` wrote
`header_.bitsPerWeight` correctly but left `census_.bpw100` at 0, so the
converter's own cross-check compared the correct header against a zero census:

```ini
HEADER_BITS_FIELD_RAW=0
FAIL=HEADER_BITS_PER_WEIGHT_ZERO
FAIL=CENSUS_BPW_DISAGREES_WITH_DERIVATION
```

The census is what a caller uses to decide whether the writer's output is
self-consistent, so it must carry the same number.

## 9. Measured scope limit, not fixed

The converter reads `llama.*` metadata keys only. A `qwen2` model produces:

```ini
GEOMETRY_FATAL hidden=0 heads=0 headDim=0 hidden%heads=0   EXIT=3
```

It refuses rather than emitting a wrong header, which is the correct failure
mode, but GGUF→NQB is currently llama-only. Per-architecture key resolution is
unimplemented.

## 10. Current state

```ini
RAWRXD_NQB_PRODUCTION_REOPEN_001
    GATE_IMPLEMENTATION=FUNCTIONAL
    GATE_SELFTEST_BASELINE=PASS
    NEGATIVE_CONTROLS=4/4
    GATE_HAS_POWER=1

CURRENT_F32_ARTIFACT
    PHYSICAL_GEOMETRY=PASS
    PAYLOAD_COVERAGE=PASS
    PAYLOAD_FINITE=PASS
    READER_METADATA=PASS
    READER_BF16_SELF_CONSISTENCY=255/255
    SEMANTIC_HEADER=PASS
    TARGET_ARTIFACT_VERDICT=PASS
    SHA256=068b6781e9f62d242be003e49b7975dfa34a6cae59d283ea059e9f495bef81b2

ONE_FORMAT_AUTHORITY=1
TRANSACTIONAL_WRITER=1
DERIVED_HEADER_FIELDS=1
CODEC_CENSUS=1

FORENSIC_CORPUS
    stale_semantic_header.nqb=REJECTED_AS_EXPECTED

EXISTING_REAL_Q0
    CODEC_IDENTITY=FAIL  FOOTERS_DENSE_F32=255/255  Q0_CODEC_APPLIED=0
    CURRENT_Q0_WRITER=UNMEASURED

NEXT
    SOURCE_F32_MANIFEST_VS_NQB   (255/255, gate #2)
    READER_BF16_VS_SOURCE_GGUF   (gate #3)
    TOKENIZER_ROUNDTRIP          (gate #4)
    MANIFEST_V1 + TOOL/TARGET/NC status renaming
```

Gate #2 now has everything it needs: a build-identified artifact, a
content-addressed manifest, and a reader proven to reproduce its own policy for
255/255 tensors.