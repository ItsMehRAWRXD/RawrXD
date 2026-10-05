# RAWRXD_NQB_SOURCE_F32_PARITY_001 — Item 7 closed

Gate #2 of the NQB build order: does the container hold exactly what the GGUF
source decodes to, proven without any single process seeing both sides.

```ini
GGUF_PRODUCTION_DEQUANT_TO_NQB_PAYLOAD_FIDELITY=PASS
CHECKS_TOTAL=21  CHECKS_PASS=21  CHECKS_FAIL=0
NEGATIVE_CONTROLS=4/4  GATE_HAS_POWER=1  VERDICT=PASS  EXIT=0
```

## 1. Three authorities, three processes

```text
GGUF ──> nqb_source_f32_manifest.exe ──> source.manifest  ──┐
        (opens the GGUF only)                                ├──> nqb_manifest_compare.exe
NQB  ──> nqb_production_reopen.exe  ──> payload.manifest ──┘      (opens NEITHER model)
        (opens the .nqb only)
```

```ini
SOURCE_GENERATION_AUTHORITY=GGUF_ONLY
PAYLOAD_GENERATION_AUTHORITY=NQB_ONLY
COMPARISON_AUTHORITY=MANIFESTS_ONLY
OPENS_SOURCE_MODEL=0
OPENS_PAYLOAD_MODEL=0
```

A comparator that could open the container could recompute a hash from the
container and quietly agree with itself. It cannot.

## 2. One schema, not two copies

`src/deep2/Nanof32BraidManifest.hpp` holds the schema version, the field list,
the serialiser, the strict parser, the manifest-root derivation, SHA-256, and the
canonical F32 hash primitive. Both sides call it.

This exists because the schema already drifted once: the writer emitted
`reverseIndex name hash…` and the reader parsed `name hash`, so a tensor name was
handed to `strtoull` and returned 0, and a clean baseline reported
`mismatches=3 of 3`. Two hand-maintained copies of a schema will drift.

Parsing is strict by construction. `nqbParseU64Full` accepts digits only and
requires complete consumption, so `"blk.1.attn_q.weight"` is `NOT_A_NUMBER`
rather than zero:

```ini
enum NqbParseStatus { Ok, MissingSchema, SchemaMismatch, FieldCountMismatch,
                      NotANumber, TrailingGarbage, EmptyName };
```

A schema fault is `INVALID`, not `FAIL`: the manifests were not validly read, so
no comparison happened and no fidelity verdict exists.

## 3. Hash domain, stated rather than assumed

```ini
HASH_DOMAIN=gguf_tensor > production_dequant > logical_element_order
            > ieee754_binary32 > little_endian_bytes > fnv1a64+sha256
```

Bytes are re-encoded float → uint32 → explicit little-endian rather than hashing
a `float*` directly. On x64 those are identical today; making it explicit means
the claim does not depend on that staying true, and a future mismatch arrives
labelled as a platform bug instead of a fidelity failure.

## 4. Result — 255/255 on every axis

```ini
SOURCE_GGUF_SHA256=ee1ca8b716933587127f6feb9ff5a247f1e4460e72dcf6293331b9617f8a8aa2
NQB_SHA256=068b6781e9f62d242be003e49b7975dfa34a6cae59d283ea059e9f495bef81b2

                     SOURCE              NQB
TENSORS              255                 255
ELEMENTS             3212749888          3212749888
F32_BYTES            12850999552         12850999552

NAME_MATCH           255/255
SHAPE_MATCH          255/255
ELEMENT_COUNT_MATCH  255/255
BYTE_COUNT_MATCH     255/255
FNV1A64_MATCH        255/255
SHA256_MATCH         255/255

MANIFEST_ROOT_MATCH=1
  both fc2737bb1d7a031aacd8e0df5cc17d6313b6dfd9ce122a4cf0ab23009eff2618
MISSING_SOURCE=0  MISSING_NQB=0  DUPLICATE_NAMES=0  MISMATCHES=0
```

Conservation is checked separately so a comparator bug cannot hide an omitted
tensor behind 254 good hash matches.

Geometry is compared even though the hashes cover the bytes, because a correct
byte stream attached to the wrong tensor name is not payload fidelity.

## 5. Two identities, and that is the point

```ini
NQB_CONTAINER_SHA256=068b6781e9f62d242be003e49b7975dfa34a6cae59d283ea059e9f495bef81b2
F32_SEMANTIC_MANIFEST_ROOT=fc2737bb1d7a031aacd8e0df5cc17d6313b6dfd9ce122a4cf0ab23009eff2618
```

The first identifies the whole serialized file. The second identifies the logical
F32 tensor image and is independent of serialization order, record order, and
physical representation. When genuinely lossy codecs exist the container hashes
will differ while `SOURCE_MODEL_ID` stays shared — which is what makes
representation-independent replay identity possible later.

## 6. Negative controls, one predicate each

```ini
NC_HASH_FLIP=PASS      EXPECTED=MISMATCH_ONE_TENSOR   OBSERVED_MISMATCHES=1
NC_NAME_SWAP=PASS      EXPECTED=AT_LEAST_TWO          OBSERVED_MISMATCHES=2
NC_MISSING_RECORD=PASS EXPECTED_COUNT_DELTA=1         OBSERVED_MISSING_NQB=1
NC_RECORD_REORDER=PASS EXPECTED=STILL_PASS            mismatches=0 rootsMatch=1
NEGATIVE_CONTROLS=4/4
```

`NC_RECORD_REORDER` rotates all 255 records and requires the verdict not to move,
which is what proves the join is genuinely name-keyed rather than accidentally
positional. The rotation is deterministic, not random: a control whose own
randomness could fail is a control that fails for the wrong reason.

## 7. A real defect the three-way split caught

The first comparator run returned:

```ini
SHA256_MATCH=255/255   PASS
FNV1A64_MATCH=58/255   FAIL
TOTAL_MISMATCHES=197
MANIFEST_ROOT_MATCH=0
```

Two hashes over one byte stream cannot disagree, so this was not a fidelity
failure — one side was not hashing what it reported. `nqbHashCanonicalF32` opened
with `fnvOut = nqbFnvBegin();`, making it single-call-only. The source side calls
it once per tensor and was correct. The payload side calls it once per 8 MiB
chunk, so every tensor larger than one chunk had its FNV reset at each chunk and
only the final chunk survived.

**58 is exactly the number of tensors that fit in a single chunk.** SHA-256 was
unaffected because its state is a member object rather than a reset-on-entry
value.

The fix moved accumulator initialisation to the caller
(`nqbHashCanonicalF32Chunk`). Independent confirmation that the source side was
always right: its manifest root was `fc2737bb…` both before and after the fix,
and repairing the payload side moved it to that same value.

This is the strongest available argument for the three-authority split. The
defect lived in the payload authority, and it was found by a comparator that
never opened either model — on the same run whose SHA-256 result said the actual
weights were fine.

## 8. Memory, reported rather than claimed

```ini
SOURCE_MANIFEST_MATERIALIZES_FULL_MODEL=0
SOURCE_PEAK_TENSOR_BYTES=1576009728
PHASE1_PEAK_BUFFER_BYTES=8388608
```

The source side does not materialize 12.85 GB, but it is **not** a few MiB either:
the production dequant kernels take `(src, dst, elementCount)` and write a whole
tensor at once, so streaming inside a tensor is not available at that boundary.
Peak is the largest single tensor, `token_embd` at 1.58 GB. Claiming a small peak
would have been false.

## 9. Claim boundary

```ini
CLAIMED   = the .nqb payload is exactly what the production GGUF Q2_K decode
            path produced, for all 255 tensors, byte for byte
NOT_CLAIMED = that the production Q2_K decoder is numerically canonical
```

Both sides share the dequant kernel, so an independent codec oracle remains a
separate gate. The chain is deliberately staged so no single gate certifies all
of it:

```text
independent codec oracle  ->  proves the dequant is right
RAWRXD_NQB_SOURCE_F32_PARITY_001  ->  proves the serialization is right
execution parity         ->  proves the computation is right
```

## 10. What this closes, and the diagnostic split it earns

```ini
SOURCE_DEQUANT_TO_NQB_PAYLOAD=EXACT
WEIGHT_DATA_PATH=CLOSED
FIRST_BAD_STATE_001=NEXT_INSTRUMENT
```

Every weight-path explanation for a residual NQB logit discrepancy is now
eliminated by measurement. What remains is metadata/runtime geometry, tensor
binding, compute, or state — and `FIRST_BAD_STATE_001` is unambiguously the next
gate.

Had any single tensor failed, the correct reading would have been the opposite:
`FIRST_BAD_STATE_001=PREMATURE`, because the divergence would have been found
before execution and serialization would have been repaired first.

## 11. Current state

```ini
RAWRXD_NQB_SOURCE_F32_PARITY_001
    GATE_IMPLEMENTATION=FUNCTIONAL
    COMPARISON_AUTHORITY=MANIFESTS_ONLY
    TENSORS_COMPARED=255/255
    NAME/SHAPE/ELEMENTS/BYTES/FNV1A64/SHA256 = 255/255
    MANIFEST_ROOT_MATCH=1
    NEGATIVE_CONTROLS=4/4   GATE_HAS_POWER=1
    VERDICT=PASS
    NOT_CLAIMED=CANONICAL_QUANT_DECODER_NUMERICAL_CORRECTNESS

BUILD_ORDER
    1 build identity          CLOSED (pre-existing, verified)
    2 one canonical writer    CLOSED
    3 transactional finalize  CLOSED
    4 derived header fields   CLOSED
    5 artifact regenerated    CLOSED
    6 reopen gate             CLOSED  PASS
    7 source->payload parity  CLOSED  PASS   <-- this record

NEXT
    MANIFEST_V1 + status renaming in the reopen tool (cosmetic, still open)
    INDEPENDENT_CODEC_ORACLE for Q2_K
    FIRST_BAD_STATE_001 coarse layer sweep
    gate #3 reader BF16 vs source GGUF
    gate #4 tokenizer roundtrip
```