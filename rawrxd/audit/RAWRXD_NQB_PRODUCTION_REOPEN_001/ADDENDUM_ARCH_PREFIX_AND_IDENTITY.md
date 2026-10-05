# RAWRXD_NQB_ARCH_PREFIX_AND_IDENTITY — 2026-10-05

Two real converter defects, both found by asking what it refuses to do rather than
by reading its own output.

## 1. The converter was llama-only and did not say so

Every geometry read was hardcoded `llama.*`, while the same file had already read
`general.architecture` into `archMeta.archName` and then ignored it. GGUF
namespaces metadata under the architecture name, so every non-llama model produced
zeros:

```text
gguf_to_nqb_converter qwen2.5-coder-1.5b-base.gguf out.nqb
GEOMETRY_FATAL hidden=0 heads=0 headDim=0 hidden%heads=0      exit 3
```

The refusal was *correct* — a header of zeros is not a model — but the reason was a
missing key prefix, not an unsupported architecture. The tool silently had a
one-model scope.

`RAWRXD_GGUF_ARCH_PREFIXED_KEYS_001` resolves `<arch>.<suffix>` with a fallback
to `llama.<suffix>` for models whose keys genuinely live under `llama.*`, so
nothing that worked before stops working:

```ini
ARCH_METADATA_PREFIX=qwen2
HEAD_DIM_DERIVED value=128 from hidden=1536 / heads=12
GEOMETRY_CONSISTENT=1 headDim=128 confirmed_by_attn_q_rows
CONVERTED=338  SKIPPED=0  HEADER_PARAM_COUNT=1543714304
CODEC_REQUEST_APPLIED=1  PHYSICAL_BITS_PER_WEIGHT=32.0000
FAILURES=0  VERDICT=PASS  TRANSACTIONAL_WRITE=1
```

Independently re-verified by the reopen gate:

```ini
CHAIN_TENSOR_COUNT=338  CHAIN_PARAM_COUNT=1543714304
PAYLOAD_BYTES_STREAMED=6174857216
FINAL_REVERSE_HEAD=5020153  GAPS=0  OVERLAPS=0
ARTIFACT_VERDICT=PASS  VERDICT=PASS
```

Also fixed in the same pass: `head_count_kv` is **omitted entirely** by GGUF when
it equals `head_count` (MHA with no GQA reduction). Reading the absent key as `0`
produced `numKVHeads = 0` and failed every downstream head-count invariant for a
reason unrelated to the model. It now falls back to `numHeads`.

## 2. Every container was written with its own identity erased

`Nanof32BraidStreamWriter::open()` copied the caller's arch block and then zeroed
the two name fields out of the copy:

```cpp
Nanof32BraidArchMeta archMeta = archMetaIn;   // modelName / archName populated
std::memset(header.reserved,      0, sizeof(header.reserved));
std::memset(archMeta.modelName,   0, sizeof(archMeta.modelName));   // destroyed
std::memset(archMeta.archName,    0, sizeof(archMeta.archName));    // destroyed
```

They plainly intended to zero the fields *before* they were filled. As written,
every `.nqb` this writer produced shipped with an empty `modelName` and
`archName`. Read straight out of two independent artifacts:

```ini
REGEN : arch=            layers=28 hidden=3072 heads=24 kvHeads=8
BASE  : arch=            layers=28 hidden=3072 heads=24 kvHeads=8
```

That defeats the purpose of carrying an arch block: a reader cannot tell a llama
container from a qwen2 one without reopening the source GGUF, and the new
architecture-prefixed resolution has nowhere to record which prefix was used. The
strings arrive from the caller already NUL-terminated via `snprintf`, so the
memsets achieved nothing except the loss.

After the fix:

```ini
QWEN : model='Qwen2.5 Coder 1.5B' arch='qwen2' layers=28 hidden=1536 vocab=151936 headDim=128
TINY : model='unknown'             arch='llama' layers=2  hidden=64   vocab=64      headDim=8
```

## 3. A measurement trap found while regression-testing

The llama artifact regenerated after the arch change hashed differently from the
one produced earlier in the session. That is expected to be a red flag, so it was
investigated rather than dismissed — and the difference was **not** the arch change.

```ini
field     BASE (earlier)   REGEN (after arch fix)
ropeType  1                2
```

`ropeType` is derived from the architecture by `RAWRXD_NQB_ROPE_TYPE_DERIVE_001`
(`2 == GPT-J adjacent == NORM` for llama), a block this session never touched.
The build identity explains it:

```ini
earlier run   GIT_HEAD=b5b2796725c0630c11f50e6c83a1323dca64b59b
current run   GIT_HEAD=bf93f1e81189632177d9a4c4d16e5759acba019a
```

**The tree advanced underneath this session.** Another lane committed. Byte-identity
comparisons across time are therefore invalid unless the run pins `SOURCE_SET_ID`
and `BUILD_ID` — which is exactly the provenance rule already agreed, now with a
live demonstration of why it is needed rather than merely tidy.

This is also a live reminder that a hash difference is a question, not a verdict.

## 4. Scratch reclaimed

Five multi-GB `.nqb` artifacts had accumulated under the temp tree during this
session's verification runs, including a 11.97 GB regeneration used for the
comparison above.

```ini
freed 35.46 GB
C: free 550.8 GB -> 586.3 GB
```

## State

```ini
CONVERTER_ARCH_SCOPE        GGUF_ARCH_PREFIXED_KEYS (llama + qwen2 verified)
CONVERTER_KV_HEAD_FALLBACK  head_count_kv absent -> numHeads
CONVERTER_IDENTITY          modelName + archName persisted
QWEN2_1.5B_CONVERSION       PASS, 338/338 tensors, reopen ARTIFACT_VERDICT=PASS
LLAMA_3B_CONVERSION         PASS (unchanged behaviour; byte delta traced to a
                            peer commit, not to this change)

TREE_MUTATION_DURING_SESSION=YES
  GIT_HEAD b5b27967 -> bf93f1e8
  PROVENANCE_RULE=NECESSARY_NOT_TIDY
```

Nothing in the shipping runtime was touched in this tranche.