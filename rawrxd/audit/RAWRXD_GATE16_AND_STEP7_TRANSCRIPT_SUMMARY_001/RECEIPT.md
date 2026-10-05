# RAWRXD_GATE16_AND_STEP7_TRANSCRIPT_SUMMARY_001

Compact durable replacement for two oversized tracked transcripts. Both are
regenerable run output; both leave the index at this commit. The originals are
**not deleted from disk** and remain recoverable from any historical commit.

```ini
SOURCE_LOG_1 = rawrxd/gate16_out.txt
SOURCE_LOG_1_SHA256 = 53F2FD6CFC0325A12E87C179EEDDBD04643F285FB55055BA75CE49F9240B4CE2
SOURCE_LOG_1_BYTES  = 81598806
SOURCE_LOG_1_LINES  = 1321893

SOURCE_LOG_2 = 85_step7_merged.txt
SOURCE_LOG_2_SHA256 = 947B2078E7CEF3F0AB15597895CDC5B740B4EBF65D070DAF36C1137FA01661B3
SOURCE_LOG_2_BYTES  = 80882330
SOURCE_LOG_2_LINES  = 1477941

SOURCE_LOG_2_DISTINCT_NORMALIZED_SHAPES = 633
BYTES_REMOVED_FROM_HEAD = 162481136
```

Classification: **B — regenerable test/probe output.** Nothing below is a
source change; it is a census of what a run actually emitted.

---

## 1. What both transcripts establish

Both describe the same model and the same per-layer progression counts, which
is consistent with one run lineage captured twice at different verbosity.

```ini
ARCH                    = gemma3
SHARDS                  = 1
TENSORS                 = 340
LAYERS                  = 26
HIDDEN                  = 1152
ROPE_ARCH               = gemma3
ROPE_THETA_GLOBAL       = 1000000.0
CPU_FEATURES            = AVX512F AVX512BW AVX512DQ AVX512VNNI AVX2 FMA F16C
KERNELS_REGISTERED      = 14 GEMV + 14 dequant
GPU                     = AMD Radeon AI PRO R9700  vendor=0x1002 device=0x7551
GPU_LOCAL_GB            = 31.86
GPU_DEVICE_COUNT        = 1
```

Per-layer progression, counted over the **whole** file rather than a sample:

```ini
CHECK_WEIGHT_DATA distinct layers = 26   (ids 0..25, complete)
CYC_OK            distinct layers = 26   (ids 0..25, complete)
CHECK_WEIGHT_DATA total occurrences = 9776
CYC_OK            total occurrences = 9776
DERIVED_PASSES_PER_LAYER = 9776 / 26 = 376
```

`CHECK_WEIGHT_DATA` and `CYC_OK` totals are identical, and both cover all 26
layer ids — this is why `CYC_OK_LAYERS=26/26` is recorded rather than inferred
from the first few lines. An earlier partial read of this file stopped at layer
17 and would have understated coverage; the count above is from a full pass.

```ini
CONTIGUOUS_RANGE_REACHED = 1
HOT_LANE_PREP_OK         = slot=0 maxIn=6912 maxRows=262144
SCRATCH_RESERVE_OK       = attention bytes=134217728   (128 MiB)
```

## 2. What both transcripts do NOT establish

**`GPU_FORWARD_OK` does not imply correct logits.** It records that the forward
pass completed. No CPU/GPU parity comparison, no top-1 agreement check, and no
reference value appears anywhere in either transcript. Neither file can support
a numerical-correctness claim.

## 3. Both transcripts contain a hard strict-mode FATAL

This is the load-bearing finding, and it is why these logs must not be reduced
to their successful-looking lines.

```text
gate16_out.txt    L1318353  FATAL_LINEAR_QKV layer=0
                                exc=LinearW: GPU path failed under strict mode
                  L1318354  VSGW_FORWARD_BLOCK_FAIL

85_step7_merged.txt         FATAL_LINEAR_QKV layer=0
                                exc=LinearWBatch4: geometry mismatch
```

Counted over the complete files:

```ini
FATAL_OCCURRENCES                = 1   (per file)
VSGW_FORWARD_BLOCK_FAIL          = 1
LINEARW_RESULT=FAIL              = 63  (gate16)
  ALL_ON_SAME_TENSOR             = blk.0.attn_q.weight
  strict                         = 1
GEMV_SINGLE fullView failed      = 63  (gate16, same tensor)
ERROR / ASSERT / EXCEPTION       = 0
NaN literal                      = 0
nan= / inf= fields               = 64 each  -> all read nan=0 inf=0, benign
CPU_FALLBACK                     = 0
```

The 63 failures are all the **same tensor**, `blk.0.attn_q.weight` — layer-0
attention Q projection, under `strict=1`. This is not 63 independent defects;
it is one failing site retried 63 times.

## 4. Sequence within `gate16_out.txt`

Ordering matters, because the successful tail is last and would otherwise read
as a clean pass:

```text
line         34    GPU_FORWARD_ENTER
line       7042    first GPU_FORWARD_OK
line    1098761    first LINEARW_RESULT=FAIL   <-- failure block begins
line    1318352    last  LINEARW_RESULT=FAIL
line    1318353    FATAL_LINEAR_QKV (strict mode)
line    1318354    VSGW_FORWARD_BLOCK_FAIL
line    1321873    last GPU_FORWARD_OK
line    1321891    COMPUTE_LOGITS_RETURNED
line    1321892    LOGITS_SANITY
line    1321893    SAMPLER_RESULT   <-- final line of file
```

So the transcript contains a 63-attempt strict-mode failure block at
`blk.0.attn_q.weight` **followed by** one attempt that reached logits and
sampling. Both facts are true; neither cancels the other.

Terminal state as recorded:

```text
LOGITS_SANITY   count=262144 finite=262144 nan=0 inf=0 min=-44.4173 max=35.2323
SAMPLER_RESULT  token=218075 vocab=262144
LINEARW_RESULT  =SINGLE_GPU name=token_embd.weight
```

`finite=262144, nan=0, inf=0` is a real finiteness measurement over the full
vocabulary projection. It is **not** a correctness measurement.

## 5. Semantic reduction of `85_step7_merged.txt`

The file is 1,477,941 lines over 633 distinct normalized event shapes — i.e.
repetitive tracing, not 1.48 million distinct observations. Addresses, decimal
values, integers, and absolute paths were normalized away before grouping.

Dominant shapes:

```ini
DISPATCH_OPS_ENTER op=#                     136864
ENSUREWF32_ENTER   key=#                      87984
ENSUREWF32_FIND    key=#                      87984
ENSUREWF32_HIT     key=#                      87750
DISPATCH_GEMV_DEVICE_{ENTER,ENSURE,DISPATCH,DISPATCH_DONE} rows=#  68432 each
weights=<addr>                               68428
```

The 9,776-count families (`GPU_FWD_REF_OK`, `ENSURE_F32_*`, `GEMV_*`,
`CHECK_WEIGHT_DATA`, `WEIGHT_DATA_OK`, `CYC_OK`, `SET_EPOCH`) match the per-layer
counts from section 1 exactly.

### Allocation conservation

```ini
ALLOC_BEGIN (bare)  = 1375
ALLOC_OK            = 1375
CONSERVATION_MATCH  = TRUE
UNMATCHED_BEGIN     = 0
END_OR_FREE events  = 0
```

Every `BEGIN_CMD_ALLOC` is answered by exactly one `BEGIN_CMD_ALLOC_OK`.

Stated precisely, because the weaker claim would be wrong: this demonstrates
**BEGIN↔OK pairing**, not release. The format emits no `END_CMD_ALLOC` or free
event at all, so these logs **cannot** demonstrate that any allocation was
returned. Any claim that this proves no leak would be unsupported.

## 6. Relation to the two failures

The two files report *different* exceptions at the same site:

| log | exception |
|---|---|
| `gate16_out.txt` | `LinearW: GPU path failed under strict mode` |
| `85_step7_merged.txt` | `LinearWBatch4: geometry mismatch` |

Same tensor (`blk.0.attn_q.weight`, layer 0 Q projection), two different
failure modes. One is a strict-mode rejection of the GPU path; the other is a
shape disagreement. They are not the same defect observed twice, and neither is
established as the cause of the other. Localising this is open work, not a
conclusion of this receipt.

## Status

```ini
RAWRXD_GATE16_AND_STEP7_TRANSCRIPT_SUMMARY_001 = MEASURED_FULL_FILE_CENSUS
EXECUTION_PROGRESS_EVIDENCE   = PRESENT   (26/26 layers, 9776 passes)
Finiteness_EVIDENCE           = PRESENT   (262144/262144 finite, nan=0, inf=0)
STRICT_MODE_FATAL_PRESENT     = YES       (1 per file, blk.0.attn_q.weight)
NUMERICAL_CORRECTNESS_CLAIMED  = NO
PARITY_OR_CPU_REFERENCE_IN_LOG = NO
LEAK_FREEDOM_CLAIMED           = NO       (format emits no free event)
VERDICT = EVIDENCE_PRESERVED_WITH_TWO_OPEN_FINDINGS
```

Regenerating either transcript requires re-running the corresponding gate; the
originals remain at the SHAs above in any pre-hygiene commit.