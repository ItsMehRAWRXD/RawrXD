# Deep2Engine / SsVk product binding points

This is the only source-specific step not executable in the portable self-test.

The certification branch already exposes native model open, tokenizer,
generation/streaming APIs and `Deep2GpuForward.hpp` counters. Bind the callbacks
to those existing objects rather than introducing another engine.

## `prepare_persistent`

Prepare/reuse actual Vulkan command buffers, descriptors, imported/mapped weight
ranges and persistent KV storage exactly once for the session.

Required witness after the first token:

```text
PERSISTENT_PREPARES=1
COMMAND_REBUILDS_THIS_TOKEN=0
KV_HOST_ROUNDTRIPS=0
```

The branch `Deep2GpuForward.hpp` already records:

- `hostSyncBoundaries`
- `hostMaterializations`
- `ownershipTransfers`
- `intraSlotHostTransfers`
- `liveDecodeResidentTokens`
- `hostForwardLayerCalls`
- `gpuLayersLastToken`
- packed-op counters
- CPU F32 expand counter

Use these fields in the receipt. Do not create parallel counters.

## `run_full_forward`

Call the **same Deep2Engine token forward** that currently performs the full
transformer block loop. Route eligible packed Q2_K GEMV operators through the
already-passing `DEEP2_PACKED_Q2K_PRODUCT_DUAL_AGGREGATE_001` implementation.

This callback must finish with:

```text
AGGREGATE_BW_AUTHORITY=1
PRODUCT_LINKED=1
PACKED_Q2K_LIVE=1
MATERIAL_SAME_TOKEN_OVERLAP=1
FULL_MODEL_FORWARD=1
HOST_FORWARD_LAYER_CALLS=0
HOST_MATERIALIZATIONS=0
CPU_F32_EXPANDS=0
```

Do not call the evidence binary as a subprocess. The packed-dual implementation
must be linked/invoked inside the product decode operator.

## `final_norm_lm_head`

Use the real full-forward activation. Do not reuse a sealed prior logits buffer.

Required:

```text
FINAL_NORM_REAL=1
LM_HEAD_REAL=1
SEALED_LOGITS_REUSE=0
```

## `sample_commit`

Use the existing native Deep2 sampler on those exact logits. Emit the committed
token ID and UTF-8 fragment.

Required:

```text
SAMPLER_COMMIT_REAL=1
TOKEN_ID_VALID=1
EXTERNAL_RUNTIME_CALLS=0
```

## `kv_advance`

Advance the existing persistent KV owner **after** sample commit. No host copy
may be inserted just to satisfy the adapter.

Required:

```text
KV_ADVANCE_REAL=1
KV_HOST_ROUNDTRIPS=0
```

## `prefetch_next`

Enqueue exact-range N+1 weights/experts without waiting for them on the current
token. A prefetch miss may affect the next token, but storage I/O for token N
must not be counted outside its critical path.

Required live invariant:

```text
CRITICAL_PATH_NVME_READS_PER_TOKEN=0
```

## First live decode-bind gate

```text
GATE=DEEP2_ENGINE_SSVK_DECODE_BIND_001
TOKENS=16

required all 16:
  aggregate_bw_authority=1
  full_model_forward=1
  final_norm_real=1
  lm_head_real=1
  sampler_commit_real=1
  kv_advance_real=1
  output_parity=1
  sealed_logits_reuse=0
  host_forward_layer_calls=0
  host_materializations=0
  cpu_f32_expands=0
  command_rebuilds_this_token=0
  kv_host_roundtrips=0
  critical_path_nvme_reads=0
  device_lost=0
  external_runtime_calls=0

PROMOTE=0
```
