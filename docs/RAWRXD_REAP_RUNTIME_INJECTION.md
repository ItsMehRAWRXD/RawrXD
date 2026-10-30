# REAP runtime injection

REAP has two deliberately separate execution modes:

* `reap`/`plan` and the GGUF writer are offline model-reduction operations.
* `runtime` is a non-destructive execution policy. It hotpatches the resident
  MoE router top-k and the existing `MoEWeightProxy` streamer/cache before the
  next `Deep2Engine` model load. It never rewrites, truncates, or replaces a
  GGUF source file.

## Target syntax

The runtime target is:

```text
<parameter-target>/<expert-count>
```

Examples:

```powershell
rawr-reap runtime <model.gguf> --target 1B/8
rawr-reap runtime <model.gguf> --target 35B/8
rawr-reap runtime <model.gguf> --target 100T/8
rawr run <model.gguf> --reap 35B/8 "inspect the loaded model"
```

Parameter targets accept `K`, `M`, `B`, `T` and IEC `Ki`, `Mi`, `Gi`, `Ti`
suffixes. Expert targets accept a positive integer, optionally followed by
`E`. Both values are parsed as `uint64_t`; there is no application-defined
minimum or maximum target size. The planner can therefore represent targets
below or above the model's measured parameter count.

The runtime admission check is a physical-topology check, not a product-size
cap: a dense model may only use `/1`, and an MoE model cannot select more
physical experts than its GGUF declares. Such a request fails closed instead
of fabricating experts or silently clamping the target.

## Runtime behavior

For a single-file MoE model, the parameter target is converted to a working-set
byte budget using the inspected tensor-byte/parameter ratio and applied to the
existing `MoEWeightsLoader` cache. The expert target is applied to the existing
router configuration. The streamer path remains the production
`MoEWeightProxy+VulkanPrefetch` path.

For multi-shard models, router admission and the production
`GlobalTensorIndex`/`TensorResidencyCache` mapping path are enabled. The
requested working-set budget is applied to the residency cache, including the
alignment delta charged by each Windows mapping. Pinned mappings are never
evicted to satisfy the budget; acquisition fails closed when the requested
window cannot be admitted. A receipt reports `working_set_configured=true`
only after the active cache exposes the exact configured byte budget.

The parser has no arbitrary application cap in either direction. A target may
be smaller or larger than the inspected model, and an expert count may be
larger or smaller than the model's current top-k. Runtime admission still
rejects physically impossible topology requests (for example, selecting more
physical experts than the GGUF declares) rather than clamping or fabricating
experts.

## Evidence contract

Every runtime invocation emits `rawrxd.reap.runtime_receipt.v1` with:

* requested and inspected parameter/expert topology;
* `UPSIZE`, `DOWNSIZE`, `MIXED`, or `MATCH` direction;
* runtime activation, route, streamer, and working-set status;
* `source_immutable=true` and `writer_invoked=false`;
* generation and load evidence when a prompt is supplied.

Exit `0` requires a successful load, an active runtime policy, immutable source
state, and—when generation is requested—completed non-empty generation. A
receipt or process exit does not certify numerical parity or model quality;
those remain independent gates.
