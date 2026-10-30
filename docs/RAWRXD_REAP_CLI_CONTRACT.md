# RawrXD REAP CLI contract

REAP has two explicit modes. The production `--reap <parameters>/<experts>`
form is a live, non-destructive streamer/router injection. It changes the
resident parameter working-set budget and the active MoE expert target for
the model session, then runs that model. It does not quantize, prune, rewrite,
or replace GGUF files.

```text
rawr run <model> --reap 1B/8 "run the model with the requested runtime policy"
rawr run <model> --reap 100T/16 "run the model with the requested runtime policy"
rawr-reap runtime <model> --target 1B/8
```

The first value is the requested parameter/working-set target. It may be
smaller or larger than the inspected model and is applied as the runtime
working-set budget. The second value is the requested active MoE expert target
and is likewise allowed to move below or above the model's normal top-k. The
only expert limit is physical topology: a model cannot route to experts that
do not exist, and dense models require `/1`. Impossible topology requests fail
closed; they are never silently clamped or fabricated.

Every live invocation emits `rawrxd.reap.runtime_receipt.v1` with the
requested values, effective values, direction (`DOWNSIZE`, `UPSIZE`, `MIXED`,
or `MATCH`), runtime activation, generation result, `source_immutable`, and
`writer_invoked=false`.

The separate `rawr reap ... --target-size ...` form below remains the guarded
offline model-reduction/writer contract. It is not used by the live
`--reap A/B` execution path.

The native CLI accepts the guarded REAP request in either form:

```text
rawr run <model> --reap \
  --target-size 30GB \
  --active-experts 64 \
  --expert-budget 20GB \
  --quality-floor 0.95

rawr reap <model> \
  --target-size 30GB \
  --active-experts 64 \
  --expert-budget 20GB \
  --quality-floor 0.95
```

All four REAP parameters are required.  Sizes accept `B`, `KB`/`KiB`,
`MB`/`MiB`, `GB`/`GiB`, and `TB`/`TiB`.  `--active-experts` is a positive
integer and `--quality-floor` is a finite value in `[0,1]`.  The expert budget
cannot exceed the target size.  REAP parameters without `--reap`, malformed
values, and `--size` mixed with `--reap` are rejected before backend startup.

A valid request currently returns exit code 4 and a machine-readable receipt:

```json
{
  "status": "BLOCKED",
  "reason": "REAP_RUNTIME_UNAVAILABLE",
  "gates": {
    "mla_cert_001": false,
    "calibration_complete": false,
    "selection_complete": false,
    "rewriter_certified": false
  },
  "transformation_enabled": false
}
```

This is intentional.  Parsing a request is not evidence that a model can be
pruned.  The production path stays disabled until the same model has a real
MLA-CERT-001 witness, a complete model-specific calibration and selection
receipt, and a parity-certified GGUF rewriter.  No environment variable or
CLI option can manufacture those gates, and the ordinary model path is never
silently used as a substitute.
