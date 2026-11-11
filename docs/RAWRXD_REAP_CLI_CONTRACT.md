# RawrXD REAP CLI contract

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
