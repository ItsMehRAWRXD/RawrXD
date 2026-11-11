# Next gate

Run one bounded real Qwen3.6 production-executor witness against the exact
current build, with model identity, executable/library hashes, GPU dispatch
telemetry, CPU fallback count, finite-logit checks, and the GDN differential
receipt captured together. The existing independent and class-level GDN
component receipts must remain separate from full-model parity.

Before implementing runtime IR MoE or SSM, perform the pending read-only
dependency mapping: call sites, dispatch conditions, affected model families,
and whether the Qwen3.6 production path reaches either operation.

Open certification state remains:

```ini
GDN_COMPONENT=PASS
QWEN36_FULL_MODEL_PARITY=OPEN
GPU_ONLY_CERTIFICATION=OPEN
RUNTIME_IR_MOE=UNIMPLEMENTED_UNMAPPED
RUNTIME_IR_SSM=UNIMPLEMENTED_UNMAPPED
PROMOTE=0
CERTIFIED=0
```

