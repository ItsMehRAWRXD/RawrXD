# R32 — Universal compression compatibility receipt

Source commit: `cac179fa81`

This receipt records the native compatibility implementation and the runtime
checks executed against the current build. It does not promote runtime
calibration, GPU execution, numerical parity, semantic quality, or production
readiness.

## Build and executable hashes

| Artifact | Result |
|---|---|
| `rawr-reap` Release build | PASS |
| `reap-moe-transform-test` Release build | PASS |
| `rawr-reap.exe` SHA-256 | `C4A4B5F544EB4DC8B365146E60FDEF63C3991A336FCB6480DDF16CB90D211A4A` |
| `reap-moe-transform-test.exe` SHA-256 | `46A581FA02892F8A915277EDD50A4F8DD90FA996515CBDD171B3D39289A4D16E` |

## Native regression results

`reap_moe_transform_test.exe` exited `0` and reported:

```text
R32_UNIVERSAL_COMPATIBILITY_PASS
R22A_SHORT_WRITE_ROLLBACK_PASS
NATIVE_Q2_TRANSFORM_PASS
REAP_MOE_TRANSFORM_PASS
SOURCE_UNCHANGED=1
RELOAD_PASS=1
TARGET_ENFORCEMENT_PASS=1
PARTIAL_OUTPUT_ROLLBACK_PASS=1
```

The compatibility probe uses the production GGUF parser and read-only
transform planner. The physical writer remains separately exercised by the
same executable.

## Real-model compatibility matrix

| Model | Physical transform | Runtime calibration | Observed layout |
|---|---:|---:|---|
| DeepSeek R1 (`deepseek2`, 11 shards, 1025 tensors) | PASS | PASS | packed expert axis last |
| Kimi K2 (`deepseek2`, 13 shards, 1096 tensors) | PASS | PASS | packed expert axis last |
| MiniMax M2.7 (`minimax-m2`, 3 shards, 809 tensors) | PASS | GATED | packed expert axis last |
| Nemotron 3.5 (`nemotron_h_moe`, 1 shard, 417 tensors) | PASS | GATED | packed expert axis last |
| Dense Qwen3.5 (`qwen35`, 1 shard, 1275 tensors) | FAIL CLOSED | N/A | no supported packed expert bank |

The matrix was run with the native `rawr-reap capabilities` command. The
PowerShell shard regression completed with exit `0`:

```text
ALL REAP SHARD AND CAPABILITY VERIFICATION TESTS PASSED
```

## Capability separation

The CLI now reports independent fields for architecture recognition, tensor
geometry, physical transformation, runtime calibration, virtual transformation,
streaming, GPU execution, numerical parity, quality certification, and
production certification. Unsupported or unverified modes remain false and do
not become implicit fallbacks.

## Disposition

```ini
R32_PHYSICAL_MOE_COMPATIBILITY=PASS
R32_RUNTIME_CALIBRATION_SEPARATION=PASS
DENSE_REAP_TRANSFORM=NOT_IMPLEMENTED
VIRTUAL_REAP=NOT_IMPLEMENTED
STREAMING_REAP=NOT_IMPLEMENTED
GPU_EXECUTION=NOT_CERTIFIED
NUMERICAL_PARITY=NOT_CERTIFIED
QUALITY_CERTIFICATION=NOT_CERTIFIED
PRODUCTION_CERTIFICATION=NOT_CERTIFIED
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
