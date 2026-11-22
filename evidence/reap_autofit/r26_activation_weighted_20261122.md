# R26 — Activation-Weighted Quantization Optimization

## Receipt

```ini
SOURCE_COMMIT=af24f5d61f
EXECUTABLE=build/Release/reap_activation_optimizer_test.exe
EXECUTABLE_SHA256=752603C26F02B47EE7671098F65044CFF129B1743344524D0AE0FEF20A5941B8
OBJECTIVE=activation_energy_times_reconstruction_error
UPGRADE_POLICY=largest_weighted_error_reduction_per_incremental_byte
EXIT_CODE=0
NEW_EXTERNAL_DEPENDENCIES=0
STUBS=0
```

## Acceptance output

```text
PASS activation-weighted plan builds
PASS activation plan stays within hard budget
PASS activation-weighted reconstruction error improves
PASS high-energy high-loss expert reaches Q4_K
PASS low-energy expert remains at Q2_K
PASS next best activation gain reaches Q3_K
PASS activation allocation is deterministic
PASS activation budget below Q2 floor rejected
PASS nonfinite reconstruction metric rejected
PASS_COUNT=9 FAIL_COUNT=0
EXIT=0
```

## Disposition

The optimizer uses measured activation energy and per-precision reconstruction
error to choose upgrades under a hard byte budget. It demonstrates a lower
weighted reconstruction error than the Q2 baseline on the controlled fixture.
Real-model calibration and physical-export binding remain open under R27–R31.
