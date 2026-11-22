# R22B — Abrupt Termination and Recovery

## Receipt

```ini
SOURCE_COMMIT=dbb24453e2
EXECUTABLE=build/Release/reap-moe-transform-test.exe
EXECUTABLE_SHA256=7D3742F96B1535D0E658B6D444C99E9DF4F9C3F7D81ADBFE369509FE810F1AD5
COMMAND=cmake --build build --config Release --target reap-moe-transform-test -- /m:6
RUN_COMMAND=build/Release/reap-moe-transform-test.exe
EXIT_CODE=0
GPU_EXECUTION=NOT_RUN_BY_DESIGN
EXTERNAL_DEPENDENCIES=0
STUBS=0
```

## Runtime evidence

The test exercises the production `transformMoEGGUF()` path. A child process is
terminated after serialization and staged GGUF validation, while it still owns
the transaction lease and before directory publication. The parent then retries
the same export and verifies that the abandoned transaction state is recovered.

```text
R32_UNIVERSAL_COMPATIBILITY_PASS
R22A_SHORT_WRITE_ROLLBACK_PASS
R22A_PUBLICATION_FAILURE_ROLLBACK_PASS
R22A_CONCURRENT_PUBLICATION_COLLISION_PASS
R22B_STALE_TRANSACTION_RECOVERY_PASS
R22B_ABRUPT_TERMINATION_RECOVERY_PASS
NATIVE_Q2_TRANSFORM_PASS
REAP_MOE_TRANSFORM_PASS
SOURCE_BYTES=880
OUTPUT_BYTES=944
TRANSFORMED_TENSORS=5
SOURCE_UNCHANGED=1
RELOAD_PASS=1
TARGET_ENFORCEMENT_PASS=1
PARTIAL_OUTPUT_ROLLBACK_PASS=1
EXIT=0
```

## Disposition

`R22B_ABRUPT_TERMINATION_RECOVERY=PASS` for the tested native Windows
transaction path. This receipt does not certify power-loss durability or GPU
execution; those remain separate gates.
