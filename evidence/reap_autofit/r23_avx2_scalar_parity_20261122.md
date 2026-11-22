# R23 — AVX2 / Scalar Numerical Parity

## Receipt

```ini
SOURCE_COMMIT=cc32c52b4c
AVX2_EXECUTABLE=build/Release/reap_q4k_to_q2k_test.exe
AVX2_EXECUTABLE_SHA256=E6343D0AB343DDBFCE85E01651CCCAC29DF53C019415B0D5981CAE4F53E17AB5
RANGE_EXECUTABLE=build/Release/reap_quant_range_test.exe
RANGE_EXECUTABLE_SHA256=BA46E26026256D36F670849EBE5E040B879DE89DACDECED1AD1C5E3F85C3A951
AVX2_RUNTIME_CHECK=PASS
NEW_EXTERNAL_DEPENDENCIES=0
STUBS=0
```

## Acceptance output

```text
PASS R23 AVX2/scalar Q4_K decode parity
PASS R23 AVX2/scalar Q4_K to Q2_K parity
PASS_COUNT=21 FAIL_COUNT=0
EXIT=0

PASS multi-batch exact size
PASS first and final block match codec
PASS measured aggregate error
PASS relative reconstruction metric
PASS truncated batch rejected
PASS partial block rejected
PASS write failure retains prior stats
PASS invalid block rejected
PASS zero signal zero error
PASS_COUNT=9 FAIL_COUNT=0
EXIT=0
```

## Disposition

The native AVX2 decoder and conversion path match the scalar reference for the
tested packed Q4_K blocks and conversion metrics. The range/streaming regression
also passes. This closes the tested R23 parity scope; it does not certify
real-model semantic quality or GPU execution.
