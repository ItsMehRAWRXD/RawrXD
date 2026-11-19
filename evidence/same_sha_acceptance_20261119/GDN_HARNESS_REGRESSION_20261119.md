# GDN parity harness regression

```ini
SOURCE_SHA=1d25df56695e75969a3db922f30c8374b5c5653a
BUILD_TARGET=deep2_gdn_parity_harness
BUILD_EXIT=0
EXECUTABLE=F:\\rawrxd\\build\\bin\\Release\\deep2_gdn_parity_harness.exe
EXECUTABLE_SHA256=E990C9499906A96620A39BA1B28BB37C8F333E4CC54EE584AC2AC2AB999BD922
RUN_EXIT=0
GDN_GEOMETRY=PASS
GDN_REFERENCE_FINITE=PASS
GDN_STATE_CONTINUITY=PASS
GDN_GPU_DISPATCHES=0
GDN_CERTIFICATION=NOT_CERTIFIED
```

The regression harness passes its CPU/reference checks. It performs no GPU dispatches, so this does not certify Vulkan GDN execution.
