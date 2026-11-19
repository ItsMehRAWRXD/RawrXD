# Vulkan GDN interleaved mapping result

```ini
TARGET=deep2_vulkan_gdn_dispatch_probe
BUILD=PASS
GPU=AMD Radeon AI PRO R9700
PIPELINE=READY
FIRST_PARITY=PASS max_abs=8.9407e-08
STATE_CONTINUITY=PASS max_abs=1.19209e-07
RESET_CONTINUITY=PASS max_abs=8.9407e-08
DISPATCHES=3
RESULT=PASS
```

The corrected shader is exercised by a real Vulkan stateful GDN probe and
passes first dispatch, state continuity, reset continuity, and independence.
The full Qwen3.8 parity trace still falls back to the CPU GDN reference path
because the full-model executor does not yet wire the stateful Vulkan GDN
dispatch into its graph.

```ini
FULL_MODEL_VULKAN_GDN_INTEGRATION=OPEN
FULL_LOGIT_PARITY=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
