# D2 GPU batching acceptance receipt

- Branch: `codex/d2-gpu-batching`
- Base commit: `d09d513a2d53da2290ca2b99e18c83cd4b9bc4c8`
- Accepted D1 integration: `a5768bfe58`
- D2 implementation: `595bc60f6d439d12f0fc259e3e13c82be2d060fd`
- Working tree after implementation commit: clean

## Scope

The D2 commit is limited to quant-dot dispatch and Vulkan submission behavior:

- always closes the backend batch after a queue failure before CPU replay;
- validates queued Q8 activation spans before deferring work;
- reports the hard 32-entry batch capacity;
- pins queued weight buffers against cache eviction during batch assembly;
- cleans Vulkan buffer and memory handles on allocation/bind failure;
- adds a focused single-entry, two-entry, and over-capacity recovery harness.

## Build

MSVC Release compile completed with exit code `0`:

```text
cl /std:c++20 /EHsc /O2 /W3 /nologo /I C:\VulkanSDK\1.4.357.0\Include /I include /I . /Fe:tools\d2_quant_dot_batch_verify.exe tools\d2_quant_dot_batch_verify.cpp src\deep2\quant_dot_dispatch.cpp src\vulkan_compute.cpp /link C:\VulkanSDK\1.4.357.0\Lib\vulkan-1.lib
```

The canonical verifier compiled with exit code `0` using the same Vulkan backend.

## Receipts

- `d2_batch_verify.log`: `D2_BATCH_RESULT: PASS capacity=32 single_entries=1 two_entries=2 overflow_recovery=1`, exit `0`.
- `gpu_quant_dot_verify.log`: `SHAPES_PASSED=15/15`, `VERDICT=PASS`, exit `0`.
- Device: `AMD Radeon AI PRO R9700`.
- D2 performance comparison is not claimed by this receipt; it is eligible only after these correctness and recovery checks.
