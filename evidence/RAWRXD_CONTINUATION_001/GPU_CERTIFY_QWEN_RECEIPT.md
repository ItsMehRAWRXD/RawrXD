# Qwen3.6 GPU certification probe

## Result

`VULKAN_INIT=PASS` · `GPU_KERNEL_ACTIVITY=OBSERVED` · `GPU_ONLY_CERTIFICATION=BLOCKED` · `PROMOTE=0`

- Executable: `build_reap/bin/deep2_gpu_certify.exe`
- Executable SHA-256: `22FCA0D35D123CB85078802C6B91D490783E5C3AA214384E330902DB85F24E5D`
- Model: Qwen3.6-35B-A3B-Q4_K_M.gguf
- Model SHA-256: `4AC6A06BCE551257267F49AD2226F8671A22519CCC1A4DDE9D5B433D1F2A410D`
- Vulkan device: AMD Radeon AI PRO R9700
- GPU calls: `1271`
- CPU calls: `30`
- Nonfinite logits: `0`
- Elapsed: `61526 ms`
- Status: `BLOCKED_GPU_FALLBACK`

The run proves real Vulkan activity and finite output, but not GPU-only correctness. The 30 CPU calls are the GDN reference recurrence because stateful Vulkan GDN remains unavailable. The generated JSON receipt is `gpu_certify_qwen/full_model_receipt.json`.

```ini
VULKAN_DEVICE_INIT=PASS
GPU_ACTIVITY=PASS_REPORTED
GPU_ONLY=BLOCKED
VULKAN_GDN=FAIL_CLOSED
NUMERICAL_PARITY=NOT_CERTIFIED
PROMOTE=0
```
