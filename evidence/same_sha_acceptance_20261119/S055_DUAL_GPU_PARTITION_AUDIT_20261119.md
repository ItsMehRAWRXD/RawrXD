# S055 dual-GPU partition audit

Retained runtime receipts show explicit device binding for both AMD Vulkan devices:

- R9700: device index 0, GPU-only run, 601 GPU calls, zero CPU calls, 2.700 decode TPS.
- RX 7800 XT: device index 4, GPU-only run, 601 GPU calls, zero CPU calls, 2.131 decode TPS.
- Both runs reported finite logits and clean per-run verdicts.

These are independent device-bound executions, not proof of a single model partition spanning both devices. The retained receipts do not show cross-device layer ownership, transfer barriers, partition reconstruction parity, or simultaneous dual-device execution for one request.

```ini
S055=DEVICE_BOUND_BASELINES_CAPTURED_PARTITION_OPEN
R9700_BINDING=PASS_REPORTED
RX7800XT_BINDING=PASS_REPORTED
SINGLE_REQUEST_DUAL_GPU_PARTITION=NOT_VERIFIED
CROSS_DEVICE_TRANSFER_PARITY=NOT_VERIFIED
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
