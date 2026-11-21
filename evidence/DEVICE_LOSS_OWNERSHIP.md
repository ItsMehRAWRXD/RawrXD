# Device-loss state ownership — resolved — 2026-11-21

Sprint gate: **establish the authoritative producer/consumer for device-loss state**

## Producer

`src/deep2/lavapath/GpuDeviceLostReset_Vk.cpp:24`

```cpp
bool VulkanCompute::NoteVkResult(int vk, const char* stage) {
    lastLostVk_ = vk;
    if (vk == VK_SUCCESS) { lastLostPhase_ = "ok"; return true; }
    if (GpuLost::IsLostCode(vk)) {
        GpuLost::Mark(lostSeq_, vk);
        lastLostPhase_ = GpuLost::PhaseFor(vk);
        deviceLostCount_ = lostSeq_.mark;     // telemetry mirror
        return false;
    }
    ...
}

bool VulkanCompute::DeviceIsLost() const noexcept { return lostSeq_.lost; }
```

* `lostSeq_.lost` is the **current health** flag (set by `Mark`, cleared by `RecoverDeviceIfOptIn`).
- `lostSeq_.mark` is a **cumulative** event count.
- `deviceLostCount_` is a mirror of `mark` — useful for telemetry, **not** for health. My earlier statement that it is "never written" was wrong: it is written here, just not in `vulkan_compute.cpp`.

## Consumer

`src/deep2/vulkan_compute.cpp` guards now read `lostSeq_.lost` (committed in `5d16fece80`):
- `endSubmitWait` (submission)
- `downloadFromBuffer` (readback)
- `DispatchGemvDevice`, `DispatchGemvQuant` (dispatch)

## Injection contract

```cpp
void VulkanCompute::InjectDeviceLostForTest(int code) { NoteVkResult(code, "inject"); }
```

`code` is a **VkResult**, so:
- `InjectDeviceLostForTest(-4)` → `VK_ERROR_DEVICE_LOST` → `IsLostCode` true → `lostSeq_.lost = true`.
- `InjectDeviceLostForTest(1)` → `VK_NOT_READY` → **not** a lost code → no state change.

Use `-4` in tests.

## Verified run (no injection)

```
exe SHA256 AB83243F0A4FAD74717C1EE287A2ACC3BC8190C2FA0A7360AFA57A11DD74CBE8
[CHAT_DEEP2_NATIVE] entered / generate_begin loaded=1
DEEP2_GPU_DEVICE_LOST mark=1 code=-4 phase=device_lost
[BRIDGE_GEN] gpu_dispatches=20 gpu_fallbacks=0 submissions=20 quant_kernels=1170560 chars=1080
transcript 409 -> 1125, exit 0
```

The IDE survived a real device-loss event and returned 1,080 characters.

## Still open

- Guards are wired but were **not observed firing** (no `refused` line) — the loss occurred after the final submit.
- Deterministic test: `InjectDeviceLostForTest(-4)` then dispatch → expect refusal.
- Mid-token abort and invalid-logit rejection are not implemented.
- Output quality is poor (repetitive), independent of containment.

## Non-claims

Containment is **implemented but not demonstrated**. No crash was reproduced in this run; exit code 0 is a natural exit, cause of the ~80 s shutdown still unknown.