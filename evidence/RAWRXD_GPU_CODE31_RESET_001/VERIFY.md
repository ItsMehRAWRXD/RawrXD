# Verify

1. Source recognition (no GPU needed):
   - `GpuIsCode31(31)` / `GpuProblemCodeRecoverable(31)` in GpuPreflightReset.cpp
   - stderr keys: `GPU_0_CODE31`, `GPU_RESET_CANDIDATE`, `GPU_RESET_BEGIN`

2. Live smoke:
   ```
   powershell -NoProfile -ExecutionPolicy Bypass -File G:\~dev\rawrxd\evidence\RAWRXD_GPU_CODE31_RESET_001\build_and_run.ps1
   ```
   Expect `RECOG_*=1`. If `LIVE_CODE31=1`, elevated Admin is required for DevNode reset (`GPU_RESET=PASS`).

3. Deep2 Vulkan lost path:
   - On `VK_ERROR_DEVICE_LOST` (`LastD2hPhase()=="device_lost"`), GEMV calls `recoverVulkanAfterDeviceLost()`:
     GpuPreflightCheck ? DualStick unbind ? clear pins ? destroy devices ? `enableVulkan(true)`.

4. Fail-closed: `NOT_RUN != PASS`. Current live Code31 reset without elevation = FAIL (honest).
