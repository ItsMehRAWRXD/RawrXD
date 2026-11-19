# Gate: IDE generation records zero GPU dispatches (OPEN)

Sprint: 2026-11-19. Status: **OPEN — localised, not fixed.**

## Observation

`RawrXD-Win32IDE-Native.exe` (SHA256 `6CFF40B025A09B258BD187926BC8A3185ACC061FCAAB84B718B00AE57BDC85B8`)
running the `IDM_DEEP2_GGUF_PROBE` (9614) with
`RAWRXD_DEEP2_PROBE_MODEL=tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`:

```
init=1 load=1 gen=1 gen_len=32
Backend: Deep2Engine (GPU active)   GPU Devices: 2
GPU Dispatches: 0  CPU Fallbacks: 0  GPU Weight Bytes: 0
GPU Cmd Dispatches: 0  GPU Queue Submits: 0  GPU Fence Waits: 0  GPU Matrix Rows: 0
GPU Forward Real: 0
```

Text is generated, so inference works; no GPU counter moves.

## Source trace (this sprint)

* `Deep2Bridge::GenerateSync` -> `Deep2Engine::generateText` (Deep2Engine.cpp:8978)
  -> `generateStream` -> `forwardTokenAllLayers`.
* `LinearW` attempts GPU only when
  `!plannedCpu && !p2lwForceCpu && vulkanEnabled_ && vulkanInitialized_ && !vulkanDevices_.empty()`
  (Deep2Engine.cpp:7079) -> `tryVulkanGEMV` (:14203), which increments
  `vulkanGemvOk_` (:14299) or `vulkanGemvFail_` (:14312).
* `isVulkanInitialized()` is true and `vulkanDeviceCount()` is 2, yet **both**
  `vulkanGemvOk_` and `vulkanGemvFail_` stay 0, so the :7079 branch is not entered.
  The only untaken predicate that is not observable from the bridge is
  `vulkanEnabled_`.

`vulkanEnabled_` is cleared at Deep2Engine.cpp:1961, :14014 (GPU policy -> CpuOnly),
:14146, :14197, and :14716 (explicit `enableVulkan(false)`).

## Next diagnostic (smallest next step)

1. Expose `bool vulkanEnabled() const { return vulkanEnabled_; }` on `Deep2Engine`
   and print it in `Deep2Bridge::GetModelInfo()`.
2. Re-run the probe. If it prints `GPU Enabled: 0`, find which of the five clear
   sites fired during `initialize -> enableVulkan(true) -> loadModel` and make the
   bridge re-assert `enableVulkan(true)` after `loadModel`.
3. If it prints `GPU Enabled: 1`, the dispatch guard is failing on
   `plannedCpu`/`p2lwForceCpu` or `vulkanDevices_` being empty at generation time;
   instrument :7079 with a one-shot stderr line.

## Explicit non-claims

* IDE chat is serverless (in-process Deep2, no HTTP listener) — verified.
* IDE chat is **not** demonstrated to use the GPU — zero dispatches, zero submits.
* No kernel or dispatch-policy change was made in this sprint.