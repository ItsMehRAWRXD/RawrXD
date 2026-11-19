# S023 — Serverless Deep2 bridge memory reclaim

Date: 2026-11-19  
Source SHA: `0b607ea52e7c6c43ff31f1142b22929bdbac9e4d`

## Source lifecycle

`Deep2Bridge::UnloadModel()` calls `Deep2Engine::unloadModel()` and clears the
model path. `Deep2Engine::unloadModel()` logs and performs GGUF tensor cleanup,
KV-cache reset, and Vulkan `deallocateBuffers`; the Vulkan backend cleanup path
destroys scratch, cache, resident, GDN, and staging buffers.

## Acceptance status

The retained serverless generation receipt proves allocations were used, but
it does not contain before/after device allocation totals around
`UnloadModel()`. No post-unload baseline or host-allocation measurement is
available. Reclamation is therefore not claimed.

```ini
UNLOAD_SOURCE=FOUND
VULKAN_BUFFER_CLEANUP=SOURCE_VERIFIED
DEVICE_BASELINE_AFTER_UNLOAD=NOT_MEASURED
HOST_ALLOCATION_BASELINE=NOT_MEASURED
MEMORY_RECLAIM_RUNTIME=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
