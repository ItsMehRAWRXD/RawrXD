# Phase 3: Track 3 - GPU Tensor Upload Pipeline

## Overview

Track 3 implements the GPU tensor upload pipeline that bridges GGUF model data from CPU memory to Vulkan device memory. This enables zero-copy hotpatching where model weights are pre-uploaded to GPU and atomically swapped during epoch rotation.

## Architecture

### Components

1. **Extended ModelDescriptor** (`hotpatch_model_manager.hpp`)
   - `tensorBuffers`: Vector of per-tensor VulkanBuffer handles
   - `unifiedBuffer`: Single large buffer for small models (<2GB)
   - `gpuUploadComplete`: Atomic flag for upload status
   - `tensors`: Metadata for each tensor (name, offset, size, type)

2. **GPU Upload Methods** (`hotpatch_model_manager.cpp`)
   - `UploadTensorsToGPU()`: Entry point, selects strategy based on model size
   - `UploadTensorUnified()`: Single buffer allocation for small models
   - `UploadTensorPerTensor()`: Per-tensor buffers for large models

3. **GPU Swap Bridge** (`rawrxd_gpu_swap_bridge.asm`)
   - `RawrXD_PrepareShadowGPUBuffer()`: Prepare shadow slot for upload
   - `RawrXD_CommitGPUBufferSwap()`: Mark buffer ready for epoch rotation
   - `RawrXD_SwapGPUBuffer()`: Atomic swap during epoch rotation
   - `RawrXD_GetGPUBuffer()`: Safe read of current GPU buffer

4. **JSON Commands** (`pipe_server_callback.cpp`)
   - `gpu_upload`: Trigger GPU upload for a loaded model
   - `gpu_status`: Query active GPU slot and buffer handle

## Memory Layout

```
GPU Buffer Registry (64-byte aligned slots):
┌─────────────────────────────────────────────────────────────┐
│ Slot 0: Active Model                                          │
│   [0-7]   bufferHandle  (VulkanBuffer*)                       │
│   [8-15]  fenceHandle   (VkFence)                             │
│   [16-23] uploadComplete (bool)                               │
│   [24-31] assignedEpoch  (uint64)                              │
│   [32-63] padding                                             │
├─────────────────────────────────────────────────────────────┤
│ Slot 1: Shadow A (preparing)                                  │
│   ...                                                         │
├─────────────────────────────────────────────────────────────┤
│ Slot 2: Shadow B (preparing)                                  │
│   ...                                                         │
└─────────────────────────────────────────────────────────────┘
```

## Upload Strategies

### Unified Buffer (< 2GB models)
- Single `vkCreateBuffer` allocation
- All tensors packed contiguously
- Better memory locality
- Simpler management

### Per-Tensor Buffer (>= 2GB models)
- Separate `vkCreateBuffer` per tensor
- Allows individual tensor replacement
- Better memory management for sparse updates
- More granular control

## Integration with Epoch-RCU

```
1. Load Model (CPU)
   └─> GGUFLoader parses file
   └─> Copy to heap buffer
   └─> ModelDescriptor created

2. GPU Upload (Async)
   └─> PrepareShadowGPUBuffer(slot=1)
   └─> UploadTensorsToGPU()
   └─> CommitGPUBufferSwap(slot=1, epoch=N)

3. Epoch Rotation
   └─> RequestHotpatch(newModel)
   └─> CheckEpochSwap()
   └─> SwapGPUBuffer(slot=1)
   └─> Old slot retired, new slot active

4. Inference
   └─> GetGPUBuffer() returns active buffer
   └─> BeginInference() increments reader count
   └─> EndInference() decrements reader count
```

## JSON Protocol

### Upload Command
```json
{
  "cmd": "gpu_upload",
  "model_handle": "0x12345678"
}
```

Response:
```json
{
  "status": "ok",
  "model_handle": "0x12345678"
}
```

### Status Command
```json
{
  "cmd": "gpu_status"
}
```

Response:
```json
{
  "status": "ok",
  "active_gpu_slot": 0,
  "buffer_handle": "0xABCDEF00"
}
```

## Build Integration

The GPU upload pipeline integrates with the existing build system:

```cmake
# Vulkan compute backend (already exists)
target_sources(rawrxd PRIVATE
    src/backend/vulkan_compute.cpp
)

# GPU swap bridge (new MASM file)
target_sources(rawrxd PRIVATE
    src/asm/rawrxd_gpu_swap_bridge.asm
)

# Extended model manager
target_sources(rawrxd PRIVATE
    src/cli/hotpatch_model_manager.cpp
)
```

## Next Steps

1. **Staging Buffer Upload**: Implement actual data transfer using `vkCmdCopyBuffer`
2. **Async Upload**: Use compute queue for parallel upload during inference
3. **Memory Pool**: Implement buffer pooling to reduce allocation overhead
4. **Sparse Updates**: Support partial tensor updates for delta hotpatching

## Performance Targets

- Upload bandwidth: > 10 GB/s (PCIe 4.0 x16)
- Latency: < 100ms for 7B model (4GB)
- Zero-copy inference: GPU buffers directly used by compute shaders
