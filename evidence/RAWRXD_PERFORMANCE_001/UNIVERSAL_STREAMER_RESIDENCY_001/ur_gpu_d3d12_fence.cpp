/* ur_gpu_d3d12_fence.cpp — SHARED producer fence for Vulkan wait */
#define WIN32_LEAN_AND_MEAN
#include "ur_gpu_d3d12_internal.h"
#include <windows.h>

extern "C" int ur_gpu_share_fence(UrGpuDevice *g)
{
    ID3D12Device *dev; ID3D12Fence *f; HANDLE nt = 0; UINT64 val;
    if (!g || !g->dev || !g->queue) return UR_E_ARG;
    dev = (ID3D12Device *)g->dev;
    if (!g->share_fence) {
        if (FAILED(dev->CreateFence(0, D3D12_FENCE_FLAG_SHARED, __uuidof(ID3D12Fence),
                                    &g->share_fence)))
            return UR_E_IO;
    }
    f = (ID3D12Fence *)g->share_fence;
    val = ++g->share_fence_val;
    if (FAILED(((ID3D12CommandQueue *)g->queue)->Signal(f, val))) return UR_E_IO;
    if (f->GetCompletedValue() < val) {
        if (FAILED(f->SetEventOnCompletion(val, (HANDLE)g->fence_event))) return UR_E_IO;
        if (WaitForSingleObject((HANDLE)g->fence_event, INFINITE) != WAIT_OBJECT_0)
            return UR_E_IO;
    }
    if (!g->share_fence_nt) {
        if (FAILED(dev->CreateSharedHandle(f, 0, GENERIC_ALL, 0, &nt)) || !nt)
            return UR_E_IO;
        g->share_fence_nt = nt;
    }
    return UR_OK;
}

#ifdef __cplusplus
extern "C" {
#endif
void *ur_gpudev_fence_nt(const UrGpuDevice *g)
{
    return g ? g->share_fence_nt : 0;
}
uint64_t ur_gpudev_fence_val(const UrGpuDevice *g)
{
    return g ? g->share_fence_val : 0;
}
#ifdef __cplusplus
}
#endif
