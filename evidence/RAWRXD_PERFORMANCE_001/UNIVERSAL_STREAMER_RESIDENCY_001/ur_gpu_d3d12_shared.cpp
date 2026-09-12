/* ur_gpu_d3d12_shared.cpp — NT export of exact DEFAULT buffer (not consumer auth) */
#define WIN32_LEAN_AND_MEAN
#include "ur_gpu_d3d12_internal.h"
#include <windows.h>

int ur_gpu_export_hot(UrGpuDevice *g, void *handle)
{
    UrGpuHandle *h = (UrGpuHandle *)handle;
    ID3D12Device *dev; ID3D12CommandAllocator *al; ID3D12GraphicsCommandList *cl;
    HANDLE nt = 0;
    if (!g || !h || !h->def || !g->dev) return UR_E_ARG;
    al = (ID3D12CommandAllocator *)g->allocator;
    cl = (ID3D12GraphicsCommandList *)g->list;
    if (FAILED(al->Reset()) || FAILED(cl->Reset(al, 0))) return UR_E_IO;
    ur_gpu_barrier(cl, h->def, D3D12_RESOURCE_STATE_COPY_SOURCE, D3D12_RESOURCE_STATE_COMMON);
    if (ur_gpu_exec(g) || ur_gpu_signal(g) || ur_gpu_wait(g)) return UR_E_IO;
    if (h->nt) return UR_OK;
    dev = (ID3D12Device *)g->dev;
    if (FAILED(dev->CreateSharedHandle(h->def, 0, GENERIC_ALL, 0, &nt)) || !nt)
        return UR_E_IO;
    h->nt = nt;
    ur_gpu_share_fence(g);
    return UR_OK;
}

#ifdef __cplusplus
extern "C" {
#endif
void *ur_gpu_nt(void *handle)
{
    UrGpuHandle *h = (UrGpuHandle *)handle;
    return h ? h->nt : 0;
}

uint64_t ur_gpudev_luid(const UrGpuDevice *g)
{
    return g ? g->adapter_luid : 0;
}
#ifdef __cplusplus
}
#endif
