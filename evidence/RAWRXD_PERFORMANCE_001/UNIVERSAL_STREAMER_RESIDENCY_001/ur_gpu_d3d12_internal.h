/* ur_gpu_d3d12_internal.h — D3D12 helpers (no HOT semantics) */
#ifndef UR_GPU_D3D12_INTERNAL_H
#define UR_GPU_D3D12_INTERNAL_H
#include "ur_device.h"
#include <d3d12.h>

struct UrGpuHandle {
    ID3D12Resource *def;
    ID3D12Resource *up;
    uint64_t bytes;
    int parity_ok;
    void *nt;
};

ID3D12Resource *ur_gpu_mk_buf(ID3D12Device *dev, UINT64 n,
                              D3D12_HEAP_TYPE ht, D3D12_RESOURCE_STATES st,
                              D3D12_HEAP_FLAGS hf);
int ur_gpu_export_hot(UrGpuDevice *g, void *handle);
void *ur_gpu_nt(void *handle);
void ur_gpu_barrier(ID3D12GraphicsCommandList *cl, ID3D12Resource *r,
                    D3D12_RESOURCE_STATES a, D3D12_RESOURCE_STATES b);
int ur_gpu_exec(UrGpuDevice *g);
int ur_gpu_signal(UrGpuDevice *g);
int ur_gpu_wait(UrGpuDevice *g);
int ur_gpu_upload_begin(void *ctx, const uint8_t *src, uint64_t n,
                        UrDeviceId *dev_id, UrAllocGeneration *agen, void **handle);
int ur_gpu_upload_wait(void *ctx, void *handle, const uint8_t *src, uint64_t n);

#endif
