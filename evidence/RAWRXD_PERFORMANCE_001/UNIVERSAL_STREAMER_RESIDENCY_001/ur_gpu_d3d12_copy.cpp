/* ur_gpu_d3d12_copy.cpp — UPLOAD→DEFAULT + signal; does not declare HOT */
#define WIN32_LEAN_AND_MEAN
#include "ur_gpu_d3d12_internal.h"
#include <windows.h>
#include <string.h>

int ur_gpu_upload_begin(void *ctx, const uint8_t *src, uint64_t n,
                        UrDeviceId *dev_id, UrAllocGeneration *agen, void **handle)
{
    UrGpuDevice *g = (UrGpuDevice *)ctx;
    ID3D12Device *dev; ID3D12Resource *dst, *up; void *map = 0;
    ID3D12CommandAllocator *al; ID3D12GraphicsCommandList *cl;
    UrGpuHandle *h;
    if (!g || !g->dev || !g->discrete || g->uma || !src || !n || !dev_id || !agen || !handle)
        return UR_E_ARG;
    dev = (ID3D12Device *)g->dev;
    dst = ur_gpu_mk_buf(dev, n, D3D12_HEAP_TYPE_DEFAULT, D3D12_RESOURCE_STATE_COMMON,
                        D3D12_HEAP_FLAG_SHARED);
    if (!dst)
        dst = ur_gpu_mk_buf(dev, n, D3D12_HEAP_TYPE_DEFAULT, D3D12_RESOURCE_STATE_COMMON,
                            D3D12_HEAP_FLAG_NONE);
    up = ur_gpu_mk_buf(dev, n, D3D12_HEAP_TYPE_UPLOAD, D3D12_RESOURCE_STATE_GENERIC_READ,
                       D3D12_HEAP_FLAG_NONE);
    if (!dst || !up) { if (dst) dst->Release(); if (up) up->Release(); return UR_E_OOM; }
    g->default_created++; g->upload_created++;
    if (FAILED(up->Map(0, 0, &map))) { dst->Release(); up->Release(); return UR_E_IO; }
    memcpy(map, src, (size_t)n); up->Unmap(0, 0);
    al = (ID3D12CommandAllocator *)g->allocator;
    cl = (ID3D12GraphicsCommandList *)g->list;
    if (FAILED(al->Reset()) || FAILED(cl->Reset(al, 0))) {
        dst->Release(); up->Release(); return UR_E_IO;
    }
    ur_gpu_barrier(cl, dst, D3D12_RESOURCE_STATE_COMMON, D3D12_RESOURCE_STATE_COPY_DEST);
    cl->CopyBufferRegion(dst, 0, up, 0, n);
    if (ur_gpu_exec(g) || ur_gpu_signal(g)) { dst->Release(); up->Release(); return UR_E_IO; }
    if (g->after_signal) SetEvent((HANDLE)g->after_signal);
    h = (UrGpuHandle *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *h);
    if (!h) { dst->Release(); up->Release(); return UR_E_OOM; }
    h->def = dst; h->up = up; h->bytes = n;
    *dev_id = g->device_id; *agen = ++g->next_gen; *handle = h;
    return UR_OK;
}
