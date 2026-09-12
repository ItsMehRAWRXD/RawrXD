/* ur_gpu_d3d12_readback.cpp — fence wait + DEFAULT→READBACK + memcmp */
#define WIN32_LEAN_AND_MEAN
#include "ur_gpu_d3d12_internal.h"
#include <windows.h>
#include <string.h>

int ur_gpu_upload_wait(void *ctx, void *handle, const uint8_t *src, uint64_t n)
{
    UrGpuDevice *g = (UrGpuDevice *)ctx;
    UrGpuHandle *h = (UrGpuHandle *)handle;
    ID3D12Device *dev; ID3D12Resource *rb; void *map = 0;
    ID3D12CommandAllocator *al; ID3D12GraphicsCommandList *cl;
    if (!g || !h || !h->def || !src || !n || n != h->bytes) return UR_E_ARG;
    if (g->wait_go) WaitForSingleObject((HANDLE)g->wait_go, INFINITE);
    if (ur_gpu_wait(g)) return UR_E_IO;
    dev = (ID3D12Device *)g->dev;
    rb = ur_gpu_mk_buf(dev, n, D3D12_HEAP_TYPE_READBACK, D3D12_RESOURCE_STATE_COPY_DEST,
                       D3D12_HEAP_FLAG_NONE);
    if (!rb) return UR_E_OOM;
    g->readback_created++;
    al = (ID3D12CommandAllocator *)g->allocator;
    cl = (ID3D12GraphicsCommandList *)g->list;
    if (FAILED(al->Reset()) || FAILED(cl->Reset(al, 0))) { rb->Release(); return UR_E_IO; }
    ur_gpu_barrier(cl, h->def, D3D12_RESOURCE_STATE_COPY_DEST, D3D12_RESOURCE_STATE_COPY_SOURCE);
    cl->CopyBufferRegion(rb, 0, h->def, 0, n);
    if (ur_gpu_exec(g) || ur_gpu_signal(g) || ur_gpu_wait(g)) { rb->Release(); return UR_E_IO; }
    if (FAILED(rb->Map(0, 0, &map)) || !map) { rb->Release(); return UR_E_IO; }
    h->parity_ok = memcmp(map, src, (size_t)n) == 0;
    rb->Unmap(0, 0); rb->Release();
    if (h->up) { h->up->Release(); h->up = 0; }
    if (!h->parity_ok) return UR_E_IO;
    g->byte_parity++;
    ur_gpu_export_hot(g, h);
    return UR_OK;
}

static int gpu_release(void *ctx, void *handle)
{
    UrGpuHandle *h = (UrGpuHandle *)handle;
    (void)ctx;
    if (!h) return UR_E_ARG;
    if (h->nt) CloseHandle((HANDLE)h->nt);
    if (h->up) h->up->Release();
    if (h->def) h->def->Release();
    HeapFree(GetProcessHeap(), 0, h);
    return UR_OK;
}

void ur_gpudev_as_vtable(UrGpuDevice *g, UrDeviceVTable *vt)
{
    memset(vt, 0, sizeof *vt);
    vt->ctx = g; vt->kind = UR_DEVKIND_GPU; vt->physical_gpu = 1;
    vt->alloc_copy = 0;
    vt->upload_begin = ur_gpu_upload_begin;
    vt->upload_wait = ur_gpu_upload_wait;
    vt->release = gpu_release;
}

uint64_t ur_gpudev_handle_bytes(void *handle)
{
    UrGpuHandle *h = (UrGpuHandle *)handle;
    return h ? h->bytes : 0;
}

int ur_gpudev_handle_parity(void *handle)
{
    UrGpuHandle *h = (UrGpuHandle *)handle;
    return h ? h->parity_ok : 0;
}
