/* ur_gpu_d3d12_util.cpp — buffers, barriers, fence */
#define WIN32_LEAN_AND_MEAN
#include "ur_gpu_d3d12_internal.h"
#include <windows.h>

ID3D12Resource *ur_gpu_mk_buf(ID3D12Device *dev, UINT64 n,
                              D3D12_HEAP_TYPE ht, D3D12_RESOURCE_STATES st,
                              D3D12_HEAP_FLAGS hf)
{
    D3D12_HEAP_PROPERTIES hp = {}; D3D12_RESOURCE_DESC rd = {}; ID3D12Resource *r = 0;
    hp.Type = ht;
    rd.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    rd.Width = n; rd.Height = 1; rd.DepthOrArraySize = 1; rd.MipLevels = 1;
    rd.SampleDesc.Count = 1; rd.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    if (FAILED(dev->CreateCommittedResource(&hp, hf, &rd, st, 0,
                                            __uuidof(ID3D12Resource), (void **)&r)))
        return 0;
    return r;
}

void ur_gpu_barrier(ID3D12GraphicsCommandList *cl, ID3D12Resource *r,
                    D3D12_RESOURCE_STATES a, D3D12_RESOURCE_STATES b)
{
    D3D12_RESOURCE_BARRIER bar = {};
    bar.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    bar.Transition.pResource = r;
    bar.Transition.StateBefore = a;
    bar.Transition.StateAfter = b;
    bar.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    cl->ResourceBarrier(1, &bar);
}

int ur_gpu_exec(UrGpuDevice *g)
{
    ID3D12CommandList *lists[1];
    lists[0] = (ID3D12CommandList *)g->list;
    ((ID3D12GraphicsCommandList *)g->list)->Close();
    ((ID3D12CommandQueue *)g->queue)->ExecuteCommandLists(1, lists);
    return UR_OK;
}

int ur_gpu_signal(UrGpuDevice *g)
{
    ID3D12Fence *f = (ID3D12Fence *)g->fence;
    UINT64 v = ++g->fence_value;
    if (FAILED(((ID3D12CommandQueue *)g->queue)->Signal(f, v))) return UR_E_IO;
    g->fence_signaled++;
    return UR_OK;
}

int ur_gpu_wait(UrGpuDevice *g)
{
    ID3D12Fence *f = (ID3D12Fence *)g->fence;
    UINT64 v = g->fence_value;
    if (f->GetCompletedValue() < v) {
        if (FAILED(f->SetEventOnCompletion(v, (HANDLE)g->fence_event))) return UR_E_IO;
        if (WaitForSingleObject((HANDLE)g->fence_event, INFINITE) != WAIT_OBJECT_0)
            return UR_E_IO;
    }
    g->fence_completed++;
    return UR_OK;
}
