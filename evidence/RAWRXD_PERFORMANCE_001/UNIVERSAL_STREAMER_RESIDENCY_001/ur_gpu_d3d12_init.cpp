/* ur_gpu_d3d12_init.cpp — select first discrete (UMA=0) D3D12 device */
#define WIN32_LEAN_AND_MEAN
#include "ur_device.h"
#include <windows.h>
#include <dxgi1_6.h>
#include <d3d12.h>
#include <string.h>

static void rel(IUnknown *p) { if (p) p->Release(); }

int ur_gpudev_init(UrGpuDevice *g)
{
    IDXGIFactory1 *fac = 0; IDXGIAdapter1 *ad = 0;
    ID3D12Device *dev = 0; UINT i; D3D12_COMMAND_QUEUE_DESC qd = {};
    if (!g) return UR_E_ARG;
    memset(g, 0, sizeof *g);
    if (FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void **)&fac)))
        return UR_E_IO;
    for (i = 0; fac->EnumAdapters1(i, &ad) != DXGI_ERROR_NOT_FOUND; ++i) {
        DXGI_ADAPTER_DESC1 d = {}; D3D12_FEATURE_DATA_ARCHITECTURE1 arch = {};
        ad->GetDesc1(&d);
        if (d.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) { ad->Release(); continue; }
        if (FAILED(D3D12CreateDevice(ad, D3D_FEATURE_LEVEL_11_0,
                                     __uuidof(ID3D12Device), (void **)&dev))) {
            ad->Release(); continue;
        }
        if (FAILED(dev->CheckFeatureSupport(D3D12_FEATURE_ARCHITECTURE1, &arch, sizeof arch))
            || arch.UMA) {
            dev->Release(); ad->Release(); dev = 0; continue;
        }
        g->adapter = ad; g->dev = dev; g->vendor = d.VendorId; g->pci = d.DeviceId;
        g->vram = (uint64_t)d.DedicatedVideoMemory; g->device_id = d.DeviceId;
        g->adapter_luid = (uint64_t)(uint32_t)d.AdapterLuid.LowPart |
                          ((uint64_t)(uint32_t)d.AdapterLuid.HighPart << 32);
        g->uma = 0; g->discrete = 1;
        g->cache_coherent_uma = arch.CacheCoherentUMA;
        g->isolated_mmu = arch.IsolatedMMU;
        break;
    }
    fac->Release();
    if (!g->dev) return UR_E_IO;
    dev = (ID3D12Device *)g->dev;
    qd.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
    if (FAILED(dev->CreateCommandQueue(&qd, __uuidof(ID3D12CommandQueue), &g->queue)))
        return UR_E_IO;
    if (FAILED(dev->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT,
            __uuidof(ID3D12CommandAllocator), &g->allocator)))
        return UR_E_IO;
    if (FAILED(dev->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT,
            (ID3D12CommandAllocator *)g->allocator, 0,
            __uuidof(ID3D12GraphicsCommandList), &g->list)))
        return UR_E_IO;
    ((ID3D12GraphicsCommandList *)g->list)->Close();
    if (FAILED(dev->CreateFence(0, D3D12_FENCE_FLAG_NONE, __uuidof(ID3D12Fence), &g->fence)))
        return UR_E_IO;
    g->fence_event = CreateEventA(0, 0, 0, 0);
    return g->fence_event ? UR_OK : UR_E_IO;
}

void ur_gpudev_shutdown(UrGpuDevice *g)
{
    if (!g) return;
    if (g->share_fence_nt) CloseHandle((HANDLE)g->share_fence_nt);
    rel((IUnknown *)g->share_fence);
    if (g->fence_event) CloseHandle((HANDLE)g->fence_event);
    rel((IUnknown *)g->fence); rel((IUnknown *)g->list);
    rel((IUnknown *)g->allocator); rel((IUnknown *)g->queue);
    rel((IUnknown *)g->dev); rel((IUnknown *)g->adapter);
    memset(g, 0, sizeof *g);
}
