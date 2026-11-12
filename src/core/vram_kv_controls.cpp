#include "vram_kv_controls.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dxgi1_4.h>
#pragma comment(lib, "dxgi.lib")

namespace RawrXD {
namespace Perf {

namespace {
int g_offloadLayers = 0;
int g_evictedLayers = 0;
}  // namespace

VramSnapshot QueryLocalVram() {
    VramSnapshot info{};
    IDXGIFactory4* factory = nullptr;
    if (FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory4), reinterpret_cast<void**>(&factory))) ||
        !factory) {
        return info;
    }
    IDXGIAdapter1* adapter1 = nullptr;
    if (SUCCEEDED(factory->EnumAdapters1(0, &adapter1)) && adapter1) {
        IDXGIAdapter3* adapter3 = nullptr;
        if (SUCCEEDED(adapter1->QueryInterface(__uuidof(IDXGIAdapter3),
                                               reinterpret_cast<void**>(&adapter3))) &&
            adapter3) {
            DXGI_QUERY_VIDEO_MEMORY_INFO localInfo{};
            if (SUCCEEDED(adapter3->QueryVideoMemoryInfo(0, DXGI_MEMORY_SEGMENT_GROUP_LOCAL,
                                                         &localInfo))) {
                info.totalMB = static_cast<double>(localInfo.Budget) / (1024.0 * 1024.0);
                info.usedMB = static_cast<double>(localInfo.CurrentUsage) / (1024.0 * 1024.0);
                info.availableMB =
                    (info.totalMB > info.usedMB) ? (info.totalMB - info.usedMB) : 0.0;
            }
            adapter3->Release();
        } else {
            DXGI_ADAPTER_DESC desc{};
            if (SUCCEEDED(adapter1->GetDesc(&desc))) {
                info.totalMB = static_cast<double>(desc.DedicatedVideoMemory) / (1024.0 * 1024.0);
                info.availableMB = info.totalMB;
            }
        }
        adapter1->Release();
    }
    factory->Release();
    return info;
}

void SetGpuLayerOffload(int layers) { g_offloadLayers = layers; }
int GetGpuLayerOffload() { return g_offloadLayers; }
void EvictLayers(int count) { g_evictedLayers += count; }
int GetEvictedLayers() { return g_evictedLayers; }

}  // namespace Perf
}  // namespace RawrXD
