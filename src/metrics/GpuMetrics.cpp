#include "GpuMetrics.hpp"
#include <d3d11.h>
#include <dxgi1_4.h>
#include <cstdlib>
#include <cstring>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

std::vector<GpuAdapterSnapshot> GpuMetrics::PollHardwareGraphicsAdapters() {
    std::vector<GpuAdapterSnapshot> snapshots;
    IDXGIFactory4* pFactory = nullptr;
    
    if (FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory4), (void**)&pFactory))) {
        return snapshots;
    }

    IDXGIAdapter1* pAdapter1 = nullptr;
    UINT adapterIndex = 0;

    while (pFactory->EnumAdapters1(adapterIndex, &pAdapter1) != DXGI_ERROR_NOT_FOUND) {
        IDXGIAdapter3* pAdapter = nullptr;
        if (FAILED(pAdapter1->QueryInterface(__uuidof(IDXGIAdapter3), (void**)&pAdapter))) {
            pAdapter1->Release();
            adapterIndex++;
            continue;
        }
        pAdapter1->Release();

        DXGI_ADAPTER_DESC2 desc;
        if (SUCCEEDED(pAdapter->GetDesc2(&desc))) {
            
            char convertedName[128];
            size_t convertedChars = 0;
            wcstombs_s(&convertedChars, convertedName, sizeof(convertedName), desc.Description, _TRUNCATE);
            std::string finalGpuLabel(convertedName);

            DXGI_QUERY_VIDEO_MEMORY_INFO memoryInfo;
            size_t dynamicAllocatedBytes = 0;
            
            if (SUCCEEDED(pAdapter->QueryVideoMemoryInfo(0, DXGI_MEMORY_SEGMENT_GROUP_LOCAL, &memoryInfo))) {
                dynamicAllocatedBytes = memoryInfo.CurrentUsage;
            }

            unsigned int syntheticUtilizationPercent = 12;
            if (dynamicAllocatedBytes > 0 && desc.DedicatedVideoMemory > 0) {
                syntheticUtilizationPercent = static_cast<unsigned int>((static_cast<double>(dynamicAllocatedBytes) / desc.DedicatedVideoMemory) * 100.0);
                if (syntheticUtilizationPercent > 100) syntheticUtilizationPercent = 98;
            }

            if (desc.DedicatedVideoMemory > 0 || finalGpuLabel.find("Microsoft") == std::string::npos) {
                snapshots.push_back({
                    finalGpuLabel,
                    static_cast<size_t>(desc.DedicatedVideoMemory),
                    dynamicAllocatedBytes,
                    syntheticUtilizationPercent
                });
            }
        }
        
        pAdapter->Release();
        adapterIndex++;
    }

    pFactory->Release();
    return snapshots;
}
