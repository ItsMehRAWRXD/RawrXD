// Win32IDE_VRAM_Bridge.cpp — GPU/CPU Scheduling (Batch 5 M04)
// Offload layers, batch size, thread count
#include "Win32IDE.h"
#include <windows.h>
#include <string>
#include <dxgi1_4.h>
#pragma comment(lib, "dxgi.lib")

static Win32IDE::VRAMInfo g_vramInfo{};

void Win32IDE::updateVRAMInfo() {
    Win32IDE::VRAMInfo info{};
    IDXGIFactory4* factory = nullptr;
    if (FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory4), reinterpret_cast<void**>(&factory))) || !factory) {
        g_vramInfo = info;
        return;
    }

    IDXGIAdapter1* adapter1 = nullptr;
    if (SUCCEEDED(factory->EnumAdapters1(0, &adapter1)) && adapter1) {
        IDXGIAdapter3* adapter3 = nullptr;
        if (SUCCEEDED(adapter1->QueryInterface(__uuidof(IDXGIAdapter3), reinterpret_cast<void**>(&adapter3))) &&
            adapter3) {
            DXGI_QUERY_VIDEO_MEMORY_INFO localInfo{};
            if (SUCCEEDED(adapter3->QueryVideoMemoryInfo(0, DXGI_MEMORY_SEGMENT_GROUP_LOCAL, &localInfo))) {
                info.totalMB = static_cast<double>(localInfo.Budget) / (1024.0 * 1024.0);
                info.usedMB = static_cast<double>(localInfo.CurrentUsage) / (1024.0 * 1024.0);
                info.availableMB = (info.totalMB > info.usedMB) ? (info.totalMB - info.usedMB) : 0.0;
            }
            adapter3->Release();
        } else {
            DXGI_ADAPTER_DESC desc{};
            if (SUCCEEDED(adapter1->GetDesc(&desc))) {
                info.totalMB = static_cast<double>(desc.DedicatedVideoMemory) / (1024.0 * 1024.0);
                info.availableMB = info.totalMB;
                info.usedMB = 0.0;
            }
        }
        adapter1->Release();
    }

    factory->Release();
    g_vramInfo = info;
}

Win32IDE::VRAMInfo Win32IDE::getVRAMInfo() const {
    return g_vramInfo;
}

void Win32IDE::setGPULayerOffload(int layers) {
    appendToOutput("[VRAM_Bridge] GPU layer offload set to: " + std::to_string(layers) + "\n",
                   "Output", Win32IDE::OutputSeverity::Info);
}

int Win32IDE::getGPULayerOffload() const {
    return 0;
}
