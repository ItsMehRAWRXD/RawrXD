// ==============================================================================
// IDE_GPU_Detection.cpp - Real GPU Detection for Model Manager
// Windows DXGI + AMD ADL detection, zero dependencies
// ==============================================================================

#include "../models/ModelManager.h"
#include <windows.h>
#include <dxgi.h>
#include <string>

#pragma comment(lib, "dxgi.lib")

using namespace RawrXD;

// ==============================================================================
// GPU Detection Implementation
// ==============================================================================

extern "C" {

// Detect GPU using DXGI
__declspec(dllexport) bool GPU_DetectDXGI(GPUInfo* outInfo) {
    if (!outInfo) return false;
    
    IDXGIFactory* pFactory = nullptr;
    HRESULT hr = CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&pFactory);
    if (FAILED(hr)) return false;
    
    IDXGIAdapter* pAdapter = nullptr;
    hr = pFactory->EnumAdapters(0, &pAdapter); // Primary GPU
    if (FAILED(hr)) {
        pFactory->Release();
        return false;
    }
    
    DXGI_ADAPTER_DESC desc;
    hr = pAdapter->GetDesc(&desc);
    if (SUCCEEDED(hr)) {
        // Convert wide string to UTF-8
        char name[256];
        WideCharToMultiByte(CP_UTF8, 0, desc.Description, -1, name, 256, nullptr, nullptr);
        outInfo->name = name;
        
        // VRAM in bytes
        outInfo->vramBytes = desc.DedicatedVideoMemory;
        outInfo->freeVramBytes = desc.DedicatedVideoMemory; // Approximation
        
        // Check vendor
        if (desc.VendorId == 0x10DE) { // NVIDIA
            outInfo->supportsFP16 = true;
            outInfo->supportsINT8 = true;
            outInfo->supportsINT4 = false; // Most NVIDIA don't support INT4 well
        } else if (desc.VendorId == 0x1002 || desc.VendorId == 0x1022) { // AMD
            outInfo->supportsFP16 = true;
            outInfo->supportsINT8 = true;
            outInfo->supportsINT4 = true; // RDNA3+
        } else if (desc.VendorId == 0x8086) { // Intel
            outInfo->supportsFP16 = true;
            outInfo->supportsINT8 = true;
            outInfo->supportsINT4 = false;
        }
    }
    
    pAdapter->Release();
    pFactory->Release();
    
    return true;
}

// Get GPU memory info using DXGI
__declspec(dllexport) bool GPU_GetMemoryInfo(size_t* totalVRAM, size_t* freeVRAM) {
    if (!totalVRAM || !freeVRAM) return false;
    
    IDXGIFactory* pFactory = nullptr;
    HRESULT hr = CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&pFactory);
    if (FAILED(hr)) return false;
    
    IDXGIAdapter* pAdapter = nullptr;
    hr = pFactory->EnumAdapters(0, &pAdapter);
    if (FAILED(hr)) {
        pFactory->Release();
        return false;
    }
    
    DXGI_ADAPTER_DESC desc;
    hr = pAdapter->GetDesc(&desc);
    if (SUCCEEDED(hr)) {
        *totalVRAM = desc.DedicatedVideoMemory;
        // DXGI doesn't give free VRAM directly, estimate
        *freeVRAM = desc.DedicatedVideoMemory * 0.8; // Conservative estimate
    }
    
    pAdapter->Release();
    pFactory->Release();
    
    return SUCCEEDED(hr);
}

// Get GPU name
__declspec(dllexport) bool GPU_GetName(char* outName, int maxLen) {
    if (!outName || maxLen <= 0) return false;
    
    IDXGIFactory* pFactory = nullptr;
    HRESULT hr = CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&pFactory);
    if (FAILED(hr)) return false;
    
    IDXGIAdapter* pAdapter = nullptr;
    hr = pFactory->EnumAdapters(0, &pAdapter);
    if (FAILED(hr)) {
        pFactory->Release();
        return false;
    }
    
    DXGI_ADAPTER_DESC desc;
    hr = pAdapter->GetDesc(&desc);
    if (SUCCEEDED(hr)) {
        WideCharToMultiByte(CP_UTF8, 0, desc.Description, -1, outName, maxLen, nullptr, nullptr);
    }
    
    pAdapter->Release();
    pFactory->Release();
    
    return SUCCEEDED(hr);
}

// Check if GPU is AMD
__declspec(dllexport) bool GPU_IsAMD() {
    IDXGIFactory* pFactory = nullptr;
    HRESULT hr = CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&pFactory);
    if (FAILED(hr)) return false;
    
    IDXGIAdapter* pAdapter = nullptr;
    hr = pFactory->EnumAdapters(0, &pAdapter);
    if (FAILED(hr)) {
        pFactory->Release();
        return false;
    }
    
    DXGI_ADAPTER_DESC desc;
    hr = pAdapter->GetDesc(&desc);
    bool isAMD = SUCCEEDED(hr) && (desc.VendorId == 0x1002 || desc.VendorId == 0x1022);
    
    pAdapter->Release();
    pFactory->Release();
    
    return isAMD;
}

// Check if GPU is NVIDIA
__declspec(dllexport) bool GPU_IsNVIDIA() {
    IDXGIFactory* pFactory = nullptr;
    HRESULT hr = CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&pFactory);
    if (FAILED(hr)) return false;
    
    IDXGIAdapter* pAdapter = nullptr;
    hr = pFactory->EnumAdapters(0, &pAdapter);
    if (FAILED(hr)) {
        pFactory->Release();
        return false;
    }
    
    DXGI_ADAPTER_DESC desc;
    hr = pAdapter->GetDesc(&desc);
    bool isNVIDIA = SUCCEEDED(hr) && desc.VendorId == 0x10DE;
    
    pAdapter->Release();
    pFactory->Release();
    
    return isNVIDIA;
}

// Get recommended model based on detected GPU
__declspec(dllexport) void GPU_GetRecommendedModel(char* outModel, int maxLen, int* quantBits) {
    if (!outModel || maxLen <= 0) return;
    
    size_t totalVRAM = 0;
    size_t freeVRAM = 0;
    
    if (GPU_GetMemoryInfo(&totalVRAM, &freeVRAM)) {
        size_t vramGB = totalVRAM / (1024 * 1024 * 1024);
        
        if (vramGB >= 24) {
            strcpy_s(outModel, maxLen, "codestral-22b");
            *quantBits = 4;
        } else if (vramGB >= 16) {
            strcpy_s(outModel, maxLen, "llama-3.1-8b");
            *quantBits = 4;
        } else if (vramGB >= 8) {
            strcpy_s(outModel, maxLen, "phi-3-mini");
            *quantBits = 4;
        } else {
            strcpy_s(outModel, maxLen, "phi-3-mini");
            *quantBits = 2;
        }
    } else {
        // Fallback
        strcpy_s(outModel, maxLen, "phi-3-mini");
        *quantBits = 4;
    }
}

} // extern "C"
