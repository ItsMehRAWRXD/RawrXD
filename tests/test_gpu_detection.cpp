/**
 * @file test_gpu_detection.cpp
 * @brief Detect and test available GPU APIs (CUDA, Vulkan, DirectX 12)
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdint.h>

#ifdef _WIN32
    #include <windows.h>
    #include <d3d12.h>
    #include <dxgi1_6.h>
    #pragma comment(lib, "dxgi.lib")
    #pragma comment(lib, "d3d12.lib")
#endif

// CUDA function pointers
typedef int (*cuInit_t)(unsigned int);
typedef int (*cuDeviceGetCount_t)(int*);
typedef int (*cuDeviceGetName_t)(char*, int, int);
typedef int (*cuDeviceGetAttribute_t)(int*, int, int);
typedef int (*cuMemAlloc_t)(void**, size_t);
typedef int (*cuMemFree_t)(void*);
typedef int (*cuMemcpyHtoD_t)(void*, const void*, size_t);
typedef int (*cuMemcpyDtoH_t)(void*, const void*, size_t);

#define CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT 16

// Test CUDA availability
bool test_cuda() {
    printf("\n📦 Testing CUDA...\n");
    
    #ifdef _WIN32
        HMODULE cudaModule = LoadLibraryA("nvcuda.dll");
    #else
        void* cudaModule = dlopen("libcuda.so", RTLD_LAZY);
    #endif
    
    if (!cudaModule) {
        printf("   ❌ CUDA runtime not found\n");
        return false;
    }
    
    printf("   ✓ CUDA runtime found (nvcuda.dll)\n");
    
    // Get function pointers
    #ifdef _WIN32
        cuInit_t cuInit = (cuInit_t)GetProcAddress(cudaModule, "cuInit");
        cuDeviceGetCount_t cuDeviceGetCount = (cuDeviceGetCount_t)GetProcAddress(cudaModule, "cuDeviceGetCount");
        cuDeviceGetName_t cuDeviceGetName = (cuDeviceGetName_t)GetProcAddress(cudaModule, "cuDeviceGetName");
    #else
        cuInit_t cuInit = (cuInit_t)dlsym(cudaModule, "cuInit");
        cuDeviceGetCount_t cuDeviceGetCount = (cuDeviceGetCount_t)dlsym(cudaModule, "cuDeviceGetCount");
        cuDeviceGetName_t cuDeviceGetName = (cuDeviceGetName_t)dlsym(cudaModule, "cuDeviceGetName");
    #endif
    
    if (!cuInit || !cuDeviceGetCount) {
        printf("   ❌ CUDA functions not found\n");
        return false;
    }
    
    // Initialize CUDA
    int result = cuInit(0);
    if (result != 0) {
        printf("   ❌ CUDA init failed (code %d)\n", result);
        return false;
    }
    
    // Get device count
    int deviceCount = 0;
    cuDeviceGetCount(&deviceCount);
    
    if (deviceCount == 0) {
        printf("   ⚠️  No CUDA devices found\n");
        return false;
    }
    
    printf("   ✓ CUDA devices: %d\n", deviceCount);
    
    // Get device names
    for (int i = 0; i < deviceCount && i < 4; i++) {
        char name[256];
        cuDeviceGetName(name, sizeof(name), i);
        printf("      [%d] %s\n", i, name);
    }
    
    return true;
}

// Test DirectX 12 availability
bool test_d3d12() {
    printf("\n🎮 Testing DirectX 12...\n");
    
    #ifdef _WIN32
        // Create DXGI factory
        IDXGIFactory4* pFactory = nullptr;
        HRESULT hr = CreateDXGIFactory1(__uuidof(IDXGIFactory4), (void**)&pFactory);
        
        if (FAILED(hr)) {
            printf("   ❌ Failed to create DXGI factory (0x%08X)\n", (unsigned int)hr);
            return false;
        }
        
        printf("   ✓ DXGI factory created\n");
        
        // Enumerate adapters
        UINT adapterIndex = 0;
        IDXGIAdapter1* pAdapter = nullptr;
        int adapterCount = 0;
        
        while (pFactory->EnumAdapters1(adapterIndex, &pAdapter) != DXGI_ERROR_NOT_FOUND) {
            DXGI_ADAPTER_DESC1 desc;
            pAdapter->GetDesc1(&desc);
            
            // Skip software adapters
            if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) {
                pAdapter->Release();
                adapterIndex++;
                continue;
            }
            
            // Check D3D12 support
            ID3D12Device* pDevice = nullptr;
            hr = D3D12CreateDevice(pAdapter, D3D_FEATURE_LEVEL_11_0, __uuidof(ID3D12Device), (void**)&pDevice);
            
            if (SUCCEEDED(hr)) {
                adapterCount++;
                
                // Convert wide char to regular char
                char name[128];
                wcstombs(name, desc.Description, sizeof(name));
                
                printf("   ✓ Adapter %d: %s\n", adapterIndex, name);
                printf("      Dedicated VRAM: %.2f GB\n", desc.DedicatedVideoMemory / (1024.0 * 1024.0 * 1024.0));
                printf("      Shared RAM: %.2f GB\n", desc.SharedSystemMemory / (1024.0 * 1024.0 * 1024.0));
                
                // Get feature level
                D3D12_FEATURE_DATA_FEATURE_LEVELS featureLevels = {};
                D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_11_1, 
                                               D3D_FEATURE_LEVEL_12_0, D3D_FEATURE_LEVEL_12_1 };
                featureLevels.NumFeatureLevels = 4;
                featureLevels.pFeatureLevelsRequested = levels;
                
                pDevice->CheckFeatureSupport(D3D12_FEATURE_FEATURE_LEVELS, &featureLevels, sizeof(featureLevels));
                printf("      Feature Level: 0x%X\n", featureLevels.NumFeatureLevels);
                
                pDevice->Release();
            }
            
            pAdapter->Release();
            adapterIndex++;
        }
        
        pFactory->Release();
        
        if (adapterCount == 0) {
            printf("   ⚠️  No D3D12-capable adapters found\n");
            return false;
        }
        
        printf("   ✓ D3D12 available with %d adapter(s)\n", adapterCount);
        return true;
    #else
        printf("   ⚠️  DirectX 12 is Windows-only\n");
        return false;
    #endif
}

// Test Vulkan availability (basic check)
bool test_vulkan() {
    printf("\n🔺 Testing Vulkan...\n");
    
    #ifdef _WIN32
        HMODULE vulkanModule = LoadLibraryA("vulkan-1.dll");
    #else
        void* vulkanModule = dlopen("libvulkan.so.1", RTLD_LAZY);
    #endif
    
    if (!vulkanModule) {
        printf("   ❌ Vulkan runtime not found\n");
        return false;
    }
    
    printf("   ✓ Vulkan runtime found\n");
    
    // Note: Full Vulkan initialization requires more code
    // This is just a basic availability check
    printf("   ⚠️  Full Vulkan test not implemented (runtime available)\n");
    
    return true;
}

// Test GPU memory allocation
bool test_gpu_memory() {
    printf("\n💾 Testing GPU Memory...\n");
    
    #ifdef _WIN32
        // Try D3D12
        IDXGIFactory4* pFactory = nullptr;
        HRESULT hr = CreateDXGIFactory1(__uuidof(IDXGIFactory4), (void**)&pFactory);
        
        if (FAILED(hr)) {
            printf("   ❌ DXGI not available\n");
            return false;
        }
        
        IDXGIAdapter1* pAdapter = nullptr;
        if (pFactory->EnumAdapters1(0, &pAdapter) == DXGI_ERROR_NOT_FOUND) {
            printf("   ❌ No adapters found\n");
            pFactory->Release();
            return false;
        }
        
        ID3D12Device* pDevice = nullptr;
        hr = D3D12CreateDevice(pAdapter, D3D_FEATURE_LEVEL_11_0, __uuidof(ID3D12Device), (void**)&pDevice);
        
        if (FAILED(hr)) {
            printf("   ❌ D3D12 device creation failed\n");
            pAdapter->Release();
            pFactory->Release();
            return false;
        }
        
        // Create command queue
        D3D12_COMMAND_QUEUE_DESC queueDesc = {};
        queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
        queueDesc.Flags = D3D12_COMMAND_QUEUE_FLAG_NONE;
        
        ID3D12CommandQueue* pCommandQueue = nullptr;
        hr = pDevice->CreateCommandQueue(&queueDesc, __uuidof(ID3D12CommandQueue), (void**)&pCommandQueue);
        
        if (FAILED(hr)) {
            printf("   ❌ Command queue creation failed\n");
            pDevice->Release();
            pAdapter->Release();
            pFactory->Release();
            return false;
        }
        
        printf("   ✓ D3D12 device and command queue created\n");
        
        // Try to allocate GPU memory
        D3D12_HEAP_PROPERTIES heapProps = {};
        heapProps.Type = D3D12_HEAP_TYPE_DEFAULT;
        
        D3D12_RESOURCE_DESC resourceDesc = {};
        resourceDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
        resourceDesc.Width = 1024 * 1024;  // 1MB
        resourceDesc.Height = 1;
        resourceDesc.DepthOrArraySize = 1;
        resourceDesc.MipLevels = 1;
        resourceDesc.Format = DXGI_FORMAT_UNKNOWN;
        resourceDesc.SampleDesc.Count = 1;
        resourceDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
        resourceDesc.Flags = D3D12_RESOURCE_FLAG_NONE;
        
        ID3D12Resource* pResource = nullptr;
        hr = pDevice->CreateCommittedResource(
            &heapProps,
            D3D12_HEAP_FLAG_NONE,
            &resourceDesc,
            D3D12_RESOURCE_STATE_COMMON,
            nullptr,
            __uuidof(ID3D12Resource),
            (void**)&pResource
        );
        
        if (FAILED(hr)) {
            printf("   ❌ GPU memory allocation failed (0x%08X)\n", (unsigned int)hr);
            pCommandQueue->Release();
            pDevice->Release();
            pAdapter->Release();
            pFactory->Release();
            return false;
        }
        
        printf("   ✓ GPU memory allocated (1MB buffer)\n");
        
        // Cleanup
        pResource->Release();
        pCommandQueue->Release();
        pDevice->Release();
        pAdapter->Release();
        pFactory->Release();
        
        return true;
    #else
        printf("   ⚠️  GPU memory test not implemented for this platform\n");
        return false;
    #endif
}

int main() {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  RawrXD GPU Detection Test                                     ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Testing available GPU APIs and capabilities...\n");
    printf("\n");
    
    int availableApis = 0;
    
    // Test each API
    if (test_cuda()) {
        availableApis++;
    }
    
    if (test_d3d12()) {
        availableApis++;
    }
    
    if (test_vulkan()) {
        availableApis++;
    }
    
    if (test_gpu_memory()) {
        availableApis++;
    }
    
    // Summary
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Summary                                                       ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    if (availableApis == 0) {
        printf("❌ No GPU APIs available\n");
        printf("\n");
        printf("This system does not have compatible GPU drivers installed.\n");
        printf("To use GPU acceleration, install:\n");
        printf("  - NVIDIA drivers (for CUDA)\n");
        printf("  - Vulkan runtime (for Vulkan)\n");
        printf("  - Windows 10/11 with DirectX 12 (for D3D12)\n");
        return 1;
    } else {
        printf("✅ GPU APIs available: %d\n", availableApis);
        printf("\n");
        printf("GPU acceleration is possible on this system.\n");
        printf("Recommended backend: DirectX 12 (best Windows support)\n");
        return 0;
    }
}
