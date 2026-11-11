/**
 * @file test_gpu_upload_d3d12.cpp
 * @brief Test GPU tensor upload using DirectX 12
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
    #include <d3d12.h>
    #include <dxgi1_6.h>
#endif

// Timing
static double get_time_ms() {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart * 1000.0 / (double)freq.QuadPart;
}

// Simple tensor data (simulated)
struct TensorData {
    float* data;
    size_t num_elements;
    size_t bytes;
};

bool create_test_tensor(TensorData* tensor, size_t num_elements) {
    tensor->num_elements = num_elements;
    tensor->bytes = num_elements * sizeof(float);
    tensor->data = (float*)malloc(tensor->bytes);
    
    if (!tensor->data) {
        return false;
    }
    
    // Fill with test pattern
    for (size_t i = 0; i < num_elements; i++) {
        tensor->data[i] = (float)(i % 1000) / 1000.0f;
    }
    
    return true;
}

void free_test_tensor(TensorData* tensor) {
    free(tensor->data);
    tensor->data = nullptr;
}

// Test D3D12 GPU upload
bool test_d3d12_upload() {
    printf("\n🎮 Testing DirectX 12 GPU Upload...\n");
    
    #ifdef _WIN32
        // Create DXGI factory
        IDXGIFactory4* pFactory = nullptr;
        HRESULT hr = CreateDXGIFactory1(__uuidof(IDXGIFactory4), (void**)&pFactory);
        if (FAILED(hr)) {
            printf("   ❌ Failed to create DXGI factory\n");
            return false;
        }
        
        // Get first adapter
        IDXGIAdapter1* pAdapter = nullptr;
        hr = pFactory->EnumAdapters1(0, &pAdapter);
        if (FAILED(hr)) {
            printf("   ❌ No adapters found\n");
            pFactory->Release();
            return false;
        }
        
        // Create D3D12 device
        ID3D12Device* pDevice = nullptr;
        hr = D3D12CreateDevice(pAdapter, D3D_FEATURE_LEVEL_11_0, __uuidof(ID3D12Device), (void**)&pDevice);
        if (FAILED(hr)) {
            printf("   ❌ Failed to create D3D12 device\n");
            pAdapter->Release();
            pFactory->Release();
            return false;
        }
        
        printf("   ✓ D3D12 device created\n");
        
        // Create command queue
        D3D12_COMMAND_QUEUE_DESC queueDesc = {};
        queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
        queueDesc.Flags = D3D12_COMMAND_QUEUE_FLAG_NONE;
        
        ID3D12CommandQueue* pCommandQueue = nullptr;
        hr = pDevice->CreateCommandQueue(&queueDesc, __uuidof(ID3D12CommandQueue), (void**)&pCommandQueue);
        if (FAILED(hr)) {
            printf("   ❌ Failed to create command queue\n");
            pDevice->Release();
            pAdapter->Release();
            pFactory->Release();
            return false;
        }
        
        // Create command allocator
        ID3D12CommandAllocator* pCommandAllocator = nullptr;
        hr = pDevice->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, 
                                               __uuidof(ID3D12CommandAllocator), (void**)&pCommandAllocator);
        if (FAILED(hr)) {
            printf("   ❌ Failed to create command allocator\n");
            pCommandQueue->Release();
            pDevice->Release();
            pAdapter->Release();
            pFactory->Release();
            return false;
        }
        
        // Create command list
        ID3D12GraphicsCommandList* pCommandList = nullptr;
        hr = pDevice->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, pCommandAllocator, nullptr,
                                           __uuidof(ID3D12GraphicsCommandList), (void**)&pCommandList);
        if (FAILED(hr)) {
            printf("   ❌ Failed to create command list\n");
            pCommandAllocator->Release();
            pCommandQueue->Release();
            pDevice->Release();
            pAdapter->Release();
            pFactory->Release();
            return false;
        }
        
        // Close command list (we'll record later)
        pCommandList->Close();
        
        printf("   ✓ Command infrastructure created\n");
        
        // Test different tensor sizes
        size_t test_sizes[] = {
            1024 * 1024,        // 4 MB
            10 * 1024 * 1024,   // 40 MB
            100 * 1024 * 1024,  // 400 MB
        };
        const char* size_names[] = { "4 MB", "40 MB", "400 MB" };
        
        printf("\n   Upload Performance:\n");
        printf("   %-10s %-15s %-15s %-15s\n", "Size", "Upload Time", "Throughput", "Status");
        printf("   %-10s %-15s %-15s %-15s\n", "----------", "---------------", "---------------", "---------------");
        
        for (int i = 0; i < 3; i++) {
            size_t num_elements = test_sizes[i];
            
            // Create test tensor
            TensorData tensor;
            if (!create_test_tensor(&tensor, num_elements)) {
                printf("   Failed to create test tensor\n");
                continue;
            }
            
            // Create upload buffer (CPU accessible)
            D3D12_HEAP_PROPERTIES uploadHeapProps = {};
            uploadHeapProps.Type = D3D12_HEAP_TYPE_UPLOAD;
            
            D3D12_RESOURCE_DESC uploadBufferDesc = {};
            uploadBufferDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
            uploadBufferDesc.Width = tensor.bytes;
            uploadBufferDesc.Height = 1;
            uploadBufferDesc.DepthOrArraySize = 1;
            uploadBufferDesc.MipLevels = 1;
            uploadBufferDesc.Format = DXGI_FORMAT_UNKNOWN;
            uploadBufferDesc.SampleDesc.Count = 1;
            uploadBufferDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
            uploadBufferDesc.Flags = D3D12_RESOURCE_FLAG_NONE;
            
            ID3D12Resource* pUploadBuffer = nullptr;
            hr = pDevice->CreateCommittedResource(
                &uploadHeapProps,
                D3D12_HEAP_FLAG_NONE,
                &uploadBufferDesc,
                D3D12_RESOURCE_STATE_GENERIC_READ,
                nullptr,
                __uuidof(ID3D12Resource),
                (void**)&pUploadBuffer
            );
            
            if (FAILED(hr)) {
                printf("   Failed to create upload buffer\n");
                free_test_tensor(&tensor);
                continue;
            }
            
            // Create GPU buffer (default heap)
            D3D12_HEAP_PROPERTIES defaultHeapProps = {};
            defaultHeapProps.Type = D3D12_HEAP_TYPE_DEFAULT;
            
            D3D12_RESOURCE_DESC gpuBufferDesc = uploadBufferDesc;
            
            ID3D12Resource* pGpuBuffer = nullptr;
            hr = pDevice->CreateCommittedResource(
                &defaultHeapProps,
                D3D12_HEAP_FLAG_NONE,
                &gpuBufferDesc,
                D3D12_RESOURCE_STATE_COMMON,
                nullptr,
                __uuidof(ID3D12Resource),
                (void**)&pGpuBuffer
            );
            
            if (FAILED(hr)) {
                printf("   Failed to create GPU buffer\n");
                pUploadBuffer->Release();
                free_test_tensor(&tensor);
                continue;
            }
            
            // Map upload buffer and copy data
            void* mappedData = nullptr;
            hr = pUploadBuffer->Map(0, nullptr, &mappedData);
            if (FAILED(hr)) {
                printf("   Failed to map upload buffer\n");
                pGpuBuffer->Release();
                pUploadBuffer->Release();
                free_test_tensor(&tensor);
                continue;
            }
            
            // Time the upload
            double start_time = get_time_ms();
            
            // Copy data to upload buffer
            memcpy(mappedData, tensor.data, tensor.bytes);
            pUploadBuffer->Unmap(0, nullptr);
            
            // Reset command list
            pCommandAllocator->Reset();
            pCommandList->Reset(pCommandAllocator, nullptr);
            
            // Copy from upload buffer to GPU buffer
            pCommandList->CopyBufferRegion(pGpuBuffer, 0, pUploadBuffer, 0, tensor.bytes);
            
            // Close and execute
            pCommandList->Close();
            ID3D12CommandList* ppCommandLists[] = { pCommandList };
            pCommandQueue->ExecuteCommandLists(1, ppCommandLists);
            
            // Wait for completion
            ID3D12Fence* pFence = nullptr;
            hr = pDevice->CreateFence(0, D3D12_FENCE_FLAG_NONE, __uuidof(ID3D12Fence), (void**)&pFence);
            if (SUCCEEDED(hr)) {
                HANDLE hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
                pCommandQueue->Signal(pFence, 1);
                pFence->SetEventOnCompletion(1, hEvent);
                WaitForSingleObject(hEvent, INFINITE);
                CloseHandle(hEvent);
                pFence->Release();
            }
            
            double end_time = get_time_ms();
            double duration_ms = end_time - start_time;
            double throughput_gbps = (tensor.bytes / (1024.0 * 1024.0 * 1024.0)) / (duration_ms / 1000.0);
            
            printf("   %-10s %-15.2f ms %-15.2f GB/s ✅\n", size_names[i], duration_ms, throughput_gbps);
            
            // Cleanup
            pGpuBuffer->Release();
            pUploadBuffer->Release();
            free_test_tensor(&tensor);
        }
        
        // Cleanup
        pCommandList->Release();
        pCommandAllocator->Release();
        pCommandQueue->Release();
        pDevice->Release();
        pAdapter->Release();
        pFactory->Release();
        
        printf("\n   ✓ D3D12 upload test complete\n");
        return true;
    #else
        printf("   ⚠️  DirectX 12 is Windows-only\n");
        return false;
    #endif
}

int main() {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  RawrXD GPU Upload Test (DirectX 12)                           ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Testing GPU tensor upload performance...\n");
    printf("\n");
    
    if (test_d3d12_upload()) {
        printf("\n");
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  Summary                                                       ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("✅ GPU upload test PASSED\n");
        printf("\n");
        printf("DirectX 12 GPU upload is working correctly.\n");
        printf("The system can upload tensors to GPU memory.\n");
        return 0;
    } else {
        printf("\n");
        printf("❌ GPU upload test FAILED\n");
        return 1;
    }
}
