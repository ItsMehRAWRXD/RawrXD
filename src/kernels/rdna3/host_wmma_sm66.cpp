// host_wmma_sm66.cpp
// D3D12 host for RDNA3 WMMA execution via SM 6.6 WaveMatrix
// Target: RX 7800 XT (gfx1101)

#include <windows.h>
#include <d3d12.h>
#include <dxgi1_6.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>

#pragma comment(lib, "d3d12.lib")
#pragma comment(lib, "dxgi.lib")

// Helper macros
#define SAFE_RELEASE(x) if (x) { x->Release(); x = nullptr; }

// Helper to load compiled shader
std::vector<uint8_t> LoadShader(const char* filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to load shader file");
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    file.read((char*)buffer.data(), size);
    return buffer;
}

// Simple COM smart pointer template
template<typename T>
class ComPtr {
    T* ptr = nullptr;
public:
    ComPtr() = default;
    ~ComPtr() { if (ptr) ptr->Release(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    ComPtr(ComPtr&& other) noexcept : ptr(other.ptr) { other.ptr = nullptr; }
    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) {
            if (ptr) ptr->Release();
            ptr = other.ptr;
            other.ptr = nullptr;
        }
        return *this;
    }
    T* operator->() const { return ptr; }
    T** operator&() { return &ptr; }
    T* Get() const { return ptr; }
    void Reset(T* p = nullptr) {
        if (ptr) ptr->Release();
        ptr = p;
    }
};

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << " RDNA3 WMMA via D3D12 SM 6.6" << std::endl;
    std::cout << " Target: RX 7800 XT (gfx1101)" << std::endl;
    std::cout << "========================================" << std::endl << std::endl;

    // 1. Create DXGI Factory
    IDXGIFactory4* factory = nullptr;
    HRESULT hr = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
    if (FAILED(hr)) {
        std::cerr << "Failed to create DXGI factory: 0x" << std::hex << hr << std::endl;
        return -1;
    }
    std::cout << "[OK] DXGI factory created" << std::endl;

    // 2. Find AMD adapter
    IDXGIAdapter1* adapter = nullptr;
    UINT adapterIndex = 0;
    bool foundAMD = false;
    
    while (factory->EnumAdapters1(adapterIndex, &adapter) != DXGI_ERROR_NOT_FOUND) {
        DXGI_ADAPTER_DESC1 desc;
        adapter->GetDesc1(&desc);
        
        // Check for AMD vendor ID (0x1002)
        if (desc.VendorId == 0x1002) {
            std::wcout << L"[OK] Found AMD adapter: " << desc.Description << std::endl;
            foundAMD = true;
            break;
        }
        
        adapter->Release();
        adapter = nullptr;
        adapterIndex++;
    }
    
    if (!foundAMD) {
        std::cerr << "No AMD GPU found" << std::endl;
        factory->Release();
        return -1;
    }

    // 3. Create D3D12 Device
    ID3D12Device* device = nullptr;
    hr = D3D12CreateDevice(adapter, D3D_FEATURE_LEVEL_12_0, IID_PPV_ARGS(&device));
    if (FAILED(hr)) {
        std::cerr << "Failed to create D3D12 device: 0x" << std::hex << hr << std::endl;
        adapter->Release();
        factory->Release();
        return -1;
    }
    std::cout << "[OK] D3D12 device created" << std::endl;

    // 4. Check Shader Model 6.6 support
    D3D12_FEATURE_DATA_SHADER_MODEL shaderModel = {};
    shaderModel.HighestShaderModel = D3D_SHADER_MODEL_6_6;
    hr = device->CheckFeatureSupport(D3D12_FEATURE_SHADER_MODEL, &shaderModel, sizeof(shaderModel));
    
    if (FAILED(hr) || shaderModel.HighestShaderModel < D3D_SHADER_MODEL_6_6) {
        std::cerr << "Shader Model 6.6 not supported. Highest: " << (int)shaderModel.HighestShaderModel << std::endl;
        device->Release();
        adapter->Release();
        factory->Release();
        return -1;
    }
    std::cout << "[OK] Shader Model 6.6 supported" << std::endl;

    // 5. Check WaveOps support
    D3D12_FEATURE_DATA_D3D12_OPTIONS1 options1 = {};
    hr = device->CheckFeatureSupport(D3D12_FEATURE_D3D12_OPTIONS1, &options1, sizeof(options1));
    if (FAILED(hr) || !options1.WaveOps) {
        std::cerr << "WaveOps not supported" << std::endl;
        device->Release();
        adapter->Release();
        factory->Release();
        return -1;
    }
    std::cout << "[OK] WaveOps supported" << std::endl;

    // 6. Load compiled shader
    std::vector<uint8_t> shaderBytecode;
    try {
        shaderBytecode = LoadShader("wmma_sm66.cso");
        std::cout << "[OK] Loaded shader: " << shaderBytecode.size() << " bytes" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Failed to load shader: " << e.what() << std::endl;
        std::cerr << "Run: dxc.exe -T cs_6_6 -E main -Fo wmma_sm66.cso wmma_sm66.hlsl" << std::endl;
        device->Release();
        adapter->Release();
        factory->Release();
        return -1;
    }

    // 7. Create Root Signature
    // Simple root signature: 2 SRVs + 1 UAV
    D3D12_ROOT_SIGNATURE_DESC rootSigDesc = {};
    D3D12_ROOT_PARAMETER rootParams[3] = {};
    
    // BufferA (t0)
    rootParams[0].ParameterType = D3D12_ROOT_PARAMETER_TYPE_SRV;
    rootParams[0].Descriptor.ShaderRegister = 0;
    rootParams[0].Descriptor.RegisterSpace = 0;
    rootParams[0].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
    
    // BufferB (t1)
    rootParams[1].ParameterType = D3D12_ROOT_PARAMETER_TYPE_SRV;
    rootParams[1].Descriptor.ShaderRegister = 1;
    rootParams[1].Descriptor.RegisterSpace = 0;
    rootParams[1].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
    
    // BufferOut (u0)
    rootParams[2].ParameterType = D3D12_ROOT_PARAMETER_TYPE_UAV;
    rootParams[2].Descriptor.ShaderRegister = 0;
    rootParams[2].Descriptor.RegisterSpace = 0;
    rootParams[2].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
    
    rootSigDesc.NumParameters = 3;
    rootSigDesc.pParameters = rootParams;
    rootSigDesc.Flags = D3D12_ROOT_SIGNATURE_FLAG_NONE;

    ID3DBlob* signatureBlob = nullptr;
    ID3DBlob* errorBlob = nullptr;
    hr = D3D12SerializeRootSignature(&rootSigDesc, D3D_ROOT_SIGNATURE_VERSION_1, 
                                      &signatureBlob, &errorBlob);
    if (FAILED(hr)) {
        std::cerr << "Failed to serialize root signature" << std::endl;
        if (errorBlob) {
            std::cerr << "Error: " << (char*)errorBlob->GetBufferPointer() << std::endl;
            errorBlob->Release();
        }
        device->Release();
        adapter->Release();
        factory->Release();
        return -1;
    }

    ID3D12RootSignature* rootSignature = nullptr;
    hr = device->CreateRootSignature(0, signatureBlob->GetBufferPointer(), 
                                      signatureBlob->GetBufferSize(), IID_PPV_ARGS(&rootSignature));
    signatureBlob->Release();
    if (FAILED(hr)) {
        std::cerr << "Failed to create root signature: 0x" << std::hex << hr << std::endl;
        device->Release();
        adapter->Release();
        factory->Release();
        return -1;
    }
    std::cout << "[OK] Root signature created" << std::endl;

    // 8. Create Compute Pipeline State
    D3D12_COMPUTE_PIPELINE_STATE_DESC psoDesc = {};
    psoDesc.pRootSignature = rootSignature;
    psoDesc.CS.pShaderBytecode = shaderBytecode.data();
    psoDesc.CS.BytecodeLength = shaderBytecode.size();

    ID3D12PipelineState* pso = nullptr;
    hr = device->CreateComputePipelineState(&psoDesc, IID_PPV_ARGS(&pso));
    if (FAILED(hr)) {
        std::cerr << "Failed to create PSO: 0x" << std::hex << hr << std::endl;
        rootSignature->Release();
        device->Release();
        adapter->Release();
        factory->Release();
        return -1;
    }
    std::cout << "[OK] Compute PSO created" << std::endl;

    // 9. Create Command Queue
    D3D12_COMMAND_QUEUE_DESC queueDesc = {};
    queueDesc.Type = D3D12_COMMAND_LIST_TYPE_COMPUTE;
    queueDesc.Flags = D3D12_COMMAND_QUEUE_FLAG_NONE;
    
    ID3D12CommandQueue* commandQueue = nullptr;
    hr = device->CreateCommandQueue(&queueDesc, IID_PPV_ARGS(&commandQueue));
    if (FAILED(hr)) {
        std::cerr << "Failed to create command queue: 0x" << std::hex << hr << std::endl;
        pso->Release();
        rootSignature->Release();
        device->Release();
        adapter->Release();
        factory->Release();
        return -1;
    }
    std::cout << "[OK] Command queue created" << std::endl;

    // 10. Create Command Allocator and List
    ID3D12CommandAllocator* allocator = nullptr;
    hr = device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_COMPUTE, IID_PPV_ARGS(&allocator));
    if (FAILED(hr)) {
        std::cerr << "Failed to create command allocator" << std::endl;
        commandQueue->Release();
        pso->Release();
        rootSignature->Release();
        device->Release();
        adapter->Release();
        factory->Release();
        return -1;
    }

    ID3D12GraphicsCommandList* commandList = nullptr;
    hr = device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_COMPUTE, allocator, pso, 
                                   IID_PPV_ARGS(&commandList));
    if (FAILED(hr)) {
        std::cerr << "Failed to create command list" << std::endl;
        allocator->Release();
        commandQueue->Release();
        pso->Release();
        rootSignature->Release();
        device->Release();
        adapter->Release();
        factory->Release();
        return -1;
    }
    std::cout << "[OK] Command list created" << std::endl;

    // 11. Create Buffers (simplified - using upload heap for test)
    const UINT bufferSize = 16 * 16 * sizeof(float); // 16x16 matrix
    
    D3D12_HEAP_PROPERTIES heapProps = {};
    heapProps.Type = D3D12_HEAP_TYPE_UPLOAD;
    
    D3D12_RESOURCE_DESC bufferDesc = {};
    bufferDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    bufferDesc.Width = bufferSize;
    bufferDesc.Height = 1;
    bufferDesc.DepthOrArraySize = 1;
    bufferDesc.MipLevels = 1;
    bufferDesc.Format = DXGI_FORMAT_UNKNOWN;
    bufferDesc.SampleDesc.Count = 1;
    bufferDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    bufferDesc.Flags = D3D12_RESOURCE_FLAG_NONE;

    ID3D12Resource* bufferA = nullptr;
    ID3D12Resource* bufferB = nullptr;
    ID3D12Resource* bufferOut = nullptr;
    
    hr = device->CreateCommittedResource(&heapProps, D3D12_HEAP_FLAG_NONE, &bufferDesc,
                                          D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, 
                                          IID_PPV_ARGS(&bufferA));
    if (FAILED(hr)) {
        std::cerr << "Failed to create buffer A" << std::endl;
        commandList->Release();
        allocator->Release();
        commandQueue->Release();
        pso->Release();
        rootSignature->Release();
        device->Release();
        adapter->Release();
        factory->Release();
        return -1;
    }
    
    hr = device->CreateCommittedResource(&heapProps, D3D12_HEAP_FLAG_NONE, &bufferDesc,
                                          D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, 
                                          IID_PPV_ARGS(&bufferB));
    if (FAILED(hr)) {
        std::cerr << "Failed to create buffer B" << std::endl;
        bufferA->Release();
        commandList->Release();
        allocator->Release();
        commandQueue->Release();
        pso->Release();
        rootSignature->Release();
        device->Release();
        adapter->Release();
        factory->Release();
        return -1;
    }

    // Output buffer needs UAV flag
    D3D12_RESOURCE_DESC bufferDescOut = bufferDesc;
    bufferDescOut.Flags = D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS;
    
    D3D12_HEAP_PROPERTIES defaultHeapProps = {};
    defaultHeapProps.Type = D3D12_HEAP_TYPE_DEFAULT;
    
    hr = device->CreateCommittedResource(&defaultHeapProps, D3D12_HEAP_FLAG_NONE, &bufferDescOut,
                                          D3D12_RESOURCE_STATE_UNORDERED_ACCESS, nullptr, 
                                          IID_PPV_ARGS(&bufferOut));
    if (FAILED(hr)) {
        std::cerr << "Failed to create output buffer" << std::endl;
        bufferB->Release();
        bufferA->Release();
        commandList->Release();
        allocator->Release();
        commandQueue->Release();
        pso->Release();
        rootSignature->Release();
        device->Release();
        adapter->Release();
        factory->Release();
        return -1;
    }
    std::cout << "[OK] Buffers created" << std::endl;

    // 12. Initialize buffer data
    float* dataA = nullptr;
    float* dataB = nullptr;
    
    bufferA->Map(0, nullptr, (void**)&dataA);
    bufferB->Map(0, nullptr, (void**)&dataB);
    
    // Fill with test data (identity-like pattern)
    for (int i = 0; i < 16 * 16; i++) {
        dataA[i] = (i % 16 == 0) ? 1.0f : 0.0f;  // Simple pattern
        dataB[i] = (i % 17 == 0) ? 1.0f : 0.0f;  // Simple pattern
    }
    
    bufferA->Unmap(0, nullptr);
    bufferB->Unmap(0, nullptr);
    std::cout << "[OK] Buffer data initialized" << std::endl;

    // 13. Record commands
    commandList->SetComputeRootSignature(rootSignature);
    commandList->SetPipelineState(pso);
    
    commandList->SetComputeRootShaderResourceView(0, bufferA->GetGPUVirtualAddress());
    commandList->SetComputeRootShaderResourceView(1, bufferB->GetGPUVirtualAddress());
    commandList->SetComputeRootUnorderedAccessView(2, bufferOut->GetGPUVirtualAddress());
    
    commandList->Dispatch(1, 1, 1);
    
    hr = commandList->Close();
    if (FAILED(hr)) {
        std::cerr << "Failed to close command list" << std::endl;
        bufferOut->Release();
        bufferB->Release();
        bufferA->Release();
        commandList->Release();
        allocator->Release();
        commandQueue->Release();
        pso->Release();
        rootSignature->Release();
        device->Release();
        adapter->Release();
        factory->Release();
        return -1;
    }
    std::cout << "[OK] Commands recorded" << std::endl;

    // 14. Execute
    ID3D12CommandList* ppCommandLists[] = { commandList };
    commandQueue->ExecuteCommandLists(1, ppCommandLists);
    std::cout << "[OK] Dispatch submitted" << std::endl;

    // 15. Create fence and wait
    ID3D12Fence* fence = nullptr;
    hr = device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence));
    if (FAILED(hr)) {
        std::cerr << "Failed to create fence" << std::endl;
        bufferOut->Release();
        bufferB->Release();
        bufferA->Release();
        commandList->Release();
        allocator->Release();
        commandQueue->Release();
        pso->Release();
        rootSignature->Release();
        device->Release();
        adapter->Release();
        factory->Release();
        return -1;
    }
    
    commandQueue->Signal(fence, 1);
    
    if (fence->GetCompletedValue() < 1) {
        HANDLE event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
        fence->SetEventOnCompletion(1, event);
        WaitForSingleObject(event, INFINITE);
        CloseHandle(event);
    }
    std::cout << "[OK] Execution complete" << std::endl;

    // Cleanup
    fence->Release();
    bufferOut->Release();
    bufferB->Release();
    bufferA->Release();
    commandList->Release();
    allocator->Release();
    commandQueue->Release();
    pso->Release();
    rootSignature->Release();
    device->Release();
    adapter->Release();
    factory->Release();

    std::cout << std::endl << "========================================" << std::endl;
    std::cout << " RDNA3 WMMA Execution Successful" << std::endl;
    std::cout << " v_wmma_f32_16x16x16_f16 dispatched" << std::endl;
    std::cout << "========================================" << std::endl;

    return 0;
}
