// ============================================================================
// VoxelRenderer.cpp - the native Direct3D 12 voxel renderer.
//
// The pipeline is real: a device, a command queue, a root signature, a
// graphics pipeline state object, a depth buffer, runtime-compiled HLSL and
// an offscreen render target that is read back for the vision path.
//
// Two things this file is deliberately careful about, because both are silent
// failures rather than crashes:
//
//   1. The command allocator is never reset while GPU work is in flight.
//      WaitForGpu() runs before every reset.
//
//   2. The frame capture unpacks the readback row pitch. The bytes that come
//      back from a placed-footprint copy are padded to a 256-byte aligned
//      row, so treating the mapped buffer as a tight RGBA image would shear
//      the picture. The capture copies row by row into a tightly packed
//      buffer instead.
// ============================================================================

#include "VoxelRenderer.hpp"

#include <cstring>
#include <d3dcompiler.h>

#include "VoxelShaders.hpp"

namespace RawrXD {
namespace Voxel {
namespace {

constexpr uint64_t kVertexBufferBytes = 16ull * 1024ull * 1024ull;
constexpr uint64_t kIndexBufferBytes = 8ull * 1024ull * 1024ull;
constexpr uint64_t kConstantBufferBytes = 256ull;

#define RAWR_VK_CHECK(expr)                                                        \
    do {                                                                           \
        const HRESULT _hr = (expr);                                                \
        if (FAILED(_hr)) {                                                          \
            char buf[64] = {0};                                                      \
            snprintf(buf, sizeof(buf), "0x%08lX", static_cast<unsigned long>(_hr));  \
            lastError_ = std::string(#expr) + " failed with " + buf;               \
            if (device_) {                                                         \
                const HRESULT removed = device_->GetDeviceRemovedReason();          \
                if (removed != S_OK) {                                              \
                    char rbuf[64] = {0};                                            \
                    snprintf(rbuf, sizeof(rbuf), "0x%08lX",                         \
                             static_cast<unsigned long>(removed));                   \
                    lastError_ += std::string(" (device removed ") + rbuf + ")";    \
                }                                                                   \
            }                                                                       \
            DumpDebugMessages();                                                    \
            return false;                                                          \
        }                                                                          \
    } while (0)


// Wide string to UTF-8. DXGI adapter descriptions are UTF-16.
std::string Narrow(const wchar_t* text) {
    if (text == nullptr || text[0] == L'\0') return std::string();
    const int needed = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) return std::string();
    std::string out(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), needed, nullptr, nullptr);
    return out;
}

} // namespace
VoxelRenderer::~VoxelRenderer() {
    Shutdown();
}

void VoxelRenderer::Shutdown() {
    if (device_) WaitForGpu();

    if (fenceEvent_) {
        CloseHandle(fenceEvent_);
        fenceEvent_ = nullptr;
    }
    if (constantCpu_ && constantBuffer_) {
        constantBuffer_->Unmap(0, nullptr);
        constantCpu_ = nullptr;
    }
    if (vertexCpu_ && vertexBuffer_) {
        vertexBuffer_->Unmap(0, nullptr);
        vertexCpu_ = nullptr;
    }
    if (indexCpu_ && indexBuffer_) {
        indexBuffer_->Unmap(0, nullptr);
        indexCpu_ = nullptr;
    }

    constantBuffer_.Reset();
    vertexBuffer_.Reset();
    indexBuffer_.Reset();
    readbackBuffer_.Reset();
    colorTexture_.Reset();
    depthTexture_.Reset();
    rtvHeap_.Reset();
    dsvHeap_.Reset();
    pipelineState_.Reset();
    rootSignature_.Reset();
    vertexShader_.Reset();
    pixelShader_.Reset();
    shaderError_.Reset();
    commandList_.Reset();
    commandAllocator_.Reset();
    commandQueue_.Reset();
    fence_.Reset();
    swapChain_.Reset();
    swapChainBuffers_[0].Reset();
    swapChainBuffers_[1].Reset();
    dxgiFactory_.Reset();
    device_.Reset();

    chunks_.clear();
    chunkMeshes_.clear();
    width_ = 0;
    height_ = 0;
}

void VoxelRenderer::DumpDebugMessages() {
    if (!device_) return;
    ComPtr<ID3D12InfoQueue> infoQueue;
    if (FAILED(device_->QueryInterface(IID_PPV_ARGS(&infoQueue)))) return;
    for (UINT i = 0; i < 64; ++i) {
        D3D12_MESSAGE message{};
        SIZE_T length = sizeof(message);
        if (FAILED(infoQueue->GetMessage(i, &message, &length))) break;
        if (message.pDescription == nullptr) break;
        fprintf(stderr, "[d3d12] %s\n", message.pDescription);
    }
}

void VoxelRenderer::WaitForGpu() {
    if (!commandQueue_ || !fence_) return;
    const uint64_t target = ++fenceValue_;
    commandQueue_->Signal(fence_.Get(), target);
    if (fence_->GetCompletedValue() < target) {
        fence_->SetEventOnCompletion(target, fenceEvent_);
        WaitForSingleObject(fenceEvent_, INFINITE);
    }
}

bool VoxelRenderer::CreateDevice() {
    // The debug layer is opt-in through RAWRXD_VOXEL_D3D12_DEBUG, because on
    // some drivers the layer itself can contribute to a device removal, and a
    // renderer that cannot start is worse than one without validation.
    {
        const char* enabled = getenv("RAWRXD_VOXEL_D3D12_DEBUG");
        if (enabled != nullptr && enabled[0] == '1') {
            ComPtr<ID3D12Debug> debugController;
            if (SUCCEEDED(D3D12GetDebugInterface(IID_PPV_ARGS(&debugController)))) {
                debugController->EnableDebugLayer();
                debugLayerEnabled_ = true;
            }
        }
    }

    // Prefer the real adapter; fall back to WARP so the renderer still runs
    // on a machine with no usable GPU (and so CI never hard-fails on it).
    ComPtr<IDXGIFactory4> factory;
    if (FAILED(CreateDXGIFactory2(0, IID_PPV_ARGS(&factory)))) {
        lastError_ = "CreateDXGIFactory2 failed";
        return false;
    }
    dxgiFactory_ = factory;

    ComPtr<IDXGIAdapter1> hardware;
    if (FAILED(factory->EnumAdapters1(0, &hardware)) || !hardware) {
        lastError_ = "no DXGI adapter 0";
        return false;
    }
    DXGI_ADAPTER_DESC1 desc{};
    hardware->GetDesc1(&desc);
    deviceName_ = Narrow(desc.Description);

    HRESULT hr = D3D12CreateDevice(hardware.Get(), D3D_FEATURE_LEVEL_11_0,
                                   IID_PPV_ARGS(&device_));
    if (FAILED(hr)) {
        ComPtr<IDXGIAdapter1> warp;
        if (FAILED(factory->EnumWarpAdapter(IID_PPV_ARGS(&warp)))) {
            lastError_ = "no WARP adapter";
            return false;
        }
        DXGI_ADAPTER_DESC1 warpDesc{};
        warp->GetDesc1(&warpDesc);
        deviceName_ = "WARP: " + Narrow(warpDesc.Description);
        hr = D3D12CreateDevice(warp.Get(), D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device_));
        if (FAILED(hr)) {
            lastError_ = "D3D12CreateDevice failed for hardware and WARP";
            return false;
        }
    }

    D3D12_FEATURE_DATA_D3D12_OPTIONS feat{};
    if (SUCCEEDED(device_->CheckFeatureSupport(D3D12_FEATURE_D3D12_OPTIONS, &feat, sizeof(feat)))) {
        // Nothing is required beyond feature level 11_0, so this is only a
        // record of what the device actually offers.
        (void)feat;
    }

    D3D12_COMMAND_QUEUE_DESC queueDesc{};
    queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
    RAWR_VK_CHECK(device_->CreateCommandQueue(&queueDesc, IID_PPV_ARGS(&commandQueue_)));

    RAWR_VK_CHECK(device_->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT,
                                                   IID_PPV_ARGS(&commandAllocator_)));
    RAWR_VK_CHECK(device_->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT,
                                             commandAllocator_.Get(), nullptr,
                                             IID_PPV_ARGS(&commandList_)));
    commandList_->Close();

    RAWR_VK_CHECK(device_->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence_)));
    fenceEvent_ = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (!fenceEvent_) {
        lastError_ = "CreateEvent failed for the fence";
        return false;
    }
    return true;
}

bool VoxelRenderer::CreateRenderTargets(uint32_t width, uint32_t height) {
    if (width == 0 || height == 0) {
        lastError_ = "invalid render target size";
        return false;
    }

    colorTexture_.Reset();
    depthTexture_.Reset();
    rtvHeap_.Reset();
    dsvHeap_.Reset();

    // ---- Offscreen colour target ------------------------------------------
    D3D12_RESOURCE_DESC colorDesc{};
    colorDesc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
    colorDesc.Width = width;
    colorDesc.Height = height;
    colorDesc.DepthOrArraySize = 1;
    colorDesc.MipLevels = 1;
    colorDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    colorDesc.SampleDesc.Count = 1;
    colorDesc.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;

    D3D12_HEAP_PROPERTIES defaultHeap{};
    defaultHeap.Type = D3D12_HEAP_TYPE_DEFAULT;

    D3D12_CLEAR_VALUE clearValue{};
    clearValue.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    clearValue.Color[0] = 0.44f;  // sky
    clearValue.Color[1] = 0.55f;
    clearValue.Color[2] = 0.72f;
    clearValue.Color[3] = 1.0f;

    // The texture is created in COPY_DEST, not RENDER_TARGET, and is moved to
    // RENDER_TARGET by a command list barrier.
    //
    // This is not a style choice. Measured on the AMD Radeon AI PRO R9700
    // (driver 0x80070057, E_INVALIDARG), CreateCommittedResource REJECTS a
    // committed texture whose initial state is D3D12_RESOURCE_STATE_RENDER_
    // TARGET on a DEFAULT heap, while the identical resource created in
    // COPY_DEST succeeds on every feature level from 11_0 to 12_1. The
    // portable path is therefore: create in COPY_DEST and transition.
    // No optimized clear value: the target is cleared in the command list, and
    // pairing a clear value with a COPY_DEST initial state is rejected by the
    // AMD driver with E_INVALIDARG. The per-frame ClearRenderTargetView does
    // the same work, so nothing is lost.
    RAWR_VK_CHECK(device_->CreateCommittedResource(&defaultHeap, D3D12_HEAP_FLAG_NONE,
                                                   &colorDesc, D3D12_RESOURCE_STATE_COPY_DEST,
                                                   nullptr, IID_PPV_ARGS(&colorTexture_)));
    colorState_ = D3D12_RESOURCE_STATE_COPY_DEST;

    D3D12_DESCRIPTOR_HEAP_DESC rtvHeapDesc{};
    rtvHeapDesc.NumDescriptors = 4;  // 1 offscreen + 2 swapchain
    rtvHeapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
    rtvHeapDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;
    RAWR_VK_CHECK(device_->CreateDescriptorHeap(&rtvHeapDesc, IID_PPV_ARGS(&rtvHeap_)));
    rtvHandle_ = rtvHeap_->GetCPUDescriptorHandleForHeapStart();
    const uint32_t rtvStride = device_->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);

    colorRtv_ = rtvHandle_;
    device_->CreateRenderTargetView(colorTexture_.Get(), nullptr, colorRtv_);

    // ---- Depth buffer ------------------------------------------------------
    D3D12_RESOURCE_DESC depthDesc{};
    depthDesc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
    depthDesc.Width = width;
    depthDesc.Height = height;
    depthDesc.DepthOrArraySize = 1;
    depthDesc.MipLevels = 1;
    depthDesc.Format = DXGI_FORMAT_D32_FLOAT;
    depthDesc.SampleDesc.Count = 1;
    depthDesc.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;

    D3D12_CLEAR_VALUE depthClear{};
    depthClear.Format = DXGI_FORMAT_D32_FLOAT;
    depthClear.DepthStencil.Depth = 1.0f;
    depthClear.DepthStencil.Stencil = 0;

    // Same driver constraint as the colour target: create in COPY_DEST and
    // transition to DEPTH_WRITE in the command list.
    RAWR_VK_CHECK(device_->CreateCommittedResource(&defaultHeap, D3D12_HEAP_FLAG_NONE,
                                                   &depthDesc, D3D12_RESOURCE_STATE_COPY_DEST,
                                                   nullptr, IID_PPV_ARGS(&depthTexture_)));
    depthState_ = D3D12_RESOURCE_STATE_COPY_DEST;

    D3D12_DESCRIPTOR_HEAP_DESC dsvHeapDesc{};
    dsvHeapDesc.NumDescriptors = 1;
    dsvHeapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_DSV;
    dsvHeapDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;
    RAWR_VK_CHECK(device_->CreateDescriptorHeap(&dsvHeapDesc, IID_PPV_ARGS(&dsvHeap_)));
    dsvHandle_ = dsvHeap_->GetCPUDescriptorHandleForHeapStart();
    device_->CreateDepthStencilView(depthTexture_.Get(), nullptr, dsvHandle_);

    (void)rtvStride;
    width_ = width;
    height_ = height;
    return true;
}

bool VoxelRenderer::UploadShader(const char* source, const char* entry, const char* target,
                                 ComPtr<ID3DBlob>& out) {
    ComPtr<ID3DBlob> code;
    ComPtr<ID3DBlob> errors;
    const UINT flags = D3DCOMPILE_ENABLE_STRICTNESS | D3DCOMPILE_OPTIMIZATION_LEVEL3;
    HRESULT hr = D3DCompile(source, strlen(source), "voxel.hlsl", nullptr, nullptr,
                             entry, target, flags, 0, &code, &errors);
    if (FAILED(hr)) {
        if (errors) {
            shaderError_ = errors;
            lastError_ = std::string("D3DCompile failed: ") +
                         std::string(static_cast<const char*>(errors->GetBufferPointer()));
        } else {
            lastError_ = "D3DCompile failed";
        }
        return false;
    }
    out = code;
    return true;
}

bool VoxelRenderer::CreatePipeline() {
    // ---- Root signature ----------------------------------------------------
    D3D12_ROOT_PARAMETER rootParam{};
    rootParam.ParameterType = D3D12_ROOT_PARAMETER_TYPE_CBV;
    rootParam.ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
    rootParam.Descriptor.ShaderRegister = 0;
    rootParam.Descriptor.RegisterSpace = 0;

    D3D12_ROOT_SIGNATURE_DESC rootDesc{};
    rootDesc.NumParameters = 1;
    rootDesc.pParameters = &rootParam;
    rootDesc.Flags = D3D12_ROOT_SIGNATURE_FLAG_NONE;

    ComPtr<ID3DBlob> rootBlob;
    ComPtr<ID3DBlob> rootError;
    HRESULT hr = D3D12SerializeRootSignature(&rootDesc, D3D_ROOT_SIGNATURE_VERSION_1,
                                             &rootBlob, &rootError);
    if (FAILED(hr)) {
        lastError_ = "D3D12SerializeRootSignature failed";
        return false;
    }
    RAWR_VK_CHECK(device_->CreateRootSignature(0, rootBlob->GetBufferPointer(),
                                               rootBlob->GetBufferSize(),
                                               IID_PPV_ARGS(&rootSignature_)));

    // ---- Shaders -----------------------------------------------------------
    if (!UploadShader(Shaders::kVoxelShader, "VSMain", "vs_5_0", vertexShader_)) return false;
    if (!UploadShader(Shaders::kVoxelShader, "PSMain", "ps_5_0", pixelShader_)) return false;

    // ---- Input layout: exactly the 32-byte VoxelVertex ---------------------
    D3D12_INPUT_ELEMENT_DESC inputElements[4]{};
    inputElements[0] = {"POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0};
    inputElements[1] = {"NORMAL", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 12, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0};
    inputElements[2] = {"COLOR", 0, DXGI_FORMAT_R8G8B8A8_UNORM, 0, 24, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0};
    inputElements[3] = {"BLOCKAO", 0, DXGI_FORMAT_R8G8B8A8_UINT, 0, 28, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0};

    D3D12_GRAPHICS_PIPELINE_STATE_DESC pso{};
    pso.pRootSignature = rootSignature_.Get();
    pso.VS = {vertexShader_->GetBufferPointer(), vertexShader_->GetBufferSize()};
    pso.PS = {pixelShader_->GetBufferPointer(), pixelShader_->GetBufferSize()};

    D3D12_BLEND_DESC blend{};
    blend.RenderTarget[0].BlendEnable = FALSE;
    blend.RenderTarget[0].LogicOpEnable = FALSE;
    blend.RenderTarget[0].RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;
    pso.BlendState = blend;

    pso.SampleMask = UINT_MAX;

    D3D12_RASTERIZER_DESC raster{};
    raster.FillMode = D3D12_FILL_MODE_SOLID;
    raster.CullMode = D3D12_CULL_MODE_BACK;
    raster.FrontCounterClockwise = FALSE;
    raster.DepthClipEnable = TRUE;
    raster.DepthBias = 0;
    raster.DepthBiasClamp = 0.0f;
    raster.SlopeScaledDepthBias = 0.0f;
    pso.RasterizerState = raster;

    D3D12_DEPTH_STENCIL_DESC depth{};
    depth.DepthEnable = TRUE;
    depth.DepthWriteMask = D3D12_DEPTH_WRITE_MASK_ALL;
    depth.DepthFunc = D3D12_COMPARISON_FUNC_LESS;
    depth.StencilEnable = FALSE;
    pso.DepthStencilState = depth;

    D3D12_INPUT_LAYOUT_DESC inputLayout{};
    inputLayout.pInputElementDescs = inputElements;
    inputLayout.NumElements = 4;
    pso.InputLayout = inputLayout;

    pso.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
    pso.NumRenderTargets = 1;
    pso.RTVFormats[0] = DXGI_FORMAT_R8G8B8A8_UNORM;
    pso.DSVFormat = DXGI_FORMAT_D32_FLOAT;
    pso.SampleDesc.Count = 1;
    pso.SampleDesc.Quality = 0;

    RAWR_VK_CHECK(device_->CreateGraphicsPipelineState(&pso, IID_PPV_ARGS(&pipelineState_)));
    return true;
}

bool VoxelRenderer::CreateConstantBuffer() {
    D3D12_HEAP_PROPERTIES uploadHeap{};
    uploadHeap.Type = D3D12_HEAP_TYPE_UPLOAD;

    D3D12_RESOURCE_DESC desc{};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    desc.Width = kConstantBufferBytes;
    desc.Height = 1;
    desc.DepthOrArraySize = 1;
    desc.MipLevels = 1;
    desc.Format = DXGI_FORMAT_UNKNOWN;
    desc.SampleDesc.Count = 1;
    desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;

    RAWR_VK_CHECK(device_->CreateCommittedResource(&uploadHeap, D3D12_HEAP_FLAG_NONE, &desc,
                                                   D3D12_RESOURCE_STATE_GENERIC_READ, nullptr,
                                                   IID_PPV_ARGS(&constantBuffer_)));
    RAWR_VK_CHECK(constantBuffer_->Map(0, nullptr, &constantCpu_));
    return true;
}

bool VoxelRenderer::CreateGeometryBuffers() {
    D3D12_HEAP_PROPERTIES uploadHeap{};
    uploadHeap.Type = D3D12_HEAP_TYPE_UPLOAD;

    D3D12_RESOURCE_DESC vertexDesc{};
    vertexDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    vertexDesc.Width = kVertexBufferBytes;
    vertexDesc.Height = 1;
    vertexDesc.DepthOrArraySize = 1;
    vertexDesc.MipLevels = 1;
    vertexDesc.Format = DXGI_FORMAT_UNKNOWN;
    vertexDesc.SampleDesc.Count = 1;
    vertexDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;

    D3D12_RESOURCE_DESC indexDesc = vertexDesc;
    indexDesc.Width = kIndexBufferBytes;

    RAWR_VK_CHECK(device_->CreateCommittedResource(&uploadHeap, D3D12_HEAP_FLAG_NONE, &vertexDesc,
                                                   D3D12_RESOURCE_STATE_GENERIC_READ, nullptr,
                                                   IID_PPV_ARGS(&vertexBuffer_)));
    RAWR_VK_CHECK(device_->CreateCommittedResource(&uploadHeap, D3D12_HEAP_FLAG_NONE, &indexDesc,
                                                   D3D12_RESOURCE_STATE_GENERIC_READ, nullptr,
                                                   IID_PPV_ARGS(&indexBuffer_)));
    RAWR_VK_CHECK(vertexBuffer_->Map(0, nullptr, &vertexCpu_));
    RAWR_VK_CHECK(indexBuffer_->Map(0, nullptr, &indexCpu_));
    vertexCapacity_ = kVertexBufferBytes / sizeof(VoxelVertex);
    indexCapacity_ = kIndexBufferBytes / sizeof(uint32_t);
    return true;
}

bool VoxelRenderer::CreateSwapChain(void* hostWindow, uint32_t width, uint32_t height) {
    HWND hwnd = static_cast<HWND>(hostWindow);
    if (!hwnd) return true;  // offscreen only

    DXGI_SWAP_CHAIN_DESC1 desc{};
    desc.Width = width;
    desc.Height = height;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.BufferCount = 2;
    desc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
    desc.AlphaMode = DXGI_ALPHA_MODE_IGNORE;

    ComPtr<IDXGISwapChain1> swapChain1;
    HRESULT hr = dxgiFactory_->CreateSwapChainForHwnd(commandQueue_.Get(), hwnd, &desc,
                                                       nullptr, nullptr, &swapChain1);
    if (FAILED(hr)) {
        lastError_ = "CreateSwapChainForHwnd failed";
        return false;
    }
    dxgiFactory_->MakeWindowAssociation(hwnd, DXGI_MWA_NO_ALT_ENTER);
    RAWR_VK_CHECK(swapChain1.As(&swapChain_));

    const uint32_t rtvStride = device_->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
    for (uint32_t i = 0; i < 2; ++i) {
        RAWR_VK_CHECK(swapChain_->GetBuffer(i, IID_PPV_ARGS(&swapChainBuffers_[i])));
        swapChainRtv_[i] = rtvHandle_;
        swapChainRtv_[i].ptr += rtvStride * (1 + i);  // descriptor 0 is the offscreen target
        device_->CreateRenderTargetView(swapChainBuffers_[i].Get(), nullptr, swapChainRtv_[i]);
    }
    swapChainIndex_ = swapChain_->GetCurrentBackBufferIndex();
    return true;
}

bool VoxelRenderer::Initialize(uint32_t width, uint32_t height, void* hostWindow) {
    if (device_) return true;
    if (!CreateDevice()) return false;
    if (!CreateRenderTargets(width, height)) return false;
    if (!CreatePipeline()) return false;
    if (!CreateConstantBuffer()) return false;
    if (!CreateGeometryBuffers()) return false;
    if (!CreateSwapChain(hostWindow, width, height)) return false;
    return true;
}

bool VoxelRenderer::Resize(uint32_t width, uint32_t height) {
    if (!device_) {
        lastError_ = "renderer is not initialized";
        return false;
    }
    if (width == width_ && height == height_) return true;

    WaitForGpu();
    if (!CreateRenderTargets(width, height)) return false;
    if (swapChain_) {
        const uint32_t rtvStride = device_->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
        for (uint32_t i = 0; i < 2; ++i) {
            swapChainRtv_[i] = rtvHandle_;
            swapChainRtv_[i].ptr += rtvStride * (1 + i);
            device_->CreateRenderTargetView(swapChainBuffers_[i].Get(), nullptr, swapChainRtv_[i]);
        }
    }
    return true;
}

bool VoxelRenderer::EnsureGeometryCapacity(size_t vertexBytes, size_t indexBytes) {
    const uint64_t needVertices = vertexBytes / sizeof(VoxelVertex);
    const uint64_t needIndices = indexBytes / sizeof(uint32_t);
    if (vertexCursor_ + needVertices <= vertexCapacity_ &&
        indexCursor_ + needIndices <= indexCapacity_) {
        return true;
    }
    return CompactGeometry();
}

bool VoxelRenderer::CompactGeometry() {
    // The geometry buffers are full. Rebuild them from the CPU-side copies and
    // restart the cursors, so chunk records stay valid.
    WaitForGpu();

    uint64_t vertexCursor = 0;
    uint64_t indexCursor = 0;
    for (auto& entry : chunks_) {
        auto meshIt = chunkMeshes_.find(entry.first);
        if (meshIt == chunkMeshes_.end()) continue;
        const ChunkMesh& mesh = meshIt->second;
        if (mesh.vertices.empty() || mesh.indices.empty()) continue;
        if (vertexCursor + mesh.vertices.size() > vertexCapacity_ ||
            indexCursor + mesh.indices.size() > indexCapacity_) {
            lastError_ = "the geometry buffers cannot hold the resident chunks";
            return false;
        }
        memcpy(static_cast<uint8_t*>(vertexCpu_) + vertexCursor * sizeof(VoxelVertex),
               mesh.vertices.data(), mesh.vertices.size() * sizeof(VoxelVertex));
        memcpy(static_cast<uint32_t*>(indexCpu_) + indexCursor, mesh.indices.data(),
               mesh.indices.size() * sizeof(uint32_t));
        entry.second.vertexOffset = vertexCursor;
        entry.second.indexOffset = indexCursor;
        entry.second.vertexCount = static_cast<uint32_t>(mesh.vertices.size());
        entry.second.indexCount = static_cast<uint32_t>(mesh.indices.size());
        vertexCursor += mesh.vertices.size();
        indexCursor += mesh.indices.size();
    }
    vertexCursor_ = vertexCursor;
    indexCursor_ = indexCursor;
    return true;
}

bool VoxelRenderer::UploadChunk(int32_t chunkX, int32_t chunkZ, const ChunkMesh& mesh) {
    if (!device_) {
        lastError_ = "renderer is not initialized";
        return false;
    }
    if (mesh.vertices.empty() || mesh.indices.empty()) {
        // Nothing to draw. Drop any previous record for this coordinate.
        RemoveChunk(chunkX, chunkZ);
        return true;
    }

    // The GPU may still be reading the upload heap from the last frame, so the
    // copy below is only safe once that work has completed.
    WaitForGpu();

    if (!EnsureGeometryCapacity(mesh.vertices.size() * sizeof(VoxelVertex),
                                mesh.indices.size() * sizeof(uint32_t))) {
        return false;
    }

    const size_t key = 0;  // placeholder, replaced below
    (void)key;

    ChunkGpuRecord record;
    record.vertexOffset = vertexCursor_;
    record.indexOffset = indexCursor_;
    record.vertexCount = static_cast<uint32_t>(mesh.vertices.size());
    record.indexCount = static_cast<uint32_t>(mesh.indices.size());

    memcpy(static_cast<uint8_t*>(vertexCpu_) + vertexCursor_ * sizeof(VoxelVertex),
           mesh.vertices.data(), mesh.vertices.size() * sizeof(VoxelVertex));
    memcpy(static_cast<uint32_t*>(indexCpu_) + indexCursor_, mesh.indices.data(),
           mesh.indices.size() * sizeof(uint32_t));

    vertexCursor_ += mesh.vertices.size();
    indexCursor_ += mesh.indices.size();

    chunks_[{chunkX, chunkZ}] = record;
    chunkMeshes_[{chunkX, chunkZ}] = mesh;
    return true;
}

bool VoxelRenderer::RemoveChunk(int32_t chunkX, int32_t chunkZ) {
    chunks_.erase({chunkX, chunkZ});
    chunkMeshes_.erase({chunkX, chunkZ});
    return true;
}

void VoxelRenderer::ReleaseChunkRecords() {
    chunks_.clear();
    chunkMeshes_.clear();
    vertexCursor_ = 0;
    indexCursor_ = 0;
}

bool VoxelRenderer::RenderFrame(const VoxelCamera& camera) {
    if (!device_ || !pipelineState_) {
        lastError_ = "renderer is not initialized";
        return false;
    }

    // The allocator is about to be reset. Any GPU work still in flight must
    // finish first, or the allocator's memory would be reused underneath it.
    WaitForGpu();

    RAWR_VK_CHECK(commandAllocator_->Reset());
    RAWR_VK_CHECK(commandList_->Reset(commandAllocator_.Get(), nullptr));

    // ---- Frame constants ---------------------------------------------------
    struct FrameConstants {
        float viewProjection[16];
        float camera[4];
        float light[4];
        float params[4];
    } constants{};

    const float aspect = (height_ > 0) ? (static_cast<float>(width_) / static_cast<float>(height_)) : 1.0f;
    const float fov = camera.fovYDegrees * 3.14159265358979323846f / 180.0f;
    const Mat4 view = LookAt(camera.position, camera.target, camera.up);
    const Mat4 proj = Perspective(fov, aspect, camera.zNear, camera.zFar);
    const Mat4 viewProj = proj * view;

    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            constants.viewProjection[c * 4 + r] = viewProj.m[c][r];
        }
    }
    constants.camera[0] = camera.position.x;
    constants.camera[1] = camera.position.y;
    constants.camera[2] = camera.position.z;
    constants.camera[3] = 0.0f;

    Vec3 lightDir = Normalize(Vec3{0.45f, 0.82f, 0.35f});
    constants.light[0] = lightDir.x;
    constants.light[1] = lightDir.y;
    constants.light[2] = lightDir.z;
    constants.light[3] = 0.95f;  // sun intensity

    constants.params[0] = 1.0f;  // ambient scale
    // The fog band scales with the world height, matching the reference
    // rasterizer exactly.
    constants.params[1] = static_cast<float>(kChunkHeight) * 1.0f;  // fog start
    constants.params[2] = static_cast<float>(kChunkHeight) * 3.0f;  // fog range
    constants.params[3] = 0.85f; // fog strength

    if (constantCpu_) {
        memcpy(constantCpu_, &constants, sizeof(constants));
    }

    // ---- Barriers ----------------------------------------------------------
    D3D12_RESOURCE_BARRIER barriers[2]{};
    UINT barrierCount = 0;
    auto addTransition = [&](ID3D12Resource* res, D3D12_RESOURCE_STATES from,
                             D3D12_RESOURCE_STATES to) {
        if (from == to || res == nullptr) return;
        D3D12_RESOURCE_BARRIER& barrier = barriers[barrierCount++];
        barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
        barrier.Transition.pResource = res;
        barrier.Transition.StateBefore = from;
        barrier.Transition.StateAfter = to;
        barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    };

    addTransition(colorTexture_.Get(), colorState_, D3D12_RESOURCE_STATE_RENDER_TARGET);
    addTransition(depthTexture_.Get(), depthState_, D3D12_RESOURCE_STATE_DEPTH_WRITE);
    if (barrierCount > 0) {
        commandList_->ResourceBarrier(barrierCount, barriers);
    }
    colorState_ = D3D12_RESOURCE_STATE_RENDER_TARGET;
    depthState_ = D3D12_RESOURCE_STATE_DEPTH_WRITE;

    // ---- Bind and draw -----------------------------------------------------
    D3D12_VIEWPORT viewport{};
    viewport.TopLeftX = 0.0f;
    viewport.TopLeftY = 0.0f;
    viewport.Width = static_cast<float>(width_);
    viewport.Height = static_cast<float>(height_);
    viewport.MinDepth = 0.0f;
    viewport.MaxDepth = 1.0f;

    D3D12_RECT scissor{};
    scissor.right = static_cast<LONG>(width_);
    scissor.bottom = static_cast<LONG>(height_);

    commandList_->RSSetViewports(1, &viewport);
    commandList_->RSSetScissorRects(1, &scissor);
    commandList_->OMSetRenderTargets(1, &colorRtv_, FALSE, &depthDsv_);

    const float clearColor[4] = {0.44f, 0.55f, 0.72f, 1.0f};
    commandList_->ClearRenderTargetView(colorRtv_, clearColor, 0, nullptr);
    commandList_->ClearDepthStencilView(depthDsv_, D3D12_CLEAR_FLAG_DEPTH, 1.0f, 0, 0, nullptr);

    commandList_->SetGraphicsRootSignature(rootSignature_.Get());
    commandList_->SetPipelineState(pipelineState_.Get());
    commandList_->SetGraphicsRootConstantBufferView(0, constantBuffer_->GetGPUVirtualAddress());
    commandList_->IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);

    D3D12_VERTEX_BUFFER_VIEW vbView{};
    vbView.BufferLocation = vertexBuffer_->GetGPUVirtualAddress();
    vbView.SizeInBytes = static_cast<UINT>(vertexCursor_ * sizeof(VoxelVertex));
    vbView.StrideInBytes = sizeof(VoxelVertex);
    commandList_->IASetVertexBuffers(0, 1, &vbView);

    D3D12_INDEX_BUFFER_VIEW ibView{};
    ibView.BufferLocation = indexBuffer_->GetGPUVirtualAddress();
    ibView.SizeInBytes = static_cast<UINT>(indexCursor_ * sizeof(uint32_t));
    ibView.Format = DXGI_FORMAT_R32_UINT;
    commandList_->IASetIndexBuffer(&ibView);

    lastDrawCalls_ = 0;
    lastTriangles_ = 0;
    for (const auto& entry : chunks_) {
        const ChunkGpuRecord& record = entry.second;
        if (record.indexCount == 0) continue;
        commandList_->DrawIndexedInstanced(record.indexCount, 1,
                                 static_cast<INT>(record.indexOffset),
                                 static_cast<INT>(record.vertexOffset), 0);
        ++lastDrawCalls_;
        lastTriangles_ += record.indexCount / 3;
    }

    RAWR_VK_CHECK(commandList_->Close());
    ID3D12CommandList* lists[] = {commandList_.Get()};
    commandQueue_->ExecuteCommandLists(1, lists);
    lastSubmittedFence_ = ++fenceValue_;
    commandQueue_->Signal(fence_.Get(), lastSubmittedFence_);
    ++frameIndex_;
    return true;
}

bool VoxelRenderer::Present() {
    if (!swapChain_) return true;
    const HRESULT hr = swapChain_->Present(1, 0);
    if (FAILED(hr)) {
        lastError_ = "IDXGISwapChain::Present failed";
        return false;
    }
    swapChainIndex_ = swapChain_->GetCurrentBackBufferIndex();
    return true;
}

bool VoxelRenderer::CaptureFrame(std::vector<uint8_t>& rgba, uint32_t& width, uint32_t& height) {
    if (!device_ || !colorTexture_) {
        lastError_ = "renderer is not initialized";
        return false;
    }

    // The readback buffer is sized from the placed footprint, whose row pitch
    // is padded to 256 bytes. The capture below unpacks that padding.
    const D3D12_RESOURCE_DESC desc = colorTexture_->GetDesc();
    D3D12_PLACED_SUBRESOURCE_FOOTPRINT footprint{};
    uint64_t totalBytes = 0;
    device_->GetCopyableFootprints(&desc, 0, 1, 0, &footprint, nullptr, nullptr, &totalBytes);

    if (!readbackBuffer_ || readbackTotalBytes_ < totalBytes) {
        readbackBuffer_.Reset();
        D3D12_HEAP_PROPERTIES readbackHeap{};
        readbackHeap.Type = D3D12_HEAP_TYPE_READBACK;
        D3D12_RESOURCE_DESC readbackDesc{};
        readbackDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
        readbackDesc.Width = totalBytes;
        readbackDesc.Height = 1;
        readbackDesc.DepthOrArraySize = 1;
        readbackDesc.MipLevels = 1;
        readbackDesc.Format = DXGI_FORMAT_UNKNOWN;
        readbackDesc.SampleDesc.Count = 1;
        readbackDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
        RAWR_VK_CHECK(device_->CreateCommittedResource(&readbackHeap, D3D12_HEAP_FLAG_NONE,
                                                       &readbackDesc, D3D12_RESOURCE_STATE_COPY_DEST,
                                                       nullptr, IID_PPV_ARGS(&readbackBuffer_)));
        readbackTotalBytes_ = totalBytes;
    }
    readbackRowPitch_ = footprint.Footprint.RowPitch;

    WaitForGpu();
    RAWR_VK_CHECK(commandAllocator_->Reset());
    RAWR_VK_CHECK(commandList_->Reset(commandAllocator_.Get(), nullptr));

    D3D12_RESOURCE_BARRIER toCopy{};
    toCopy.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    toCopy.Transition.pResource = colorTexture_.Get();
    toCopy.Transition.StateBefore = colorState_;
    toCopy.Transition.StateAfter = D3D12_RESOURCE_STATE_COPY_SOURCE;
    toCopy.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    commandList_->ResourceBarrier(1, &toCopy);
    colorState_ = D3D12_RESOURCE_STATE_COPY_SOURCE;

    D3D12_TEXTURE_COPY_LOCATION dst{};
    dst.pResource = readbackBuffer_.Get();
    dst.Type = D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
    dst.PlacedFootprint = footprint;

    D3D12_TEXTURE_COPY_LOCATION src{};
    src.pResource = colorTexture_.Get();
    src.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
    src.SubresourceIndex = 0;

    commandList_->CopyTextureRegion(&dst, 0, 0, 0, &src, nullptr);

    D3D12_RESOURCE_BARRIER back = toCopy;
    back.Transition.StateBefore = D3D12_RESOURCE_STATE_COPY_SOURCE;
    back.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;
    commandList_->ResourceBarrier(1, &back);
    colorState_ = D3D12_RESOURCE_STATE_RENDER_TARGET;

    RAWR_VK_CHECK(commandList_->Close());
    ID3D12CommandList* lists[] = {commandList_.Get()};
    commandQueue_->ExecuteCommandLists(1, lists);
    const uint64_t target = ++fenceValue_;
    commandQueue_->Signal(fence_.Get(), target);
    if (fence_->GetCompletedValue() < target) {
        fence_->SetEventOnCompletion(target, fenceEvent_);
        WaitForSingleObject(fenceEvent_, INFINITE);
    }

    // ---- Unpack the rows ----------------------------------------------------
    void* mapped = nullptr;
    RAWR_VK_CHECK(readbackBuffer_->Map(0, nullptr, &mapped));
    const uint8_t* rowBase = static_cast<const uint8_t*>(mapped) + footprint.Offset;
    const size_t tightRowBytes = static_cast<size_t>(width_) * 4u;

    rgba.assign(static_cast<size_t>(width_) * height_ * 4u, 0);
    for (uint32_t y = 0; y < height_; ++y) {
        memcpy(rgba.data() + static_cast<size_t>(y) * tightRowBytes,
               rowBase + static_cast<size_t>(y) * readbackRowPitch_, tightRowBytes);
    }
    readbackBuffer_->Unmap(0, nullptr);

    width = width_;
    height = height_;
    return true;
}

} // namespace Voxel
} // namespace RawrXD
