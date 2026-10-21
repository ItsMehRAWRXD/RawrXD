// ============================================================================
// VoxelRenderer.hpp - the native Direct3D 12 voxel renderer.
//
// This is a real graphics pipeline, not a simulation:
//   * ID3D12Device / ID3D12CommandQueue / ID3D12GraphicsCommandList
//   * ID3D12RootSignature and ID3D12PipelineState
//   * a depth buffer, so voxels occlude each other correctly
//   * HLSL compiled at runtime with D3DCompile
//   * an offscreen render target that is copied back to the CPU for Deep2
//     vision, with the row pitch unpacked correctly
//
// The render target is offscreen by design. The browser bridge needs a
// texture it can sample, the certification harness needs pixels it can
// verify, and neither needs a window. A swapchain is optional and is used
// only when a host window is supplied.
//
// Synchronization rule enforced here: the command allocator is never reset
// while GPU work from a previous frame is still in flight. WaitForGpu() is
// called before every allocator reset.
// ============================================================================

#pragma once

#include <cstdint>
#include <d3d12.h>
#include <dxgi1_6.h>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <wrl/client.h>

#include "Math3D.hpp"
#include "VoxelMesher.hpp"

namespace RawrXD {
namespace Voxel {

using Microsoft::WRL::ComPtr;

// The GPU-side record of one uploaded chunk.
struct ChunkGpuRecord {
    uint64_t vertexOffset = 0;  // in vertices
    uint64_t indexOffset = 0;   // in indices
    uint32_t indexCount = 0;
    uint32_t vertexCount = 0;
};

class VoxelRenderer {
public:
    VoxelRenderer() = default;
    ~VoxelRenderer();
    VoxelRenderer(const VoxelRenderer&) = delete;
    VoxelRenderer& operator=(const VoxelRenderer&) = delete;

    // Creates the device, the offscreen target, the depth buffer, the root
    // signature, the PSO and the geometry buffers.
    // `hostWindow` may be null: the renderer then runs fully offscreen.
    bool Initialize(uint32_t width, uint32_t height, void* hostWindow = nullptr);
    void Shutdown();
    bool IsInitialized() const { return device_ != nullptr; }

    // Rebuilds the offscreen target and the depth buffer at a new size.
    bool Resize(uint32_t width, uint32_t height);

    // Uploads one chunk's mesh into the GPU geometry buffers. The mesh is
    // copied to the CPU as well, so a later compaction can re-upload it.
    bool UploadChunk(int32_t chunkX, int32_t chunkZ, const ChunkMesh& mesh);
    bool RemoveChunk(int32_t chunkX, int32_t chunkZ);
    size_t uploadedChunkCount() const { return chunks_.size(); }
    size_t residentChunkCount() const { return chunkMeshes_.size(); }

    // Renders one frame into the offscreen target.
    bool RenderFrame(const VoxelCamera& camera);

    // Presents the offscreen target to the host window, if there is one.
    bool Present();

    // Copies the offscreen target back to the CPU as tightly packed RGBA8,
    // one row after another, with the readback row pitch unpacked.
    bool CaptureFrame(std::vector<uint8_t>& rgba, uint32_t& width, uint32_t& height);

    const std::string& LastError() const { return lastError_; }

    // Diagnostics, filled in by RenderFrame.
    uint32_t lastDrawCallCount() const { return lastDrawCalls_; }
    uint64_t lastTriangleCount() const { return lastTriangles_; }
    const char* deviceName() const { return deviceName_.c_str(); }

private:
    bool CreateDevice();
    bool CreateRenderTargets(uint32_t width, uint32_t height);
    bool CreatePipeline();
    bool CreateGeometryBuffers();
    bool CreateConstantBuffer();
    bool CreateSwapChain(void* hostWindow, uint32_t width, uint32_t height);
    bool UploadShader(const char* source, const char* entry, const char* target,
                      ComPtr<ID3DBlob>& out);
    bool EnsureGeometryCapacity(size_t vertexBytes, size_t indexBytes);
    bool CompactGeometry();
    void WaitForGpu();
    void DumpDebugMessages();
    void ReleaseChunkRecords();

    ComPtr<ID3D12Device> device_;
    ComPtr<ID3D12CommandQueue> commandQueue_;
    ComPtr<ID3D12CommandAllocator> commandAllocator_;
    ComPtr<ID3D12GraphicsCommandList> commandList_;
    ComPtr<ID3D12Fence> fence_;
    HANDLE fenceEvent_ = nullptr;
    uint64_t fenceValue_ = 0;
    bool debugLayerEnabled_ = false;
    uint64_t lastSubmittedFence_ = 0;

    ComPtr<ID3D12DescriptorHeap> rtvHeap_;
    ComPtr<ID3D12DescriptorHeap> dsvHeap_;
    D3D12_CPU_DESCRIPTOR_HANDLE rtvHandle_{};
    D3D12_CPU_DESCRIPTOR_HANDLE dsvHandle_{};

    ComPtr<ID3D12Resource> colorTexture_;
    ComPtr<ID3D12Resource> depthTexture_;
    D3D12_CPU_DESCRIPTOR_HANDLE colorRtv_{};
    D3D12_CPU_DESCRIPTOR_HANDLE depthDsv_{};
    // The states the targets are actually in. Tracked rather than assumed,
    // because the capture path moves the colour target to COPY_SOURCE.
    D3D12_RESOURCE_STATES colorState_ = D3D12_RESOURCE_STATE_COPY_DEST;
    D3D12_RESOURCE_STATES depthState_ = D3D12_RESOURCE_STATE_COPY_DEST;

    ComPtr<ID3D12RootSignature> rootSignature_;
    ComPtr<ID3D12PipelineState> pipelineState_;
    ComPtr<ID3DBlob> vertexShader_;
    ComPtr<ID3DBlob> pixelShader_;
    ComPtr<ID3DBlob> shaderError_;

    ComPtr<ID3D12Resource> constantBuffer_;
    void* constantCpu_ = nullptr;

    ComPtr<ID3D12Resource> vertexBuffer_;
    ComPtr<ID3D12Resource> indexBuffer_;
    void* vertexCpu_ = nullptr;
    void* indexCpu_ = nullptr;
    uint64_t vertexCapacity_ = 0;
    uint64_t indexCapacity_ = 0;
    uint64_t vertexCursor_ = 0;
    uint64_t indexCursor_ = 0;

    // Offscreen readback.
    ComPtr<ID3D12Resource> readbackBuffer_;
    uint64_t readbackRowPitch_ = 0;
    uint64_t readbackTotalBytes_ = 0;

    // Optional host presentation.
    ComPtr<IDXGIFactory4> dxgiFactory_;
    ComPtr<IDXGISwapChain3> swapChain_;
    ComPtr<ID3D12Resource> swapChainBuffers_[2]{};
    D3D12_CPU_DESCRIPTOR_HANDLE swapChainRtv_[2]{};
    uint32_t swapChainIndex_ = 0;
    uint32_t frameIndex_ = 0;

    std::map<std::pair<int32_t, int32_t>, ChunkGpuRecord> chunks_;
    std::map<std::pair<int32_t, int32_t>, ChunkMesh> chunkMeshes_;

    uint32_t width_ = 0;
    uint32_t height_ = 0;
    uint32_t lastDrawCalls_ = 0;
    uint64_t lastTriangles_ = 0;
    std::string deviceName_;
    std::string lastError_;
};

} // namespace Voxel
} // namespace RawrXD
