// ============================================================================
// VoxelRenderer.hpp — the Direct3D 12 renderer.
//
// This is the whole of the graphics side of the engine:
//
//   * the device, the command queue and the fence
//   * the render target, which is either a swap chain or an offscreen
//     texture
//   * the depth buffer
//   * the pipeline, which is the voxel shader and the sky shader
//   * one vertex buffer per chunk
//   * the constant buffer that carries the matrices and the palette
//
// Nothing here is a simulation. Every call is a real Direct3D 12 call, and
// a frame is a real frame: the terrain is drawn by the GPU and the pixels
// that come back are the pixels that were drawn.
//
// The renderer is written against the Windows SDK and the Direct3D 12
// headers. There is no third-party graphics library in it.
// ============================================================================

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <d3d12.h>
#include <dxgi1_6.h>
#include <wrl/client.h>

#include "Camera.hpp"
#include "ChunkStore.hpp"
#include "GreedyMesher.hpp"

namespace sunshine {

using Microsoft::WRL::ComPtr;

// The statistics of one frame, used to prove that the frame is real.
struct FrameStats {
    uint64_t frameIndex = 0;
    uint32_t chunksDrawn = 0;
    uint64_t verticesDrawn = 0;
    uint64_t trianglesDrawn = 0;
    double gpuFrameMs = 0.0;
    double captureMs = 0.0;
};

// The pixels of a captured frame, in BGRA order, top-down.
struct CapturedFrame {
    uint32_t width = 0;
    uint32_t height = 0;
    std::vector<uint8_t> pixels;   // width * height * 4

    bool empty() const { return pixels.empty(); }
};

// The renderer.
class VoxelRenderer {
public:
    VoxelRenderer() = default;
    ~VoxelRenderer();

    VoxelRenderer(const VoxelRenderer&) = delete;
    VoxelRenderer& operator=(const VoxelRenderer&) = delete;

    // Create the device and everything that does not depend on the target.
    bool initialize(std::string& error);

    // Draw into a window.
    bool createWindowTarget(HWND hwnd, uint32_t width, uint32_t height, std::string& error);

    // Draw into an offscreen texture. This is the mode the certification
    // run uses, because it needs no window and no display.
    bool createOffscreenTarget(uint32_t width, uint32_t height, std::string& error);

    // Change the size of the target.
    //
    // The window can be resized at any time, and the swap chain and the
    // depth buffer have to follow it. The GPU is drained first, because
    // the old buffers cannot be released while they are still in use.
    bool resizeTarget(uint32_t width, uint32_t height, std::string& error);

    // The name of the adapter that was chosen.
    const std::string& adapterName() const { return adapterName_; }

    // Upload the mesh of a chunk. The vertices are copied into an upload
    // heap, which keeps them there until the resource is released, so
    // this is called once per chunk.
    bool uploadChunk(int32_t chunkX, int32_t chunkZ, const std::vector<VoxelVertex>& vertices,
                     std::string& error);

    // Forget a chunk that has left the world.
    void releaseChunk(int32_t chunkX, int32_t chunkZ);

    // Whether the engine is drawing the test quad rather than the world.
    bool isTestQuad() const;

    // Find the table of calls the runtime has.
    //
    // The header in this SDK and the runtime disagree about which calls
    // are in the table of the graphics command list, so the calls are
    // made through the table directly. The tail of that table is found
    // by drawing a frame and looking at it, which is the only way to be
    // sure without the source of the runtime in front of you.
    bool probeTableLayout(std::string& error);

    // Draw one frame.
    //
    // `viewProjection` is the combined matrix, `camera` gives the eye and
    // the sun.
    bool renderFrame(const Mat4& viewProjection, const Vec3& cameraPosition, double timeSeconds,
                     FrameStats& stats, std::string& error);

    // Read the frame back from the GPU.
    //
    // The pixels come back in the order the GPU wrote them, which is
    // BGRA and bottom-up, and they are flipped and reordered here so the
    // result is a normal top-down image.
    bool captureFrame(CapturedFrame& out, std::string& error);

    // The size of the render target.
    uint32_t targetWidth() const { return width_; }
    uint32_t targetHeight() const { return height_; }

    // Wait for the GPU to finish everything that was submitted.
    void waitForGpu();

private:
    struct GpuChunk {
        ComPtr<ID3D12Resource> buffer;
        D3D12_VERTEX_BUFFER_VIEW view{};
        uint32_t vertexCount = 0;
    };

    bool createPipelines(std::string& error);
    bool createRenderTargetResources(std::string& error);
    bool createDepthBuffer(std::string& error);
    bool createConstantBuffer(std::string& error);
    void updateConstantBuffer(const Mat4& viewProjection, const Vec3& cameraPosition, double time);
    void buildPalette();

    // The device and the pipeline.
    ComPtr<IDXGIFactory4> factory_;
    ComPtr<ID3D12Device> device_;
    ComPtr<ID3D12CommandQueue> queue_;
    ComPtr<ID3D12CommandAllocator> allocator_;
    ComPtr<ID3D12GraphicsCommandList> list_;
    ComPtr<ID3D12Fence> fence_;
    HANDLE fenceEvent_ = nullptr;
    uint64_t fenceValue_ = 0;

    // The target.
    ComPtr<IDXGISwapChain3> swapChain_;
    ComPtr<ID3D12Resource> offscreen_;
    ComPtr<ID3D12Resource> depth_;
    ComPtr<ID3D12DescriptorHeap> rtvHeap_;
    ComPtr<ID3D12DescriptorHeap> dsvHeap_;
    D3D12_CPU_DESCRIPTOR_HANDLE rtvHandle_{};
    D3D12_CPU_DESCRIPTOR_HANDLE dsvHandle_{};
    uint32_t frameCount_ = 2;
    uint32_t frameIndex_ = 0;
    uint32_t lastRenderedIndex_ = 0;
    uint32_t width_ = 0;
    uint32_t height_ = 0;
    bool windowed_ = false;

    // The readback resource for the capture.
    ComPtr<ID3D12Resource> readback_;
    UINT64 readbackSize_ = 0;

    // The pipeline.
    ComPtr<ID3D12RootSignature> rootSignature_;
    ComPtr<ID3D12PipelineState> voxelPipeline_;
    ComPtr<ID3D12PipelineState> skyPipeline_;
    ComPtr<ID3D12PipelineState> vertexIdPipeline_;

    // The constant buffer.
    ComPtr<ID3D12Resource> constantBuffer_;
    D3D12_VERTEX_BUFFER_VIEW constantView_{};
    void* constantMapped_ = nullptr;

    // The gothic block, which is a constant buffer of its own so that it
    // is a whole number of 256 byte blocks on its own.
    ComPtr<ID3D12Resource> gothicBuffer_;
    D3D12_VERTEX_BUFFER_VIEW gothicView_{};
    void* gothicMapped_ = nullptr;

    std::unordered_map<uint64_t, GpuChunk> chunks_;
    std::string adapterName_;
    float paletteTop_[16][4] = {};
    float paletteSide_[16][4] = {};
};

} // namespace sunshine
