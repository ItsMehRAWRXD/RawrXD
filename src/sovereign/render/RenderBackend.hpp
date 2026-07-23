// ============================================================================
// RenderBackend.hpp - D3D12/Vulkan Render Substrate
// Zero-copy GPU rasterizer for the Sovereign IDE Canvas
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Sovereign {

// Surface format
enum class SurfaceFormat {
    R8G8B8A8_UNORM,
    R16G16B16A16_FLOAT,
    R32G32B32A32_FLOAT,
    B8G8R8A8_UNORM,
    R10G10B10A2_UNORM
};

// Render backend type
enum class RenderBackendType {
    D3D12,
    VULKAN,
    AUTO_DETECT
};

// Swap chain config
struct SwapChainConfig {
    uint32_t width = 1920;
    uint32_t height = 1080;
    SurfaceFormat format = SurfaceFormat::R8G8B8A8_UNORM;
    uint32_t bufferCount = 3;
    bool vsync = true;
    bool fullscreen = false;
    void* windowHandle = nullptr;
};

// GPU device info
struct GPUDeviceInfo {
    std::string name;
    uint64_t dedicatedMemory;
    uint64_t sharedMemory;
    uint32_t computeUnits;
    uint32_t maxThreads;
    bool supportsRaytracing;
    bool supportsMeshShaders;
    uint32_t driverVersion;
    std::string vendor;
};

// Render statistics
struct RenderStats {
    double frameTimeMs;
    double gpuTimeMs;
    double presentTimeMs;
    uint64_t drawCalls;
    uint64_t triangles;
    uint64_t vertices;
    uint64_t bytesUploaded;
    uint32_t fps;
};

// Surface descriptor
struct SurfaceDescriptor {
    void* nativeHandle;
    uint32_t width;
    uint32_t height;
    SurfaceFormat format;
    uint64_t bufferAddress; // GPU virtual address for zero-copy
    uint32_t bufferSize;
    bool isMapped;
};

// Render backend interface
class IRenderBackend {
public:
    virtual ~IRenderBackend() = default;
    
    virtual bool Initialize(const SwapChainConfig& config) = 0;
    virtual void Shutdown() = 0;
    virtual bool IsInitialized() const = 0;
    
    virtual bool BeginFrame() = 0;
    virtual void EndFrame() = 0;
    virtual void Present() = 0;
    
    virtual SurfaceDescriptor GetSurface() = 0;
    virtual void* GetDevice() = 0;
    virtual void* GetCommandQueue() = 0;
    
    virtual GPUDeviceInfo GetDeviceInfo() const = 0;
    virtual RenderStats GetStats() const = 0;
    
    virtual bool Resize(uint32_t width, uint32_t height) = 0;
    virtual bool SetVSync(bool enabled) = 0;
    
    virtual uint64_t GetFrameCount() const = 0;
};

// D3D12 backend
class D3D12Backend : public IRenderBackend {
public:
    D3D12Backend();
    ~D3D12Backend() override;
    
    bool Initialize(const SwapChainConfig& config) override;
    void Shutdown() override;
    bool IsInitialized() const override;
    
    bool BeginFrame() override;
    void EndFrame() override;
    void Present() override;
    
    SurfaceDescriptor GetSurface() override;
    void* GetDevice() override;
    void* GetCommandQueue() override;
    
    GPUDeviceInfo GetDeviceInfo() const override;
    RenderStats GetStats() const override;
    
    bool Resize(uint32_t width, uint32_t height) override;
    bool SetVSync(bool enabled) override;
    
    uint64_t GetFrameCount() const override { return frameCount_; }

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
    uint64_t frameCount_ = 0;
    bool initialized_ = false;
};

// Vulkan backend
class VulkanBackend : public IRenderBackend {
public:
    VulkanBackend();
    ~VulkanBackend() override;
    
    bool Initialize(const SwapChainConfig& config) override;
    void Shutdown() override;
    bool IsInitialized() const override;
    
    bool BeginFrame() override;
    void EndFrame() override;
    void Present() override;
    
    SurfaceDescriptor GetSurface() override;
    void* GetDevice() override;
    void* GetCommandQueue() override;
    
    GPUDeviceInfo GetDeviceInfo() const override;
    RenderStats GetStats() const override;
    
    bool Resize(uint32_t width, uint32_t height) override;
    bool SetVSync(bool enabled) override;
    
    uint64_t GetFrameCount() const override { return frameCount_; }

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
    uint64_t frameCount_ = 0;
    bool initialized_ = false;
};

// Render backend factory
class RenderBackendFactory {
public:
    static std::unique_ptr<IRenderBackend> Create(RenderBackendType type = RenderBackendType::AUTO_DETECT);
    static std::vector<GPUDeviceInfo> EnumerateDevices();
};

} // namespace Sovereign
