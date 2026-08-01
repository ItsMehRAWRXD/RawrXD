#pragma once
#include <string>
#include <vector>
#include <cstdint>

// ============================================================================
// Graphics API Abstraction — single interface for Vulkan, DirectX 12, or
// software rasterizer. The engine selects the best available backend at init.
// ============================================================================

// ---------------------------------------------------------------------------
// Resource types
// ---------------------------------------------------------------------------
enum class GpuBackendType : uint8_t {
    None,
    Vulkan,
    DirectX12,
    SoftwareRaster
};

struct GpuAdapterInfo {
    std::string name;
    uint64_t    dedicatedVramBytes;
    uint64_t    sharedVramBytes;
    uint32_t    vendorId;
    uint32_t    deviceId;
    bool        supportsRaytracing;
    bool        supportsCompute;
};

struct GpuBufferDesc {
    uint64_t    size;
    bool        isVertex;
    bool        isIndex;
    bool        isUniform;
    bool        isStorage;
    bool        isCpuVisible;
};

struct GpuTextureDesc {
    uint32_t    width;
    uint32_t    height;
    uint32_t    depth;
    uint32_t    mipLevels;
    uint32_t    format;       // DXGI_FORMAT or VkFormat
    bool        isRenderTarget;
    bool        isDepthStencil;
    bool        isUnorderedAccess;
};

struct GpuShaderDesc {
    std::vector<uint8_t> bytecode;
    std::string          entryPoint;
    uint32_t             stage;  // 0=VS, 1=PS, 2=CS, 3=GS, 4=HS, 5=DS
};

// ---------------------------------------------------------------------------
// Abstract GPU device interface
// ---------------------------------------------------------------------------
class IGpuDevice {
public:
    virtual ~IGpuDevice() = default;

    // Lifecycle
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual GpuBackendType GetBackendType() const = 0;

    // Adapter info
    virtual std::vector<GpuAdapterInfo> EnumerateAdapters() = 0;
    virtual bool SelectAdapter(uint32_t index) = 0;

    // Resource creation
    virtual uint64_t CreateBuffer(const GpuBufferDesc& desc) = 0;
    virtual void     DestroyBuffer(uint64_t handle) = 0;
    virtual void*    MapBuffer(uint64_t handle) = 0;
    virtual void     UnmapBuffer(uint64_t handle) = 0;

    virtual uint64_t CreateTexture(const GpuTextureDesc& desc) = 0;
    virtual void     DestroyTexture(uint64_t handle) = 0;

    virtual uint64_t CreateShader(const GpuShaderDesc& desc) = 0;
    virtual void     DestroyShader(uint64_t handle) = 0;

    // Execution
    virtual bool ExecuteCompute(uint64_t shader, uint32_t x, uint32_t y, uint32_t z) = 0;
    virtual bool Present() = 0;

    // Memory query
    virtual uint64_t GetDedicatedVramBytes() const = 0;
    virtual uint64_t GetUsedVramBytes() const = 0;
};

// ---------------------------------------------------------------------------
// Factory — creates the best available GPU backend
// ---------------------------------------------------------------------------
IGpuDevice* CreateGpuDevice(GpuBackendType preferred = GpuBackendType::Vulkan);
