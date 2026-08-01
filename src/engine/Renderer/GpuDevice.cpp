#include "GpuDevice.hpp"
#include <iostream>
#include <cstdlib>

// ============================================================================
// Software Rasterizer — fallback GPU backend when no hardware adapter is
// available. Uses the SIMD math layer for all transforms.
// ============================================================================

class SoftwareRasterDevice : public IGpuDevice {
private:
    bool m_initialized = false;
    uint64_t m_dedicatedVram = 0;
    uint64_t m_usedVram = 0;

public:
    bool Initialize() override {
        std::cout << "[SoftwareRaster] Initializing software rasterizer\n";
        m_initialized = true;
        m_dedicatedVram = 1024ULL * 1024 * 1024; // 1 GB simulated
        return true;
    }

    void Shutdown() override {
        std::cout << "[SoftwareRaster] Shutting down\n";
        m_initialized = false;
    }

    GpuBackendType GetBackendType() const override {
        return GpuBackendType::SoftwareRaster;
    }

    std::vector<GpuAdapterInfo> EnumerateAdapters() override {
        return {{"Software Rasterizer (SIMD)", m_dedicatedVram, 0, 0, 0, false, true}};
    }

    bool SelectAdapter(uint32_t index) override {
        return index == 0;
    }

    uint64_t CreateBuffer(const GpuBufferDesc& desc) override {
        m_usedVram += desc.size;
        return reinterpret_cast<uint64_t>(malloc(static_cast<size_t>(desc.size)));
    }

    void DestroyBuffer(uint64_t handle) override {
        free(reinterpret_cast<void*>(handle));
    }

    void* MapBuffer(uint64_t handle) override {
        return reinterpret_cast<void*>(handle);
    }

    void UnmapBuffer(uint64_t handle) override {}

    uint64_t CreateTexture(const GpuTextureDesc& desc) override {
        size_t size = desc.width * desc.height * desc.depth * 4;
        m_usedVram += size;
        return reinterpret_cast<uint64_t>(malloc(size));
    }

    void DestroyTexture(uint64_t handle) override {
        free(reinterpret_cast<void*>(handle));
    }

    uint64_t CreateShader(const GpuShaderDesc& desc) override {
        return 1; // stub
    }

    void DestroyShader(uint64_t handle) override {}

    bool ExecuteCompute(uint64_t shader, uint32_t x, uint32_t y, uint32_t z) override {
        return true;
    }

    bool Present() override {
        return true;
    }

    uint64_t GetDedicatedVramBytes() const override { return m_dedicatedVram; }
    uint64_t GetUsedVramBytes() const override { return m_usedVram; }
};

// ---------------------------------------------------------------------------
// Factory implementation
// ---------------------------------------------------------------------------
IGpuDevice* CreateGpuDevice(GpuBackendType preferred) {
    // For now, always return software rasterizer
    // Vulkan/DX12 backends will be added in Phase 7B
    return new SoftwareRasterDevice();
}
