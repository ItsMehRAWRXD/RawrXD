// ============================================================================
// GpuManager.hpp — GPU Backend Manager
// Device detection, memory allocation, kernel dispatch
// ============================================================================

#ifndef GPU_MANAGER_HPP
#define GPU_MANAGER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <mutex>

namespace rawr {

// ============================================================================
// GPU Backend Type
// ============================================================================
enum class GpuBackend : uint8_t {
    None = 0,
    Vulkan,
    HIP,
    CUDA,
    DirectML,
    CPU
};

// ============================================================================
// GPU Device Info
// ============================================================================
struct GpuDeviceInfo {
    uint32_t index;
    std::string name;
    GpuBackend backend;
    uint64_t totalVRAM;
    uint64_t freeVRAM;
    uint32_t computeUnits;
    bool available;
};

// ============================================================================
// Memory Allocation
// ============================================================================
struct GpuMemoryBlock {
    void* devicePtr;
    uint64_t size;
    bool hostVisible;
};

// ============================================================================
// GpuManager — Detects, manages, and dispatches to GPU backends
// ============================================================================
class GpuManager {
public:
    static GpuManager& Get();

    bool Initialize();
    void Shutdown();

    // Device enumeration
    uint32_t EnumerateDevices();
    const GpuDeviceInfo* GetDevice(uint32_t index) const;
    uint32_t GetDeviceCount() const { return static_cast<uint32_t>(m_devices.size()); }
    int32_t GetBestDevice() const;

    // Memory management
    GpuMemoryBlock* Allocate(uint64_t size, bool hostVisible = true);
    void Free(GpuMemoryBlock* block);
    bool CopyToDevice(GpuMemoryBlock* block, const void* hostData, uint64_t size);
    bool CopyFromDevice(void* hostData, const GpuMemoryBlock* block, uint64_t size);

    // Kernel dispatch
    bool DispatchGemm(const GpuMemoryBlock* A, const GpuMemoryBlock* B,
                      GpuMemoryBlock* C, uint32_t M, uint32_t N, uint32_t K);
    bool DispatchAttention(const GpuMemoryBlock* Q, const GpuMemoryBlock* K,
                           const GpuMemoryBlock* V, GpuMemoryBlock* O,
                           uint32_t seqLen, uint32_t headDim);

    // Backend selection
    GpuBackend GetActiveBackend() const { return m_activeBackend; }
    bool SetActiveBackend(GpuBackend backend);

    // Fallback
    bool HasBackend(GpuBackend backend) const;
    bool IsGPUAvailable() const { return m_gpuAvailable; }

    // Stats
    struct GpuStats {
        uint32_t deviceCount;
        uint64_t totalVRAM;
        uint64_t usedVRAM;
        uint32_t allocations;
    };
    GpuStats GetStats() const;

private:
    GpuManager() = default;
    ~GpuManager() = default;
    GpuManager(const GpuManager&) = delete;
    GpuManager& operator=(const GpuManager&) = delete;

    bool DetectVulkan();
    bool DetectHIP();
    bool DetectCUDA();

    std::vector<GpuDeviceInfo> m_devices;
    std::vector<GpuMemoryBlock> m_allocations;
    GpuBackend m_activeBackend = GpuBackend::CPU;
    bool m_gpuAvailable = false;
    mutable std::mutex m_mutex;
};

} // namespace rawr

#endif // GPU_MANAGER_HPP
