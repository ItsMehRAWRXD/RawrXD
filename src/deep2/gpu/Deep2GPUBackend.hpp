// ============================================================================
// Deep2GPUBackend.hpp - AMD GPU Backend for Deep2 Engine
// Supports: Radeon AI PRO R9700 32GB, Radeon RX 7800 XT 16GB
// Backends: Vulkan Compute, ROCm/HIP
// ============================================================================

#ifndef DEEP2_GPU_BACKEND_H
#define DEEP2_GPU_BACKEND_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Deep2 {
namespace GPU {

// ============================================================================
// GPU Device Information
// ============================================================================
struct GPUDevice {
    uint32_t index = 0;                    // Device index in enumeration
    std::string name;                      // Device name (e.g., "AMD Radeon AI PRO R9700")
    std::string shortName;                 // Short identifier (e.g., "R9700")
    uint64_t vramBytes = 0;                // Total VRAM in bytes
    uint32_t vramMB = 0;                   // VRAM in MB for display
    uint32_t gfxArch = 0;                  // GFX architecture (e.g., 0x1201 for gfx1201)
    uint32_t computeUnits = 0;             // Number of compute units
    uint32_t maxWorkGroupSize = 256;       // Maximum work group size
    bool isAvailable = false;              // Device is available for use
    bool isPrimary = false;                // Primary inference device
    bool isSecondary = false;              // Secondary/offload device
    
    // Performance characteristics
    float computeScore = 0.0f;             // Relative compute performance
    float memoryBandwidth = 0.0f;          // GB/s estimated
    
    // Backend-specific handles (opaque)
    void* vulkanPhysicalDevice = nullptr;
    void* vulkanDevice = nullptr;
    void* rocmDevice = nullptr;
    
    std::string GetInfoString() const;
};

// ============================================================================
// VRAM Allocation Tracking
// ============================================================================
struct VRAMAllocation {
    uint32_t deviceIndex = 0;
    size_t sizeBytes = 0;
    void* devicePtr = nullptr;
    void* hostPtr = nullptr;               // For mapped memory
    bool isHostVisible = false;
    std::string tag;                       // For debugging
};

// ============================================================================
// Kernel Dispatch Configuration
// ============================================================================
struct KernelConfig {
    uint32_t workGroupSizeX = 256;
    uint32_t workGroupSizeY = 1;
    uint32_t workGroupSizeZ = 1;
    uint32_t globalSizeX = 0;
    uint32_t globalSizeY = 1;
    uint32_t globalSizeZ = 1;
    uint32_t deviceIndex = 0;
};

// ============================================================================
// GPU Backend Interface
// ============================================================================
class Deep2GPUBackend {
public:
    Deep2GPUBackend();
    ~Deep2GPUBackend();
    
    // Initialize GPU backend (Vulkan first, fallback to ROCm)
    bool Initialize();
    
    // Shutdown and cleanup
    void Shutdown();
    
    // Check if backend is initialized
    bool IsInitialized() const { return initialized_; }
    
    // Enumerate available GPU devices
    std::vector<GPUDevice> EnumerateDevices();
    
    // Get specific device
    const GPUDevice* GetDevice(uint32_t index) const;
    
    // Get primary device (R9700 if available)
    const GPUDevice* GetPrimaryDevice() const;
    
    // Get secondary device (7800 XT if available)
    const GPUDevice* GetSecondaryDevice() const;
    
    // VRAM Management
    bool AllocateVRAM(uint32_t deviceIndex, size_t bytes, VRAMAllocation& allocation, const char* tag = nullptr);
    bool FreeVRAM(VRAMAllocation& allocation);
    bool CopyToDevice(const VRAMAllocation& allocation, const void* hostData, size_t bytes);
    bool CopyFromDevice(void* hostData, const VRAMAllocation& allocation, size_t bytes);
    
    // Get VRAM usage stats
    size_t GetAllocatedVRAM(uint32_t deviceIndex) const;
    size_t GetFreeVRAM(uint32_t deviceIndex) const;
    
    // Kernel Dispatch
    bool DispatchRMSNorm(uint32_t deviceIndex, const VRAMAllocation& input, VRAMAllocation& output, 
                         size_t dim, float eps);
    bool DispatchSwiGLU(uint32_t deviceIndex, const VRAMAllocation& gate, const VRAMAllocation& up,
                        VRAMAllocation& output, size_t dim);
    bool DispatchVecDot(uint32_t deviceIndex, const VRAMAllocation& a, const VRAMAllocation& b,
                        float* result, size_t n);
    bool DispatchMatMul(uint32_t deviceIndex, const VRAMAllocation& A, const VRAMAllocation& B,
                        VRAMAllocation& C, size_t M, size_t N, size_t K);
    
    // Multi-GPU tensor placement
    bool PlaceTensor(const std::string& tensorName, size_t bytes, uint32_t preferredDevice);
    uint32_t GetTensorDevice(const std::string& tensorName) const;
    
    // Synchronization
    bool SynchronizeDevice(uint32_t deviceIndex);
    bool SynchronizeAll();
    
    // Performance queries
    float GetLastKernelTimeMs() const { return lastKernelTimeMs_; }
    
    // Print device info
    void PrintDeviceInfo() const;
    
    // Get backend info
    std::string GetBackendName() const;
    std::string GetBackendVersion() const;

private:
    bool initialized_ = false;
    bool vulkanInitialized_ = false;
    bool rocmInitialized_ = false;
    
    std::vector<GPUDevice> devices_;
    std::vector<VRAMAllocation> allocations_;
    
    float lastKernelTimeMs_ = 0.0f;
    
    // Vulkan-specific
    void* vulkanInstance_ = nullptr;
    void* vulkanDebugMessenger_ = nullptr;
    
    // ROCm-specific  
    void* rocmContext_ = nullptr;
    
    // Internal methods
    bool InitializeVulkan();
    bool InitializeROCm();
    void DetectAMDDevices();
    uint32_t ParseGfxArch(const std::string& deviceName);
    float CalculateComputeScore(const GPUDevice& device);
};

// ============================================================================
// GPU Backend Singleton
// ============================================================================
Deep2GPUBackend& GetGPUBackend();

// ============================================================================
// Convenience Functions
// ============================================================================
bool InitializeGPUBackend();
void ShutdownGPUBackend();
bool IsGPUAvailable();

// Multi-GPU topology for R9700 + 7800 XT
struct MultiGPUTopology {
    bool hasPrimary = false;      // R9700 detected
    bool hasSecondary = false;    // 7800 XT detected
    uint32_t primaryIndex = 0;
    uint32_t secondaryIndex = 1;
    
    // Layer distribution
    uint32_t layersOnPrimary = 48;    // First 48 layers on R9700
    uint32_t layersOnSecondary = 16;    // Remaining 16 on 7800 XT
    
    // Memory allocation strategy
    size_t kvCacheOnPrimary = 0;        // KV cache bytes on R9700
    size_t weightsOnPrimary = 0;        // Weight bytes on R9700
    size_t weightsOnSecondary = 0;    // Weight bytes on 7800 XT
};

MultiGPUTopology DetectMultiGPUTopology();

} // namespace GPU
} // namespace Deep2

#endif // DEEP2_GPU_BACKEND_H
