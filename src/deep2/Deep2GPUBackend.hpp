// ============================================================================
// Deep2GPUBackend.hpp - GPU Backend Management
// Multi-GPU support for AMD Radeon AI PRO R9700 + RX 7800 XT
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <map>

namespace Deep2 {

// GPU Device Information
struct GPUDeviceInfo {
    int index;
    std::string name;
    uint64_t vramBytes;
    uint32_t computeUnits;
    std::string architecture;
    bool available;
    float utilization; // 0.0 - 1.0
    uint64_t vramUsed;
};

// GPU Backend Interface
class Deep2GPUBackend {
public:
    Deep2GPUBackend();
    ~Deep2GPUBackend();

    // Initialize GPU backend (Vulkan/ROCm)
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;

    // Device enumeration
    std::vector<GPUDeviceInfo> EnumerateDevices();
    GPUDeviceInfo GetDeviceInfo(int index);
    int GetDeviceCount() const;

    // VRAM management
    bool AllocateVRAM(int deviceIndex, size_t bytes);
    void FreeVRAM(int deviceIndex);
    size_t GetAvailableVRAM(int deviceIndex);

    // Kernel dispatch
    bool DispatchKernel(const char* kernelName, int deviceIndex);
    bool DispatchKernelWithData(const char* kernelName, int deviceIndex, 
                                 void* data, size_t size);

    // Synchronization
    void SynchronizeDevice(int deviceIndex);
    void SynchronizeAll();

    // Performance queries
    float GetDeviceUtilization(int deviceIndex);
    float GetMemoryUtilization(int deviceIndex);

private:
    bool initialized_;
    std::vector<GPUDeviceInfo> devices_;
    void* context_; // Backend-specific context
};

// GPU Memory Pool
class GPUMemoryPool {
public:
    GPUMemoryPool();
    ~GPUMemoryPool();

    bool Initialize(int deviceIndex, size_t poolSize);
    void* Allocate(size_t size);
    void Free(void* ptr);
    void Defragment();

    size_t GetUsed() const;
    size_t GetAvailable() const;

private:
    int deviceIndex_;
    size_t poolSize_;
    size_t used_;
    void* pool_;
};

// GPU Kernel Registry
class GPUKernelRegistry {
public:
    static GPUKernelRegistry& Instance();

    void RegisterKernel(const char* name, void* kernel);
    void* GetKernel(const char* name);
    bool HasKernel(const char* name);

private:
    GPUKernelRegistry();
    std::map<std::string, void*> kernels_;
};

} // namespace Deep2
