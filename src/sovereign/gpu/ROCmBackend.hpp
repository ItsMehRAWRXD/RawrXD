// ============================================================================
// ROCmBackend.hpp - ROCm/HIP Backend for AMD GPU Inference
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace Sovereign {

struct ROCmDeviceInfo {
    std::string name;
    std::string gcnArch;
    uint64_t globalMem;
    uint32_t computeUnits;
    uint32_t maxThreadsPerBlock;
    bool supportsWMMA;
    bool supportsMFMA;
};

struct ROCmBuffer {
    uint64_t id;
    void* devicePtr;
    uint64_t size;
    bool isMapped;
    void* hostPtr;
};

class ROCmBackend {
public:
    ROCmBackend();
    ~ROCmBackend();

    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    std::vector<ROCmDeviceInfo> EnumerateDevices();
    bool SelectDevice(int index);
    ROCmDeviceInfo GetDeviceInfo() const;

    ROCmBuffer Allocate(uint64_t size);
    void Free(ROCmBuffer& buffer);
    bool CopyToDevice(ROCmBuffer& dst, const void* src, uint64_t size);
    bool CopyToHost(void* dst, const ROCmBuffer& src, uint64_t size);

    bool LaunchKernel(const std::string& kernelName, uint32_t gridX, uint32_t gridY, uint32_t gridZ,
                      uint32_t blockX, uint32_t blockY, uint32_t blockZ, const std::vector<void*>& args);
    bool Synchronize();

    bool LaunchGEMV(const ROCmBuffer& weights, const ROCmBuffer& input, ROCmBuffer& output, uint32_t rows, uint32_t cols);

    struct ROCmStats {
        uint64_t totalAllocations;
        uint64_t totalKernelLaunches;
        uint64_t totalBytesTransferred;
    };
    ROCmStats GetStats() const { return stats_; }

private:
    bool initialized_ = false;
    int selectedDevice_ = -1;
    ROCmStats stats_;
    std::vector<ROCmDeviceInfo> devices_;
    uint64_t nextBufferId_ = 1;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
