// ============================================================================
// CUDABackend.hpp - CUDA Backend Stub for GPU Inference
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Sovereign {

struct CUDADeviceInfo {
    std::string name;
    int computeCapabilityMajor;
    int computeCapabilityMinor;
    uint64_t totalGlobalMem;
    uint64_t sharedMemPerBlock;
    int maxThreadsPerBlock;
    int multiprocessorCount;
    bool supportsTensorCores;
    bool supportsFP16;
    bool supportsBF16;
    bool supportsFP8;
};

struct CUDABuffer {
    uint64_t id;
    void* devicePtr;
    uint64_t size;
    bool isMapped;
    void* hostPtr;
};

class CUDABackend {
public:
    CUDABackend();
    ~CUDABackend();

    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    std::vector<CUDADeviceInfo> EnumerateDevices();
    bool SelectDevice(int deviceId);
    CUDADeviceInfo GetDeviceInfo() const;

    CUDABuffer Allocate(uint64_t size);
    void Free(CUDABuffer& buffer);
    bool CopyToDevice(CUDABuffer& dst, const void* src, uint64_t size);
    bool CopyToHost(void* dst, const CUDABuffer& src, uint64_t size);
    bool CopyBuffer(CUDABuffer& dst, const CUDABuffer& src, uint64_t size);

    bool LaunchKernel(const std::string& kernelName, dim3 gridDim, dim3 blockDim, const std::vector<void*>& args);
    bool Synchronize();

    bool LaunchGEMV(const CUDABuffer& weights, const CUDABuffer& input, CUDABuffer& output, uint32_t rows, uint32_t cols);
    bool LaunchFlashAttention(const CUDABuffer& Q, const CUDABuffer& K, const CUDABuffer& V, CUDABuffer& output, uint32_t seqLen, uint32_t headDim);

    struct CUDAStats {
        uint64_t totalAllocations;
        uint64_t totalBytesAllocated;
        uint64_t totalKernelLaunches;
        uint64_t totalMemcpyBytes;
    };
    CUDAStats GetStats() const { return stats_; }

private:
    bool initialized_ = false;
    int selectedDevice_ = -1;
    CUDAStats stats_;
    std::vector<CUDADeviceInfo> devices_;
    uint64_t nextBufferId_ = 1;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
