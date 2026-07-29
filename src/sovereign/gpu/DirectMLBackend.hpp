// ============================================================================
// DirectMLBackend.hpp - DirectML Backend for Windows GPU Inference
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace Sovereign {

struct DirectMLDeviceInfo {
    std::string name;
    uint64_t dedicatedMemory;
    uint64_t sharedMemory;
    uint32_t computeUnits;
    bool supportsFP16;
    bool supportsINT8;
};

struct DirectMLBuffer {
    uint64_t id;
    void* resource;
    uint64_t size;
    void* mappedPtr;
};

class DirectMLBackend {
public:
    DirectMLBackend();
    ~DirectMLBackend();
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    std::vector<DirectMLDeviceInfo> EnumerateDevices();
    DirectMLBuffer Allocate(uint64_t size);
    void Free(DirectMLBuffer& buffer);
    bool CopyBuffer(DirectMLBuffer& dst, const DirectMLBuffer& src, uint64_t size);
    bool DispatchOperator(const std::string& opName, const std::vector<DirectMLBuffer>& inputs, const std::vector<DirectMLBuffer>& outputs);
    bool DispatchGEMV(const DirectMLBuffer& weights, const DirectMLBuffer& input, DirectMLBuffer& output, uint32_t rows, uint32_t cols);
    struct DirectMLStats { uint64_t totalAllocations; uint64_t totalDispatches; };
    DirectMLStats GetStats() const { return stats_; }
private:
    bool initialized_ = false;
    DirectMLStats stats_;
    std::vector<DirectMLDeviceInfo> devices_;
    uint64_t nextBufferId_ = 1;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
