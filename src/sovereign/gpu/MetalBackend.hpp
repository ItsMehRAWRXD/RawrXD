// ============================================================================
// MetalBackend.hpp - Metal Backend for Apple GPU Inference
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace Sovereign {

struct MetalDeviceInfo {
    std::string name;
    uint64_t recommendedMaxBufferSize;
    bool supportsFP16;
    bool supportsInt8;
    bool supportsBF16;
    uint32_t maxThreadsPerThreadgroup;
};

struct MetalBuffer {
    uint64_t id;
    void* buffer;
    uint64_t size;
    void* contents;
};

class MetalBackend {
public:
    MetalBackend();
    ~MetalBackend();
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    std::vector<MetalDeviceInfo> EnumerateDevices();
    MetalBuffer Allocate(uint64_t size);
    void Free(MetalBuffer& buffer);
    bool WriteBuffer(MetalBuffer& buffer, const void* data, uint64_t size);
    bool ReadBuffer(const MetalBuffer& buffer, void* data, uint64_t size);
    bool DispatchKernel(const std::string& shaderName, const std::vector<MetalBuffer>& buffers, uint32_t gridWidth, uint32_t threadgroupSize);
    bool DispatchGEMV(const MetalBuffer& weights, const MetalBuffer& input, MetalBuffer& output, uint32_t rows, uint32_t cols);
    struct MetalStats { uint64_t totalAllocations; uint64_t totalDispatches; };
    MetalStats GetStats() const { return stats_; }
private:
    bool initialized_ = false;
    MetalStats stats_;
    std::vector<MetalDeviceInfo> devices_;
    uint64_t nextBufferId_ = 1;
    void* device_ = nullptr;
    void* commandQueue_ = nullptr;
    void* library_ = nullptr;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
