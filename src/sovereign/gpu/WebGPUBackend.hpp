// ============================================================================
// WebGPUBackend.hpp - WebGPU Backend for Browser-Based Inference
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace Sovereign {

struct WebGPUDeviceInfo {
    std::string name;
    bool supportsCompute;
    uint64_t maxBufferSize;
    uint32_t maxComputeWorkgroupsPerDimension;
};

struct WebGPUBuffer {
    uint64_t id;
    void* buffer;
    uint64_t size;
    void* mappedPtr;
};

class WebGPUBackend {
public:
    WebGPUBackend();
    ~WebGPUBackend();
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    WebGPUBuffer Allocate(uint64_t size);
    void Free(WebGPUBuffer& buffer);
    bool WriteBuffer(WebGPUBuffer& buffer, const void* data, uint64_t size);
    bool ReadBuffer(const WebGPUBuffer& buffer, void* data, uint64_t size);
    bool DispatchCompute(const std::string& shaderCode, const std::vector<WebGPUBuffer>& buffers, uint32_t workgroupCountX, uint32_t workgroupCountY, uint32_t workgroupCountZ);
    struct WebGPUStats { uint64_t totalAllocations; uint64_t totalDispatches; };
    WebGPUStats GetStats() const { return stats_; }
private:
    bool initialized_ = false;
    WebGPUStats stats_;
    uint64_t nextBufferId_ = 1;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
