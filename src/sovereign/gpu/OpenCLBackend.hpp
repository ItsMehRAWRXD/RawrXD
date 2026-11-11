// ============================================================================
// OpenCLBackend.hpp - OpenCL Backend for Cross-Platform GPU Inference
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace Sovereign {

struct OpenCLDeviceInfo {
    std::string name;
    std::string vendor;
    uint64_t globalMem;
    uint32_t computeUnits;
    uint32_t maxWorkgroupSize;
    bool supportsFP16;
    std::string clVersion;
};

struct OpenCLBuffer {
    uint64_t id;
    void* memObject;
    uint64_t size;
    bool isMapped;
    void* mappedPtr;
};

class OpenCLBackend {
public:
    OpenCLBackend();
    ~OpenCLBackend();
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    std::vector<OpenCLDeviceInfo> EnumerateDevices();
    bool SelectDevice(int index);
    OpenCLBuffer Allocate(uint64_t size);
    void Free(OpenCLBuffer& buffer);
    bool WriteBuffer(OpenCLBuffer& buffer, const void* data, uint64_t size, uint64_t offset = 0);
    bool ReadBuffer(const OpenCLBuffer& buffer, void* data, uint64_t size, uint64_t offset = 0);
    bool ExecuteKernel(const std::string& source, const std::string& kernelName, const std::vector<OpenCLBuffer>& args, uint32_t globalSize, uint32_t localSize);
    bool Finish();
    struct OpenCLStats { uint64_t totalAllocations; uint64_t totalKernelExecs; };
    OpenCLStats GetStats() const { return stats_; }
private:
    bool initialized_ = false;
    int selectedDevice_ = -1;
    OpenCLStats stats_;
    std::vector<OpenCLDeviceInfo> devices_;
    uint64_t nextBufferId_ = 1;
    void* context_ = nullptr;
    void* commandQueue_ = nullptr;
    void* program_ = nullptr;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
