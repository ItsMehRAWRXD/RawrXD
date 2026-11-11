// ============================================================================
// MultiGPU.hpp - Multi-GPU Execution & Async Memory Transfers
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

struct GPUDevice {
    uint32_t id;
    std::string name;
    uint64_t memoryTotal;
    uint64_t memoryFree;
    uint32_t computeUnits;
    bool isActive;
    double load;
};

struct TransferBatch {
    uint64_t id;
    uint32_t srcDevice;
    uint32_t dstDevice;
    void* srcPtr;
    void* dstPtr;
    uint64_t size;
    bool isComplete;
    uint64_t durationUs;
};

class MultiGPUManager {
public:
    MultiGPUManager();
    ~MultiGPUManager();

    bool Initialize();
    void Shutdown();

    std::vector<GPUDevice> EnumerateDevices();
    bool AssignWork(uint32_t deviceId, std::function<void()> work);
    bool SyncDevice(uint32_t deviceId);
    bool SyncAll();

    TransferBatch BeginTransfer(uint32_t srcDevice, uint32_t dstDevice, void* srcPtr, void* dstPtr, uint64_t size);
    bool WaitForTransfer(const TransferBatch& batch);
    bool IsTransferComplete(const TransferBatch& batch) const;

    bool SetActiveDevices(const std::vector<uint32_t>& deviceIds);
    std::vector<uint32_t> GetActiveDevices() const;
    uint32_t GetDeviceCount() const { return devices_.size(); }

    struct MultiGPUStats {
        uint64_t totalTransfers;
        uint64_t totalBytesTransferred;
        uint64_t totalKernelLaunches;
        double avgTransferTimeUs;
    };
    MultiGPUStats GetStats() const { return stats_; }

private:
    std::vector<GPUDevice> devices_;
    std::vector<uint32_t> activeDevices_;
    MultiGPUStats stats_;
    bool initialized_ = false;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
