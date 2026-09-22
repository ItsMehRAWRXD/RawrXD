#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace RawrXD::Memory {

using TensorId = uint64_t;

enum class MemoryTier : uint8_t {
    SSD = 0,
    SYSTEM_RAM = 1,
    GPU_VRAM = 2
};

enum class TransferPriority : uint8_t {
    Background = 0,
    Normal = 1,
    Imminent = 2,
    Critical = 3
};

struct TransferRequest {
    TensorId tensor = 0;
    MemoryTier source = MemoryTier::SSD;
    MemoryTier destination = MemoryTier::SYSTEM_RAM;
    uint64_t bytes = 0;
    uint64_t deadline = 0;
    TransferPriority priority = TransferPriority::Normal;
    bool speculative = false;
};

class TransferScheduler {
public:
    TransferScheduler() = default;
    ~TransferScheduler() = default;

    void schedule(const TransferRequest& req,
                  std::function<void(TensorId, bool)> callback = nullptr);

    bool cancel(TensorId tensor);

    void setBandwidthLimitMBps(double limit);

    std::size_t pendingCount() const;

private:
    mutable std::mutex m_mutex;
    std::vector<TransferRequest> m_queue;
    std::vector<std::function<void(TensorId, bool)>> m_callbacks;
    double m_bwLimitMBps = 0.0;
};

} // namespace RawrXD::Memory
