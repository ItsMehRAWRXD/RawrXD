// ============================================================================
// TransferScheduler.hpp
// Asynchronous, priority-ordered tensor transfer queue.
// ============================================================================
#pragma once

#include "PlacementPolicy.hpp"
#include <functional>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <unordered_set>
#include <memory>

namespace RawrXD {
namespace Memory {

// Called when a transfer completes (success) or fails.
using TransferCallback = std::function<void(TensorId, bool /*success*/)>;

class TransferScheduler {
public:
    // maxConcurrent: how many transfers may run in parallel.
    // Use 1 for a single PCIe channel, 2+ for concurrent DMA.
    explicit TransferScheduler(uint32_t maxConcurrent = 1);
    ~TransferScheduler();

    // Post a transfer.  Callback is invoked on the worker thread.
    void schedule(const TransferRequest& req, TransferCallback cb = {});

    // Post a transfer and return a token for async completion tracking.
    // The caller owns the token; wait() or poll isReady() to know when done.
    // This replaces the blocking spin-wait in TensorPlacementManager.
    std::shared_ptr<TransferCompletionToken> scheduleAsync(const TransferRequest& req);

    // Cancel all speculative/opportunistic transfers for a tensor.
    // Blocking transfers are never cancelled.
    void cancelSpeculative(TensorId id);

    // Drain the queue (block until all pending transfers complete or time out).
    void flush(uint32_t timeoutMs = 5000);

    // Telemetry accessors (approximate, no lock).
    uint64_t completedCount()  const noexcept { return m_completed.load(); }
    uint64_t failedCount()     const noexcept { return m_failed.load(); }
    uint32_t queueDepth()      const noexcept { return m_queueDepth.load(); }

    // Called by the actual DMA/PCIe implementation to signal a slot is free.
    // If not installed, the scheduler simulates immediate completion.
    using TransferExecutor =
        std::function<bool(const TransferRequest&)>;   // returns true on success
    void setExecutor(TransferExecutor exec);

private:
    struct Entry {
        TransferRequest  req;
        TransferCallback cb;
        bool operator>(const Entry& o) const noexcept {
            return static_cast<uint32_t>(req.priority)
                 > static_cast<uint32_t>(o.req.priority);
        }
    };

    void workerLoop();

    // Priority queue: lower priority value = higher urgency.
    std::priority_queue<Entry,
                        std::vector<Entry>,
                        std::greater<Entry>>   m_queue;
    std::unordered_set<TensorId>               m_cancelled;
    mutable std::mutex                         m_mtx;
    std::condition_variable                    m_cv;
    std::thread                                m_worker;
    std::atomic<bool>                          m_stop{false};
    std::atomic<uint64_t>                      m_completed{0};
    std::atomic<uint64_t>                      m_failed{0};
    std::atomic<uint32_t>                      m_queueDepth{0};
    uint32_t                                   m_maxConcurrent;
    TransferExecutor                           m_executor;
};

} // namespace Memory
} // namespace RawrXD
