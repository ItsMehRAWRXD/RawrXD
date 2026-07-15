#pragma once
#include "CommandRouter.hpp"
#include "SharedSessionLayout.hpp"
#include <windows.h>
#include <atomic>
#include <thread>
#include <functional>

namespace RawrXD {

// Command job node for SLIST
// SLIST_ENTRY MUST be the first member for alignment
struct CommandJob {
    SLIST_ENTRY itemEntry;      // FIRST: Required for SLIST operations
    uint32_t commandHash;
    uint64_t timestamp;
    uint32_t sourceComponent;
    
    // Inline payload to avoid heap allocation
    static constexpr size_t MAX_PAYLOAD = 256;
    uint8_t payload[MAX_PAYLOAD];
    uint32_t payloadLen;
    
    CommandJob() 
        : commandHash(0)
        , timestamp(0)
        , sourceComponent(0)
        , payloadLen(0) {
        // itemEntry initialized by InitializeSListHead
    }
};

// Lock-free command queue using Win32 SLIST
// 16-byte aligned for cmpxchg16b atomic operations
class alignas(16) CommandQueue {
public:
    using JobProcessor = std::function<void(CommandJob* job)>;
    
    CommandQueue();
    ~CommandQueue();
    
    // Disable copy/move
    CommandQueue(const CommandQueue&) = delete;
    CommandQueue& operator=(const CommandQueue&) = delete;
    CommandQueue(CommandQueue&&) = delete;
    CommandQueue& operator=(CommandQueue&&) = delete;
    
    // Initialize the queue (call before use)
    bool Initialize();
    
    // Shutdown the queue (stops worker thread)
    void Shutdown();
    
    // Push a command to the queue (lock-free, thread-safe)
    // Returns false if queue is full
    bool Push(uint32_t commandHash, const void* payload, uint32_t payloadLen,
              uint32_t sourceComponent = 0);
    
    // Convenience: Push from SharedEventFrame
    bool PushEvent(const SharedEventFrame& frame, uint32_t sourceComponent = 0);
    
    // Start worker thread for async processing
    bool StartWorker(JobProcessor processor);
    
    // Stop worker thread
    void StopWorker();
    
    // Check if worker is running
    bool IsWorkerRunning() const { return m_workerRunning.load(); }
    
    // Get queue statistics
    struct Stats {
        uint64_t pushedCount;
        uint64_t processedCount;
        uint64_t droppedCount;
        uint32_t currentDepth;
    };
    Stats GetStats() const;
    
private:
    // SLIST_HEADER MUST be 16-byte aligned for cmpxchg16b
    alignas(16) SLIST_HEADER m_listHead;
    
    // Pre-allocated job pool (avoids heap allocation during push)
    static constexpr size_t JOB_POOL_SIZE = 1024;
    CommandJob* m_jobPool = nullptr;
    alignas(64) std::atomic<uint32_t> m_poolIndex{0};
    
    // Worker thread
    std::thread m_workerThread;
    std::atomic<bool> m_workerRunning{false};
    std::atomic<bool> m_shutdownRequested{false};
    JobProcessor m_processor;
    
    // Statistics
    alignas(64) std::atomic<uint64_t> m_pushedCount{0};
    alignas(64) std::atomic<uint64_t> m_processedCount{0};
    alignas(64) std::atomic<uint64_t> m_droppedCount{0};
    
    // Worker thread function
    void WorkerLoop();
    
    // Allocate job from pool
    CommandJob* AllocateJob();
    
    // Free job back to pool (no-op for ring buffer style)
    void FreeJob(CommandJob* job);
    
    // Process all pending jobs (called by worker)
    void ProcessPendingJobs();
};

// Global command queue instance
extern CommandQueue g_CommandQueue;

} // namespace RawrXD
