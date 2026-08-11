// ============================================================================
// SSDWriteBackQueue.hpp
// Producer/consumer queue for asynchronous SSD write-back.
//
// Architecture:
//   DRP_EnqueueSSDFlush()
//        ↓
//   SSD queue (lock-free or mutex-backed)
//        ↓
//   Flush worker thread
//        ↓
//   WriteFile(OVERLAPPED) → completion port
//        ↓
//   block = CLEAN (SSD_WRITE_COMPLETE → RAM_CLEAN)
//
// This prevents synchronous SSD writes from stalling inference.
// ============================================================================
#pragma once

#include "BlockTable.hpp"
#include <windows.h>
#include <stdint.h>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <functional>

namespace RawrXD {
namespace Memory {

// ── Flush completion callback ────────────────────────────────────────────────
using FlushCompletionCallback = std::function<void(BlockId id, bool success)>;

// ── Per-flush job ────────────────────────────────────────────────────────────

struct FlushJob {
    BlockId     blockId     = 0;
    uint64_t    srcPtr      = 0;        // host VA of data to write
    uint64_t    ssdOffset   = 0;        // destination offset in backing file
    uint64_t    bytes       = 0;
    uint64_t    cpuGen      = 0;        // generation at time of enqueue
};

// ── SSD Write-Back Queue ─────────────────────────────────────────────────────

class SSDWriteBackQueue {
public:
    explicit SSDWriteBackQueue(BlockTable& table, HANDLE hBackingFile);
    ~SSDWriteBackQueue();

    // Non-copyable, non-movable.
    SSDWriteBackQueue(const SSDWriteBackQueue&) = delete;
    SSDWriteBackQueue& operator=(const SSDWriteBackQueue&) = delete;

    // Start / stop the worker thread.
    bool start(uint32_t numWorkers = 1);
    void stop();

    // Enqueue a block for async flush.
    // Caller must have already transitioned block: RAM_DIRTY → FLUSH_PENDING.
    bool enqueue(const FlushJob& job);

    // Set callback invoked when a flush completes (success or failure).
    void setCompletionCallback(FlushCompletionCallback cb);

    // Telemetry
    uint64_t completedCount() const noexcept { return m_completed.load(); }
    uint64_t failedCount()    const noexcept { return m_failed.load(); }
    uint64_t pendingCount()   const noexcept { return m_pending.load(); }
    uint64_t bytesWritten()   const noexcept { return m_bytesWritten.load(); }

    // Drain all pending flushes (blocks until queue empty or timeout).
    bool drain(uint32_t timeoutMs = 5000);

private:
    void workerLoop();
    bool doFlush(const FlushJob& job);

    BlockTable&               m_table;
    HANDLE                    m_hFile;          // backing SSD file handle
    HANDLE                    m_hIOCP;          // I/O completion port

    std::queue<FlushJob>      m_queue;
    std::mutex                m_queueMtx;
    std::condition_variable   m_queueCv;
    std::atomic<bool>        m_stop{false};
    std::thread               m_worker;

    FlushCompletionCallback   m_callback;
    std::mutex                m_cbMtx;

    std::atomic<uint64_t>    m_completed{0};
    std::atomic<uint64_t>    m_failed{0};
    std::atomic<uint64_t>    m_pending{0};
    std::atomic<uint64_t>    m_bytesWritten{0};
};

} // namespace Memory
} // namespace RawrXD
