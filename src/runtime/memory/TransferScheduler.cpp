// ============================================================================
// TransferScheduler.cpp
// ============================================================================
#include "TransferScheduler.hpp"
#include <chrono>
#include <cstdio>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace RawrXD {
namespace Memory {

// Unified telemetry logger for all transfers
static void logTransferTelemetry(const TransferRequest& req, bool success, uint64_t durationNs = 0) {
    const char* srcName = "UNKNOWN";
    switch (req.source) {
        case MemoryTier::VRAM:       srcName = "VRAM"; break;
        case MemoryTier::SYSTEM_RAM: srcName = "RAM";  break;
        case MemoryTier::SSD:        srcName = "NVMe"; break;
        default: break;
    }
    const char* dstName = "UNKNOWN";
    switch (req.destination) {
        case MemoryTier::VRAM:       dstName = "VRAM"; break;
        case MemoryTier::SYSTEM_RAM: dstName = "RAM";  break;
        case MemoryTier::SSD:        dstName = "NVMe"; break;
        default: break;
    }
    const char* prioName = "UNKNOWN";
    switch (req.priority) {
        case TransferPriority::Blocking:      prioName = "Blocking";      break;
        case TransferPriority::Imminent:        prioName = "Imminent";      break;
        case TransferPriority::Lookahead:       prioName = "Lookahead";     break;
        case TransferPriority::Speculative:     prioName = "Speculative";   break;
        case TransferPriority::Opportunistic:   prioName = "Opportunistic"; break;
        default: break;
    }

    char buf[512];
    if (success && durationNs > 0) {
        double ms = static_cast<double>(durationNs) / 1'000'000.0;
        double gbps = (ms > 0.0) ? (static_cast<double>(req.bytes) / (1024.0 * 1024.0 * 1024.0)) / (ms / 1000.0) : 0.0;
        snprintf(buf, sizeof(buf),
            "[TRANSFER] tensor=%llu %s→%s bytes=%llu prio=%s duration_ms=%.2f throughput_GBps=%.2f",
            static_cast<unsigned long long>(req.tensor), srcName, dstName,
            static_cast<unsigned long long>(req.bytes), prioName, ms, gbps);
    } else {
        snprintf(buf, sizeof(buf),
            "[TRANSFER] tensor=%llu %s→%s bytes=%llu prio=%s status=%s",
            static_cast<unsigned long long>(req.tensor), srcName, dstName,
            static_cast<unsigned long long>(req.bytes), prioName,
            success ? "OK" : "FAILED");
    }
    // Write to both OutputDebugString and stderr for IDE capture
    OutputDebugStringA(buf);
    OutputDebugStringA("\n");
    fprintf(stderr, "%s\n", buf);
}

TransferScheduler::TransferScheduler(uint32_t maxConcurrent)
    : m_maxConcurrent(maxConcurrent)
{
    m_worker = std::thread(&TransferScheduler::workerLoop, this);
}

TransferScheduler::~TransferScheduler() {
    {
        std::unique_lock<std::mutex> lk(m_mtx);
        m_stop = true;
    }
    m_cv.notify_all();
    if (m_worker.joinable()) m_worker.join();
}

void TransferScheduler::setExecutor(TransferExecutor exec) {
    std::unique_lock<std::mutex> lk(m_mtx);
    m_executor = std::move(exec);
}

void TransferScheduler::schedule(const TransferRequest& req, TransferCallback cb) {
    {
        std::unique_lock<std::mutex> lk(m_mtx);
        // Drop cancelled entries before they get a worker thread.
        if (m_cancelled.count(req.tensor) &&
            req.priority != TransferPriority::Blocking &&
            req.priority != TransferPriority::Imminent) {
            if (cb) cb(req.tensor, false);
            return;
        }
        m_queue.push({req, std::move(cb)});
        m_queueDepth.fetch_add(1, std::memory_order_relaxed);
    }
    m_cv.notify_one();
}

std::shared_ptr<TransferCompletionToken> TransferScheduler::scheduleAsync(const TransferRequest& req) {
    auto token = std::make_shared<TransferCompletionToken>();
    {
        std::unique_lock<std::mutex> lk(m_mtx);
        // Drop cancelled entries before they get a worker thread.
        if (m_cancelled.count(req.tensor) &&
            req.priority != TransferPriority::Blocking &&
            req.priority != TransferPriority::Imminent) {
            token->signalFailed();
            return token;
        }
        m_queue.push({req, [token](TensorId, bool success) {
            if (success) token->signalReady(0);  // address filled by executor
            else         token->signalFailed();
        }});
        m_queueDepth.fetch_add(1, std::memory_order_relaxed);
    }
    m_cv.notify_one();
    return token;
}

void TransferScheduler::cancelSpeculative(TensorId id) {
    std::unique_lock<std::mutex> lk(m_mtx);
    m_cancelled.insert(id);
}

void TransferScheduler::flush(uint32_t timeoutMs) {
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeoutMs);
    std::unique_lock<std::mutex> lk(m_mtx);
    m_cv.wait_until(lk, deadline, [this]{ return m_queue.empty(); });
}

void TransferScheduler::workerLoop() {
    while (true) {
        Entry entry;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cv.wait(lk, [this]{ return m_stop || !m_queue.empty(); });
            if (m_stop && m_queue.empty()) break;
            entry = m_queue.top();
            m_queue.pop();
            m_queueDepth.fetch_sub(1, std::memory_order_relaxed);

            // Drop speculative entries for cancelled tensors.
            if (m_cancelled.count(entry.req.tensor) &&
                entry.req.priority != TransferPriority::Blocking &&
                entry.req.priority != TransferPriority::Imminent) {
                if (entry.cb) entry.cb(entry.req.tensor, false);
                continue;
            }
        }

        // Execute transfer (simulate success if no executor installed).
        auto t0 = std::chrono::steady_clock::now();
        bool ok = true;
        if (m_executor) {
            ok = m_executor(entry.req);
        }
        auto t1 = std::chrono::steady_clock::now();
        uint64_t durationNs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());

        if (ok) m_completed.fetch_add(1, std::memory_order_relaxed);
        else    m_failed.fetch_add(1, std::memory_order_relaxed);

        // Unified telemetry for every transfer
        logTransferTelemetry(entry.req, ok, durationNs);

        if (entry.cb) entry.cb(entry.req.tensor, ok);

        // Remove from cancelled set on success so future uses work normally.
        if (ok) {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cancelled.erase(entry.req.tensor);
        }
    }
}

} // namespace Memory
} // namespace RawrXD
