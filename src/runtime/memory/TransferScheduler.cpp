// ============================================================================
// TransferScheduler.cpp
// ============================================================================
#include "TransferScheduler.hpp"
#include <chrono>

namespace RawrXD {
namespace Memory {

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
            return;
        }
        m_queue.push({req, std::move(cb)});
        m_queueDepth.fetch_add(1, std::memory_order_relaxed);
    }
    m_cv.notify_one();
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
        bool ok = true;
        if (m_executor) {
            ok = m_executor(entry.req);
        }

        if (ok) m_completed.fetch_add(1, std::memory_order_relaxed);
        else    m_failed.fetch_add(1, std::memory_order_relaxed);

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
