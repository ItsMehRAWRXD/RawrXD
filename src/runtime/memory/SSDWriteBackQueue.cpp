// ============================================================================
// SSDWriteBackQueue.cpp
// ============================================================================
#include "SSDWriteBackQueue.hpp"
#include <cstdio>

namespace RawrXD {
namespace Memory {

SSDWriteBackQueue::SSDWriteBackQueue(BlockTable& table, HANDLE hBackingFile)
    : m_table(table)
    , m_hFile(hBackingFile)
    , m_hIOCP(nullptr)
{
    if (m_hFile != INVALID_HANDLE_VALUE) {
        m_hIOCP = CreateIoCompletionPort(m_hFile, nullptr, 0, 0);
    }
}

SSDWriteBackQueue::~SSDWriteBackQueue() {
    stop();
    if (m_hIOCP != nullptr) {
        CloseHandle(m_hIOCP);
        m_hIOCP = nullptr;
    }
}

bool SSDWriteBackQueue::start(uint32_t numWorkers) {
    if (m_hFile == INVALID_HANDLE_VALUE || m_hIOCP == nullptr) {
        std::fprintf(stderr, "[SSDWriteBackQueue] Invalid file handle or IOCP\n");
        return false;
    }
    m_stop.store(false, std::memory_order_release);
    m_worker = std::thread(&SSDWriteBackQueue::workerLoop, this);
    return true;
}

void SSDWriteBackQueue::stop() {
    m_stop.store(true, std::memory_order_release);
    m_queueCv.notify_all();
    if (m_worker.joinable()) {
        m_worker.join();
    }
}

bool SSDWriteBackQueue::enqueue(const FlushJob& job) {
    {
        std::lock_guard<std::mutex> lk(m_queueMtx);
        m_queue.push(job);
    }
    m_pending.fetch_add(1, std::memory_order_relaxed);
    m_queueCv.notify_one();
    return true;
}

void SSDWriteBackQueue::setCompletionCallback(FlushCompletionCallback cb) {
    std::lock_guard<std::mutex> lk(m_cbMtx);
    m_callback = std::move(cb);
}

bool SSDWriteBackQueue::drain(uint32_t timeoutMs) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (m_pending.load(std::memory_order_acquire) > 0) {
        if (std::chrono::steady_clock::now() > deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return true;
}

void SSDWriteBackQueue::workerLoop() {
    while (!m_stop.load(std::memory_order_acquire)) {
        FlushJob job{};
        {
            std::unique_lock<std::mutex> lk(m_queueMtx);
            m_queueCv.wait(lk, [this] { return m_stop.load(std::memory_order_acquire) || !m_queue.empty(); });
            if (m_stop.load(std::memory_order_acquire) && m_queue.empty()) break;
            job = m_queue.front();
            m_queue.pop();
        }

        bool ok = doFlush(job);
        m_pending.fetch_sub(1, std::memory_order_relaxed);

        if (ok) {
            m_completed.fetch_add(1, std::memory_order_relaxed);
            // Transition block: FLUSH_PENDING → SSD_WRITE_COMPLETE
            m_table.completeFlush(job.blockId);
        } else {
            m_failed.fetch_add(1, std::memory_order_relaxed);
            // On failure, leave block dirty so it can be retried
            // (caller or retry logic must transition back to RAM_DIRTY)
        }

        {
            std::lock_guard<std::mutex> lk(m_cbMtx);
            if (m_callback) m_callback(job.blockId, ok);
        }
    }
}

bool SSDWriteBackQueue::doFlush(const FlushJob& job) {
    if (m_hFile == INVALID_HANDLE_VALUE || job.srcPtr == 0 || job.bytes == 0) {
        return false;
    }

    OVERLAPPED ov{};
    ov.Offset = static_cast<DWORD>(job.ssdOffset);
    ov.OffsetHigh = static_cast<DWORD>(job.ssdOffset >> 32);

    BOOL ok = WriteFile(
        m_hFile,
        reinterpret_cast<LPCVOID>(job.srcPtr),
        static_cast<DWORD>(job.bytes),
        nullptr,
        &ov
    );

    if (!ok && GetLastError() != ERROR_IO_PENDING) {
        std::fprintf(stderr, "[SSDWriteBackQueue] WriteFile failed for block %llu: %lu\n",
            static_cast<unsigned long long>(job.blockId), GetLastError());
        return false;
    }

    // Wait for completion (synchronous within worker; queue gives concurrency)
    DWORD written = 0;
    BOOL overlappedOk = GetOverlappedResult(m_hFile, &ov, &written, TRUE);
    if (!overlappedOk || written != static_cast<DWORD>(job.bytes)) {
        std::fprintf(stderr, "[SSDWriteBackQueue] GetOverlappedResult failed for block %llu\n",
            static_cast<unsigned long long>(job.blockId));
        return false;
    }

    m_bytesWritten.fetch_add(written, std::memory_order_relaxed);
    return true;
}

} // namespace Memory
} // namespace RawrXD
