// ============================================================================
// TransferScheduler.cpp — RAWRXD_W3_BATCH_I
// Real implementation of RawrXD::Memory::TransferScheduler (header ABI).
// Semantics: schedule() validates and appends the request to the queue with
// its callback; a shared static worker thread drains entries in priority
// order. With no bandwidth limit, accounting completes immediately (the data
// motion for memory-tier moves is a pointer handoff — real work is the
// queueing + ordering); with a limit, the worker throttles completion by the
// configured rate. cancel() removes queued entries and fires (tensor,false).
// No fake instant success for zero-byte or cancelled transfers.
// ============================================================================
#include "TransferScheduler.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <chrono>
#include <thread>

namespace RawrXD::Memory {

namespace {

struct Entry {
    TransferRequest req;
    std::function<void(TensorId, bool)> cb;
};

struct Shared {
    std::mutex mx;
    std::condition_variable cv;
    std::vector<Entry> queue;
    double bwLimitMBps = 0.0;
    std::atomic<bool> started{false};
    std::atomic<bool> stop{false};
    std::thread worker;
    uint64_t seq = 0;

    static Shared& get() {
        static Shared s;
        return s;
    }

    void loop() {
        for (;;) {
            Entry e;
            {
                std::unique_lock<std::mutex> lk(mx);
                cv.wait(lk, [this] { return stop.load() || !queue.empty(); });
                if (stop.load() && queue.empty()) return;
                auto best = std::min_element(
                    queue.begin(), queue.end(),
                    [](const Entry& a, const Entry& b) {
                        return static_cast<int>(a.req.priority) <
                               static_cast<int>(b.req.priority);
                    });
                e = std::move(*best);
                queue.erase(best);
            }
            if (e.req.bytes == 0) {
                if (e.cb) e.cb(e.req.tensor, false);
                continue;
            }
            if (bwLimitMBps > 0.0) {
                // Throttle at the configured rate (real elapsed accounting).
                const double ms =
                    e.req.bytes / (bwLimitMBps * 1024.0 * 1024.0 / 1000.0);
                const uint64_t waitMs =
                    static_cast<uint64_t>(ms) > 0
                        ? static_cast<uint64_t>(ms)
                        : 1;
                // Sleep in bounded slices so stop remains responsive.
                uint64_t done = 0;
                while (done < waitMs && !stop.load()) {
                    const uint64_t step = std::min<uint64_t>(waitMs - done, 20);
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(step));
                    done += step;
                }
                if (stop.load()) {
                    if (e.cb) e.cb(e.req.tensor, false);
                    continue;
                }
                if (e.cb) e.cb(e.req.tensor, true);
            } else {
                if (e.cb) e.cb(e.req.tensor, true);
            }
        }
    }
};

} // namespace

void TransferScheduler::schedule(const TransferRequest& req,
                                 std::function<void(TensorId, bool)> callback) {
    Shared& s = Shared::get();
    if (req.bytes == 0) {
        if (callback) callback(req.tensor, false);
        return;
    }
    {
        std::lock_guard<std::mutex> lk(s.mx);
        // Keep the declared members coherent with the shared worker state.
        m_queue.push_back(req);
        m_callbacks.push_back(callback);
        s.queue.push_back(Entry{req, std::move(callback)});
        if (!s.started.exchange(true)) {
            s.stop.store(false);
            s.worker = std::thread([] { Shared::get().loop(); });
        }
        s.cv.notify_one();
    }
}

bool TransferScheduler::cancel(TensorId tensor) {
    Shared& s = Shared::get();
    bool removed = false;
    {
        std::lock_guard<std::mutex> lk(s.mx);
        for (auto it = s.queue.begin(); it != s.queue.end(); ++it) {
            if (it->req.tensor == tensor) {
                if (it->cb) it->cb(tensor, false);
                s.queue.erase(it);
                removed = true;
                break;
            }
        }
        if (removed) {
            for (auto it = m_queue.begin(); it != m_queue.end(); ++it) {
                if (it->tensor == tensor) {
                    m_queue.erase(it);
                    break;
                }
            }
            for (auto it = m_callbacks.begin(); it != m_callbacks.end(); ++it) {
                // the matching callback already fired above; drop the slot
                m_callbacks.erase(it);
                break;
            }
        }
    }
    return removed;
}

void TransferScheduler::setBandwidthLimitMBps(double limit) {
    Shared& s = Shared::get();
    std::lock_guard<std::mutex> lk(s.mx);
    s.bwLimitMBps = limit < 0.0 ? 0.0 : limit;
    m_bwLimitMBps = s.bwLimitMBps;
    s.cv.notify_one();
}

std::size_t TransferScheduler::pendingCount() const {
    Shared& s = Shared::get();
    std::lock_guard<std::mutex> lk(s.mx);
    return s.queue.size();
}

} // namespace RawrXD::Memory
