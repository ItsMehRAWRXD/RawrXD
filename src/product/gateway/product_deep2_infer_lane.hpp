#pragma once
/* ProductRun/Vulkan must run on the process main (bound) thread.
 * HTTP pool threads → enqueue; Headless run loop Drain() executes. */
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>

namespace rawr {
namespace product_infer_lane {

inline std::mutex& QMu() {
    static std::mutex m;
    return m;
}
inline std::condition_variable& QCv() {
    static std::condition_variable cv;
    return cv;
}
inline std::condition_variable& IdleCv() {
    static std::condition_variable cv;
    return cv;
}
inline std::deque<std::function<void()>>& Q() {
    static std::deque<std::function<void()>> q;
    return q;
}
inline std::thread::id& BoundId() {
    static std::thread::id id{};
    return id;
}

inline void BindCurrentThreadAsLane() {
    std::lock_guard<std::mutex> lk(QMu());
    BoundId() = std::this_thread::get_id();
}

inline void Drain(int maxJobs = 8) {
    for (int n = 0; n < maxJobs; ++n) {
        std::function<void()> job;
        {
            std::lock_guard<std::mutex> lk(QMu());
            if (Q().empty()) return;
            if (BoundId() != std::this_thread::get_id()) return;
            job = std::move(Q().front());
            Q().pop_front();
        }
        if (job) job();
    }
}

inline void PumpWait(int ms) {
    std::unique_lock<std::mutex> lk(QMu());
    IdleCv().wait_for(lk, std::chrono::milliseconds(ms),
                      [] { return !Q().empty(); });
}

template <typename Fn>
auto Run(Fn&& fn) -> decltype(fn()) {
    using R = decltype(fn());
    std::thread::id bound;
    {
        std::lock_guard<std::mutex> lk(QMu());
        bound = BoundId();
    }
    /* Unbound (CLI) or already on bound thread: run inline. */
    if (bound == std::thread::id{} ||
        std::this_thread::get_id() == bound)
        return fn();

    std::mutex doneMu;
    std::condition_variable doneCv;
    bool done = false;
    R result{};
    {
        std::lock_guard<std::mutex> lk(QMu());
        Q().push_back([&] {
            result = fn();
            {
                std::lock_guard<std::mutex> d(doneMu);
                done = true;
            }
            doneCv.notify_one();
        });
    }
    IdleCv().notify_one();
    std::unique_lock<std::mutex> d(doneMu);
    doneCv.wait(d, [&] { return done; });
    return result;
}

} // namespace product_infer_lane
} // namespace rawr
