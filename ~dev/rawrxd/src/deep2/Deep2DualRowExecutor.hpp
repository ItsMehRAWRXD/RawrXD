// Deep2DualRowExecutor.hpp -- fixed two-lane executor for dual-GPU work.
// Header-only, standard C++20; separate submission gate prevents concurrent
// callers from overwriting another call's in-flight lane contexts.
#pragma once
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

namespace Deep2 {
struct DualRowJob {
    bool (*fn)(void*) noexcept = nullptr;
    void* ctx = nullptr;
};

class DualRowExecutor {
public:
    DualRowExecutor() {
        worker_[0] = std::thread([this] { loop(0); });
        worker_[1] = std::thread([this] { loop(1); });
    }
    ~DualRowExecutor() {
        {
            std::lock_guard<std::mutex> g(mu_);
            stop_ = true;
            ++generation_;
        }
        cv_.notify_all();
        doneCv_.notify_all();
        for (auto& t : worker_)
            if (t.joinable()) t.join();
    }
    DualRowExecutor(const DualRowExecutor&) = delete;
    DualRowExecutor& operator=(const DualRowExecutor&) = delete;

    bool run(DualRowJob a, DualRowJob b) {
        // Serialize submitters for the lifetime of the entire job pair.
        // mu_ alone is insufficient: wait() releases it while workers run.
        std::lock_guard<std::mutex> submitLock(submitMutex_);
        std::unique_lock<std::mutex> lk(mu_);
        if (stop_) return false;
        done_[0] = done_[1] = false;
        result_[0] = result_[1] = false;
        job_[0] = a;
        job_[1] = b;
        const uint64_t generation = ++generation_;
        cv_.notify_all();
        doneCv_.wait(lk, [&] {
            return stop_ ||
                (done_[0] && done_[1] && completedGeneration_ == generation);
        });
        return !stop_ && result_[0] && result_[1];
    }

private:
    void loop(unsigned lane) {
        uint64_t seen = 0;
        for (;;) {
            DualRowJob job{};
            uint64_t generation = 0;
            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_.wait(lk, [&] { return stop_ || generation_ != seen; });
                if (stop_) return;
                seen = generation_;
                generation = seen;
                job = job_[lane];
            }
            const bool result = job.fn ? job.fn(job.ctx) : false;
            {
                std::lock_guard<std::mutex> lk(mu_);
                result_[lane] = result;
                done_[lane] = true;
                if (done_[0] && done_[1]) {
                    completedGeneration_ = generation;
                    doneCv_.notify_one();
                }
            }
        }
    }

    std::mutex submitMutex_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::condition_variable doneCv_;
    std::thread worker_[2];
    DualRowJob job_[2]{};
    bool done_[2] = {false, false};
    bool result_[2] = {false, false};
    bool stop_ = false;
    uint64_t generation_ = 0;
    uint64_t completedGeneration_ = 0;
};

inline DualRowExecutor& rowExecutor() {
    static DualRowExecutor executor;
    return executor;
}
} // namespace Deep2
