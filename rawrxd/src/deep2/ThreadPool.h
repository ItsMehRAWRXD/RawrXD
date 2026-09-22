#pragma once
// ============================================================================
// ThreadPool.h — Batch 8 bounded worker pool (C++17, no dependencies)
// ============================================================================
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace Deep2 {

class ThreadPool {
public:
    explicit ThreadPool(size_t threadCount = 0, size_t maxQueuedTasks = 0) {
        if (threadCount == 0) {
            threadCount = static_cast<size_t>(std::thread::hardware_concurrency());
            if (threadCount == 0) threadCount = 1;
        }
        maxQueuedTasks_ = maxQueuedTasks
            ? maxQueuedTasks
            : std::max<size_t>(256, threadCount * 64);

        workers_.reserve(threadCount);
        try {
            for (size_t i = 0; i < threadCount; ++i) {
                workers_.emplace_back([this] { workerLoop(); });
            }
        } catch (...) {
            {
                std::lock_guard<std::mutex> lock(mu_);
                stopping_ = true;
                drainOnStop_ = false;
                tasks_.clear();
            }
            cvTask_.notify_all();
            for (auto& t : workers_) if (t.joinable()) t.join();
            throw;
        }
    }

    ~ThreadPool() { shutdown(true); }

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;

    template<class F, class... Args>
    auto enqueue(F&& f, Args&&... args)
        -> std::future<typename std::invoke_result<F, Args...>::type>
    {
        using R = typename std::invoke_result<F, Args...>::type;
        auto task = std::make_shared<std::packaged_task<R()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...));
        std::future<R> result = task->get_future();

        {
            std::unique_lock<std::mutex> lock(mu_);
            cvSpace_.wait(lock, [this] {
                return stopping_ || tasks_.size() < maxQueuedTasks_;
            });
            if (stopping_)
                throw std::runtime_error("ThreadPool::enqueue on stopped pool");
            tasks_.emplace_back([task] { (*task)(); });
        }
        cvTask_.notify_one();
        return result;
    }

    template<class F>
    void parallelFor(size_t begin, size_t end, size_t grain, F&& fn) {
        if (begin >= end) return;
        if (grain == 0) grain = 1;

        if (isWorkerThread() || workers_.size() <= 1 || end - begin <= grain) {
            for (size_t i = begin; i < end; ++i) fn(i);
            return;
        }

        std::vector<std::future<void>> futures;
        for (size_t lo = begin; lo < end; lo += grain) {
            const size_t hi = std::min(end, lo + grain);
            futures.emplace_back(enqueue([lo, hi, &fn] {
                for (size_t i = lo; i < hi; ++i) fn(i);
            }));
        }
        for (auto& f : futures) f.get();
    }

    void waitIdle() {
        std::unique_lock<std::mutex> lock(mu_);
        cvIdle_.wait(lock, [this] {
            return tasks_.empty() && activeWorkers_ == 0;
        });
    }

    void shutdown(bool drain) noexcept {
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (joined_) return;
            stopping_ = true;
            drainOnStop_ = drain;
            if (!drain) tasks_.clear();
        }
        cvTask_.notify_all();
        cvSpace_.notify_all();

        for (auto& t : workers_) {
            if (t.joinable()) t.join();
        }
        workers_.clear();

        {
            std::lock_guard<std::mutex> lock(mu_);
            joined_ = true;
        }
        cvIdle_.notify_all();
    }

    size_t threadCount() const noexcept { return workers_.size(); }

    size_t pendingCount() const {
        std::lock_guard<std::mutex> lock(mu_);
        return tasks_.size();
    }

    size_t activeCount() const {
        std::lock_guard<std::mutex> lock(mu_);
        return activeWorkers_;
    }

    bool isWorkerThread() const noexcept { return tlsPool_ == this; }

private:
    void workerLoop() noexcept {
        tlsPool_ = this;
        for (;;) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(mu_);
                cvTask_.wait(lock, [this] {
                    return stopping_ || !tasks_.empty();
                });

                if (stopping_) {
                    if (!drainOnStop_ || tasks_.empty()) break;
                }
                if (tasks_.empty()) continue;

                task = std::move(tasks_.front());
                tasks_.pop_front();
                ++activeWorkers_;
                cvSpace_.notify_one();
            }

            try { task(); } catch (...) {}

            {
                std::lock_guard<std::mutex> lock(mu_);
                if (activeWorkers_ > 0) --activeWorkers_;
                if (tasks_.empty() && activeWorkers_ == 0)
                    cvIdle_.notify_all();
            }
        }

        {
            std::lock_guard<std::mutex> lock(mu_);
            if (tasks_.empty() && activeWorkers_ == 0)
                cvIdle_.notify_all();
        }
        tlsPool_ = nullptr;
    }

    mutable std::mutex mu_;
    std::condition_variable cvTask_;
    std::condition_variable cvSpace_;
    std::condition_variable cvIdle_;
    std::deque<std::function<void()>> tasks_;
    std::vector<std::thread> workers_;
    size_t maxQueuedTasks_ = 0;
    size_t activeWorkers_ = 0;
    bool stopping_ = false;
    bool drainOnStop_ = true;
    bool joined_ = false;
    inline static thread_local const ThreadPool* tlsPool_ = nullptr;
};

} // namespace Deep2
