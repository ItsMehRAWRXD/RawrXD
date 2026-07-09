// ============================================================================
// Thread Pool for Multi-threaded MatMul
// ============================================================================
// Simple, efficient thread pool for parallelizing transformer operations
// ============================================================================

#pragma once

#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <future>
#include <cstdint>

namespace RawrXD {
namespace Inference {

// Simple thread pool for parallel execution
class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads = 0);
    ~ThreadPool();

    // Initialize thread pool
    void Initialize(size_t num_threads);
    
    // Shutdown thread pool
    void Shutdown();
    
    // Submit work to thread pool
    template<typename Func, typename... Args>
    auto Submit(Func&& func, Args&&... args) -> std::future<decltype(func(args...))> {
        using ReturnType = decltype(func(args...));
        
        auto task = std::make_shared<std::packaged_task<ReturnType()>>(
            std::bind(std::forward<Func>(func), std::forward<Args>(args)...)
        );
        
        std::future<ReturnType> result = task->get_future();
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (shutdown_) {
                throw std::runtime_error("Cannot submit to shutdown thread pool");
            }
            tasks_.emplace([task]() { (*task)(); });
        }
        
        condition_.notify_one();
        return result;
    }
    
    // Parallel for - execute function over range in parallel
    void ParallelFor(size_t start, size_t end, std::function<void(size_t)> func);
    
    // Get number of threads
    size_t GetNumThreads() const { return num_threads_; }
    
    // Get hardware concurrency
    static size_t HardwareConcurrency() {
        return std::thread::hardware_concurrency();
    }

private:
    void WorkerThread();
    
    size_t num_threads_ = 0;
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    
    std::mutex queue_mutex_;
    std::condition_variable condition_;
    std::atomic<bool> shutdown_{false};
};

// Global thread pool instance
ThreadPool& GetGlobalThreadPool();

} // namespace Inference
} // namespace RawrXD
