// ============================================================================
// Thread Pool Implementation
// ============================================================================

#include "thread_pool.hpp"
#include <algorithm>

namespace RawrXD {
namespace Inference {

ThreadPool::ThreadPool(size_t num_threads) {
    if (num_threads > 0) {
        Initialize(num_threads);
    }
}

ThreadPool::~ThreadPool() {
    Shutdown();
}

void ThreadPool::Initialize(size_t num_threads) {
    if (num_threads == 0) {
        num_threads = HardwareConcurrency();
    }
    if (num_threads == 0) {
        num_threads = 4; // Default fallback
    }
    
    num_threads_ = num_threads;
    shutdown_ = false;
    
    workers_.reserve(num_threads);
    for (size_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back(&ThreadPool::WorkerThread, this);
    }
}

void ThreadPool::Shutdown() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        shutdown_ = true;
    }
    
    condition_.notify_all();
    
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    workers_.clear();
    num_threads_ = 0;
}

void ThreadPool::WorkerThread() {
    while (true) {
        std::function<void()> task;
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            condition_.wait(lock, [this] { return shutdown_ || !tasks_.empty(); });
            
            if (shutdown_ && tasks_.empty()) {
                return;
            }
            
            task = std::move(tasks_.front());
            tasks_.pop();
        }
        
        task();
    }
}

void ThreadPool::ParallelFor(size_t start, size_t end, std::function<void(size_t)> func) {
    if (num_threads_ == 0 || end <= start) {
        // No parallelism, execute sequentially
        for (size_t i = start; i < end; ++i) {
            func(i);
        }
        return;
    }
    
    size_t count = end - start;
    size_t num_threads = std::min(num_threads_, count);
    size_t chunk_size = count / num_threads;
    size_t remainder = count % num_threads;
    
    std::vector<std::future<void>> futures;
    futures.reserve(num_threads);
    
    size_t current = start;
    for (size_t t = 0; t < num_threads; ++t) {
        size_t local_start = current;
        size_t local_end = local_start + chunk_size + (t < remainder ? 1 : 0);
        current = local_end;
        
        futures.push_back(Submit([local_start, local_end, &func]() {
            for (size_t i = local_start; i < local_end; ++i) {
                func(i);
            }
        }));
    }
    
    // Wait for all tasks to complete
    for (auto& future : futures) {
        future.wait();
    }
}

// Global thread pool instance
ThreadPool& GetGlobalThreadPool() {
    static ThreadPool pool;
    if (pool.GetNumThreads() == 0) {
        pool.Initialize(0); // Use hardware concurrency
    }
    return pool;
}

} // namespace Inference
} // namespace RawrXD
