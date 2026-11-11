// ============================================================================
// Parallel GEMM with Thread Pool
// ============================================================================
// Multi-threaded matrix multiplication for maximum CPU utilization
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <functional>
#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include "int8_gemm.hpp"

namespace SEG {

// Simple thread pool for parallel operations
class ThreadPool {
public:
    ThreadPool(size_t num_threads);
    ~ThreadPool();
    
    // Submit work to thread pool
    void Submit(std::function<void()> task);
    
    // Wait for all tasks to complete
    void WaitForAll();
    
    // Get number of threads
    size_t GetNumThreads() const { return num_threads_; }
    
private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex queue_mutex_;
    std::condition_variable condition_;
    std::condition_variable finished_;
    std::atomic<size_t> active_tasks_{0};
    bool stop_ = false;
    size_t num_threads_;
};

// Parallel vector-matrix multiplication
// Distributes N dimension across threads
void ParallelVecMatMul(const float* input, const float* weights,
                       float* output, size_t N, size_t K,
                       ThreadPool& pool);

// Parallel INT8 vector-matrix multiplication
void ParallelInt8VecMatMul(const float* input, const Q8Matrix& weights,
                           float* output, ThreadPool& pool);

// Get optimal thread count for current system
size_t GetOptimalThreadCount();

} // namespace SEG
