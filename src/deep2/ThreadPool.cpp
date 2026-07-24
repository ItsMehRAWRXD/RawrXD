// ============================================================================
// ThreadPool.cpp - Persistent Thread Pool Implementation
// ============================================================================

#include "ThreadPool.h"
#include <cstdio>
#ifdef _WIN32
#include <windows.h>
#endif

namespace Deep2 {

// ============================================================================
// ThreadPool Implementation
// ============================================================================

ThreadPool::ThreadPool(size_t numThreads) : stop(false) {
    if (numThreads == 0) {
        numThreads = std::thread::hardware_concurrency();
        if (numThreads == 0) numThreads = 4; // Fallback
    }
    
    printf("[ThreadPool] Initializing with %zu threads...\n", numThreads);
    
    workers.reserve(numThreads);
    for (size_t i = 0; i < numThreads; ++i) {
        workers.emplace_back([this, i] {
            // Pin thread to specific core for cache affinity
            #ifdef _WIN32
                SetThreadAffinityMask(GetCurrentThread(), 1ULL << i);
            #endif
            
            for (;;) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(queueMutex);
                    condition.wait(lock, [this] { 
                        return stop || !tasks.empty(); 
                    });
                    
                    if (stop && tasks.empty()) {
                        return;
                    }
                    
                    task = std::move(tasks.front());
                    tasks.pop();
                }
                
                // Execute task outside the lock
                task();

                // Notify waitAll() if queue is now empty and no active tasks remain
                if (activeTasks.fetch_sub(1) == 1) {
                    std::unique_lock<std::mutex> lock(queueMutex);
                    if (tasks.empty()) {
                        finished.notify_all();
                    }
                }
            }
        });
    }
    
    printf("[ThreadPool] Initialized %zu worker threads\n", workers.size());
}

ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        stop = true;
    }
    
    condition.notify_all();
    
    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    printf("[ThreadPool] Shutdown complete\n");
}

void ThreadPool::waitAll() {
    std::unique_lock<std::mutex> lock(queueMutex);
    // Wait without holding the lock so workers can acquire it to notify us
    finished.wait(lock, [this] {
        return tasks.empty() && activeTasks.load() == 0;
    });
}

// ============================================================================
// Parallel GEMV Implementation
// ============================================================================

void ParallelGEMV(ThreadPool& pool, 
                  const float* input, 
                  const float* weights, 
                  float* output,
                  int rows, 
                  int cols,
                  void (*kernel)(const float*, const float*, float*, size_t)) {
    
    size_t numThreads = pool.size();
    if (numThreads == 0) numThreads = 1;
    
    // Ensure rows per thread is aligned to 8 (AVX2 width)
    int rowsPerThread = (rows / numThreads + 7) & ~7;
    if (rowsPerThread < 8) rowsPerThread = 8;
    
    std::vector<std::future<void>> futures;
    futures.reserve(numThreads);
    
    for (size_t t = 0; t < numThreads; ++t) {
        int startRow = static_cast<int>(t * rowsPerThread);
        int endRow = static_cast<int>(std::min<size_t>(startRow + rowsPerThread, static_cast<size_t>(rows)));
        
        if (startRow >= rows) break;
        
        futures.push_back(pool.enqueue([=]() {
            for (int r = startRow; r < endRow; ++r) {
                // Each row is a dot product
                kernel(input, weights + r * cols, &output[r], cols);
            }
        }));
    }
    
    // Wait for all chunks to complete
    for (auto& f : futures) {
        f.wait();
    }
}

} // namespace Deep2
