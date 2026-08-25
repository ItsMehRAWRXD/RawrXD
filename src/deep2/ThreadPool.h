// ============================================================================
// ThreadPool.h - Persistent Thread Pool for Deep2 Inference
// Zero-dependency, C++17 implementation
// ============================================================================

#ifndef DEEP2_THREADPOOL_H
#define DEEP2_THREADPOOL_H

#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>
#include <future>

namespace Deep2 {

// ============================================================================
// Persistent Thread Pool
// Avoids OS thread creation overhead during inference
// ============================================================================
class ThreadPool {
public:
    ThreadPool() : ThreadPool(0) {}  // Default constructor - auto-detect threads
    explicit ThreadPool(size_t numThreads);
    ~ThreadPool();

    // Submit work to the pool
    template<typename F, typename... Args>
    auto enqueue(F&& f, Args&&... args) -> std::future<typename std::invoke_result_t<F, Args...>>;

    // Fire-and-forget enqueue (no future returned)
    template<typename F>
    void enqueue_void(F&& f) {
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            if (stop) return;
            activeTasks++;
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }

    // Wait for all tasks to complete
    void waitAll();

    // Get thread count
    size_t size() const { return workers.size(); }

    // Initialize/reinitialize with specific thread count (0 = auto-detect)
    void init(size_t numThreads);

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    
    std::mutex queueMutex;
    std::condition_variable condition;
    std::condition_variable finished;
    
    std::atomic<size_t> activeTasks{0};
    bool stop = false;
};

// Template implementation
template<typename F, typename... Args>
auto ThreadPool::enqueue(F&& f, Args&&... args) -> std::future<typename std::invoke_result_t<F, Args...>> {
    using return_type = typename std::invoke_result_t<F, Args...>;
    
    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...)
    );
    
    std::future<return_type> res = task->get_future();
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        if (stop) {
            throw std::runtime_error("enqueue on stopped ThreadPool");
        }
        activeTasks++;  // Increment before enqueue so waitAll() sees it immediately
        tasks.emplace([task]() {
            (*task)();
        });
    }
    condition.notify_one();
    return res;
}

// ============================================================================
// Parallel GEMV using ThreadPool
// ============================================================================
void ParallelGEMV(ThreadPool& pool, 
                  const float* input, 
                  const float* weights, 
                  float* output,
                  int rows, 
                  int cols,
                  void (*kernel)(const float*, const float*, float*, size_t));

} // namespace Deep2

#endif // DEEP2_THREADPOOL_H
