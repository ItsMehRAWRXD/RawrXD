// ============================================================================
// ggml-threading.cpp - Full Implementation
// Thread pool and synchronization primitives for ggml compute operations
// ============================================================================

#include "ggml-threading.h"
#include <iostream>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <vector>
#include <queue>
#include <functional>
#include <atomic>

#ifdef _WIN32
#include <windows.h>
#endif

// ============================================================================
// Global Critical Section
// ============================================================================

std::mutex ggml_critical_section_mutex;

void ggml_critical_section_start() {
    ggml_critical_section_mutex.lock();
}

void ggml_critical_section_end(void) {
    ggml_critical_section_mutex.unlock();
}

// ============================================================================
// Thread Pool Implementation
// ============================================================================

namespace {

class ThreadPool {
public:
    ThreadPool(size_t numThreads)
        : m_stop(false)
        , m_activeJobs(0)
    {
        for (size_t i = 0; i < numThreads; ++i) {
            m_workers.emplace_back([this, i]() {
                setThreadAffinity(i);
                workerLoop();
            });
        }
    }

    ~ThreadPool() {
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            m_stop = true;
        }
        m_condition.notify_all();
        for (auto& worker : m_workers) {
            if (worker.joinable()) worker.join();
        }
    }

    template<typename F>
    void enqueue(F&& task) {
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            m_tasks.emplace(std::forward<F>(task));
        }
        m_condition.notify_one();
    }

    void waitAll() {
        std::unique_lock<std::mutex> lock(m_queueMutex);
        m_doneCondition.wait(lock, [this]() {
            return m_tasks.empty() && m_activeJobs == 0;
        });
    }

    size_t threadCount() const { return m_workers.size(); }

private:
    void workerLoop() {
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(m_queueMutex);
                m_condition.wait(lock, [this]() {
                    return m_stop || !m_tasks.empty();
                });

                if (m_stop && m_tasks.empty()) return;

                task = std::move(m_tasks.front());
                m_tasks.pop();
                m_activeJobs++;
            }

            task();

            {
                std::lock_guard<std::mutex> lock(m_queueMutex);
                m_activeJobs--;
                if (m_tasks.empty() && m_activeJobs == 0) {
                    m_doneCondition.notify_all();
                }
            }
        }
    }

    void setThreadAffinity(size_t threadIndex) {
#ifdef _WIN32
        DWORD_PTR mask = 1ULL << threadIndex;
        SetThreadAffinityMask(GetCurrentThread(), mask);
#endif
    }

    std::vector<std::thread> m_workers;
    std::queue<std::function<void()>> m_tasks;
    std::mutex m_queueMutex;
    std::condition_variable m_condition;
    std::condition_variable m_doneCondition;
    bool m_stop;
    std::atomic<int> m_activeJobs;
};

ThreadPool* g_threadPool = nullptr;
std::mutex g_poolMutex;

} // anonymous namespace

// ============================================================================
// GGML Threading API
// ============================================================================

int ggml_threadpool_init(int n_threads) {
    std::lock_guard<std::mutex> lock(g_poolMutex);

    if (g_threadPool) {
        delete g_threadPool;
    }

    if (n_threads <= 0) {
        n_threads = static_cast<int>(std::thread::hardware_concurrency());
        if (n_threads <= 0) n_threads = 4;
    }

    g_threadPool = new ThreadPool(static_cast<size_t>(n_threads));
    std::cout << "ggml_threadpool: initialized with " << n_threads
              << " threads" << std::endl;
    return n_threads;
}

void ggml_threadpool_destroy() {
    std::lock_guard<std::mutex> lock(g_poolMutex);
    if (g_threadPool) {
        delete g_threadPool;
        g_threadPool = nullptr;
        std::cout << "ggml_threadpool: destroyed" << std::endl;
    }
}

void ggml_threadpool_submit(void (*func)(void*), void* arg) {
    if (!g_threadPool) {
        // Fallback: execute inline
        func(arg);
        return;
    }
    g_threadPool->enqueue([func, arg]() { func(arg); });
}

void ggml_threadpool_wait() {
    if (g_threadPool) {
        g_threadPool->waitAll();
    }
}

int ggml_threadpool_get_thread_count() {
    if (g_threadPool) {
        return static_cast<int>(g_threadPool->threadCount());
    }
    return 1;
}

// ============================================================================
// Parallel For Implementation
// ============================================================================

void ggml_parallel_for(int64_t start, int64_t end,
                       void (*func)(int64_t i, void* arg), void* arg) {
    if (end <= start) return;

    int64_t range = end - start;
    int numThreads = ggml_threadpool_get_thread_count();

    if (numThreads <= 1 || range <= 1) {
        // Single-threaded fallback
        for (int64_t i = start; i < end; ++i) {
            func(i, arg);
        }
        return;
    }

    // Divide work among threads
    int64_t chunkSize = (range + numThreads - 1) / numThreads;
    std::atomic<int64_t> nextStart(start);
    std::atomic<int> completed{0};
    std::mutex doneMutex;
    std::condition_variable doneCV;

    for (int t = 0; t < numThreads; ++t) {
        ggml_threadpool_submit(
            [](void* ctx) {
                auto* params = static_cast<std::tuple<
                    std::atomic<int64_t>*,
                    int64_t,
                    int64_t,
                    void (*)(int64_t, void*),
                    void*,
                    std::atomic<int>*,
                    std::mutex*,
                    std::condition_variable*
                >*>(ctx);

                auto& [nextStart, end, chunkSize, func, arg,
                       completed, doneMutex, doneCV] = *params;

                while (true) {
                    int64_t myStart = nextStart->fetch_add(chunkSize);
                    if (myStart >= end) break;
                    int64_t myEnd = std::min(myStart + chunkSize, end);
                    for (int64_t i = myStart; i < myEnd; ++i) {
                        func(i, arg);
                    }
                }

                {
                    std::lock_guard<std::mutex> lock(*doneMutex);
                    (*completed)++;
                }
                doneCV->notify_one();

                delete params;
            },
            new std::tuple<
                std::atomic<int64_t>*,
                int64_t,
                int64_t,
                void (*)(int64_t, void*),
                void*,
                std::atomic<int>*,
                std::mutex*,
                std::condition_variable*
            >(&nextStart, end, chunkSize, func, arg,
              &completed, &doneMutex, &doneCV)
        );
    }

    // Wait for all threads to complete
    {
        std::unique_lock<std::mutex> lock(doneMutex);
        doneCV.wait(lock, [&completed, numThreads]() {
            return completed.load() >= numThreads;
        });
    }
}

// ============================================================================
// Spinlock Implementation
// ============================================================================

void ggml_spinlock_init(ggml_spinlock* lock) {
    lock->flag.clear();
}

void ggml_spinlock_lock(ggml_spinlock* lock) {
    while (lock->flag.test_and_set(std::memory_order_acquire)) {
        // Spin-wait with pause to reduce power consumption
#ifdef _WIN32
        _mm_pause();
#else
        __builtin_ia32_pause();
#endif
    }
}

void ggml_spinlock_unlock(ggml_spinlock* lock) {
    lock->flag.clear(std::memory_order_release);
}

// ============================================================================
// Barrier Implementation
// ============================================================================

void ggml_barrier_init(ggml_barrier* barrier, int count) {
    barrier->count = count;
    barrier->arrived = 0;
}

void ggml_barrier_wait(ggml_barrier* barrier) {
    std::unique_lock<std::mutex> lock(barrier->mutex);
    barrier->arrived++;
    if (barrier->arrived >= barrier->count) {
        barrier->arrived = 0;
        barrier->cv.notify_all();
    } else {
        barrier->cv.wait(lock, [barrier]() {
            return barrier->arrived == 0;
        });
    }
}
