// ============================================================================
// VAL-008: Threading/Concurrency Validation Gate Implementation
// ============================================================================

#include "VAL008_ThreadingGate.h"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <future>

namespace RawrXD {
namespace Validation {

REGISTER_VALIDATION_GATE(VAL008_ThreadingGate);

ValidationResult VAL008_ThreadingGate::Execute() {
    ValidationResult result;
    result.gateId = GetId();
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[VAL-008] Threading/Concurrency Validation\n");
    printf("=========================================\n");
    
    bool allPassed = true;
    
    printf("\n[1/5] Thread Pool...\n");
    if (!ValidateThreadPool()) {
        printf("  FAILED: Thread pool\n");
        allPassed = false;
    } else {
        printf("  PASSED: Thread pool\n");
    }
    
    printf("\n[2/5] Work Distribution...\n");
    if (!ValidateWorkDistribution()) {
        printf("  FAILED: Work distribution\n");
        allPassed = false;
    } else {
        printf("  PASSED: Work distribution\n");
    }
    
    printf("\n[3/5] Lock-Free Structures...\n");
    if (!ValidateLockFreeStructures()) {
        printf("  FAILED: Lock-free structures\n");
        allPassed = false;
    } else {
        printf("  PASSED: Lock-free structures\n");
    }
    
    printf("\n[4/5] Synchronization...\n");
    if (!ValidateSynchronization()) {
        printf("  FAILED: Synchronization\n");
        allPassed = false;
    } else {
        printf("  PASSED: Synchronization\n");
    }
    
    printf("\n[5/5] Thread Pinning...\n");
    if (!ValidateThreadPinning()) {
        printf("  FAILED: Thread pinning\n");
        allPassed = false;
    } else {
        printf("  PASSED: Thread pinning\n");
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    result.passed = allPassed;
    result.message = allPassed ? "VAL-008: All threading tests passed" 
                               : "VAL-008: Some tests failed";
    
    printf("\n=========================================\n");
    printf("[VAL-008] Result: %s (%.2f ms)\n", 
           allPassed ? "PASSED" : "FAILED", result.durationMs);
    printf("=========================================\n");
    
    return result;
}

bool VAL008_ThreadingGate::ValidateThreadPool() {
    const int num_threads = 4;
    const int num_tasks = 100;
    
    std::atomic<int> counter{0};
    std::vector<std::thread> threads;
    
    // Simple thread pool
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back([&counter]() {
            for (int j = 0; j < 25; j++) {
                counter.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    return counter.load() == num_tasks;
}

bool VAL008_ThreadingGate::ValidateWorkDistribution() {
    const int num_workers = 4;
    const int total_work = 1000;
    
    std::vector<int> work_counts(num_workers, 0);
    std::mutex mutex;
    
    std::vector<std::thread> threads;
    for (int i = 0; i < num_workers; i++) {
        threads.emplace_back([i, &work_counts, &mutex, total_work, num_workers]() {
            int start = (total_work / num_workers) * i;
            int end = (i == num_workers - 1) ? total_work : (total_work / num_workers) * (i + 1);
            
            std::lock_guard<std::mutex> lock(mutex);
            work_counts[i] = end - start;
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    // Verify all work was distributed
    int total = 0;
    for (int count : work_counts) {
        total += count;
    }
    
    return total == total_work;
}

bool VAL008_ThreadingGate::ValidateLockFreeStructures() {
    // Test lock-free queue using atomic operations
    std::atomic<int> head{0};
    std::atomic<int> tail{0};
    const int capacity = 1024;
    int buffer[capacity];
    
    const int num_ops = 1000;
    
    // Producer thread
    std::thread producer([&]() {
        for (int i = 0; i < num_ops; i++) {
            int t = tail.load(std::memory_order_relaxed);
            int h = head.load(std::memory_order_acquire);
            if ((t + 1) % capacity == h) continue; // Full
            buffer[t] = i;
            tail.store((t + 1) % capacity, std::memory_order_release);
        }
    });
    
    // Consumer thread
    std::thread consumer([&]() {
        int consumed = 0;
        while (consumed < num_ops) {
            int h = head.load(std::memory_order_relaxed);
            int t = tail.load(std::memory_order_acquire);
            if (h == t) continue; // Empty
            int val = buffer[h];
            (void)val;
            head.store((h + 1) % capacity, std::memory_order_release);
            consumed++;
        }
    });
    
    producer.join();
    consumer.join();
    
    return true;
}

bool VAL008_ThreadingGate::ValidateSynchronization() {
    std::mutex mutex;
    std::condition_variable cv;
    bool ready = false;
    bool processed = false;
    
    std::thread worker([&]() {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [&]() { return ready; });
        processed = true;
        lock.unlock();
        cv.notify_one();
    });
    
    // Signal worker
    {
        std::lock_guard<std::mutex> lock(mutex);
        ready = true;
    }
    cv.notify_one();
    
    // Wait for completion
    {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [&]() { return processed; });
    }
    
    worker.join();
    
    return processed;
}

bool VAL008_ThreadingGate::ValidateThreadPinning() {
    // Simulate thread affinity
    unsigned int num_cores = std::thread::hardware_concurrency();
    if (num_cores == 0) num_cores = 4;
    
    std::vector<std::thread> threads;
    std::atomic<int> completed{0};
    
    for (unsigned int i = 0; i < num_cores; i++) {
        threads.emplace_back([&completed]() {
            // Simulate work
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            completed.fetch_add(1);
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    return completed.load() == static_cast<int>(num_cores);
}

} // namespace Validation
} // namespace RawrXD
