// ============================================================================
// WorkStealingScheduler.cpp - Work-Stealing Thread Pool Implementation
// ============================================================================

#include "WorkStealingScheduler.hpp"
#include <thread>
#include <iostream>

namespace Sovereign {

WorkStealingScheduler::WorkStealingScheduler() = default;
WorkStealingScheduler::~WorkStealingScheduler() { Shutdown(); }

bool WorkStealingScheduler::Initialize(uint32_t numWorkers) {
    numWorkers_ = numWorkers == 0 ? std::thread::hardware_concurrency() : numWorkers;
    workers_.resize(numWorkers_);
    for (auto& w : workers_) w = std::make_unique<Worker>();
    
    running_ = true;
    for (uint32_t i = 0; i < numWorkers_; ++i) {
        threads_.emplace_back(&WorkStealingScheduler::WorkerLoop, this, i);
    }
    return true;
}

void WorkStealingScheduler::Shutdown() {
    running_ = false;
    cv_.notify_all();
    for (auto& t : threads_) if (t.joinable()) t.join();
    threads_.clear();
}

void WorkStealingScheduler::Submit(const std::string& queue, std::function<void()> task) {
    uint32_t workerId = std::hash<std::string>{}(queue) % numWorkers_;
    {
        std::lock_guard<std::mutex> lock(workers_[workerId]->mutex);
        workers_[workerId]->queue.push_back(task);
    }
    stats_.totalTasks++;
    cv_.notify_one();
}

void WorkStealingScheduler::SubmitGlobal(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(globalMutex_);
        globalQueue_.push_back(task);
    }
    stats_.totalTasks++;
    cv_.notify_one();
}

void WorkStealingScheduler::WaitAll() {
    while (true) {
        bool allEmpty = true;
        for (auto& w : workers_) {
            std::lock_guard<std::mutex> lock(w->mutex);
            if (!w->queue.empty()) { allEmpty = false; break; }
        }
        if (allEmpty) {
            std::lock_guard<std::mutex> lock(globalMutex_);
            if (globalQueue_.empty()) break;
        }
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
}

void WorkStealingScheduler::WorkerLoop(uint32_t workerId) {
    while (running_.load()) {
        std::function<void()> task;
        bool found = false;
        
        // Check local queue
        {
            std::lock_guard<std::mutex> lock(workers_[workerId]->mutex);
            if (!workers_[workerId]->queue.empty()) {
                task = workers_[workerId]->queue.front();
                workers_[workerId]->queue.pop_front();
                found = true;
            }
        }
        
        // Check global queue
        if (!found) {
            std::lock_guard<std::mutex> lock(globalMutex_);
            if (!globalQueue_.empty()) {
                task = globalQueue_.front();
                globalQueue_.pop_front();
                found = true;
            }
        }
        
        // Steal from others
        if (!found) {
            found = StealTask(workerId, task);
        }
        
        if (found) {
            task();
            workers_[workerId]->tasksProcessed++;
            stats_.completedTasks++;
        } else {
            std::unique_lock<std::mutex> lock(globalMutex_);
            cv_.wait_for(lock, std::chrono::milliseconds(1));
        }
    }
}

bool WorkStealingScheduler::StealTask(uint32_t thiefId, std::function<void()>& task) {
    for (uint32_t i = 0; i < numWorkers_; ++i) {
        if (i == thiefId) continue;
        std::lock_guard<std::mutex> lock(workers_[i]->mutex);
        if (!workers_[i]->queue.empty()) {
            task = workers_[i]->queue.back();
            workers_[i]->queue.pop_back();
            stats_.stolenTasks++;
            return true;
        }
    }
    return false;
}

} // namespace Sovereign
