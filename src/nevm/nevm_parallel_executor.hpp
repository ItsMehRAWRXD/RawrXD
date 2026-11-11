//============================================================================
// nevm_parallel_executor.hpp
// RawrXD N-EVM - Parallel Gate Execution
// Runs independent validation gates concurrently for faster CI
//============================================================================

#pragma once

#include <vector>
#include <thread>
#include <mutex>
#include <future>
#include <queue>
#include <functional>
#include <chrono>
#include <json/json.h>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Parallel Task
//============================================================================

struct ParallelTask {
    std::string name;
    int gate_id;
    std::function<bool()> task;
    bool can_parallelize;
    std::vector<int> dependencies;  // Gate IDs that must complete first
};

//============================================================================
// Parallel Execution Result
//============================================================================

struct ParallelExecutionResult {
    std::string gate_name;
    int gate_id;
    bool passed;
    double duration_ms;
    std::string error_message;
    Json::Value metrics;
    
    Json::Value ToJSON() const {
        Json::Value result;
        result["gate_name"] = gate_name;
        result["gate_id"] = gate_id;
        result["passed"] = passed;
        result["duration_ms"] = duration_ms;
        result["error_message"] = error_message;
        result["metrics"] = metrics;
        return result;
    }
};

//============================================================================
// Thread Pool
//============================================================================

class ThreadPool {
public:
    ThreadPool(size_t num_threads = std::thread::hardware_concurrency()) 
        : stop_(false) {
        for (size_t i = 0; i < num_threads; ++i) {
            workers_.emplace_back([this] { WorkerLoop(); });
        }
    }
    
    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            stop_ = true;
        }
        condition_.notify_all();
        
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }
    
    template<typename F, typename... Args>
    auto Enqueue(F&& f, Args&&... args) 
        -> std::future<typename std::result_of<F(Args...)>::type> {
        using return_type = typename std::result_of<F(Args...)>::type;
        
        auto task = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );
        
        std::future<return_type> result = task->get_future();
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (stop_) {
                throw std::runtime_error("Cannot enqueue on stopped ThreadPool");
            }
            tasks_.emplace([task]() { (*task)(); });
        }
        
        condition_.notify_one();
        return result;
    }
    
    size_t GetThreadCount() const { return workers_.size(); }

private:
    void WorkerLoop() {
        while (true) {
            std::function<void()> task;
            
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                condition_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
                
                if (stop_ && tasks_.empty()) {
                    return;
                }
                
                task = std::move(tasks_.front());
                tasks_.pop();
            }
            
            task();
        }
    }
    
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex queue_mutex_;
    std::condition_variable condition_;
    bool stop_;
};

//============================================================================
// Parallel Gate Executor
//============================================================================

class ParallelGateExecutor {
public:
    struct Config {
        size_t max_threads = 0;  // 0 = hardware concurrency
        bool stop_on_first_failure = true;
        int timeout_seconds = 300;  // Per-gate timeout
    };
    
    ParallelGateExecutor(const Config& config = Config()) 
        : config_(config) {
        if (config_.max_threads == 0) {
            config_.max_threads = std::thread::hardware_concurrency();
        }
    }
    
    // Register a gate for execution
    void RegisterGate(int gate_id, const std::string& name, 
                     std::function<bool(Json::Value&)> gate_fn,
                     bool can_parallelize = true,
                     const std::vector<int>& dependencies = {}) {
        GateInfo info;
        info.gate_id = gate_id;
        info.name = name;
        info.gate_fn = gate_fn;
        info.can_parallelize = can_parallelize;
        info.dependencies = dependencies;
        info.completed = false;
        info.passed = false;
        
        gates_[gate_id] = info;
    }
    
    // Execute all gates respecting dependencies
    std::vector<ParallelExecutionResult> Execute() {
        std::vector<ParallelExecutionResult> results;
        
        // Determine execution order based on dependencies
        auto execution_order = ComputeExecutionOrder();
        
        // Execute gates
        for (const auto& batch : execution_order) {
            if (batch.size() == 1 || !config_.max_threads > 1) {
                // Sequential execution
                for (int gate_id : batch) {
                    auto result = ExecuteGate(gate_id);
                    results.push_back(result);
                    
                    if (!result.passed && config_.stop_on_first_failure) {
                        return results;
                    }
                }
            } else {
                // Parallel execution
                auto batch_results = ExecuteBatch(batch);
                results.insert(results.end(), batch_results.begin(), batch_results.end());
                
                if (config_.stop_on_first_failure) {
                    for (const auto& r : batch_results) {
                        if (!r.passed) {
                            return results;
                        }
                    }
                }
            }
        }
        
        return results;
    }
    
    // Get execution statistics
    struct ExecutionStats {
        double total_duration_ms;
        double parallel_speedup;
        size_t gates_executed;
        size_t gates_parallelized;
    };
    
    ExecutionStats GetStats() const {
        ExecutionStats stats;
        stats.total_duration_ms = total_duration_ms_;
        stats.gates_executed = gates_executed_;
        stats.gates_parallelized = gates_parallelized_;
        stats.parallel_speedup = gates_parallelized_ > 0 ? 
            (sequential_estimate_ms_ / total_duration_ms_) : 1.0;
        return stats;
    }

private:
    struct GateInfo {
        int gate_id;
        std::string name;
        std::function<bool(Json::Value&)> gate_fn;
        bool can_parallelize;
        std::vector<int> dependencies;
        bool completed;
        bool passed;
        double duration_ms;
    };
    
    Config config_;
    std::unordered_map<int, GateInfo> gates_;
    std::mutex completion_mutex_;
    std::condition_variable completion_cv_;
    
    double total_duration_ms_ = 0.0;
    double sequential_estimate_ms_ = 0.0;
    size_t gates_executed_ = 0;
    size_t gates_parallelized_ = 0;
    
    std::vector<std::vector<int>> ComputeExecutionOrder() {
        std::vector<std::vector<int>> order;
        std::unordered_set<int> completed;
        
        while (completed.size() < gates_.size()) {
            std::vector<int> ready;
            
            for (auto& [id, gate] : gates_) {
                if (completed.count(id)) continue;
                
                // Check if all dependencies are completed
                bool deps_satisfied = true;
                for (int dep : gate.dependencies) {
                    if (!completed.count(dep)) {
                        deps_satisfied = false;
                        break;
                    }
                }
                
                if (deps_satisfied) {
                    ready.push_back(id);
                }
            }
            
            if (ready.empty()) {
                // Circular dependency detected
                throw std::runtime_error("Circular dependency detected in gates");
            }
            
            order.push_back(ready);
            for (int id : ready) {
                completed.insert(id);
            }
        }
        
        return order;
    }
    
    ParallelExecutionResult ExecuteGate(int gate_id) {
        auto& gate = gates_[gate_id];
        
        auto start = std::chrono::high_resolution_clock::now();
        
        Json::Value metrics;
        bool passed = false;
        std::string error;
        
        try {
            passed = gate.gate_fn(metrics);
        } catch (const std::exception& e) {
            passed = false;
            error = e.what();
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end - start).count();
        
        gate.completed = true;
        gate.passed = passed;
        gate.duration_ms = duration;
        
        total_duration_ms_ += duration;
        sequential_estimate_ms_ += duration;
        gates_executed_++;
        
        ParallelExecutionResult result;
        result.gate_name = gate.name;
        result.gate_id = gate_id;
        result.passed = passed;
        result.duration_ms = duration;
        result.error_message = error;
        result.metrics = metrics;
        
        return result;
    }
    
    std::vector<ParallelExecutionResult> ExecuteBatch(const std::vector<int>& gate_ids) {
        std::vector<ParallelExecutionResult> results(gate_ids.size());
        std::vector<std::future<ParallelExecutionResult>> futures;
        
        ThreadPool pool(std::min(gate_ids.size(), config_.max_threads));
        
        auto batch_start = std::chrono::high_resolution_clock::now();
        
        for (size_t i = 0; i < gate_ids.size(); ++i) {
            int gate_id = gate_ids[i];
            futures.push_back(pool.Enqueue([this, gate_id]() {
                return ExecuteGate(gate_id);
            }));
        }
        
        for (size_t i = 0; i < futures.size(); ++i) {
            results[i] = futures[i].get();
        }
        
        auto batch_end = std::chrono::high_resolution_clock::now();
        double batch_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            batch_end - batch_start).count();
        
        total_duration_ms_ += batch_duration;
        gates_parallelized_ += gate_ids.size();
        
        return results;
    }
};

} // namespace NEVM
} // namespace RawrXD
