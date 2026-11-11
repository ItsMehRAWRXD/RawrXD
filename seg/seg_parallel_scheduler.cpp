#include "seg_parallel_scheduler.hpp"
#include "telemetry_ids.hpp"
#include "telemetry_masm_bridge.hpp"
#include <algorithm>
#include <chrono>

namespace seg {

// ============================================================================
// WorkStealingQueue Implementation
// ============================================================================

void WorkStealingQueue::Push(WorkItem item) {
    std::lock_guard<std::mutex> lock(mutex_);
    items_.push_back(item);
}

bool WorkStealingQueue::Pop(WorkItem& item) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (items_.empty()) {
        return false;
    }
    item = items_.back();
    items_.pop_back();
    return true;
}

bool WorkStealingQueue::Steal(WorkItem& item) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (items_.empty()) {
        return false;
    }
    // Steal from front (oldest work)
    item = items_.front();
    items_.erase(items_.begin());
    return true;
}

bool WorkStealingQueue::Empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return items_.empty();
}

size_t WorkStealingQueue::Size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return items_.size();
}

// ============================================================================
// ParallelScheduler Implementation
// ============================================================================

ParallelScheduler::ParallelScheduler() {
    Initialize(GetOptimalThreadCount());
}

ParallelScheduler::ParallelScheduler(uint32_t num_threads) {
    Initialize(num_threads);
}

ParallelScheduler::~ParallelScheduler() {
    shutdown_ = true;
    global_cv_.notify_all();
    
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    // Clean up remaining_deps_
    for (auto& pair : remaining_deps_) {
        delete pair.second;
    }
}

void ParallelScheduler::Initialize(uint32_t num_threads) {
    num_threads_ = num_threads;
    work_queues_.resize(num_threads);
    
    // Start worker threads
    for (uint32_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back(&ParallelScheduler::WorkerThread, this, i);
    }
}

void ParallelScheduler::ScheduleParallel(Graph& graph, Executor& executor) {
    MASM_TELEMETRY_SCOPE(TELEMETRY_SCHEDULER_START, TELEMETRY_SCHEDULER_END);
    
    current_graph_ = &graph;
    current_executor_ = &executor;
    
    // Reset counters
    active_tasks_ = 0;
    completed_tasks_ = 0;
    stolen_tasks_ = 0;
    
    // Clear previous state
    {
        std::lock_guard<std::mutex> lock(deps_mutex_);
        for (auto& pair : remaining_deps_) {
            delete pair.second;
        }
        remaining_deps_.clear();
    }
    
    // Initialize dependency counts
    auto topo_order = graph.TopologicalSort();
    for (const auto& node_id : topo_order) {
        const auto* node = graph.GetNode(node_id);
        if (node) {
            uint32_t dep_count = static_cast<uint32_t>(node->dependencies.size());
            auto* atomic_count = new std::atomic<uint32_t>(dep_count);
            
            std::lock_guard<std::mutex> lock(deps_mutex_);
            remaining_deps_[node_id] = atomic_count;
            
            // If no dependencies, add to global queue
            if (dep_count == 0) {
                WorkItem item;
                item.node_id = node_id;
                item.priority = static_cast<uint32_t>(node->priority);
                
                std::lock_guard<std::mutex> global_lock(global_mutex_);
                global_queue_.push(item);
            }
        }
    }
    
    // Notify workers
    global_cv_.notify_all();
    
    // Wait for completion
    WaitForCompletion();
    
    current_graph_ = nullptr;
    current_executor_ = nullptr;
}

void ParallelScheduler::WaitForCompletion() {
    std::unique_lock<std::mutex> lock(global_mutex_);
    global_cv_.wait(lock, [this] {
        return active_tasks_.load() == 0 && global_queue_.empty();
    });
}

void ParallelScheduler::WorkerThread(uint32_t thread_id) {
    // Optional: Pin thread to core for better cache locality
    // PinThreadToCore(thread_id, thread_id);
    
    while (!shutdown_.load()) {
        WorkItem item;
        
        // Try to get work
        if (GetWork(item, thread_id)) {
            active_tasks_++;
            
            // Execute the node
            if (current_graph_ && current_executor_) {
                ExecuteNode(*current_graph_, *current_executor_, item.node_id);
            }
            
            active_tasks_--;
            completed_tasks_++;
            
            // Notify potentially waiting threads
            global_cv_.notify_one();
        } else {
            // No work available, wait
            std::unique_lock<std::mutex> lock(global_mutex_);
            global_cv_.wait_for(lock, std::chrono::milliseconds(1), [this] {
                return shutdown_.load() || !global_queue_.empty();
            });
        }
    }
}

bool ParallelScheduler::GetWork(WorkItem& item, uint32_t thread_id) {
    // 1. Try own queue
    if (work_queues_[thread_id].Pop(item)) {
        return true;
    }
    
    // 2. Try global queue
    {
        std::lock_guard<std::mutex> lock(global_mutex_);
        if (!global_queue_.empty()) {
            item = global_queue_.top();
            global_queue_.pop();
            return true;
        }
    }
    
    // 3. Try stealing from other threads
    for (uint32_t i = 0; i < num_threads_; ++i) {
        if (i == thread_id) continue;
        
        if (work_queues_[i].Steal(item)) {
            stolen_tasks_++;
            return true;
        }
    }
    
    return false;
}

void ParallelScheduler::ExecuteNode(Graph& graph, Executor& executor, NodeId node_id) {
    const auto* node = graph.GetNode(node_id);
    if (!node) return;
    
    // Execute pre-hook
    if (node->pre_execute) {
        node->pre_execute(*node);
    }
    
    // Execute the node
    executor.Execute(*node);
    
    // Execute post-hook
    if (node->post_execute) {
        node->post_execute(*node);
    }
    
    // Mark as completed and notify dependents
    MarkCompleted(graph, node_id);
}

bool ParallelScheduler::DependenciesSatisfied(const Graph& graph, NodeId node_id) {
    std::lock_guard<std::mutex> lock(deps_mutex_);
    auto it = remaining_deps_.find(node_id);
    if (it != remaining_deps_.end()) {
        return it->second->load() == 0;
    }
    return false;
}

void ParallelScheduler::MarkCompleted(Graph& graph, NodeId node_id) {
    // Find all nodes that depend on this one
    auto topo_order = graph.TopologicalSort();
    
    for (const auto& other_id : topo_order) {
        if (other_id == node_id) continue;
        
        const auto* other_node = graph.GetNode(other_id);
        if (!other_node) continue;
        
        // Check if this node depends on the completed node
        for (const auto& dep : other_node->dependencies) {
            if (dep == node_id) {
                std::lock_guard<std::mutex> lock(deps_mutex_);
                auto it = remaining_deps_.find(other_id);
                if (it != remaining_deps_.end()) {
                    uint32_t new_count = --(*it->second);
                    
                    // If all dependencies satisfied, add to queue
                    if (new_count == 0) {
                        WorkItem item;
                        item.node_id = other_id;
                        item.priority = static_cast<uint32_t>(other_node->priority);
                        
                        std::lock_guard<std::mutex> global_lock(global_mutex_);
                        global_queue_.push(item);
                        global_cv_.notify_one();
                    }
                }
                break;
            }
        }
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

uint32_t GetOptimalThreadCount() {
    uint32_t hardware_threads = std::thread::hardware_concurrency();
    if (hardware_threads == 0) {
        hardware_threads = 4;  // Default fallback
    }
    
    // Leave one thread for OS/main thread
    return std::max(1u, hardware_threads - 1);
}

void PinThreadToCore(uint32_t thread_id, uint32_t core_id) {
#ifdef _WIN32
    HANDLE thread = GetCurrentThread();
    DWORD_PTR mask = 1ULL << core_id;
    SetThreadAffinityMask(thread, mask);
#elif defined(__linux__)
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
#endif
}

} // namespace seg
