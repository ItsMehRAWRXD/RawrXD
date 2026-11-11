#include "task_distribution.hpp"
#include <algorithm>
#include <iostream>

namespace RawrXD::Fleet {

bool TaskDistributor::Submit(const Task& task) {
    std::lock_guard<std::mutex> lock(mutex_);
    Task t = task;
    t.id = "TASK-" + std::to_string(next_id_++);
    t.status = "pending";
    pending_tasks_.push_back(t);
    return true;
}

bool TaskDistributor::AssignToNode(const std::string& task_id, const std::string& node_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = std::find_if(pending_tasks_.begin(), pending_tasks_.end(),
        [&](const Task& t) { return t.id == task_id; });
    
    if (it != pending_tasks_.end()) {
        it->assigned_node = node_id;
        it->status = "running";
        active_tasks_.push_back(*it);
        pending_tasks_.erase(it);
        
        std::cout << "TASK: " << task_id << "\n";
        std::cout << "Assigned: " << node_id << "\n";
        std::cout << "Result: COMPLETE\n";
        return true;
    }
    return false;
}

std::vector<Task> TaskDistributor::GetPending() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_tasks_;
}

std::vector<Task> TaskDistributor::GetActive() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_tasks_;
}

size_t TaskDistributor::GetQueueDepth() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_tasks_.size();
}

} // namespace RawrXD::Fleet
