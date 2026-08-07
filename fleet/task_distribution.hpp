#pragma once
#include <string>
#include <vector>
#include <functional>
#include <mutex>

namespace RawrXD::Fleet {

struct Task {
    std::string id;
    std::string description;
    std::string specialization;
    std::string assigned_node;
    std::string status = "pending";
    int priority = 0;
};

class TaskDistributor {
public:
    TaskDistributor() = default;
    ~TaskDistributor() = default;

    bool Submit(const Task& task);
    bool AssignToNode(const std::string& task_id, const std::string& node_id);
    std::vector<Task> GetPending() const;
    std::vector<Task> GetActive() const;
    size_t GetQueueDepth() const;

private:
    std::vector<Task> pending_tasks_;
    std::vector<Task> active_tasks_;
    mutable std::mutex mutex_;
    int next_id_ = 1;
};

} // namespace RawrXD::Fleet
