/**
 * @file SovereignTaskGraph.cpp
 * @brief DAG task scheduler implementation
 */

#include "SovereignTaskGraph.hpp"
#include <sstream>
#include <queue>
#include <algorithm>

namespace RawrXD::Autonomy {

static int64_t s_task_counter = 0;

std::string SovereignTaskGraph::AddTask(const std::string& description,
                                       const std::string& tool_name,
                                       const std::map<std::string, std::any>& params,
                                       int priority,
                                       const std::vector<std::string>& deps) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string id = "task_" + std::to_string(++s_task_counter);
    TaskNode node;
    node.id = id;
    node.description = description;
    node.tool_name = tool_name;
    node.parameters = params;
    node.priority = priority;
    node.dependencies = deps;
    node.created_at = std::chrono::steady_clock::now();
    tasks_[id] = std::move(node);
    UpdateReadyState();
    return id;
}

bool SovereignTaskGraph::RemoveTask(const std::string& task_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(task_id);
    if (it == tasks_.end()) return false;
    // Remove from dependents' dependency lists
    for (const auto& dep_id : it->second.dependencies) {
        auto dep_it = tasks_.find(dep_id);
        if (dep_it != tasks_.end()) {
            auto& d = dep_it->second.dependents;
            d.erase(std::remove(d.begin(), d.end(), task_id), d.end());
        }
    }
    tasks_.erase(it);
    return true;
}

bool SovereignTaskGraph::SetTaskAgent(const std::string& task_id, const std::string& agent_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(task_id);
    if (it == tasks_.end()) return false;
    it->second.agent_id = agent_id;
    return true;
}

bool SovereignTaskGraph::AddDependency(const std::string& task_id, const std::string& dep_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(task_id);
    auto dep = tasks_.find(dep_id);
    if (it == tasks_.end() || dep == tasks_.end() || task_id == dep_id) return false;
    std::set<std::string> visited;
    if (WouldCreateCycle(task_id, dep_id, visited)) return false;
    it->second.dependencies.push_back(dep_id);
    dep->second.dependents.push_back(task_id);
    UpdateReadyState();
    return true;
}

bool SovereignTaskGraph::RemoveDependency(const std::string& task_id, const std::string& dep_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(task_id);
    auto dep = tasks_.find(dep_id);
    if (it == tasks_.end() || dep == tasks_.end()) return false;
    auto& dlist = it->second.dependencies;
    dlist.erase(std::remove(dlist.begin(), dlist.end(), dep_id), dlist.end());
    auto& elist = dep->second.dependents;
    elist.erase(std::remove(elist.begin(), elist.end(), task_id), elist.end());
    UpdateReadyState();
    return true;
}

bool SovereignTaskGraph::HasCircularDependency(const std::string& task_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::set<std::string> visited;
    return WouldCreateCycle(task_id, task_id, visited);
}

bool SovereignTaskGraph::WouldCreateCycle(const std::string& from, const std::string& to,
                                           std::set<std::string>& visited) const {
    if (from == to) return true;
    if (visited.count(to)) return false;
    visited.insert(to);
    auto it = tasks_.find(to);
    if (it == tasks_.end()) return false;
    for (const auto& dep : it->second.dependencies) {
        if (WouldCreateCycle(from, dep, visited)) return true;
    }
    return false;
}

void SovereignTaskGraph::UpdateReadyState() {
    for (auto& [id, task] : tasks_) {
        if (task.state != TaskState::Pending) continue;
        bool deps_satisfied = true;
        for (const auto& dep_id : task.dependencies) {
            auto dep_it = tasks_.find(dep_id);
            if (dep_it == tasks_.end() || dep_it->second.state != TaskState::Completed) {
                deps_satisfied = false;
                break;
            }
        }
        if (deps_satisfied) {
            task.state = TaskState::Ready;
        }
    }
}

std::vector<std::string> SovereignTaskGraph::GetReadyTasks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [id, task] : tasks_) {
        if (task.state == TaskState::Ready) result.push_back(id);
    }
    // Sort by priority descending
    std::sort(result.begin(), result.end(), [this](const std::string& a, const std::string& b) {
        return tasks_.at(a).priority > tasks_.at(b).priority;
    });
    return result;
}

std::vector<std::string> SovereignTaskGraph::GetRunningTasks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [id, task] : tasks_) {
        if (task.state == TaskState::Running) result.push_back(id);
    }
    return result;
}

std::vector<std::string> SovereignTaskGraph::GetPendingTasks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [id, task] : tasks_) {
        if (task.state == TaskState::Pending) result.push_back(id);
    }
    return result;
}

std::vector<std::string> SovereignTaskGraph::GetFailedTasks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [id, task] : tasks_) {
        if (task.state == TaskState::Failed) result.push_back(id);
    }
    return result;
}

bool SovereignTaskGraph::MarkRunning(const std::string& task_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(task_id);
    if (it == tasks_.end() || it->second.state != TaskState::Ready) return false;
    it->second.state = TaskState::Running;
    it->second.started_at = std::chrono::steady_clock::now();
    if (on_state_change_) on_state_change_(it->second);
    return true;
}

bool SovereignTaskGraph::MarkCompleted(const std::string& task_id, const std::any& result) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(task_id);
    if (it == tasks_.end() || it->second.state != TaskState::Running) return false;
    it->second.state = TaskState::Completed;
    it->second.result = result;
    it->second.completed_at = std::chrono::steady_clock::now();
    if (it->second.started_at.has_value()) {
        it->second.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            it->second.completed_at.value() - it->second.started_at.value());
    }
    NotifyDependents(task_id);
    UpdateReadyState();
    if (on_state_change_) on_state_change_(it->second);
    return true;
}

bool SovereignTaskGraph::MarkFailed(const std::string& task_id, const std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(task_id);
    if (it == tasks_.end()) return false;
    it->second.state = TaskState::Failed;
    it->second.error_message = error;
    if (on_state_change_) on_state_change_(it->second);
    return true;
}

bool SovereignTaskGraph::MarkCancelled(const std::string& task_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(task_id);
    if (it == tasks_.end()) return false;
    it->second.state = TaskState::Cancelled;
    if (on_state_change_) on_state_change_(it->second);
    return true;
}

bool SovereignTaskGraph::MarkRetrying(const std::string& task_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(task_id);
    if (it == tasks_.end()) return false;
    it->second.state = TaskState::Retrying;
    ++it->second.retry_count;
    if (on_state_change_) on_state_change_(it->second);
    return true;
}

void SovereignTaskGraph::NotifyDependents(const std::string& task_id) {
    auto it = tasks_.find(task_id);
    if (it == tasks_.end()) return;
    for (const auto& dep_id : it->second.dependents) {
        auto dep_it = tasks_.find(dep_id);
        if (dep_it != tasks_.end() && dep_it->second.state == TaskState::Pending) {
            // Will be updated by UpdateReadyState()
        }
    }
}

bool SovereignTaskGraph::ExecuteReadyTasks(ExecuteCallback executor,
                                            TaskCallback on_complete,
                                            TaskCallback on_fail) {
    auto ready = GetReadyTasks();
    bool any_executed = false;
    for (const auto& id : ready) {
        if (!MarkRunning(id)) continue;
        auto task_opt = GetTask(id);
        if (!task_opt.has_value()) continue;
        TaskNode task = task_opt.value();
        std::any result;
        bool success = executor(task, result);
        if (success) {
            MarkCompleted(id, result);
            if (on_complete) on_complete(tasks_.at(id));
        } else {
            if (task.retry_count < task.max_retries) {
                MarkRetrying(id);
                // In a real system, schedule retry after delay
            } else {
                MarkFailed(id, "Max retries exceeded");
                if (on_fail) on_fail(tasks_.at(id));
            }
        }
        any_executed = true;
    }
    return any_executed;
}

bool SovereignTaskGraph::ExecuteAll(ExecuteCallback executor,
                                     TaskCallback on_complete,
                                     TaskCallback on_fail) {
    while (!IsComplete()) {
        if (!ExecuteReadyTasks(executor, on_complete, on_fail)) {
            // No ready tasks but not complete = deadlock or all running
            auto running = GetRunningTasks();
            if (running.empty()) break; // Deadlock
            // In real system, wait for running tasks to complete
            break;
        }
    }
    return IsSuccessful();
}

TaskState SovereignTaskGraph::GetTaskState(const std::string& task_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(task_id);
    if (it == tasks_.end()) return TaskState::Failed;
    return it->second.state;
}

std::optional<TaskNode> SovereignTaskGraph::GetTask(const std::string& task_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(task_id);
    if (it == tasks_.end()) return std::nullopt;
    return it->second;
}

std::vector<TaskNode> SovereignTaskGraph::GetAllTasks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<TaskNode> result;
    result.reserve(tasks_.size());
    for (const auto& [id, task] : tasks_) {
        result.push_back(task);
    }
    return result;
}

bool SovereignTaskGraph::IsComplete() const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [id, task] : tasks_) {
        if (task.state == TaskState::Pending ||
            task.state == TaskState::Ready ||
            task.state == TaskState::Running ||
            task.state == TaskState::Retrying) {
            return false;
        }
    }
    return !tasks_.empty();
}

bool SovereignTaskGraph::IsSuccessful() const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [id, task] : tasks_) {
        if (task.state != TaskState::Completed) return false;
    }
    return !tasks_.empty();
}

float SovereignTaskGraph::ProgressPercent() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (tasks_.empty()) return 0.0f;
    size_t done = 0;
    for (const auto& [id, task] : tasks_) {
        if (task.state == TaskState::Completed || task.state == TaskState::Failed ||
            task.state == TaskState::Cancelled) {
            ++done;
        }
    }
    return static_cast<float>(done) / static_cast<float>(tasks_.size()) * 100.0f;
}

size_t SovereignTaskGraph::TaskCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return tasks_.size();
}

size_t SovereignTaskGraph::CompletedCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [id, task] : tasks_) {
        if (task.state == TaskState::Completed) ++count;
    }
    return count;
}

size_t SovereignTaskGraph::FailedCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [id, task] : tasks_) {
        if (task.state == TaskState::Failed) ++count;
    }
    return count;
}

std::vector<std::string> SovereignTaskGraph::GetCriticalPath() const {
    // Simplified: longest chain of dependencies
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> longest;
    for (const auto& [id, task] : tasks_) {
        if (task.dependencies.empty()) {
            std::vector<std::string> chain;
            chain.push_back(id);
            // Walk dependents
            std::string current = id;
            while (true) {
                auto it = tasks_.find(current);
                if (it == tasks_.end() || it->second.dependents.empty()) break;
                current = it->second.dependents[0]; // Take first dependent
                chain.push_back(current);
            }
            if (chain.size() > longest.size()) longest = std::move(chain);
        }
    }
    return longest;
}

std::chrono::milliseconds SovereignTaskGraph::EstimatedRemainingTime() const {
    // Naive estimate: count remaining tasks * average completed duration
    std::lock_guard<std::mutex> lock(mutex_);
    size_t remaining = 0;
    std::chrono::milliseconds total_duration{0};
    size_t completed_count = 0;
    for (const auto& [id, task] : tasks_) {
        if (task.state == TaskState::Completed && task.duration_ms.has_value()) {
            total_duration += task.duration_ms.value();
            ++completed_count;
        }
        if (task.state == TaskState::Pending || task.state == TaskState::Ready ||
            task.state == TaskState::Running) {
            ++remaining;
        }
    }
    if (completed_count == 0) return std::chrono::milliseconds{0};
    auto avg = total_duration / completed_count;
    return avg * static_cast<int>(remaining);
}

std::string SovereignTaskGraph::Serialize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream oss;
    oss << "{\"tasks\":[";
    bool first = true;
    for (const auto& [id, task] : tasks_) {
        if (!first) oss << ",";
        first = false;
        oss << "{\"id\":\"" << id << "\",\"state\":" << static_cast<int>(task.state)
           << ",\"priority\":" << task.priority << "}";
    }
    oss << "]}";
    return oss.str();
}

bool SovereignTaskGraph::Deserialize(const std::string& /*data*/) {
    // TODO: Full parse if needed
    return true;
}

void SovereignTaskGraph::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    tasks_.clear();
}

} // namespace RawrXD::Autonomy
