// AgenticTaskGraph Implementation
#include "../../include/agentic_task_graph.h"

namespace RawrXD {
namespace Agentic {

AgenticTaskGraph& AgenticTaskGraph::instance() {
    static AgenticTaskGraph instance;
    return instance;
}

AgenticTaskGraph::AgenticTaskGraph() : initialized_(false) {}

bool AgenticTaskGraph::initialize() {
    initialized_ = true;
    return true;
}

void AgenticTaskGraph::shutdown() {
    tasks_.clear();
    initialized_ = false;
}

TaskId AgenticTaskGraph::createTask(const std::string& name, const std::string& description) {
    TaskId id = nextTaskId_++;
    Task task;
    task.id = id;
    task.name = name;
    task.description = description;
    task.status = TaskStatus::Pending;
    tasks_[id] = task;
    return id;
}

bool AgenticTaskGraph::addDependency(TaskId task, TaskId dependsOn) {
    if (tasks_.find(task) == tasks_.end() || tasks_.find(dependsOn) == tasks_.end()) {
        return false;
    }
    tasks_[task].dependencies.push_back(dependsOn);
    return true;
}

bool AgenticTaskGraph::setTaskStatus(TaskId task, TaskStatus status) {
    if (tasks_.find(task) == tasks_.end()) {
        return false;
    }
    tasks_[task].status = status;
    return true;
}

std::vector<TaskId> AgenticTaskGraph::getReadyTasks() const {
    std::vector<TaskId> ready;
    for (const auto& [id, task] : tasks_) {
        if (task.status != TaskStatus::Pending) continue;
        
        bool depsComplete = true;
        for (TaskId depId : task.dependencies) {
            auto it = tasks_.find(depId);
            if (it == tasks_.end() || it->second.status != TaskStatus::Completed) {
                depsComplete = false;
                break;
            }
        }
        
        if (depsComplete) {
            ready.push_back(id);
        }
    }
    return ready;
}

std::vector<TaskId> AgenticTaskGraph::getAllTasks() const {
    std::vector<TaskId> ids;
    for (const auto& [id, _] : tasks_) {
        ids.push_back(id);
    }
    return ids;
}

TaskStatus AgenticTaskGraph::getTaskStatus(TaskId task) const {
    auto it = tasks_.find(task);
    if (it == tasks_.end()) {
        return TaskStatus::Failed;
    }
    return it->second.status;
}

std::string AgenticTaskGraph::getTaskName(TaskId task) const {
    auto it = tasks_.find(task);
    if (it == tasks_.end()) {
        return "";
    }
    return it->second.name;
}

void AgenticTaskGraph::clear() {
    tasks_.clear();
    nextTaskId_ = 1;
}

size_t AgenticTaskGraph::taskCount() const {
    return tasks_.size();
}

bool AgenticTaskGraph::isInitialized() const {
    return initialized_;
}

} // namespace Agentic
} // namespace RawrXD
