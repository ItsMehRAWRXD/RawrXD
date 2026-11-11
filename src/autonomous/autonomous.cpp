#include "autonomous.hpp"
#include <iostream>
#include <chrono>
#include <sstream>

namespace rawrxd {
namespace autonomous {

TaskManager::TaskManager() : next_id_(1) {}
TaskManager::~TaskManager() = default;

std::string TaskManager::createTask(const std::string& description, const std::string& priority) {
    Task task;
    task.id = "TASK-" + std::to_string(next_id_++);
    task.description = description;
    task.priority = priority;
    task.status = "pending";
    task.created_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    tasks_.push_back(task);
    return task.id;
}

bool TaskManager::updateStatus(const std::string& task_id, const std::string& status) {
    for (auto& t : tasks_) {
        if (t.id == task_id) {
            t.status = status;
            if (status == "completed" || status == "failed") {
                t.completed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
            }
            return true;
        }
    }
    return false;
}

Task* TaskManager::getTask(const std::string& task_id) {
    for (auto& t : tasks_) {
        if (t.id == task_id) return &t;
    }
    return nullptr;
}

std::vector<Task> TaskManager::getPendingTasks() const {
    std::vector<Task> pending;
    for (const auto& t : tasks_) {
        if (t.status == "pending") pending.push_back(t);
    }
    return pending;
}

std::vector<Task> TaskManager::getAllTasks() const { return tasks_; }

WorkflowEngine::WorkflowEngine() = default;
WorkflowEngine::~WorkflowEngine() = default;

std::vector<WorkflowStep> WorkflowEngine::createPipeline(const std::string& task_type) {
    std::vector<WorkflowStep> pipeline;

    if (task_type == "implement") {
        pipeline.push_back({"analyze", "", "Analyze requirements", true});
        pipeline.push_back({"plan", "", "Create implementation plan", true});
        pipeline.push_back({"generate", "", "Generate code", true});
        pipeline.push_back({"build", "", "Build project", true});
        pipeline.push_back({"test", "", "Run tests", true});
        pipeline.push_back({"review", "", "Review changes", true});
    } else if (task_type == "fix") {
        pipeline.push_back({"diagnose", "", "Diagnose the issue", true});
        pipeline.push_back({"generate_fix", "", "Generate fix", true});
        pipeline.push_back({"apply", "", "Apply fix", true});
        pipeline.push_back({"build", "", "Verify build", true});
        pipeline.push_back({"test", "", "Verify tests", true});
    } else {
        pipeline.push_back({"process", "", "Process request", true});
        pipeline.push_back({"verify", "", "Verify result", true});
    }

    return pipeline;
}

bool WorkflowEngine::executeStep(const WorkflowStep& step) {
    std::cout << "[Workflow] Executing: " << step.action << " - " << step.description << std::endl;
    return true;
}

bool WorkflowEngine::executePipeline(const std::vector<WorkflowStep>& steps) {
    for (const auto& step : steps) {
        if (!executeStep(step)) {
            std::cerr << "[Workflow] Failed at step: " << step.action << std::endl;
            return false;
        }
    }
    return true;
}

BuildLoop::BuildLoop() = default;
BuildLoop::~BuildLoop() = default;

bool BuildLoop::runBuild(const std::string& target) {
    std::cout << "[BuildLoop] Building: " << target << std::endl;
    return system("cmake --build . --config Release 2>&1") == 0;
}

bool BuildLoop::runTests(const std::string& target) {
    std::cout << "[BuildLoop] Testing: " << target << std::endl;
    return system("ctest --output-on-failure 2>&1") == 0;
}

bool BuildLoop::runRepair(const std::string& error_log) {
    std::cout << "[BuildLoop] Repairing with: " << error_log.substr(0, 100) << "..." << std::endl;
    return true;
}

} // namespace autonomous
} // namespace rawrxd
