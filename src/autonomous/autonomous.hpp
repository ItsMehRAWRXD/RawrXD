#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace rawrxd {
namespace autonomous {

struct Task {
    std::string id;
    std::string description;
    std::string priority;   // "high", "medium", "low"
    std::string status;     // "pending", "in_progress", "completed", "failed"
    std::vector<std::string> files;
    uint64_t created_ms;
    uint64_t completed_ms;
};

struct WorkflowStep {
    std::string action;
    std::string target;
    std::string description;
    bool required;
};

class TaskManager {
public:
    TaskManager();
    ~TaskManager();

    std::string createTask(const std::string& description, const std::string& priority);
    bool updateStatus(const std::string& task_id, const std::string& status);
    Task* getTask(const std::string& task_id);
    std::vector<Task> getPendingTasks() const;
    std::vector<Task> getAllTasks() const;

private:
    std::vector<Task> tasks_;
    uint64_t next_id_;
};

class WorkflowEngine {
public:
    WorkflowEngine();
    ~WorkflowEngine();

    std::vector<WorkflowStep> createPipeline(const std::string& task_type);
    bool executeStep(const WorkflowStep& step);
    bool executePipeline(const std::vector<WorkflowStep>& steps);
};

class BuildLoop {
public:
    BuildLoop();
    ~BuildLoop();

    bool runBuild(const std::string& target);
    bool runTests(const std::string& target);
    bool runRepair(const std::string& error_log);
};

} // namespace autonomous
} // namespace rawrxd
