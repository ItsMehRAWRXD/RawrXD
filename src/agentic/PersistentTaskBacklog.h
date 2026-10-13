// =============================================================================
// PersistentTaskBacklog.h — Durable Task State for Autonomous Development
// =============================================================================
// Provides persistent task queue that survives process restarts and reboots.
// Tasks are stored as JSON in a designated directory. Each task tracks:
//   - Priority and status (pending/in_progress/completed/failed/blocked)
//   - Full conversation history with the LLM
//   - Applied source changes (git commit hash before changes)
//   - Test results and build output
//   - Retry count and backoff
//   - Resource limits (time, disk, memory)
//
// Storage: JSON object in `.rawrxd_tasks.json` in the storage directory.
// =============================================================================
#pragma once

#include <string>
#include <vector>
#include <optional>
#include <mutex>
#include <chrono>
#include <random>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace RawrXD {
namespace Agent {

// ---------------------------------------------------------------------------
// Task priority
// ---------------------------------------------------------------------------
enum class TaskPriority : int {
    Critical = 0,
    High     = 1,
    Medium   = 2,
    Low      = 3,
};

// ---------------------------------------------------------------------------
// Task status
// ---------------------------------------------------------------------------
enum class TaskStatus : int {
    Pending     = 0,
    InProgress  = 1,
    Building    = 2,
    Testing     = 3,
    Completed   = 4,
    Failed      = 5,
    Blocked     = 6,
    Reverted    = 7,
};

inline const char* TaskStatusName(TaskStatus s) {
    switch (s) {
        case TaskStatus::Pending:    return "pending";
        case TaskStatus::InProgress: return "in_progress";
        case TaskStatus::Building:   return "building";
        case TaskStatus::Testing:    return "testing";
        case TaskStatus::Completed:  return "completed";
        case TaskStatus::Failed:     return "failed";
        case TaskStatus::Blocked:    return "blocked";
        case TaskStatus::Reverted:   return "reverted";
        default:                     return "unknown";
    }
}

// ---------------------------------------------------------------------------
// Resource limits for a task
// ---------------------------------------------------------------------------
struct TaskResourceLimits {
    int     max_build_minutes  = 10;
    int     max_test_minutes   = 5;
    size_t  max_output_bytes   = 1024 * 1024;
    int     max_disk_mb        = 500;
    int     max_retries        = 3;
    int     max_tool_rounds    = 15;
};

// ---------------------------------------------------------------------------
// Task step — one stage of execution history
// ---------------------------------------------------------------------------
struct TaskStep {
    std::string action;
    std::string output;
    bool        success = false;
    std::string error;
    int64_t     timestamp = 0;

    // For source changes:
    std::vector<std::string> changed_files;
    std::string git_commit_before;
    std::string git_commit_after;
    std::string patch_content;

    json ToJson() const;
    static TaskStep FromJson(const json& j);
};

// ---------------------------------------------------------------------------
// Persistent task
// ---------------------------------------------------------------------------
struct PersistentTask {
    std::string   id;
    std::string   title;
    std::string   description;
    TaskPriority  priority = TaskPriority::Medium;
    TaskStatus    status   = TaskStatus::Pending;

    json conversation_log;
    std::vector<TaskStep> steps;
    int              retry_count = 0;
    int64_t          created_at  = 0;
    int64_t          started_at  = 0;
    int64_t          completed_at = 0;

    TaskResourceLimits limits;
    std::string active_backend = "deep2";
    std::string active_model;
    std::string final_result;
    std::string failure_reason;

    json ToJson() const;
    static PersistentTask FromJson(const json& j);
};

// ---------------------------------------------------------------------------
// TaskStep JSON serialization
// ---------------------------------------------------------------------------
inline json TaskStep::ToJson() const {
    json j;
    j["action"]           = action;
    j["output"]           = output;
    j["success"]          = success;
    j["error"]            = error;
    j["timestamp"]        = timestamp;
    j["changed_files"]    = changed_files;
    j["git_commit_before"] = git_commit_before;
    j["git_commit_after"]  = git_commit_after;
    j["patch_content"]     = patch_content;
    return j;
}

inline TaskStep TaskStep::FromJson(const json& j) {
    TaskStep s;
    s.action           = j.value("action", std::string());
    s.output           = j.value("output", std::string());
    s.success          = j.value("success", false);
    s.error            = j.value("error", std::string());
    s.timestamp        = j.value("timestamp", int64_t(0));
    s.changed_files    = j.value("changed_files", std::vector<std::string>());
    s.git_commit_before = j.value("git_commit_before", std::string());
    s.git_commit_after  = j.value("git_commit_after", std::string());
    s.patch_content     = j.value("patch_content", std::string());
    return s;
}

// ---------------------------------------------------------------------------
// PersistentTask JSON serialization
// ---------------------------------------------------------------------------
inline json PersistentTask::ToJson() const {
    json j;
    j["id"]             = id;
    j["title"]          = title;
    j["description"]    = description;
    j["priority"]       = static_cast<int>(priority);
    j["status"]         = static_cast<int>(status);
    j["conversation_log"] = conversation_log;
    j["retry_count"]    = retry_count;
    j["created_at"]     = created_at;
    j["started_at"]     = started_at;
    j["completed_at"]   = completed_at;
    j["active_backend"] = active_backend;
    j["active_model"]   = active_model;
    j["final_result"]   = final_result;
    j["failure_reason"] = failure_reason;
    j["limits"] = {
        {"max_build_minutes", limits.max_build_minutes},
        {"max_test_minutes", limits.max_test_minutes},
        {"max_output_bytes", limits.max_output_bytes},
        {"max_disk_mb", limits.max_disk_mb},
        {"max_retries", limits.max_retries},
        {"max_tool_rounds", limits.max_tool_rounds}
    };
    json steps_arr = json::array();
    for (const auto& s : steps) steps_arr.push_back(s.ToJson());
    j["steps"] = steps_arr;
    return j;
}

inline PersistentTask PersistentTask::FromJson(const json& j) {
    PersistentTask t;
    t.id               = j.value("id", std::string());
    t.title            = j.value("title", std::string());
    t.description      = j.value("description", std::string());
    t.priority         = static_cast<TaskPriority>(j.value("priority", 2));
    t.status           = static_cast<TaskStatus>(j.value("status", 0));
    t.conversation_log = j.value("conversation_log", json::array());
    t.retry_count      = j.value("retry_count", 0);
    t.created_at       = j.value("created_at", int64_t(0));
    t.started_at       = j.value("started_at", int64_t(0));
    t.completed_at     = j.value("completed_at", int64_t(0));
    t.active_backend   = j.value("active_backend", std::string("deep2"));
    t.active_model     = j.value("active_model", std::string());
    t.final_result     = j.value("final_result", std::string());
    t.failure_reason   = j.value("failure_reason", std::string());
    if (j.contains("limits")) {
        const auto& l = j["limits"];
        t.limits.max_build_minutes  = l.value("max_build_minutes", 10);
        t.limits.max_test_minutes   = l.value("max_test_minutes", 5);
        t.limits.max_output_bytes   = l.value("max_output_bytes", 1024 * 1024);
        t.limits.max_disk_mb        = l.value("max_disk_mb", 500);
        t.limits.max_retries        = l.value("max_retries", 3);
        t.limits.max_tool_rounds    = l.value("max_tool_rounds", 15);
    }
    if (j.contains("steps") && j["steps"].is_array()) {
        for (const auto& s : j["steps"]) {
            t.steps.push_back(TaskStep::FromJson(s));
        }
    }
    return t;
}

// ---------------------------------------------------------------------------
// PersistentTaskBacklog — durable task queue
// ---------------------------------------------------------------------------
class PersistentTaskBacklog {
public:
    explicit PersistentTaskBacklog(const std::string& storage_dir);
    ~PersistentTaskBacklog() { Flush(); }

    // ---- CRUD ----
    std::string AddTask(const PersistentTask& task);
    std::optional<PersistentTask> GetTask(const std::string& id) const;
    void UpdateTask(const PersistentTask& task);
    void DeleteTask(const std::string& id);
    void SaveTask(const PersistentTask& task);

    // ---- Queue operations ----
    std::vector<PersistentTask> GetAllTasks() const;
    std::vector<PersistentTask> GetTasksByStatus(TaskStatus status) const;
    std::optional<PersistentTask> NextTask(TaskPriority min_priority = TaskPriority::Low);
    void MarkTaskStarted(const std::string& id);
    void MarkTaskCompleted(const std::string& id, const std::string& result = "");
    void MarkTaskFailed(const std::string& id, const std::string& reason = "");
    void MarkTaskReverted(const std::string& id, const std::string& reason = "");
    void IncrementRetry(const std::string& id);

    // ---- Statistics ----
    int GetPendingCount() const;
    int GetInProgressCount() const;
    int GetCompletedCount() const;
    int GetFailedCount() const;
    int GetTotalCount() const;

    // ---- Persistence ----
    void Flush() const;
    void Reload();

    // ---- Disk space management ----
    size_t GetStorageSizeBytes() const;

private:
    std::string m_storage_dir;
    std::string m_storage_file;
    mutable std::mutex m_mutex;
    std::vector<PersistentTask> m_tasks;

    void LoadFromFile();
    void SaveToFile() const;
    std::string GenerateId() const;
};

} // namespace Agent
} // namespace RawrXD
