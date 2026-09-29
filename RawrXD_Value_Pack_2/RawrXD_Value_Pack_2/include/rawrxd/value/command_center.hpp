#pragma once

#include "rawrxd/value/lifecycle_bus.hpp"

#include <chrono>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace rawrxd::value {

enum class TaskState : std::uint8_t {
    Queued,
    Running,
    Validating,
    Pass,
    Fail,
    Conflict,
    MergeReady
};

struct TaskRecord {
    std::string id;
    std::string title;
    std::string model;
    TaskState state{TaskState::Queued};
    std::chrono::system_clock::time_point created_at{};
    std::chrono::system_clock::time_point updated_at{};
    std::vector<std::string> changed_files;
    std::string latest_event;
    std::string validation_state;
    std::string merge_state;
};

class CommandCenter {
public:
    CommandCenter(LifecycleBus& bus, std::string receipt_path = {});

    bool createTask(std::string id, std::string title, std::string model);
    bool transition(const std::string& id, TaskState next, std::string detail = {});
    bool addChangedFile(const std::string& id, std::string path);
    bool setValidation(const std::string& id, std::string state);
    bool setMerge(const std::string& id, std::string state);

    std::optional<TaskRecord> get(const std::string& id) const;
    std::vector<TaskRecord> snapshot() const;

    static const char* toString(TaskState state) noexcept;
    static bool validTransition(TaskState from, TaskState to) noexcept;

private:
    void persist(const TaskRecord& record, const std::string& action) const;

    LifecycleBus& bus_;
    std::string receipt_path_;
    mutable std::mutex mutex_;
    std::map<std::string, TaskRecord> tasks_;
};

} // namespace rawrxd::value
