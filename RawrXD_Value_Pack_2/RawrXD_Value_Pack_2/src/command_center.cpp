#include "rawrxd/value/command_center.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>

namespace rawrxd::value {
namespace {

std::string escapeField(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (char c : input) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '\t': out += "\\t"; break;
            case '\r': out += "\\r"; break;
            case '\n': out += "\\n"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

std::int64_t millis(std::chrono::system_clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

std::string joinFiles(const std::vector<std::string>& files) {
    std::string out;
    for (std::size_t i = 0; i < files.size(); ++i) {
        if (i) out += ';';
        out += files[i];
    }
    return out;
}

} // namespace

CommandCenter::CommandCenter(LifecycleBus& bus, std::string receipt_path)
    : bus_(bus), receipt_path_(std::move(receipt_path)) {
    if (!receipt_path_.empty()) {
        std::filesystem::path p(receipt_path_);
        if (p.has_parent_path()) {
            std::error_code ec;
            std::filesystem::create_directories(p.parent_path(), ec);
        }
    }
}

bool CommandCenter::createTask(std::string id, std::string title, std::string model) {
    if (id.empty() || title.empty()) return false;
    TaskRecord copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (tasks_.find(id) != tasks_.end()) return false;
        TaskRecord r;
        r.id = std::move(id);
        r.title = std::move(title);
        r.model = std::move(model);
        r.state = TaskState::Queued;
        r.created_at = r.updated_at = std::chrono::system_clock::now();
        r.latest_event = "task-created";
        auto [it, inserted] = tasks_.emplace(r.id, std::move(r));
        if (!inserted) return false;
        copy = it->second;
    }
    persist(copy, "create");
    bus_.emit(LifecycleEventType::SessionStart, copy.id, copy.id,
              "title=" + copy.title + ";model=" + copy.model);
    return true;
}

bool CommandCenter::transition(const std::string& id, TaskState next, std::string detail) {
    TaskRecord copy;
    TaskState previous{};
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tasks_.find(id);
        if (it == tasks_.end()) return false;
        previous = it->second.state;
        if (!validTransition(previous, next)) return false;
        it->second.state = next;
        it->second.updated_at = std::chrono::system_clock::now();
        it->second.latest_event = detail.empty() ? toString(next) : std::move(detail);
        copy = it->second;
    }
    persist(copy, "transition");

    if (next == TaskState::Running) {
        bus_.emit(LifecycleEventType::BeforeInference, id, id, copy.latest_event);
    } else if (next == TaskState::Validating) {
        bus_.emit(LifecycleEventType::AfterInference, id, id, copy.latest_event);
        bus_.emit(LifecycleEventType::BeforeBuild, id, id, copy.latest_event);
    } else if (next == TaskState::MergeReady) {
        bus_.emit(LifecycleEventType::AfterBuild, id, id, copy.latest_event);
        bus_.emit(LifecycleEventType::BeforeMerge, id, id, copy.latest_event);
    } else if (next == TaskState::Pass) {
        bus_.emit(LifecycleEventType::AfterMerge, id, id, copy.latest_event);
        bus_.emit(LifecycleEventType::SessionStop, id, id, "PASS");
    } else if (next == TaskState::Fail || next == TaskState::Conflict) {
        bus_.emit(LifecycleEventType::SessionStop, id, id, toString(next));
    }
    return true;
}

bool CommandCenter::addChangedFile(const std::string& id, std::string path) {
    if (path.empty()) return false;
    TaskRecord copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tasks_.find(id);
        if (it == tasks_.end()) return false;
        if (std::find(it->second.changed_files.begin(), it->second.changed_files.end(), path) == it->second.changed_files.end()) {
            it->second.changed_files.push_back(std::move(path));
        }
        it->second.updated_at = std::chrono::system_clock::now();
        it->second.latest_event = "file-changed";
        copy = it->second;
    }
    persist(copy, "changed-file");
    bus_.emit(LifecycleEventType::AfterMutation, id, id, copy.changed_files.back());
    return true;
}

bool CommandCenter::setValidation(const std::string& id, std::string state) {
    TaskRecord copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tasks_.find(id);
        if (it == tasks_.end()) return false;
        it->second.validation_state = std::move(state);
        it->second.updated_at = std::chrono::system_clock::now();
        it->second.latest_event = "validation=" + it->second.validation_state;
        copy = it->second;
    }
    persist(copy, "validation");
    return true;
}

bool CommandCenter::setMerge(const std::string& id, std::string state) {
    TaskRecord copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tasks_.find(id);
        if (it == tasks_.end()) return false;
        it->second.merge_state = std::move(state);
        it->second.updated_at = std::chrono::system_clock::now();
        it->second.latest_event = "merge=" + it->second.merge_state;
        copy = it->second;
    }
    persist(copy, "merge");
    return true;
}

std::optional<TaskRecord> CommandCenter::get(const std::string& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = tasks_.find(id);
    if (it == tasks_.end()) return std::nullopt;
    return it->second;
}

std::vector<TaskRecord> CommandCenter::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<TaskRecord> out;
    out.reserve(tasks_.size());
    for (const auto& [_, record] : tasks_) out.push_back(record);
    return out;
}

const char* CommandCenter::toString(TaskState state) noexcept {
    switch (state) {
        case TaskState::Queued: return "QUEUED";
        case TaskState::Running: return "RUNNING";
        case TaskState::Validating: return "VALIDATING";
        case TaskState::Pass: return "PASS";
        case TaskState::Fail: return "FAIL";
        case TaskState::Conflict: return "CONFLICT";
        case TaskState::MergeReady: return "MERGE_READY";
    }
    return "UNKNOWN";
}

bool CommandCenter::validTransition(TaskState from, TaskState to) noexcept {
    if (from == to) return true;
    switch (from) {
        case TaskState::Queued:
            return to == TaskState::Running || to == TaskState::Fail;
        case TaskState::Running:
            return to == TaskState::Validating || to == TaskState::Fail || to == TaskState::Conflict;
        case TaskState::Validating:
            return to == TaskState::MergeReady || to == TaskState::Pass || to == TaskState::Fail || to == TaskState::Conflict;
        case TaskState::MergeReady:
            return to == TaskState::Pass || to == TaskState::Fail || to == TaskState::Conflict;
        case TaskState::Conflict:
            return to == TaskState::Running || to == TaskState::Fail;
        case TaskState::Pass:
        case TaskState::Fail:
            return false;
    }
    return false;
}

void CommandCenter::persist(const TaskRecord& r, const std::string& action) const {
    if (receipt_path_.empty()) return;
    std::ofstream out(receipt_path_, std::ios::app | std::ios::binary);
    if (!out) return;
    out << millis(r.updated_at) << '\t'
        << escapeField(action) << '\t'
        << escapeField(r.id) << '\t'
        << escapeField(r.title) << '\t'
        << escapeField(r.model) << '\t'
        << toString(r.state) << '\t'
        << escapeField(r.latest_event) << '\t'
        << escapeField(r.validation_state) << '\t'
        << escapeField(r.merge_state) << '\t'
        << escapeField(joinFiles(r.changed_files)) << '\n';
}

} // namespace rawrxd::value
