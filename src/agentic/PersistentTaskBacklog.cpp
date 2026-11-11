// =============================================================================
// PersistentTaskBacklog.cpp — Implementation
// =============================================================================
#include "PersistentTaskBacklog.h"
#include <algorithm>

namespace RawrXD {
namespace Agent {

PersistentTaskBacklog::PersistentTaskBacklog(const std::string& storage_dir)
    : m_storage_dir(storage_dir) {
    std::error_code ec;
    std::filesystem::create_directories(m_storage_dir, ec);
    m_storage_file = (std::filesystem::path(m_storage_dir) / ".rawrxd_tasks.json").string();
    LoadFromFile();
}

std::string PersistentTaskBacklog::GenerateId() const {
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
    uint64_t ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
    std::mt19937 rng(static_cast<unsigned int>(ns & 0xFFFFFFFF));
    std::uniform_int_distribution<int> dist(0, 65535);
    std::ostringstream oss;
    oss << "task_" << std::hex << ns << "_" << dist(rng);
    return oss.str();
}

std::string PersistentTaskBacklog::AddTask(const PersistentTask& task) {
    std::lock_guard<std::mutex> lock(m_mutex);
    PersistentTask t = task;
    if (t.id.empty()) {
        t.id = GenerateId();
    }
    if (t.created_at == 0) {
        t.created_at = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    m_tasks.push_back(t);
    SaveToFile();
    return t.id;
}

std::optional<PersistentTask> PersistentTaskBacklog::GetTask(const std::string& id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& t : m_tasks) {
        if (t.id == id) {
            return t;
        }
    }
    return std::nullopt;
}

void PersistentTaskBacklog::UpdateTask(const PersistentTask& task) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& t : m_tasks) {
        if (t.id == task.id) {
            t = task;
            SaveToFile();
            return;
        }
    }
    // Not found — add it
    m_tasks.push_back(task);
    SaveToFile();
}

void PersistentTaskBacklog::SaveTask(const PersistentTask& task) {
    UpdateTask(task);
}

void PersistentTaskBacklog::DeleteTask(const std::string& id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_tasks.erase(std::remove_if(m_tasks.begin(), m_tasks.end(),
        [&](const PersistentTask& t) { return t.id == id; }), m_tasks.end());
    SaveToFile();
}

std::vector<PersistentTask> PersistentTaskBacklog::GetAllTasks() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_tasks;
}

std::vector<PersistentTask> PersistentTaskBacklog::GetTasksByStatus(TaskStatus status) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<PersistentTask> result;
    for (const auto& t : m_tasks) {
        if (t.status == status) {
            result.push_back(t);
        }
    }
    return result;
}

std::optional<PersistentTask> PersistentTaskBacklog::NextTask(TaskPriority min_priority) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Find the highest-priority pending/in-progress task at or below min_priority
    std::optional<PersistentTask> selected;
    int best_priority = static_cast<int>(min_priority);

    for (const auto& t : m_tasks) {
        if (t.status == TaskStatus::Pending || t.status == TaskStatus::InProgress) {
            int tp = static_cast<int>(t.priority);
            if (tp <= best_priority) {
                if (!selected || tp < static_cast<int>(selected->priority)) {
                    selected = t;
                    best_priority = tp;
                }
            }
        }
    }

    return selected;
}

void PersistentTaskBacklog::MarkTaskStarted(const std::string& id) {
    auto t = GetTask(id);
    if (!t) return;
    t->status = TaskStatus::InProgress;
    t->started_at = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    UpdateTask(*t);
}

void PersistentTaskBacklog::MarkTaskCompleted(const std::string& id, const std::string& result) {
    auto t = GetTask(id);
    if (!t) return;
    t->status = TaskStatus::Completed;
    t->final_result = result;
    t->completed_at = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    UpdateTask(*t);
}

void PersistentTaskBacklog::MarkTaskFailed(const std::string& id, const std::string& reason) {
    auto t = GetTask(id);
    if (!t) return;
    t->status = TaskStatus::Failed;
    t->failure_reason = reason;
    t->completed_at = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    UpdateTask(*t);
}

void PersistentTaskBacklog::MarkTaskReverted(const std::string& id, const std::string& reason) {
    auto t = GetTask(id);
    if (!t) return;
    t->status = TaskStatus::Reverted;
    t->failure_reason = reason;
    UpdateTask(*t);
}

void PersistentTaskBacklog::IncrementRetry(const std::string& id) {
    auto t = GetTask(id);
    if (!t) return;
    t->retry_count++;
    UpdateTask(*t);
}

int PersistentTaskBacklog::GetPendingCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<int>(std::count_if(m_tasks.begin(), m_tasks.end(),
        [](const PersistentTask& t) { return t.status == TaskStatus::Pending; }));
}

int PersistentTaskBacklog::GetInProgressCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<int>(std::count_if(m_tasks.begin(), m_tasks.end(),
        [](const PersistentTask& t) { return t.status == TaskStatus::InProgress; }));
}

int PersistentTaskBacklog::GetCompletedCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<int>(std::count_if(m_tasks.begin(), m_tasks.end(),
        [](const PersistentTask& t) { return t.status == TaskStatus::Completed; }));
}

int PersistentTaskBacklog::GetFailedCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<int>(std::count_if(m_tasks.begin(), m_tasks.end(),
        [](const PersistentTask& t) { return t.status == TaskStatus::Failed || t.status == TaskStatus::Reverted; }));
}

int PersistentTaskBacklog::GetTotalCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<int>(m_tasks.size());
}

void PersistentTaskBacklog::LoadFromFile() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_tasks.clear();

    if (!std::filesystem::exists(m_storage_file)) return;

    std::ifstream f(m_storage_file);
    if (!f) return;

    try {
        json j;
        f >> j;
        if (j.is_array()) {
            for (const auto& item : j) {
                m_tasks.push_back(PersistentTask::FromJson(item));
            }
        }
    } catch (const json::exception&) {
        // Corrupt file — start fresh
        m_tasks.clear();
    }
}

void PersistentTaskBacklog::SaveToFile() const {
    json arr = json::array();
    for (const auto& t : m_tasks) {
        arr.push_back(t.ToJson());
    }

    std::ofstream f(m_storage_file, std::ios::trunc);
    if (!f) return;
    f << arr.dump(2);
}

void PersistentTaskBacklog::Flush() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    SaveToFile();
}

void PersistentTaskBacklog::Reload() {
    LoadFromFile();
}

size_t PersistentTaskBacklog::GetStorageSizeBytes() const {
    std::error_code ec;
    return std::filesystem::file_size(m_storage_file, ec);
}

} // namespace Agent
} // namespace RawrXD
