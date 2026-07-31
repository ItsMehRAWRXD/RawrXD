// ============================================================================
// ProjectState.cpp — Persistent State Management Implementation
// ============================================================================
#include "ProjectState.hpp"
#include "CEOAgent.hpp"
#include <filesystem>
#include <fstream>
#include <iomanip>

namespace fs = std::filesystem;

namespace RawrXD {
namespace CEO {

// ============================================================================
// Constructor / Destructor
// ============================================================================
ProjectState::ProjectState() = default;
ProjectState::~ProjectState() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================
bool ProjectState::Initialize(const std::string& storagePath) {
    m_storagePath = storagePath;
    
    // Create directory if needed
    try {
        fs::create_directories(storagePath);
    } catch (...) {
        return false;
    }
    
    // Try to load existing state
    std::string stateFile = (fs::path(storagePath) / "project_state.json").string();
    if (fs::exists(stateFile)) {
        LoadFromFile(stateFile);
    }
    
    m_initialized = true;
    return true;
}

void ProjectState::Shutdown() {
    if (m_initialized) {
        AutoSave();
    }
    m_initialized = false;
}

// ============================================================================
// Goal Management
// ============================================================================
void ProjectState::SetCurrentGoal(const Goal& goal) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_currentGoal = goal;
}

Goal ProjectState::GetCurrentGoal() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_currentGoal;
}

void ProjectState::AddGoal(const Goal& goal) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_goals.push_back(goal);
}

void ProjectState::UpdateGoal(const Goal& goal) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (auto& g : m_goals) {
        if (g.id == goal.id) {
            g = goal;
            return;
        }
    }
    
    // Not found, add it
    m_goals.push_back(goal);
}

std::vector<Goal> ProjectState::GetAllGoals() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_goals;
}

std::vector<Goal> ProjectState::GetCompletedGoals() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<Goal> completed;
    for (const auto& g : m_goals) {
        if (g.completed) {
            completed.push_back(g);
        }
    }
    return completed;
}

std::vector<Goal> ProjectState::GetPendingGoals() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<Goal> pending;
    for (const auto& g : m_goals) {
        if (!g.completed) {
            pending.push_back(g);
        }
    }
    return pending;
}

// ============================================================================
// Task Tracking
// ============================================================================
void ProjectState::AddTask(const Task& task) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_tasks.push_back(task);
}

void ProjectState::UpdateTask(const Task& task) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (auto& t : m_tasks) {
        if (t.id == task.id) {
            t = task;
            return;
        }
    }
    
    // Not found, add it
    m_tasks.push_back(task);
}

Task ProjectState::GetTask(const std::string& taskId) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (const auto& t : m_tasks) {
        if (t.id == taskId) {
            return t;
        }
    }
    
    return Task{};
}

std::vector<Task> ProjectState::GetAllTasks() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_tasks;
}

std::vector<Task> ProjectState::GetCompletedTasks() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<Task> completed;
    for (const auto& t : m_tasks) {
        if (t.status == Task::Status::Success) {
            completed.push_back(t);
        }
    }
    return completed;
}

std::vector<Task> ProjectState::GetFailedTasks() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<Task> failed;
    for (const auto& t : m_tasks) {
        if (t.status == Task::Status::Failed) {
            failed.push_back(t);
        }
    }
    return failed;
}

std::vector<Task> ProjectState::GetPendingTasks() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<Task> pending;
    for (const auto& t : m_tasks) {
        if (t.status == Task::Status::Pending ||
            t.status == Task::Status::Queued ||
            t.status == Task::Status::InProgress) {
            pending.push_back(t);
        }
    }
    return pending;
}

// ============================================================================
// Statistics
// ============================================================================
int ProjectState::GetCompletedTaskCount() const {
    return static_cast<int>(GetCompletedTasks().size());
}

int ProjectState::GetFailedTaskCount() const {
    return static_cast<int>(GetFailedTasks().size());
}

int ProjectState::GetTotalTaskCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<int>(m_tasks.size());
}

// ============================================================================
// Memory
// ============================================================================
void ProjectState::AddMemory(const std::string& key, const json& value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_memory[key] = value;
}

json ProjectState::GetMemory(const std::string& key) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_memory.find(key);
    if (it != m_memory.end()) {
        return it->second;
    }
    
    return json{};
}

void ProjectState::ClearMemory() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_memory.clear();
}

// ============================================================================
// Persistence
// ============================================================================
bool ProjectState::SaveToFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    json data = ToJSON();
    
    std::ofstream file(path);
    if (!file) {
        return false;
    }
    
    file << data.dump(2);
    return file.good();
}

bool ProjectState::LoadFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        return false;
    }
    
    json data;
    try {
        file >> data;
    } catch (...) {
        return false;
    }
    
    return FromJSON(data);
}

bool ProjectState::AutoSave() {
    if (m_storagePath.empty()) {
        return false;
    }
    
    std::string stateFile = (fs::path(m_storagePath) / "project_state.json").string();
    return SaveToFile(stateFile);
}

// ============================================================================
// Export
// ============================================================================
json ProjectState::ToJSON() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    json data;
    
    // Current goal
    data["current_goal"] = {
        {"id", m_currentGoal.id},
        {"description", m_currentGoal.description},
        {"completed", m_currentGoal.completed}
    };
    
    // All goals
    data["goals"] = json::array();
    for (const auto& g : m_goals) {
        json goal;
        goal["id"] = g.id;
        goal["description"] = g.description;
        goal["completed"] = g.completed;
        data["goals"].push_back(goal);
    }
    
    // Tasks
    data["tasks"] = json::array();
    for (const auto& t : m_tasks) {
        json task;
        task["id"] = t.id;
        task["description"] = t.description;
        task["status"] = static_cast<int>(t.status);
        task["attempts"] = t.attempts;
        data["tasks"].push_back(task);
    }
    
    // Memory
    data["memory"] = m_memory;
    
    return data;
}

bool ProjectState::FromJSON(const json& data) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Load current goal
    if (data.contains("current_goal")) {
        m_currentGoal.id = data["current_goal"].value("id", "");
        m_currentGoal.description = data["current_goal"].value("description", "");
        m_currentGoal.completed = data["current_goal"].value("completed", false);
    }
    
    // Load goals
    if (data.contains("goals") && data["goals"].is_array()) {
        for (const auto& g : data["goals"]) {
            Goal goal;
            goal.id = g.value("id", "");
            goal.description = g.value("description", "");
            goal.completed = g.value("completed", false);
            m_goals.push_back(goal);
        }
    }
    
    // Load tasks
    if (data.contains("tasks") && data["tasks"].is_array()) {
        for (const auto& t : data["tasks"]) {
            Task task;
            task.id = t.value("id", "");
            task.description = t.value("description", "");
            task.status = static_cast<Task::Status>(t.value("status", 0));
            task.attempts = t.value("attempts", 0);
            m_tasks.push_back(task);
        }
    }
    
    // Load memory
    if (data.contains("memory") && data["memory"].is_object()) {
        m_memory = data["memory"];
    }
    
    return true;
}

} // namespace CEO
} // namespace RawrXD
