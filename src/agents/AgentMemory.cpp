// ============================================================================
// AgentMemory.cpp - Persistent State Management Implementation
// ============================================================================

#include "AgentMemory.hpp"
#include <fstream>
#include <filesystem>

namespace RawrXD {
namespace Agents {

AgentMemory::AgentMemory() {
    EnsureDirectory();
}

AgentMemory::~AgentMemory() = default;

void AgentMemory::EnsureDirectory() const {
    std::filesystem::path dir = ".rawrxd";
    if (!std::filesystem::exists(dir)) {
        std::filesystem::create_directories(dir);
    }
}

std::string AgentMemory::GetStatePath() const {
    return ".rawrxd/project_state.json";
}

std::string AgentMemory::GetHistoryPath() const {
    return ".rawrxd/task_history.json";
}

std::string AgentMemory::GetDecisionPath() const {
    return ".rawrxd/decisions.json";
}

std::string AgentMemory::GetArchitecturePath() const {
    return ".rawrxd/architecture.json";
}

ProjectState AgentMemory::LoadState() const {
    std::string path = GetStatePath();
    if (!std::filesystem::exists(path)) {
        return ProjectState{};
    }
    
    std::ifstream file(path);
    if (!file.is_open()) {
        return ProjectState{};
    }
    
    nlohmann::json j;
    try {
        file >> j;
        return ProjectState::fromJson(j);
    } catch (...) {
        return ProjectState{};
    }
}

void AgentMemory::SaveState(const ProjectState& state) {
    EnsureDirectory();
    
    std::ofstream file(GetStatePath());
    if (file.is_open()) {
        file << state.toJson().dump(2);
    }
}

void AgentMemory::LogTaskCompletion(const std::string& taskId, bool success, const std::string& details) {
    EnsureDirectory();
    
    nlohmann::json entry;
    entry["timestamp"] = std::time(nullptr);
    entry["task_id"] = taskId;
    entry["success"] = success;
    entry["details"] = details;
    
    std::vector<nlohmann::json> history = GetTaskHistory();
    history.push_back(entry);
    
    std::ofstream file(GetHistoryPath());
    if (file.is_open()) {
        file << nlohmann::json(history).dump(2);
    }
}

std::vector<nlohmann::json> AgentMemory::GetTaskHistory() const {
    std::string path = GetHistoryPath();
    if (!std::filesystem::exists(path)) {
        return {};
    }
    
    std::ifstream file(path);
    if (!file.is_open()) {
        return {};
    }
    
    try {
        nlohmann::json j;
        file >> j;
        return j.get<std::vector<nlohmann::json>>();
    } catch (...) {
        return {};
    }
}

void AgentMemory::LogDecision(const std::string& decision, const std::string& reason, const std::string& context) {
    EnsureDirectory();
    
    nlohmann::json entry;
    entry["timestamp"] = std::time(nullptr);
    entry["decision"] = decision;
    entry["reason"] = reason;
    entry["context"] = context;
    
    std::vector<nlohmann::json> log = GetDecisionLog();
    log.push_back(entry);
    
    std::ofstream file(GetDecisionPath());
    if (file.is_open()) {
        file << nlohmann::json(log).dump(2);
    }
}

std::vector<nlohmann::json> AgentMemory::GetDecisionLog() const {
    std::string path = GetDecisionPath();
    if (!std::filesystem::exists(path)) {
        return {};
    }
    
    std::ifstream file(path);
    if (!file.is_open()) {
        return {};
    }
    
    try {
        nlohmann::json j;
        file >> j;
        return j.get<std::vector<nlohmann::json>>();
    } catch (...) {
        return {};
    }
}

void AgentMemory::UpdateArchitecture(const std::string& component, const nlohmann::json& metadata) {
    EnsureDirectory();
    
    nlohmann::json arch = GetArchitecture();
    arch[component] = metadata;
    
    std::ofstream file(GetArchitecturePath());
    if (file.is_open()) {
        file << arch.dump(2);
    }
}

nlohmann::json AgentMemory::GetArchitecture() const {
    std::string path = GetArchitecturePath();
    if (!std::filesystem::exists(path)) {
        return nlohmann::json::object();
    }
    
    std::ifstream file(path);
    if (!file.is_open()) {
        return nlohmann::json::object();
    }
    
    try {
        nlohmann::json j;
        file >> j;
        return j;
    } catch (...) {
        return nlohmann::json::object();
    }
}

void AgentMemory::Clear() {
    std::filesystem::remove(GetStatePath());
    std::filesystem::remove(GetHistoryPath());
    std::filesystem::remove(GetDecisionPath());
    std::filesystem::remove(GetArchitecturePath());
}

} // namespace Agents
} // namespace RawrXD
