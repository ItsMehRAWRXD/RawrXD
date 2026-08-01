// ============================================================================
// AgentMemory.hpp - Persistent State Management for CEO Agent
// ============================================================================

#pragma once

#include "CEOAgent.hpp"
#include <nlohmann/json.hpp>
#include <string>

namespace RawrXD {
namespace Agents {

// ============================================================================
// Persistent Memory for CEO Agent
// ============================================================================
class AgentMemory {
public:
    AgentMemory();
    ~AgentMemory();
    
    // State persistence
    ProjectState LoadState() const;
    void SaveState(const ProjectState& state);
    
    // Task history
    void LogTaskCompletion(const std::string& taskId, bool success, const std::string& details);
    std::vector<nlohmann::json> GetTaskHistory() const;
    
    // Decision log
    void LogDecision(const std::string& decision, const std::string& reason, const std::string& context);
    std::vector<nlohmann::json> GetDecisionLog() const;
    
    // Architecture tracking
    void UpdateArchitecture(const std::string& component, const nlohmann::json& metadata);
    nlohmann::json GetArchitecture() const;
    
    // Clear all data
    void Clear();

private:
    std::string GetStatePath() const;
    std::string GetHistoryPath() const;
    std::string GetDecisionPath() const;
    std::string GetArchitecturePath() const;
    
    void EnsureDirectory() const;
};

} // namespace Agents
} // namespace RawrXD
