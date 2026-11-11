// ============================================================================
// CEOAgent.hpp - Autonomous Engineering Controller
// Top-level orchestrator for RawrXD IDE construction
// ============================================================================

#pragma once

#include "AgentMemory.hpp"
#include "Planner.hpp"
#include "ToolRegistry.hpp"
#include <memory>
#include <functional>

namespace RawrXD {
namespace Agents {

// Forward declarations
class Deep2Engine;
class AgentOrchestrator;
class HotPatcher;

// ============================================================================
// Project State Snapshot
// ============================================================================
struct ProjectState {
    std::vector<std::string> completedComponents;
    std::vector<std::string> inProgressComponents;
    std::vector<Task> pendingTasks;
    std::vector<std::string> blockers;
    
    // RawrXD-specific capabilities
    bool hasDeep2Engine = false;
    bool hasGGUFRuntime = false;
    bool hasExecutionABI = false;
    bool hasAgentOrchestrator = false;
    bool hasToolRegistry = false;
    bool hasTelemetry = false;
    bool hasHotPatcher = false;
    
    // IDE layers
    bool hasCompletionEngine = false;
    bool hasRepositoryIntelligence = false;
    bool hasModelManager = false;
    bool hasIDEShell = false;
    
    nlohmann::json toJson() const;
    static ProjectState fromJson(const nlohmann::json& j);
};

// ============================================================================
// CEO Agent - Autonomous Engineering Controller
// ============================================================================
class CEOAgent {
public:
    CEOAgent();
    ~CEOAgent();
    
    // Initialize with existing RawrXD runtime
    bool Initialize(
        Deep2Engine* engine,
        AgentOrchestrator* orchestrator,
        HotPatcher* hotpatcher
    );
    
    // Main entry: Continue building the IDE
    void ContinueBuilding();
    
    // Specific task execution
    void BuildComponent(const std::string& componentName);
    void IntegrateLayer(const std::string& layerName);
    
    // State queries
    ProjectState GetCurrentState() const;
    std::vector<std::string> GetMissingComponents() const;
    bool IsComponentReady(const std::string& name) const;
    
    // Progress callbacks
    using ProgressCallback = std::function<void(const std::string& stage, float percent)>;
    void SetProgressCallback(ProgressCallback cb);
    
    // Decision logging
    using DecisionCallback = std::function<void(const std::string& decision, const std::string& reason)>;
    void SetDecisionCallback(DecisionCallback cb);

private:
    // Core components
    std::unique_ptr<AgentMemory> memory_;
    std::unique_ptr<Planner> planner_;
    std::unique_ptr<ToolRegistry> tools_;
    
    // RawrXD runtime references
    Deep2Engine* deep2Engine_ = nullptr;
    AgentOrchestrator* orchestrator_ = nullptr;
    HotPatcher* hotpatcher_ = nullptr;
    
    // Callbacks
    ProgressCallback progressCallback_;
    DecisionCallback decisionCallback_;
    
    // Execution
    void AnalyzeCurrentState();
    void CreateImplementationPlan();
    void ExecuteTaskGraph();
    void ValidateAndCommit();
    
    // Component builders
    void BuildCompletionEngine();
    void BuildRepositoryIntelligence();
    void BuildModelManager();
    void BuildIDEShell();
    
    // Integration
    void IntegrateWithDeep2();
    void IntegrateWithOrchestrator();
    void WireTelemetry();
};

// ============================================================================
// Task Structure
// ============================================================================
struct Task {
    std::string id;
    std::string description;
    std::vector<std::string> dependencies;
    std::vector<std::string> outputs;
    std::function<bool()> executor;
    bool completed = false;
    bool failed = false;
    std::string errorMessage;
};

// ============================================================================
// Tool Interface
// ============================================================================
class Tool {
public:
    virtual ~Tool() = default;
    virtual std::string GetName() const = 0;
    virtual std::string GetDescription() const = 0;
    virtual bool Execute(const nlohmann::json& params) = 0;
};

// Concrete tools
class CreateFileTool : public Tool {
public:
    std::string GetName() const override { return "CreateFile"; }
    std::string GetDescription() const override { return "Create or overwrite a file"; }
    bool Execute(const nlohmann::json& params) override;
};

class ModifyFileTool : public Tool {
public:
    std::string GetName() const override { return "ModifyFile"; }
    std::string GetDescription() const override { return "Apply edits to existing file"; }
    bool Execute(const nlohmann::json& params) override;
};

class CompileTool : public Tool {
public:
    std::string GetName() const override { return "Compile"; }
    std::string GetDescription() const override { return "Compile source files"; }
    bool Execute(const nlohmann::json& params) override;
};

class RunTestsTool : public Tool {
public:
    std::string GetName() const override { return "RunTests"; }
    std::string GetDescription() const override { return "Execute test suite"; }
    bool Execute(const nlohmann::json& params) override;
};

class SearchCodeTool : public Tool {
public:
    std::string GetName() const override { return "SearchCode"; }
    std::string GetDescription() const override { return "Search codebase for patterns"; }
    bool Execute(const nlohmann::json& params) override;
};

} // namespace Agents
} // namespace RawrXD
