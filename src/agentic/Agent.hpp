// ============================================================================
// Agent.hpp - Base Agent Architecture for Autonomous Reverse Engineering
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <future>
#include <chrono>
#include <mutex>
#include <atomic>
#include <optional>
#include <variant>
#include <nlohmann/json.hpp>

namespace RawrXD::Agentic {

// Forward declarations
class Blackboard;
class ToolRegistry;
class KnowledgeGraph;
struct Tool;
struct Observation;
struct Action;
struct Goal;

// ============================================================================
// Core Agent Types
// ============================================================================

enum class AgentState {
    IDLE,
    PLANNING,
    EXECUTING,
    WAITING,
    COMPLETED,
    FAILED,
    ESCALATED
};

enum class AgentRole {
    SCOUT,          // Find interesting regions
    PATTERN,        // Build signatures
    DECOMPILER,     // Recover control flow
    DEBUGGER,       // Execute samples
    GRAPH,          // Build CFGs
    ML,             // Classify functions
    OPTIMIZER,      // Merge duplicate discoveries
    VALIDATOR,      // Verify confidence
    ENTROPY,        // Analyze entropy
    UNPACKER,       // Handle packed binaries
    SYMBOLIC,       // Symbolic execution
    ORCHESTRATOR    // Coordinate missions
};

enum class ConfidenceLevel {
    UNKNOWN = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CERTAIN = 4
};

// ============================================================================
// Memory System
// ============================================================================

struct WorkingMemory {
    std::vector<Observation> observations;
    std::vector<Action> actions_taken;
    std::vector<std::string> hypotheses;
    std::map<std::string, std::variant<int, double, std::string, bool>> facts;
    std::chrono::steady_clock::time_point last_updated;
    
    void addObservation(const Observation& obs);
    void addFact(const std::string& key, const std::variant<int, double, std::string, bool>& value);
    std::optional<std::variant<int, double, std::string, bool>> getFact(const std::string& key) const;
    void clear();
};

struct LongTermMemory {
    std::vector<std::string> successful_strategies;
    std::vector<std::string> failed_strategies;
    std::map<std::string, double> tool_effectiveness; // tool_name -> success_rate
    std::map<std::string, nlohmann::json> learned_patterns;
    
    void recordSuccess(const std::string& strategy);
    void recordFailure(const std::string& strategy);
    void updateToolEffectiveness(const std::string& tool, bool success);
    double getToolEffectiveness(const std::string& tool) const;
};

// ============================================================================
// Observation & Action
// ============================================================================

struct Observation {
    std::string source;           // Which agent/tool produced this
    std::string type;             // e.g., "entropy_spike", "pattern_match", "cfg_fragment"
    std::string description;
    nlohmann::json data;
    double confidence = 0.0;
    uint64_t timestamp;
    std::vector<std::string> tags;
    
    bool isAnomaly() const;
    bool isHighConfidence() const;
};

struct Action {
    std::string name;
    std::string tool_id;
    nlohmann::json parameters;
    double expected_confidence = 0.0;
    std::vector<std::string> prerequisites;
    std::chrono::milliseconds estimated_duration{0};
    bool completed = false;
    bool successful = false;
    nlohmann::json result;
    std::string error_message;
};

struct Goal {
    std::string id;
    std::string description;
    std::vector<std::string> subgoals;
    std::map<std::string, std::string> constraints;
    double priority = 1.0;
    bool achieved = false;
    std::vector<std::string> required_roles;
};

// ============================================================================
// Decision System
// ============================================================================

struct Decision {
    std::string reasoning;
    Action chosen_action;
    std::vector<Action> alternatives_considered;
    double confidence = 0.0;
    bool requires_escalation = false;
    std::string escalate_to; // Agent role to escalate to
};

struct DecisionContext {
    Goal current_goal;
    WorkingMemory working_memory;
    std::vector<Observation> recent_observations;
    std::vector<Tool> available_tools;
    double time_budget_ms = 0.0;
    size_t iteration_count = 0;
};

// ============================================================================
// Base Agent Class
// ============================================================================

class Agent {
public:
    Agent(const std::string& id, AgentRole role);
    virtual ~Agent();

    // Core lifecycle
    virtual bool initialize();
    virtual void shutdown();
    virtual void executeCycle();
    
    // Goal management
    void setGoal(const Goal& goal);
    bool isGoalAchieved() const;
    double getGoalProgress() const;
    
    // Decision making
    virtual Decision makeDecision(const DecisionContext& context) = 0;
    virtual bool executeAction(const Action& action) = 0;
    
    // Observation handling
    virtual void observe(const Observation& observation);
    virtual void processBlackboardUpdate(const std::string& region_id, const nlohmann::json& update);
    
    // Tool usage
    void setToolRegistry(std::shared_ptr<ToolRegistry> registry);
    bool canUseTool(const std::string& tool_id) const;
    nlohmann::json invokeTool(const std::string& tool_id, const nlohmann::json& params);
    
    // Memory access
    WorkingMemory& getWorkingMemory();
    LongTermMemory& getLongTermMemory();
    
    // State
    AgentState getState() const;
    AgentRole getRole() const;
    std::string getId() const;
    double getConfidence() const;
    
    // Blackboard integration
    void setBlackboard(std::shared_ptr<Blackboard> blackboard);
    void subscribeToBlackboardRegion(const std::string& region_pattern);
    
    // Knowledge graph
    void setKnowledgeGraph(std::shared_ptr<KnowledgeGraph> kg);
    void queryKnowledge(const std::string& query_type, const nlohmann::json& params);
    
    // Reporting
    virtual nlohmann::json getStatus() const;
    virtual std::vector<Observation> getFindings() const;
    
    // Self-improvement hooks
    virtual void reflectOnPerformance();
    virtual void learnFromExperience();
    
protected:
    std::string id_;
    AgentRole role_;
    std::atomic<AgentState> state_{AgentState::IDLE};
    std::atomic<double> confidence_{0.0};
    
    Goal current_goal_;
    WorkingMemory working_memory_;
    LongTermMemory long_term_memory_;
    
    std::shared_ptr<Blackboard> blackboard_;
    std::shared_ptr<ToolRegistry> tool_registry_;
    std::shared_ptr<KnowledgeGraph> knowledge_graph_;
    
    std::vector<std::string> blackboard_subscriptions_;
    std::vector<Observation> findings_;
    
    mutable std::mutex mutex_;
    
    // Helper methods
    void transitionTo(AgentState new_state);
    void reportFinding(const Observation& finding);
    void requestAssistance(AgentRole role, const std::string& reason);
    std::vector<Tool> getAvailableTools() const;
    double estimateActionValue(const Action& action) const;
};

// ============================================================================
// Agent Factory
// ============================================================================

class AgentFactory {
public:
    static std::unique_ptr<Agent> createAgent(AgentRole role, const std::string& id);
    static std::vector<std::unique_ptr<Agent>> createAgentTeam(
        const std::vector<AgentRole>& roles,
        const std::string& mission_id);
};

} // namespace RawrXD::Agentic
