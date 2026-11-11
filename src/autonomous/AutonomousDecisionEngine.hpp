// Phase R.1/5: Autonomous Decision Engine
// RawrXD Autonomous Decision Engine - Self-governing operational decisions

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace Autonomous {

// Decision types
enum class DecisionType {
    RESOURCE_ALLOCATION,    // Allocate/deallocate resources
    SCALING_ACTION,         // Scale up/down
    CONFIGURATION_CHANGE,   // Modify configuration
    WORKFLOW_ADJUSTMENT,    // Change workflow parameters
    MAINTENANCE_SCHEDULE,   // Schedule maintenance
    FAILOVER_DECISION,      // Trigger failover
    COST_OPTIMIZATION,      // Optimize costs
    PERFORMANCE_TUNING,     // Tune performance
    SECURITY_RESPONSE,      // Respond to security events
    CUSTOM                  // Custom decision
};

// Decision confidence levels
enum class ConfidenceLevel {
    LOW,      // < 60% - requires human review
    MEDIUM,   // 60-80% - can execute with monitoring
    HIGH,     // 80-95% - can execute autonomously
    CERTAIN   // > 95% - execute immediately
};

// Decision context
struct DecisionContext {
    std::string id;
    std::chrono::system_clock::time_point timestamp;
    
    // Current state
    std::unordered_map<std::string, double> metrics;
    std::unordered_map<std::string, std::string> labels;
    std::vector<std::string> active_alerts;
    std::vector<std::string> recent_anomalies;
    
    // Historical context
    std::vector<std::string> recent_decisions;
    std::vector<std::string> recent_outcomes;
    
    // Constraints
    std::unordered_map<std::string, double> constraints;
    std::vector<std::string> blocked_actions;
    
    // Objectives
    std::vector<std::string> primary_objectives;
    std::vector<std::string> secondary_objectives;
};

// Decision proposal
struct DecisionProposal {
    std::string id;
    DecisionType type;
    std::string description;
    
    // Target
    std::string resource_id;
    std::string component_id;
    
    // Proposed action
    std::string action;
    std::unordered_map<std::string, std::string> parameters;
    
    // Confidence
    ConfidenceLevel confidence;
    double confidence_score;
    std::vector<std::string> confidence_factors;
    
    // Impact prediction
    struct ImpactPrediction {
        double probability_success;
        double expected_improvement;
        std::vector<std::string> risks;
        std::vector<std::string> benefits;
        std::chrono::seconds estimated_duration;
    } impact;
    
    // Alternatives
    std::vector<std::string> alternative_actions;
    std::string recommended_alternative;
    
    // Timing
    std::chrono::system_clock::time_point proposed_at;
    std::chrono::seconds execution_window;
    bool time_sensitive;
};

// Decision outcome
struct DecisionOutcome {
    std::string decision_id;
    std::string proposal_id;
    
    enum class Status {
        PENDING_APPROVAL,
        APPROVED,
        REJECTED,
        EXECUTING,
        EXECUTED,
        FAILED,
        ROLLED_BACK
    } status;
    
    // Execution
    std::chrono::system_clock::time_point executed_at;
    std::chrono::milliseconds execution_duration;
    std::string executed_by;  // "autonomous" or user_id
    
    // Results
    bool achieved_objective;
    double actual_improvement;
    std::vector<std::string> side_effects;
    std::string error_message;
    
    // Learning
    std::vector<std::string> lessons_learned;
    bool would_recommend;
};

// Policy for autonomous decisions
struct AutonomyPolicy {
    std::string id;
    std::string name;
    std::string description;
    
    // Scope
    std::vector<DecisionType> allowed_decisions;
    std::vector<std::string> allowed_resources;
    std::vector<std::string> excluded_resources;
    
    // Confidence thresholds
    ConfidenceLevel min_confidence_auto_execute;
    ConfidenceLevel min_confidence_with_approval;
    
    // Rate limiting
    uint32_t max_decisions_per_hour;
    uint32_t max_impact_per_decision;  // Maximum impact score
    std::chrono::seconds cooldown_between_decisions;
    
    // Safety
    bool require_approval_for_reversible;
    bool dry_run_first;
    uint32_t max_concurrent_decisions;
    
    // Time windows
    std::vector<std::pair<std::chrono::hours, std::chrono::hours>> allowed_hours;
    std::vector<std::string> blackout_periods;  // Maintenance windows
    
    // Escalation
    std::string escalation_policy_id;
    bool escalate_on_failure;
    
    // State
    bool enabled;
    uint32_t decisions_made;
    uint32_t decisions_succeeded;
    std::chrono::system_clock::time_point last_decision;
};

// Decision engine interface
class IAutonomousDecisionEngine {
public:
    virtual ~IAutonomousDecisionEngine() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Policy management
    virtual std::string CreatePolicy(const AutonomyPolicy& policy) = 0;
    virtual bool UpdatePolicy(const AutonomyPolicy& policy) = 0;
    virtual bool DeletePolicy(const std::string& policy_id) = 0;
    virtual std::optional<AutonomyPolicy> GetPolicy(const std::string& policy_id) = 0;
    virtual std::vector<AutonomyPolicy> ListPolicies() = 0;
    virtual bool EnablePolicy(const std::string& policy_id) = 0;
    virtual bool DisablePolicy(const std::string& policy_id) = 0;
    
    // Decision making
    virtual std::vector<DecisionProposal> EvaluateSituation(
        const DecisionContext& context) = 0;
    virtual std::optional<DecisionProposal> RecommendDecision(
        const DecisionContext& context) = 0;
    virtual std::string ExecuteDecision(const DecisionProposal& proposal,
                                        const std::string& policy_id) = 0;
    virtual bool CancelDecision(const std::string& decision_id) = 0;
    
    // Approval workflow
    virtual bool RequestApproval(const DecisionProposal& proposal) = 0;
    virtual bool ApproveDecision(const std::string& decision_id,
                                  const std::string& approver_id) = 0;
    virtual bool RejectDecision(const std::string& decision_id,
                                 const std::string& rejecter_id,
                                 const std::string& reason) = 0;
    
    // Outcome tracking
    virtual bool RecordOutcome(const DecisionOutcome& outcome) = 0;
    virtual std::optional<DecisionOutcome> GetOutcome(
        const std::string& decision_id) = 0;
    virtual std::vector<DecisionOutcome> GetDecisionHistory(
        const std::string& resource_id = "",
        std::chrono::hours lookback = std::chrono::hours(168)) = 0;
    
    // Simulation
    virtual std::vector<DecisionOutcome> SimulateDecision(
        const DecisionProposal& proposal,
        uint32_t scenario_count = 100) = 0;
    
    // Statistics
    virtual struct DecisionStatistics {
        uint32_t total_decisions;
        uint32_t autonomous_decisions;
        uint32_t approved_decisions;
        uint32_t rejected_decisions;
        uint32_t successful_outcomes;
        uint32_t failed_outcomes;
        double success_rate;
        double average_confidence;
        std::unordered_map<DecisionType, uint32_t> decisions_by_type;
    } GetStatistics(std::chrono::hours lookback = std::chrono::hours(168)) = 0;
};

// Local autonomous decision engine
class LocalAutonomousDecisionEngine : public IAutonomousDecisionEngine {
public:
    LocalAutonomousDecisionEngine();
    ~LocalAutonomousDecisionEngine() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string CreatePolicy(const AutonomyPolicy& policy) override;
    bool UpdatePolicy(const AutonomyPolicy& policy) override;
    bool DeletePolicy(const std::string& policy_id) override;
    std::optional<AutonomyPolicy> GetPolicy(const std::string& policy_id) override;
    std::vector<AutonomyPolicy> ListPolicies() override;
    bool EnablePolicy(const std::string& policy_id) override;
    bool DisablePolicy(const std::string& policy_id) override;
    
    std::vector<DecisionProposal> EvaluateSituation(
        const DecisionContext& context) override;
    std::optional<DecisionProposal> RecommendDecision(
        const DecisionContext& context) override;
    std::string ExecuteDecision(const DecisionProposal& proposal,
                                const std::string& policy_id) override;
    bool CancelDecision(const std::string& decision_id) override;
    
    bool RequestApproval(const DecisionProposal& proposal) override;
    bool ApproveDecision(const std::string& decision_id,
                         const std::string& approver_id) override;
    bool RejectDecision(const std::string& decision_id,
                        const std::string& rejecter_id,
                        const std::string& reason) override;
    
    bool RecordOutcome(const DecisionOutcome& outcome) override;
    std::optional<DecisionOutcome> GetOutcome(
        const std::string& decision_id) override;
    std::vector<DecisionOutcome> GetDecisionHistory(
        const std::string& resource_id = "",
        std::chrono::hours lookback = std::chrono::hours(168)) override;
    
    std::vector<DecisionOutcome> SimulateDecision(
        const DecisionProposal& proposal,
        uint32_t scenario_count = 100) override;
    
    DecisionStatistics GetStatistics(
        std::chrono::hours lookback = std::chrono::hours(168)) override;
    
private:
    std::unordered_map<std::string, AutonomyPolicy> policies_;
    std::unordered_map<std::string, DecisionProposal> proposals_;
    std::unordered_map<std::string, DecisionOutcome> outcomes_;
    bool initialized_ = false;
    
    bool CheckPolicyCompliance(const DecisionProposal& proposal,
                               const AutonomyPolicy& policy);
    ConfidenceLevel CalculateConfidence(const DecisionContext& context,
                                         const DecisionProposal& proposal);
    bool ExecuteAction(const DecisionProposal& proposal,
                       DecisionOutcome& outcome);
};

// Decision tree evaluator
class DecisionTreeEvaluator {
public:
    struct Node {
        std::string condition;
        std::string action;
        std::vector<std::shared_ptr<Node>> children;
        double confidence_weight;
    };
    
    void LoadTree(const std::shared_ptr<Node>& root);
    std::vector<DecisionProposal> Evaluate(const DecisionContext& context);
    double CalculatePathConfidence(const std::vector<std::shared_ptr<Node>>& path);
    
private:
    std::shared_ptr<Node> root_;
    
    bool EvaluateCondition(const std::string& condition,
                          const DecisionContext& context);
    void TraverseTree(const std::shared_ptr<Node>& node,
                     const DecisionContext& context,
                     std::vector<std::shared_ptr<Node>>& current_path,
                     std::vector<std::vector<std::shared_ptr<Node>>>& paths);
};

// Reinforcement learning decision optimizer
class RLDecisionOptimizer {
public:
    // State representation
    struct State {
        std::vector<double> features;
        std::unordered_map<std::string, double> metrics;
    };
    
    // Action space
    struct Action {
        DecisionType type;
        std::unordered_map<std::string, std::string> parameters;
    };
    
    // Reward
    struct Reward {
        double value;
        std::vector<std::string> factors;
    };
    
    // Learn from outcome
    void UpdatePolicy(const State& state,
                      const Action& action,
                      const Reward& reward,
                      const State& next_state);
    
    // Get best action
    Action RecommendAction(const State& state);
    
    // Exploration vs exploitation
    void SetExplorationRate(double epsilon);
    double GetExplorationRate() const;
    
private:
    double epsilon_ = 0.1;
    std::unordered_map<std::string, double> q_values_;
    
    std::string StateActionKey(const State& state, const Action& action);
};

// Global decision engine
extern std::unique_ptr<IAutonomousDecisionEngine> g_autonomous_decision_engine;

// Initialize autonomous decision engine
bool InitializeAutonomousDecisionEngine(const std::string& config_path);
void ShutdownAutonomousDecisionEngine();
bool IsAutonomousDecisionEnabled();

} // namespace Autonomous
} // namespace RawrXD
