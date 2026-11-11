// Phase R.3/5: Evolution Controller
// RawrXD Evolution Controller - System adaptation and evolution management

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

// Evolution types
enum class EvolutionType {
    CONFIGURATION,      // Configuration changes
    ARCHITECTURE,       // Architectural changes
    ALGORITHM,          // Algorithm improvements
    RESOURCE,           // Resource allocation changes
    POLICY,             // Policy updates
    INTERFACE,          // API/interface changes
    DEPENDENCY,         // Dependency updates
    CUSTOM              // Custom evolution
};

// Evolution scope
enum class EvolutionScope {
    COMPONENT,          // Single component
    SERVICE,            // Single service
    SYSTEM,             // Whole system
    CLUSTER,            // Multi-node cluster
    GLOBAL              // Global deployment
};

// Evolution proposal
struct EvolutionProposal {
    std::string id;
    std::string name;
    std::string description;
    
    // Classification
    EvolutionType type;
    EvolutionScope scope;
    std::string target_component;
    
    // Current vs proposed
    std::string current_state;
    std::string proposed_state;
    std::unordered_map<std::string, std::string> changes;
    
    // Rationale
    std::string rationale;
    std::vector<std::string> expected_benefits;
    std::vector<std::string> potential_risks;
    
    // Impact assessment
    struct ImpactAssessment {
        double performance_impact;
        double reliability_impact;
        double cost_impact;
        double security_impact;
        double user_experience_impact;
        std::vector<std::string> affected_components;
        std::vector<std::string> breaking_changes;
    } impact;
    
    // Rollback plan
    std::string rollback_procedure;
    std::chrono::seconds estimated_rollback_time;
    bool can_rollback;
    
    // Confidence
    double confidence_score;
    std::vector<std::string> confidence_factors;
    
    // Timing
    std::chrono::system_clock::time_point proposed_at;
    std::chrono::seconds estimated_duration;
    std::vector<std::string> prerequisites;
};

// Evolution stage
enum class EvolutionStage {
    PROPOSED,           // Initial proposal
    ANALYZING,          // Under analysis
    APPROVED,           // Approved for implementation
    SCHEDULED,          // Scheduled for deployment
    STAGING,            // In staging environment
    CANARY,             // Canary deployment
    ROLLING_OUT,        // Rolling out
    VALIDATING,         // Post-deployment validation
    COMPLETED,          // Successfully completed
    ROLLING_BACK,       // Rolling back
    FAILED,             // Failed
    CANCELLED           // Cancelled
};

// Evolution execution
struct EvolutionExecution {
    std::string id;
    std::string proposal_id;
    EvolutionStage stage;
    
    // Progress
    uint32_t total_steps;
    uint32_t completed_steps;
    std::vector<std::string> completed_step_names;
    std::string current_step;
    double progress_percent;
    
    // Timing
    std::chrono::system_clock::time_point started_at;
    std::chrono::system_clock::time_point stage_changed_at;
    std::chrono::system_clock::time_point completed_at;
    std::chrono::seconds estimated_remaining;
    
    // Status
    std::string status_message;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    
    // Validation
    std::vector<std::string> validation_checks;
    std::vector<bool> validation_results;
    
    // Metrics
    std::unordered_map<std::string, double> before_metrics;
    std::unordered_map<std::string, double> after_metrics;
    double improvement_percentage;
};

// Fitness metrics for evolution
struct FitnessMetrics {
    std::string component_id;
    std::chrono::system_clock::time_point measured_at;
    
    // Performance
    double throughput;
    double latency_p50;
    double latency_p99;
    double error_rate;
    
    // Resource
    double cpu_efficiency;
    double memory_efficiency;
    double resource_utilization;
    double cost_per_operation;
    
    // Reliability
    double availability;
    double mtbf;  // Mean time between failures
    double mttr;  // Mean time to recovery
    double failure_rate;
    
    // Overall
    double composite_score;
    std::vector<std::string> score_factors;
};

// Evolution strategy
struct EvolutionStrategy {
    std::string id;
    std::string name;
    std::string description;
    
    // Selection criteria
    double min_fitness_improvement;
    double max_acceptable_risk;
    uint32_t min_successful_tests;
    
    // Deployment strategy
    enum class DeploymentMode {
        BLUE_GREEN,         // Blue-green deployment
        CANARY,             // Canary rollout
        ROLLING,            // Rolling update
        A_B_TEST,           // A/B testing
        SHADOW,             // Shadow mode
        IMMEDIATE           // Immediate switch
    } deployment_mode;
    
    // Rollout parameters
    double canary_percentage_start;
    double canary_percentage_increment;
    std::chrono::seconds canary_hold_time;
    
    // Safety
    bool auto_rollback_on_failure;
    std::vector<std::string> rollback_triggers;
    std::chrono::seconds validation_period;
    
    // Scheduling
    std::vector<std::string> allowed_time_windows;
    std::vector<std::string> blackout_periods;
    bool require_manual_approval;
    
    // State
    bool enabled;
    uint32_t successful_evolutions;
    uint32_t failed_evolutions;
    uint32_t rollbacks;
};

// Evolution controller interface
class IEvolutionController {
public:
    virtual ~IEvolutionController() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Proposal management
    virtual std::string SubmitProposal(const EvolutionProposal& proposal) = 0;
    virtual bool UpdateProposal(const EvolutionProposal& proposal) = 0;
    virtual bool WithdrawProposal(const std::string& proposal_id) = 0;
    virtual std::optional<EvolutionProposal> GetProposal(const std::string& proposal_id) = 0;
    virtual std::vector<EvolutionProposal> ListProposals(
        EvolutionStage stage = EvolutionStage::PROPOSED) = 0;
    
    // Analysis
    virtual std::optional<EvolutionProposal> AnalyzeProposal(
        const std::string& proposal_id) = 0;
    virtual bool ApproveProposal(const std::string& proposal_id,
                                  const std::string& approver_id) = 0;
    virtual bool RejectProposal(const std::string& proposal_id,
                                 const std::string& rejecter_id,
                                 const std::string& reason) = 0;
    
    // Execution
    virtual std::string ScheduleEvolution(const std::string& proposal_id,
                                          const std::string& strategy_id) = 0;
    virtual bool StartEvolution(const std::string& execution_id) = 0;
    virtual bool PauseEvolution(const std::string& execution_id) = 0;
    virtual bool ResumeEvolution(const std::string& execution_id) = 0;
    virtual bool CancelEvolution(const std::string& execution_id) = 0;
    virtual bool RollbackEvolution(const std::string& execution_id) = 0;
    
    // Monitoring
    virtual std::optional<EvolutionExecution> GetExecution(
        const std::string& execution_id) = 0;
    virtual std::vector<EvolutionExecution> ListExecutions(
        const std::string& proposal_id = "") = 0;
    virtual bool AdvanceStage(const std::string& execution_id,
                               EvolutionStage new_stage) = 0;
    
    // Strategy management
    virtual std::string CreateStrategy(const EvolutionStrategy& strategy) = 0;
    virtual bool UpdateStrategy(const EvolutionStrategy& strategy) = 0;
    virtual bool DeleteStrategy(const std::string& strategy_id) = 0;
    virtual std::optional<EvolutionStrategy> GetStrategy(const std::string& strategy_id) = 0;
    virtual std::vector<EvolutionStrategy> ListStrategies() = 0;
    
    // Fitness tracking
    virtual bool RecordFitness(const FitnessMetrics& metrics) = 0;
    virtual std::vector<FitnessMetrics> GetFitnessHistory(
        const std::string& component_id,
        std::chrono::hours lookback = std::chrono::hours(168)) = 0;
    virtual std::optional<FitnessMetrics> GetCurrentFitness(
        const std::string& component_id) = 0;
    virtual std::vector<std::string> IdentifyComponentsNeedingEvolution() = 0;
    
    // Auto-evolution
    virtual bool EnableAutoEvolution(const std::string& component_id) = 0;
    virtual bool DisableAutoEvolution(const std::string& component_id) = 0;
    virtual std::vector<EvolutionProposal> GenerateEvolutionProposals(
        const std::string& component_id = "") = 0;
    
    // Statistics
    virtual struct EvolutionStatistics {
        uint32_t total_proposals;
        uint32_t approved_proposals;
        uint32_t rejected_proposals;
        uint32_t completed_evolutions;
        uint32_t failed_evolutions;
        uint32_t rollbacks;
        double success_rate;
        double average_improvement;
        std::chrono::seconds average_evolution_duration;
        std::unordered_map<EvolutionType, uint32_t> evolutions_by_type;
    } GetStatistics(std::chrono::hours lookback = std::chrono::hours(168)) = 0;
};

// Local evolution controller
class LocalEvolutionController : public IEvolutionController {
public:
    LocalEvolutionController();
    ~LocalEvolutionController() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string SubmitProposal(const EvolutionProposal& proposal) override;
    bool UpdateProposal(const EvolutionProposal& proposal) override;
    bool WithdrawProposal(const std::string& proposal_id) override;
    std::optional<EvolutionProposal> GetProposal(const std::string& proposal_id) override;
    std::vector<EvolutionProposal> ListProposals(
        EvolutionStage stage = EvolutionStage::PROPOSED) override;
    
    std::optional<EvolutionProposal> AnalyzeProposal(
        const std::string& proposal_id) override;
    bool ApproveProposal(const std::string& proposal_id,
                         const std::string& approver_id) override;
    bool RejectProposal(const std::string& proposal_id,
                        const std::string& rejecter_id,
                        const std::string& reason) override;
    
    std::string ScheduleEvolution(const std::string& proposal_id,
                                  const std::string& strategy_id) override;
    bool StartEvolution(const std::string& execution_id) override;
    bool PauseEvolution(const std::string& execution_id) override;
    bool ResumeEvolution(const std::string& execution_id) override;
    bool CancelEvolution(const std::string& execution_id) override;
    bool RollbackEvolution(const std::string& execution_id) override;
    
    std::optional<EvolutionExecution> GetExecution(
        const std::string& execution_id) override;
    std::vector<EvolutionExecution> ListExecutions(
        const std::string& proposal_id = "") override;
    bool AdvanceStage(const std::string& execution_id,
                      EvolutionStage new_stage) override;
    
    std::string CreateStrategy(const EvolutionStrategy& strategy) override;
    bool UpdateStrategy(const EvolutionStrategy& strategy) override;
    bool DeleteStrategy(const std::string& strategy_id) override;
    std::optional<EvolutionStrategy> GetStrategy(const std::string& strategy_id) override;
    std::vector<EvolutionStrategy> ListStrategies() override;
    
    bool RecordFitness(const FitnessMetrics& metrics) override;
    std::vector<FitnessMetrics> GetFitnessHistory(
        const std::string& component_id,
        std::chrono::hours lookback = std::chrono::hours(168)) override;
    std::optional<FitnessMetrics> GetCurrentFitness(
        const std::string& component_id) override;
    std::vector<std::string> IdentifyComponentsNeedingEvolution() override;
    
    bool EnableAutoEvolution(const std::string& component_id) override;
    bool DisableAutoEvolution(const std::string& component_id) override;
    std::vector<EvolutionProposal> GenerateEvolutionProposals(
        const std::string& component_id = "") override;
    
    EvolutionStatistics GetStatistics(
        std::chrono::hours lookback = std::chrono::hours(168)) override;
    
private:
    std::unordered_map<std::string, EvolutionProposal> proposals_;
    std::unordered_map<std::string, EvolutionExecution> executions_;
    std::unordered_map<std::string, EvolutionStrategy> strategies_;
    std::unordered_map<std::string, std::vector<FitnessMetrics>> fitness_history_;
    bool initialized_ = false;
    
    bool ValidateProposal(const EvolutionProposal& proposal);
    bool ExecuteStep(const std::string& execution_id,
                     const std::string& step_name);
    bool ValidateEvolution(const std::string& execution_id);
    double CalculateFitness(const FitnessMetrics& metrics);
    std::vector<EvolutionProposal> GenerateProposalsForComponent(
        const std::string& component_id);
};

// Genetic algorithm for evolution optimization
class GeneticEvolutionOptimizer {
public:
    struct Genome {
        std::unordered_map<std::string, double> parameters;
        double fitness;
    };
    
    void InitializePopulation(uint32_t size);
    void EvaluateFitness(std::function<double(const Genome&)> fitness_func);
    void Evolve(uint32_t generations);
    
    Genome GetBestGenome() const;
    std::vector<Genome> GetTopGenomes(uint32_t count) const;
    
private:
    std::vector<Genome> population_;
    
    void Selection();
    void Crossover();
    void Mutation();
    Genome CreateOffspring(const Genome& parent1, const Genome& parent2);
};

// A/B testing framework
class ABTestingFramework {
public:
    struct Variant {
        std::string id;
        std::string name;
        std::unordered_map<std::string, std::string> configuration;
        double traffic_percentage;
    };
    
    struct Experiment {
        std::string id;
        std::string name;
        std::vector<Variant> variants;
        std::string success_metric;
        std::chrono::system_clock::time_point start_time;
        std::chrono::seconds duration;
        bool is_active;
    };
    
    std::string CreateExperiment(const Experiment& experiment);
    bool AssignToVariant(const std::string& experiment_id,
                        const std::string& user_id,
                        std::string& variant_id);
    bool RecordOutcome(const std::string& experiment_id,
                       const std::string& variant_id,
                       double metric_value);
    std::optional<Variant> GetWinningVariant(const std::string& experiment_id);
    bool EndExperiment(const std::string& experiment_id,
                       const std::string& winning_variant_id);
};

// Global evolution controller
extern std::unique_ptr<IEvolutionController> g_evolution_controller;

// Initialize evolution controller
bool InitializeEvolutionController(const std::string& config_path);
void ShutdownEvolutionController();
bool IsEvolutionEnabled();

} // namespace Autonomous
} // namespace RawrXD
