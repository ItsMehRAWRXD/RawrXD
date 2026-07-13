// Phase D.6 Batch 5/5: Automated Remediation
// Self-Healing and Runbook Automation
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "SovereignAnomalyDetection.hpp"
#include "SovereignPerformanceAnalytics.hpp"
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Sovereign {
namespace Intelligence {

// ============================================================================
// Remediation Types
// ============================================================================

enum class RemediationType {
    RESTART_SERVICE = 0,
    SCALE_UP = 1,
    SCALE_DOWN = 2,
    ROLLBACK_DEPLOYMENT = 3,
    CLEAR_CACHE = 4,
    RECONFIGURE = 5,
    FAILOVER = 6,
    ISOLATE_NODE = 7,
    RUN_DIAGNOSTIC = 8,
    ESCALATE = 9
};

enum class RemediationStatus {
    PENDING = 0,
    IN_PROGRESS = 1,
    SUCCEEDED = 2,
    FAILED = 3,
    CANCELLED = 4,
    APPROVAL_REQUIRED = 5
};

struct RemediationAction {
    std::string action_id;
    RemediationType type;
    std::string target_resource;
    std::map<std::string, std::string> parameters;
    int max_attempts = 3;
    int attempt_count = 0;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point executed_at;
    std::chrono::steady_clock::time_point completed_at;
    RemediationStatus status = RemediationStatus::PENDING;
    std::string error_message;
    bool requires_approval = false;
    std::string approved_by;
};

// ============================================================================
// Self-Healing Engine
// ============================================================================

class SelfHealingEngine {
public:
    struct Config {
        bool enable_auto_remediation = true;
        int max_concurrent_remediations = 5;
        int cooldown_minutes = 10;
        double confidence_threshold = 0.8;
        bool require_approval_for_critical = true;
        int escalation_timeout_minutes = 30;
    };
    
    struct HealingRule {
        std::string rule_id;
        std::string name;
        std::string condition;  // e.g., "cpu > 90 for 5m"
        RemediationType action;
        std::map<std::string, std::string> parameters;
        double confidence_threshold = 0.8;
        bool enabled = true;
        int priority = 0;
    };
    
    explicit SelfHealingEngine(const Config& config);
    ~SelfHealingEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Rule management
    bool AddRule(const HealingRule& rule);
    bool UpdateRule(const std::string& rule_id, const HealingRule& rule);
    bool DeleteRule(const std::string& rule_id);
    bool EnableRule(const std::string& rule_id);
    bool DisableRule(const std::string& rule_id);
    std::vector<HealingRule> GetRules() const;
    
    // Remediation execution
    std::string ExecuteRemediation(const RemediationAction& action);
    bool CancelRemediation(const std::string& action_id);
    RemediationStatus GetRemediationStatus(const std::string& action_id) const;
    
    // Event handling
    void OnAnomaly(const Anomaly& anomaly);
    void OnBottleneck(const Bottleneck& bottleneck);
    void OnSLOBreach(const SLOStatus& slo);
    
    // History
    struct RemediationHistory {
        std::string action_id;
        RemediationType type;
        std::string target;
        RemediationStatus status;
        std::chrono::steady_clock::time_point started_at;
        std::chrono::steady_clock::time_point completed_at;
        int duration_seconds = 0;
        bool successful = false;
        std::string triggered_by;
    };
    
    std::vector<RemediationHistory> GetHistory(int limit = 100) const;
    std::vector<RemediationHistory> GetHistoryForResource(
        const std::string& resource_id, int limit = 100) const;
    
    // Statistics
    struct HealingStats {
        int total_remediations = 0;
        int successful_remediations = 0;
        int failed_remediations = 0;
        double success_rate = 0.0;
        double avg_remediation_time_seconds = 0.0;
        std::map<RemediationType, int> remediations_by_type;
    };
    
    HealingStats GetStats() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::thread execution_thread_;
    
    mutable std::mutex rules_mutex_;
    std::map<std::string, HealingRule> rules_;
    
    mutable std::mutex remediations_mutex_;
    std::map<std::string, RemediationAction> remediations_;
    std::vector<RemediationHistory> history_;
    
    std::map<std::string, std::chrono::steady_clock::time_point> cooldowns_;
    mutable std::mutex cooldown_mutex_;
    
    void ExecutionLoop();
    bool EvaluateCondition(const std::string& condition,
                          const std::map<std::string, double>& metrics);
    bool ExecuteAction(const RemediationAction& action);
    bool CheckCooldown(const std::string& resource_id);
    void UpdateCooldown(const std::string& resource_id);
};

// ============================================================================
// Runbook Automation
// ============================================================================

class RunbookAutomation {
public:
    struct Config {
        int max_execution_time_minutes = 60;
        bool enable_parallel_steps = true;
        int max_parallel_steps = 5;
        bool require_approval_for_manual_steps = true;
    };
    
    struct RunbookStep {
        std::string step_id;
        std::string name;
        std::string description;
        std::string type;  // "automated", "manual", "approval", "decision"
        std::string action;  // Command or API call
        std::map<std::string, std::string> parameters;
        std::vector<std::string> dependencies;  // Step IDs that must complete first
        int timeout_seconds = 300;
        bool continue_on_failure = false;
        std::string condition;  // Condition to execute this step
    };
    
    struct Runbook {
        std::string runbook_id;
        std::string name;
        std::string description;
        std::string trigger;  // e.g., "anomaly:cpu_high", "manual", "schedule"
        std::vector<RunbookStep> steps;
        int version = 1;
        bool enabled = true;
        std::map<std::string, std::string> variables;
    };
    
    struct RunbookExecution {
        std::string execution_id;
        std::string runbook_id;
        std::string status;  // "pending", "running", "completed", "failed", "cancelled"
        std::chrono::steady_clock::time_point started_at;
        std::chrono::steady_clock::time_point completed_at;
        std::map<std::string, std::string> context;
        std::vector<std::pair<std::string, std::string>> step_results;
        std::string executed_by;
        std::string error_message;
    };
    
    explicit RunbookAutomation(const Config& config);
    
    bool Initialize();
    
    // Runbook management
    bool CreateRunbook(const Runbook& runbook);
    bool UpdateRunbook(const std::string& runbook_id, const Runbook& runbook);
    bool DeleteRunbook(const std::string& runbook_id);
    Runbook GetRunbook(const std::string& runbook_id) const;
    std::vector<Runbook> GetRunbooks() const;
    
    // Execution
    std::string ExecuteRunbook(const std::string& runbook_id,
                               const std::map<std::string, std::string>& context);
    bool CancelExecution(const std::string& execution_id);
    bool ApproveStep(const std::string& execution_id, 
                     const std::string& step_id,
                     const std::string& approved_by);
    
    RunbookExecution GetExecution(const std::string& execution_id) const;
    std::vector<RunbookExecution> GetExecutions(const std::string& runbook_id,
                                                 int limit = 100) const;
    
    // Template library
    static Runbook CreateRestartServiceRunbook();
    static Runbook CreateScaleUpRunbook();
    static Runbook CreateFailoverRunbook();
    static Runbook CreateIncidentResponseRunbook();
    static Runbook CreateDeploymentRollbackRunbook();
    
private:
    Config config_;
    
    mutable std::mutex runbooks_mutex_;
    std::map<std::string, Runbook> runbooks_;
    
    mutable std::mutex executions_mutex_;
    std::map<std::string, RunbookExecution> executions_;
    
    bool ExecuteStep(const RunbookStep& step, 
                    const std::map<std::string, std::string>& context,
                    std::string& result);
    bool ExecuteAutomatedStep(const RunbookStep& step,
                             const std::map<std::string, std::string>& context,
                             std::string& result);
    bool ExecuteManualStep(const RunbookStep& step,
                          const std::map<std::string, std::string>& context);
};

// ============================================================================
// Incident Response
// ============================================================================

class IncidentResponse {
public:
    struct Config {
        int severity_threshold = 2;  // CRITICAL and above
        bool auto_create_incidents = true;
        bool auto_escalate = true;
        int escalation_timeout_minutes = 15;
        std::vector<std::string> on_call_rotations;
    };
    
    enum class IncidentSeverity {
        INFO = 0,
        WARNING = 1,
        CRITICAL = 2,
        EMERGENCY = 3
    };
    
    enum class IncidentStatus {
        OPEN = 0,
        ACKNOWLEDGED = 1,
        INVESTIGATING = 2,
        MITIGATING = 3,
        RESOLVED = 4,
        CLOSED = 5
    };
    
    struct Incident {
        std::string incident_id;
        std::string title;
        std::string description;
        IncidentSeverity severity;
        IncidentStatus status;
        std::chrono::steady_clock::time_point created_at;
        std::chrono::steady_clock::time_point acknowledged_at;
        std::chrono::steady_clock::time_point resolved_at;
        std::string acknowledged_by;
        std::string resolved_by;
        std::vector<std::string> related_anomalies;
        std::vector<std::string> affected_services;
        std::string root_cause;
        std::string remediation_action;
        std::vector<std::string> timeline;
    };
    
    struct WarRoom {
        std::string war_room_id;
        std::string incident_id;
        std::vector<std::string> participants;
        std::string bridge_url;
        std::string chat_channel;
        std::chrono::steady_clock::time_point created_at;
        std::chrono::steady_clock::time_point closed_at;
        bool active = false;
    };
    
    explicit IncidentResponse(const Config& config);
    
    bool Initialize();
    
    // Incident management
    std::string CreateIncident(const std::string& title,
                               const std::string& description,
                               IncidentSeverity severity,
                               const std::vector<std::string>& affected_services);
    bool AcknowledgeIncident(const std::string& incident_id,
                            const std::string& acknowledged_by);
    bool UpdateIncidentStatus(const std::string& incident_id,
                             IncidentStatus status);
    bool ResolveIncident(const std::string& incident_id,
                        const std::string& resolved_by,
                        const std::string& root_cause);
    bool CloseIncident(const std::string& incident_id);
    
    Incident GetIncident(const std::string& incident_id) const;
    std::vector<Incident> GetOpenIncidents() const;
    std::vector<Incident> GetIncidentsBySeverity(IncidentSeverity severity) const;
    
    // War room management
    std::string CreateWarRoom(const std::string& incident_id);
    bool AddParticipant(const std::string& war_room_id, 
                       const std::string& user_id);
    bool CloseWarRoom(const std::string& war_room_id);
    
    // Post-incident
    struct PostMortem {
        std::string incident_id;
        std::string summary;
        std::string timeline;
        std::string root_cause_analysis;
        std::vector<std::string> action_items;
        std::vector<std::string> lessons_learned;
        std::chrono::steady_clock::time_point created_at;
    };
    
    bool CreatePostMortem(const std::string& incident_id,
                         const PostMortem& post_mortem);
    PostMortem GetPostMortem(const std::string& incident_id) const;
    
    // Integration with other systems
    void OnAnomaly(const Anomaly& anomaly);
    void OnRemediationComplete(const RemediationHistory& remediation);
    
private:
    Config config_;
    
    mutable std::mutex incidents_mutex_;
    std::map<std::string, Incident> incidents_;
    
    mutable std::mutex war_rooms_mutex_;
    std::map<std::string, WarRoom> war_rooms_;
    
    mutable std::mutex post_mortems_mutex_;
    std::map<std::string, PostMortem> post_mortems_;
    
    void NotifyOnCall(const Incident& incident);
    void EscalateIncident(const Incident& incident);
    std::string GenerateIncidentId();
};

// ============================================================================
// Intelligence Runtime
// ============================================================================

class IntelligenceRuntime {
public:
    struct Config {
        ForecastingEngine::Config forecasting;
        AnomalyDetector::Config anomaly_detection;
        CostAnalyzer::Config cost_analysis;
        DistributedTracer::Config tracing;
        SelfHealingEngine::Config self_healing;
        RunbookAutomation::Config runbooks;
        IncidentResponse::Config incidents;
    };
    
    explicit IntelligenceRuntime(const Config& config);
    ~IntelligenceRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Access to subsystems
    ForecastingEngine* GetForecastingEngine();
    AnomalyDetector* GetAnomalyDetector();
    CostAnalyzer* GetCostAnalyzer();
    DistributedTracer* GetTracer();
    SelfHealingEngine* GetSelfHealingEngine();
    RunbookAutomation* GetRunbookAutomation();
    IncidentResponse* GetIncidentResponse();
    
    // Unified status
    struct IntelligenceStatus {
        bool healthy = false;
        int active_anomalies = 0;
        int active_incidents = 0;
        int pending_remediations = 0;
        double current_cost_per_hour = 0.0;
        double projected_monthly_cost = 0.0;
        double avg_latency_ms = 0.0;
        double slo_compliance_percent = 0.0;
    };
    
    IntelligenceStatus GetStatus() const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<ForecastingEngine> forecasting_;
    std::unique_ptr<LoadPredictor> load_predictor_;
    std::unique_ptr<ProactiveScaler> proactive_scaler_;
    std::unique_ptr<AnomalyDetector> anomaly_detector_;
    std::unique_ptr<RootCauseAnalyzer> root_cause_;
    std::unique_ptr<AlertManager> alert_manager_;
    std::unique_ptr<CostAnalyzer> cost_analyzer_;
    std::unique_ptr<RightSizingEngine> right_sizing_;
    std::unique_ptr<SpotInstanceManager> spot_manager_;
    std::unique_ptr<ReservedInstancePlanner> ri_planner_;
    std::unique_ptr<DistributedTracer> tracer_;
    std::unique_ptr<LatencyProfiler> profiler_;
    std::unique_ptr<BottleneckDetector> bottleneck_;
    std::unique_ptr<SLOManager> slo_manager_;
    std::unique_ptr<SelfHealingEngine> self_healing_;
    std::unique_ptr<RunbookAutomation> runbooks_;
    std::unique_ptr<IncidentResponse> incidents_;
};

// ============================================================================
// Factory Functions
// ============================================================================

std::unique_ptr<IntelligenceRuntime> CreateIntelligenceRuntime(
    const IntelligenceRuntime::Config& config);

} // namespace Intelligence
} // namespace Sovereign
