// Phase D.10 Batch 5/5: Production Readiness & Deployment Automation
// Production readiness gates and automated deployment
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>

namespace Sovereign {
namespace Production {

// ============================================================================
// Readiness Gate
// ============================================================================

enum class GateStatus {
    PENDING = 0,
    IN_PROGRESS = 1,
    PASSED = 2,
    FAILED = 3,
    BLOCKED = 4
};

struct ReadinessCheck {
    std::string id;
    std::string name;
    std::string category;
    std::string description;
    std::function<bool()> check;
    bool required = true;
    std::chrono::seconds timeout{60};
    int retry_count = 0;
    std::vector<std::string> dependencies;
    std::string error_message;
};

struct GateResult {
    std::string gate_id;
    GateStatus status;
    std::chrono::steady_clock::time_point started_at;
    std::chrono::steady_clock::time_point completed_at;
    std::vector<std::pair<std::string, bool>> check_results;
    std::vector<std::string> failed_checks;
    std::string summary;
};

class ReadinessGate {
public:
    struct Config {
        bool fail_fast = true;
        bool parallel_execution = true;
        int max_parallel_checks = 5;
        std::chrono::seconds gate_timeout{300};
    };
    
    explicit ReadinessGate(const Config& config);
    
    // Check registration
    void RegisterCheck(const ReadinessCheck& check);
    void RemoveCheck(const std::string& check_id);
    
    // Gate execution
    GateResult ExecuteGate(const std::string& gate_id);
    bool ExecuteCheck(const std::string& check_id);
    
    // Predefined gates
    static std::vector<ReadinessCheck> GetDeploymentReadinessChecks();
    static std::vector<ReadinessCheck> GetSecurityReadinessChecks();
    static std::vector<ReadinessCheck> GetPerformanceReadinessChecks();
    static std::vector<ReadinessCheck> GetComplianceReadinessChecks();
    
    // Results
    std::vector<GateResult> GetGateHistory() const;
    bool IsReady() const;
    std::vector<std::string> GetBlockingIssues() const;
    
private:
    Config config_;
    std::map<std::string, ReadinessCheck> checks_;
    std::vector<GateResult> history_;
    mutable std::mutex mutex_;
    
    bool ExecuteCheckInternal(const ReadinessCheck& check);
    std::vector<std::string> GetExecutionOrder();
};

// ============================================================================
// Deployment Pipeline
// ============================================================================

enum class DeploymentStage {
    VALIDATE = 0,
    BUILD = 1,
    TEST = 2,
    STAGE = 3,
    DEPLOY = 4,
    VERIFY = 5,
    ROLLBACK = 6
};

enum class DeploymentStrategy {
    ROLLING = 0,
    BLUE_GREEN = 1,
    CANARY = 2,
    RECREATE = 3,
    SHADOW = 4
};

struct DeploymentConfig {
    std::string name;
    std::string version;
    DeploymentStrategy strategy;
    std::map<std::string, std::string> parameters;
    std::vector<std::string> health_checks;
    std::chrono::seconds timeout{600};
    bool auto_rollback = true;
    int max_retries = 3;
};

struct DeploymentStageResult {
    DeploymentStage stage;
    bool success;
    std::chrono::milliseconds duration{0};
    std::string output;
    std::string error;
    std::map<std::string, std::string> artifacts;
};

class DeploymentPipeline {
public:
    struct Config {
        std::string artifact_repository;
        std::string deployment_target;
        bool require_approval = true;
        std::vector<std::string> approvers;
        bool enable_metrics = true;
    };
    
    explicit DeploymentPipeline(const Config& config);
    ~DeploymentPipeline();
    
    bool Initialize();
    void Shutdown();
    
    // Pipeline execution
    std::string StartDeployment(const DeploymentConfig& config);
    bool CancelDeployment(const std::string& deployment_id);
    DeploymentStageResult ExecuteStage(const std::string& deployment_id, 
                                        DeploymentStage stage);
    
    // Stage implementations
    bool ExecuteValidateStage(const std::string& deployment_id);
    bool ExecuteBuildStage(const std::string& deployment_id);
    bool ExecuteTestStage(const std::string& deployment_id);
    bool ExecuteStageStage(const std::string& deployment_id);
    bool ExecuteDeployStage(const std::string& deployment_id);
    bool ExecuteVerifyStage(const std::string& deployment_id);
    bool ExecuteRollbackStage(const std::string& deployment_id);
    
    // Status
    struct DeploymentStatus {
        std::string id;
        std::string state;
        DeploymentStage current_stage;
        std::vector<DeploymentStageResult> stage_results;
        std::chrono::steady_clock::time_point started_at;
        std::chrono::steady_clock::time_point completed_at;
        int progress_percent = 0;
    };
    
    DeploymentStatus GetStatus(const std::string& deployment_id) const;
    std::vector<DeploymentStatus> GetActiveDeployments() const;
    std::vector<DeploymentStatus> GetDeploymentHistory() const;
    
    // Approval
    bool RequestApproval(const std::string& deployment_id);
    bool ApproveDeployment(const std::string& deployment_id, const std::string& approver);
    bool RejectDeployment(const std::string& deployment_id, const std::string& reason);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    struct Deployment {
        std::string id;
        DeploymentConfig config;
        std::string state;
        DeploymentStage current_stage;
        std::vector<DeploymentStageResult> results;
        std::chrono::steady_clock::time_point started_at;
        std::chrono::steady_clock::time_point completed_at;
        bool approved = false;
    };
    
    std::map<std::string, Deployment> deployments_;
    mutable std::mutex deployments_mutex_;
};

// ============================================================================
// Canary Deployment
// ============================================================================

struct CanaryConfig {
    int initial_percentage = 5;
    int step_percentage = 10;
    std::chrono::minutes step_interval{10};
    std::map<std::string, std::string> success_criteria;
    bool auto_promote = false;
    bool auto_rollback = true;
    int max_error_rate = 1;  // percentage
    int max_latency_ms = 1000;
};

class CanaryDeployment {
public:
    explicit CanaryDeployment(const CanaryConfig& config);
    
    bool Initialize();
    void Shutdown();
    
    // Canary execution
    std::string StartCanary(const std::string& service_name, 
                            const std::string& new_version);
    bool PromoteCanary(const std::string& canary_id);
    bool RollbackCanary(const std::string& canary_id);
    
    // Analysis
    bool AnalyzeMetrics(const std::string& canary_id);
    bool ShouldPromote(const std::string& canary_id);
    bool ShouldRollback(const std::string& canary_id);
    
    // Status
    struct CanaryStatus {
        std::string id;
        std::string service_name;
        std::string new_version;
        int current_percentage;
        std::string state;
        std::map<std::string, double> metrics;
        std::chrono::steady_clock::time_point started_at;
    };
    
    CanaryStatus GetStatus(const std::string& canary_id) const;
    std::vector<CanaryStatus> GetActiveCanaries() const;
    
private:
    CanaryConfig config_;
    std::atomic<bool> running_{false};
    
    struct Canary {
        std::string id;
        std::string service_name;
        std::string new_version;
        int current_percentage = 0;
        std::string state;
        std::map<std::string, double> metrics;
        std::chrono::steady_clock::time_point started_at;
        std::thread promotion_thread;
    };
    
    std::map<std::string, Canary> canaries_;
    mutable std::mutex canaries_mutex_;
    
    void PromotionLoop(const std::string& canary_id);
};

// ============================================================================
// Feature Flags
// ============================================================================

struct FeatureFlag {
    std::string id;
    std::string name;
    std::string description;
    bool enabled = false;
    std::map<std::string, std::string> targeting_rules;
    int rollout_percentage = 0;
    std::vector<std::string> allowed_users;
    std::vector<std::string> blocked_users;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point updated_at;
};

class FeatureFlagManager {
public:
    struct Config {
        std::string storage_path;
        std::chrono::seconds sync_interval{30};
        bool enable_audit_log = true;
    };
    
    explicit FeatureFlagManager(const Config& config);
    ~FeatureFlagManager();
    
    bool Initialize();
    void Shutdown();
    
    // Flag management
    std::string CreateFlag(const FeatureFlag& flag);
    bool UpdateFlag(const std::string& flag_id, const FeatureFlag& flag);
    bool DeleteFlag(const std::string& flag_id);
    
    // Evaluation
    bool IsEnabled(const std::string& flag_id, 
                   const std::map<std::string, std::string>& context = {});
    bool IsEnabledForUser(const std::string& flag_id, const std::string& user_id);
    
    // Rollout
    bool SetRolloutPercentage(const std::string& flag_id, int percentage);
    bool IncrementRollout(const std::string& flag_id, int increment);
    
    // Access
    FeatureFlag GetFlag(const std::string& flag_id) const;
    std::vector<FeatureFlag> GetAllFlags() const;
    std::vector<FeatureFlag> GetEnabledFlags() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    std::map<std::string, FeatureFlag> flags_;
    mutable std::mutex flags_mutex_;
    
    std::thread sync_thread_;
    
    void SyncLoop();
    bool EvaluateRules(const FeatureFlag& flag, 
                       const std::map<std::string, std::string>& context);
};

// ============================================================================
// Blue-Green Deployment
// ============================================================================

class BlueGreenDeployment {
public:
    struct Config {
        std::string blue_environment;
        std::string green_environment;
        std::string production_traffic_route;
        std::string health_check_endpoint;
        std::chrono::seconds health_check_interval{10};
    };
    
    explicit BlueGreenDeployment(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Deployment
    bool DeployToGreen(const std::string& version);
    bool SwitchTrafficToGreen();
    bool SwitchTrafficToBlue();
    bool PromoteGreenToBlue();
    
    // Status
    struct EnvironmentStatus {
        std::string name;
        std::string version;
        bool healthy;
        bool receiving_traffic;
        int instance_count;
        std::map<std::string, std::string> metrics;
    };
    
    EnvironmentStatus GetBlueStatus() const;
    EnvironmentStatus GetGreenStatus() const;
    std::string GetActiveEnvironment() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    struct Environment {
        std::string name;
        std::string version;
        bool healthy = false;
        bool active = false;
        int instance_count = 0;
    };
    
    Environment blue_;
    Environment green_;
    mutable std::mutex env_mutex_;
    
    bool HealthCheck(const Environment& env);
    bool RouteTraffic(const std::string& environment);
};

// ============================================================================
// Production Runtime
// ============================================================================

class ProductionRuntime {
public:
    struct Config {
        ReadinessGate::Config readiness;
        DeploymentPipeline::Config pipeline;
        CanaryConfig canary;
        FeatureFlagManager::Config feature_flags;
        BlueGreenDeployment::Config blue_green;
    };
    
    explicit ProductionRuntime(const Config& config);
    ~ProductionRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    ReadinessGate* GetReadinessGate();
    DeploymentPipeline* GetDeploymentPipeline();
    CanaryDeployment* GetCanaryDeployment();
    FeatureFlagManager* GetFeatureFlagManager();
    BlueGreenDeployment* GetBlueGreenDeployment();
    
    // Production operations
    bool RunReadinessChecks();
    std::string Deploy(const DeploymentConfig& config);
    bool IsProductionReady() const;
    
    // Health
    bool IsHealthy() const;
    std::map<std::string, bool> GetSubsystemHealth() const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<ReadinessGate> readiness_gate_;
    std::unique_ptr<DeploymentPipeline> deployment_pipeline_;
    std::unique_ptr<CanaryDeployment> canary_deployment_;
    std::unique_ptr<FeatureFlagManager> feature_flags_;
    std::unique_ptr<BlueGreenDeployment> blue_green_;
};

} // namespace Production
} // namespace Sovereign
