/**
 * TenantLifecycle.hpp
 *
 * Phase P Batch 5/5: Tenant Onboarding & Lifecycle Management
 *
 * Tenant onboarding, provisioning automation, and lifecycle
 * management for SaaS platforms.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <future>

namespace MultiTenancy {

// ============================================================================
// Forward Declarations
// ============================================================================

class OnboardingWorkflow;
class TenantProvisioner;
class TenantLifecycleManager;
class HealthChecker;

// ============================================================================
// Onboarding Stage
// ============================================================================

enum class OnboardingStage {
    REGISTRATION,
    EMAIL_VERIFICATION,
    PROFILE_SETUP,
    PLAN_SELECTION,
    PAYMENT_SETUP,
    DATA_MIGRATION,
    CONFIGURATION,
    GO_LIVE,
    COMPLETED
};

std::string OnboardingStageToString(OnboardingStage stage);

// ============================================================================
// Onboarding Workflow
// ============================================================================

/**
 * Tenant onboarding workflow.
 */
class OnboardingWorkflow {
public:
    struct StageConfig {
        OnboardingStage stage;
        std::string name;
        std::string description;
        bool required;
        bool skippable;
        std::chrono::seconds timeout;
        std::vector<OnboardingStage> dependencies;
        std::function<bool(const std::string&)> validator;
        std::function<void(const std::string&)> executor;
    };
    
    struct Progress {
        OnboardingStage currentStage;
        std::vector<OnboardingStage> completedStages;
        std::vector<OnboardingStage> pendingStages;
        double percentComplete;
        std::chrono::system_clock::time_point startedAt;
        std::optional<std::chrono::system_clock::time_point> completedAt;
        std::optional<std::string> error;
    };
    
    explicit OnboardingWorkflow(const std::string& tenantId);
    
    // Stage configuration
    void AddStage(const StageConfig& config);
    void RemoveStage(OnboardingStage stage);
    void ConfigureStage(OnboardingStage stage, const StageConfig& config);
    
    // Execution
    void Start();
    void Pause();
    void Resume();
    void SkipStage(OnboardingStage stage);
    void RetryStage(OnboardingStage stage);
    void CompleteStage(OnboardingStage stage);
    void FailStage(OnboardingStage stage, const std::string& error);
    
    // Navigation
    bool CanProceedTo(OnboardingStage stage) const;
    bool ProceedTo(OnboardingStage stage);
    bool GoBack();
    
    // Progress
    Progress GetProgress() const;
    bool IsComplete() const;
    OnboardingStage GetCurrentStage() const;
    std::vector<OnboardingStage> GetCompletedStages() const;
    std::vector<OnboardingStage> GetPendingStages() const;
    
    // Data
    void SetStageData(OnboardingStage stage,
                      const std::map<std::string, std::any>& data);
    std::map<std::string, std::any> GetStageData(OnboardingStage stage) const;
    
    // Events
    using StageChangeCallback = std::function<void(OnboardingStage, OnboardingStage)>;
    void OnStageChange(StageChangeCallback callback);
    
private:
    std::string tenantId_;
    std::map<OnboardingStage, StageConfig> stages_;
    std::set<OnboardingStage> completedStages_;
    OnboardingStage currentStage_;
    std::map<OnboardingStage, std::map<std::string, std::any>> stageData_;
    std::chrono::system_clock::time_point startedAt_;
    std::optional<std::chrono::system_clock::time_point> completedAt_;
    std::optional<std::string> error_;
    mutable std::mutex mutex_;
    
    StageChangeCallback stageChangeCallback_;
    
    void ExecuteStage(OnboardingStage stage);
    std::vector<OnboardingStage> GetStageOrder() const;
};

// ============================================================================
// Provisioning Task
// ============================================================================

/**
 * Individual provisioning task.
 */
class ProvisioningTask {
public:
    enum class Status {
        PENDING,
        RUNNING,
        COMPLETED,
        FAILED,
        SKIPPED
    };
    
    struct Config {
        std::string taskId;
        std::string name;
        std::string description;
        std::function<bool(const std::string&)> executor;
        std::function<bool(const std::string&)> rollback;
        std::vector<std::string> dependencies;
        std::chrono::seconds timeout;
        bool critical;
        bool skippable;
    };
    
    explicit ProvisioningTask(const Config& config);
    
    // Execution
    bool Execute(const std::string& tenantId);
    bool Rollback(const std::string& tenantId);
    
    // Status
    Status GetStatus() const { return status_; }
    bool IsComplete() const { return status_ == Status::COMPLETED; }
    bool IsFailed() const { return status_ == Status::FAILED; }
    
    // Dependencies
    const std::vector<std::string>& GetDependencies() const { return config_.dependencies; }
    bool HasDependency(const std::string& taskId) const;
    
    // Accessors
    const std::string& GetTaskId() const { return config_.taskId; }
    const std::string& GetName() const { return config_.name; }
    bool IsCritical() const { return config_.critical; }
    
private:
    Config config_;
    Status status_;
    std::optional<std::string> error_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Tenant Provisioner
// ============================================================================

/**
 * Automated tenant provisioning.
 */
class TenantProvisioner {
public:
    struct Config {
        bool enableParallelProvisioning;
        uint32_t maxConcurrentTasks;
        bool enableRollbackOnFailure;
        bool enableDryRun;
        std::chrono::seconds taskTimeout;
    };
    
    struct ProvisioningResult {
        bool success;
        std::string tenantId;
        std::vector<std::string> completedTasks;
        std::vector<std::string> failedTasks;
        std::optional<std::string> error;
        std::chrono::milliseconds duration;
    };
    
    explicit TenantProvisioner(const Config& config);
    
    // Task management
    void RegisterTask(std::shared_ptr<ProvisioningTask> task);
    void RemoveTask(const std::string& taskId);
    std::shared_ptr<ProvisioningTask> GetTask(const std::string& taskId) const;
    std::vector<std::shared_ptr<ProvisioningTask>> GetTasks() const;
    
    // Provisioning
    ProvisioningResult Provision(const std::string& tenantId);
    std::future<ProvisioningResult> ProvisionAsync(const std::string& tenantId);
    
    // Deprovisioning
    bool Deprovision(const std::string& tenantId);
    std::future<bool> DeprovisionAsync(const std::string& tenantId);
    
    // Reprovisioning
    bool Reprovision(const std::string& tenantId);
    
    // Status
    bool IsProvisioning(const std::string& tenantId) const;
    bool IsProvisioned(const std::string& tenantId) const;
    double GetProvisioningProgress(const std::string& tenantId) const;
    
    // Rollback
    bool Rollback(const std::string& tenantId);
    
    // Dry run
    std::vector<std::string> SimulateProvisioning(const std::string& tenantId);
    
private:
    Config config_;
    std::map<std::string, std::shared_ptr<ProvisioningTask>> tasks_;
    std::map<std::string, ProvisioningResult> provisioningStatus_;
    mutable std::mutex mutex_;
    
    std::vector<std::shared_ptr<ProvisioningTask>> GetExecutionOrder() const;
    bool ExecuteTask(std::shared_ptr<ProvisioningTask> task,
                     const std::string& tenantId);
    bool RollbackTask(std::shared_ptr<ProvisioningTask> task,
                      const std::string& tenantId);
};

// ============================================================================
// Lifecycle State
// ============================================================================

enum class LifecycleState {
    CREATED,
    ONBOARDING,
    ACTIVE,
    SUSPENDED,
    EXPIRED,
    CANCELLED,
    DECOMMISSIONING,
    ARCHIVED
};

// ============================================================================
// Lifecycle Transition
// ============================================================================

struct LifecycleTransition {
    LifecycleState from;
    LifecycleState to;
    std::string trigger;
    std::vector<std::string> requiredActions;
    std::optional<std::chrono::seconds> delay;
    bool automatic;
};

// ============================================================================
// Tenant Lifecycle Manager
// ============================================================================

/**
 * Manages tenant lifecycle transitions.
 */
class TenantLifecycleManager {
public:
    struct Config {
        bool enableAutomaticTransitions;
        std::chrono::days trialDuration;
        std::chrono::days gracePeriod;
        std::chrono::days suspensionWarningDays;
        std::chrono::days archiveAfterDays;
    };
    
    explicit TenantLifecycleManager(const Config& config);
    ~TenantLifecycleManager();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // State management
    bool Transition(const std::string& tenantId,
                    LifecycleState newState,
                    const std::string& reason = "");
    bool CanTransition(const std::string& tenantId,
                       LifecycleState newState) const;
    LifecycleState GetCurrentState(const std::string& tenantId) const;
    std::vector<LifecycleTransition> GetAllowedTransitions(
        const std::string& tenantId) const;
    
    // Automatic transitions
    void EnableAutomaticTransitions(bool enabled);
    void ProcessAutomaticTransitions();
    
    // Trial management
    void StartTrial(const std::string& tenantId, std::chrono::days duration);
    void ExtendTrial(const std::string& tenantId, std::chrono::days extension);
    bool IsInTrial(const std::string& tenantId) const;
    std::chrono::days GetTrialDaysRemaining(const std::string& tenantId) const;
    
    // Suspension
    void Suspend(const std::string& tenantId, const std::string& reason);
    void Unsuspend(const std::string& tenantId);
    bool IsSuspended(const std::string& tenantId) const;
    
    // Expiration
    void SetExpiration(const std::string& tenantId,
                       std::chrono::system_clock::time_point expiresAt);
    void RemoveExpiration(const std::string& tenantId);
    bool IsExpired(const std::string& tenantId) const;
    
    // Cancellation
    void Cancel(const std::string& tenantId, const std::string& reason);
    void ScheduleCancellation(const std::string& tenantId,
                               std::chrono::system_clock::time_point when);
    void UnscheduleCancellation(const std::string& tenantId);
    bool IsCancelled(const std::string& tenantId) const;
    
    // Decommissioning
    void StartDecommissioning(const std::string& tenantId);
    bool IsDecommissioning(const std::string& tenantId) const;
    
    // Archival
    void Archive(const std::string& tenantId);
    bool IsArchived(const std::string& tenantId) const;
    void RestoreFromArchive(const std::string& tenantId);
    
    // Notifications
    void SendExpirationWarning(const std::string& tenantId, int daysRemaining);
    void SendSuspensionWarning(const std::string& tenantId);
    void SendRenewalReminder(const std::string& tenantId);
    
    // History
    struct StateChange {
        LifecycleState from;
        LifecycleState to;
        std::string trigger;
        std::string reason;
        std::chrono::system_clock::time_point timestamp;
        std::string performedBy;
    };
    
    std::vector<StateChange> GetStateHistory(const std::string& tenantId) const;
    
    // Statistics
    struct LifecycleStats {
        std::map<LifecycleState, uint32_t> tenantsByState;
        uint64_t totalTransitions;
        double averageTenantLifetimeDays;
        double churnRate;
        std::map<std::string, uint64_t> transitionsByType;
    };
    LifecycleStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    bool autoTransitionsEnabled_;
    
    std::map<std::string, LifecycleState> tenantStates_;
    std::map<std::string, std::vector<StateChange>> stateHistory_;
    std::map<std::string, std::chrono::system_clock::time_point> expirationDates_;
    std::map<std::string, std::chrono::system_clock::time_point> scheduledCancellations_;
    mutable std::mutex mutex_;
    
    std::vector<LifecycleTransition> transitions_;
    
    std::thread monitorThread_;
    std::atomic<bool> stopMonitor_;
    
    void MonitorLoop();
    void CheckExpirations();
    void CheckScheduledCancellations();
    void RecordStateChange(const std::string& tenantId,
                           LifecycleState from,
                           LifecycleState to,
                           const std::string& trigger,
                           const std::string& reason);
    bool ValidateTransition(LifecycleState from, LifecycleState to) const;
};

// ============================================================================
// Health Check
// ============================================================================

/**
 * Tenant health monitoring.
 */
class HealthChecker {
public:
    struct HealthCheck {
        std::string name;
        std::function<bool(const std::string&)> check;
        std::chrono::seconds interval;
        uint32_t failureThreshold;
        bool critical;
    };
    
    struct HealthStatus {
        std::string tenantId;
        bool healthy;
        std::map<std::string, bool> checks;
        std::vector<std::string> failedChecks;
        std::optional<std::string> error;
        std::chrono::system_clock::time_point lastCheck;
        uint32_t consecutiveFailures;
    };
    
    explicit HealthChecker(std::chrono::seconds checkInterval);
    ~HealthChecker();
    
    // Lifecycle
    void Start();
    void Stop();
    bool IsRunning() const;
    
    // Check registration
    void RegisterCheck(const HealthCheck& check);
    void RemoveCheck(const std::string& name);
    
    // Health checking
    HealthStatus CheckHealth(const std::string& tenantId);
    std::vector<HealthStatus> CheckAllHealth();
    
    // Status
    bool IsHealthy(const std::string& tenantId) const;
    std::vector<std::string> GetUnhealthyTenants() const;
    
    // Events
    using HealthChangeCallback = std::function<void(const std::string& tenantId,
                                                        bool healthy,
                                                        const std::vector<std::string>&)>;
    void OnHealthChange(HealthChangeCallback callback);
    
private:
    std::chrono::seconds checkInterval_;
    std::atomic<bool> running_;
    
    std::vector<HealthCheck> checks_;
    std::map<std::string, HealthStatus> healthStatus_;
    mutable std::mutex mutex_;
    
    HealthChangeCallback healthChangeCallback_;
    
    std::thread checkThread_;
    
    void CheckLoop();
    void RunChecks(const std::string& tenantId);
};

// ============================================================================
// Tenant Operations
// ============================================================================

/**
 * High-level tenant operations.
 */
class TenantOperations {
public:
    struct CloneOptions {
        bool cloneData;
        bool cloneConfiguration;
        bool cloneUsers;
        bool cloneSubscriptions;
        std::optional<std::string> newPlanId;
        std::optional<TenantTier> newTier;
    };
    
    struct MergeOptions {
        std::string sourceTenantId;
        std::string targetTenantId;
        bool mergeUsers;
        bool mergeData;
        bool mergeConfigurations;
        std::map<std::string, std::string> fieldMappings;
    };
    
    struct SplitOptions {
        std::string sourceTenantId;
        std::vector<std::string> usersToMove;
        std::vector<std::string> dataToMove;
        bool keepSourceActive;
    };
    
    // Creation
    std::string CreateTenant(const Tenant::Config& config);
    std::string CreateTenantFromTemplate(const std::string& templateId,
                                          const std::string& name);
    
    // Cloning
    std::string CloneTenant(const std::string& sourceTenantId,
                            const std::string& newName,
                            const CloneOptions& options);
    
    // Merging
    bool MergeTenants(const MergeOptions& options);
    
    // Splitting
    std::string SplitTenant(const SplitOptions& options);
    
    // Migration
    bool MigrateTenant(const std::string& tenantId,
                       const std::string& targetEnvironment);
    
    // Backup/Restore
    std::string BackupTenant(const std::string& tenantId);
    bool RestoreTenant(const std::string& backupId,
                       const std::optional<std::string>& newTenantId = std::nullopt);
    
    // Import/Export
    std::string ExportTenant(const std::string& tenantId,
                              const std::string& format);
    std::string ImportTenant(const std::string& filePath,
                               const std::string& format);
    
    // Cleanup
    void PurgeDeletedData(const std::string& tenantId);
    void CompressTenantData(const std::string& tenantId);
    void OptimizeTenantStorage(const std::string& tenantId);
    
    // Validation
    bool ValidateTenantIntegrity(const std::string& tenantId);
    std::vector<std::string> GetIntegrityIssues(const std::string& tenantId);
    
private:
    std::shared_ptr<TenantManager> tenantManager_;
    std::shared_ptr<TenantProvisioner> provisioner_;
    std::shared_ptr<TenantLifecycleManager> lifecycleManager_;
};

} // namespace MultiTenancy
