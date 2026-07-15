// Phase D.5 Batch 4/5: Disaster Recovery
// Automated Failover and Backup Orchestration
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "SovereignGlobalConsensus.hpp"
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Sovereign {
namespace Federation {

// ============================================================================
// Recovery Objectives
// ============================================================================

struct RecoveryObjectives {
    int rpo_seconds = 300;      // Recovery Point Objective
    int rto_seconds = 60;       // Recovery Time Objective
    int mtpd_seconds = 3600;    // Maximum Tolerable Period of Disruption
    
    bool Validate() const {
        return rpo_seconds > 0 && rto_seconds > 0 && mtpd_seconds > 0;
    }
};

enum class FailoverType {
    AUTOMATIC = 0,      // Automatic failover on failure detection
    MANUAL = 1,         // Operator-initiated failover
    SCHEDULED = 2,      // Planned maintenance failover
    EMERGENCY = 3       // Emergency failover (split-brain recovery)
};

enum class FailoverState {
    IDLE = 0,
    DETECTING = 1,
    VALIDATING = 2,
    PREPARING = 3,
    EXECUTING = 4,
    VERIFYING = 5,
    COMPLETED = 6,
    FAILED = 7,
    ROLLING_BACK = 8
};

// ============================================================================
// Backup Types
// ============================================================================

enum class BackupType {
    FULL = 0,           // Complete state backup
    INCREMENTAL = 1,    // Incremental changes
    DIFFERENTIAL = 2,   // Differential changes
    SNAPSHOT = 3,       // Point-in-time snapshot
    CONTINUOUS = 4      // Continuous replication
};

struct BackupJob {
    std::string job_id;
    std::string region_id;
    BackupType type = BackupType::FULL;
    std::string target_location;
    std::chrono::steady_clock::time_point scheduled_time;
    std::chrono::steady_clock::time_point completed_time;
    int64_t bytes_backed_up = 0;
    int64_t duration_ms = 0;
    bool successful = false;
    std::string error_message;
    std::string checksum;
};

struct BackupPolicy {
    std::string policy_id;
    std::string name;
    BackupType type = BackupType::INCREMENTAL;
    std::string schedule;  // Cron expression
    int retention_days = 30;
    std::vector<std::string> source_regions;
    std::vector<std::string> target_regions;
    bool encrypt = true;
    bool compress = true;
    int64_t max_backup_size_gb = 1000;
};

// ============================================================================
// Failover Coordinator
// ============================================================================

class FailoverCoordinator {
public:
    struct Config {
        RecoveryObjectives objectives;
        bool auto_failover = true;
        int detection_threshold = 3;  // Consecutive failures
        int detection_interval_ms = 5000;
        int validation_timeout_ms = 30000;
        int execution_timeout_ms = 120000;
        std::vector<std::string> failover_regions;
        std::map<std::string, int> region_priorities;
    };
    
    explicit FailoverCoordinator(const Config& config);
    ~FailoverCoordinator();
    
    bool Initialize(GlobalConsensusEngine* consensus);
    void Shutdown();
    
    // Failover operations
    std::string InitiateFailover(const std::string& failed_region, 
                                  FailoverType type = FailoverType::AUTOMATIC);
    bool CancelFailover(const std::string& failover_id);
    FailoverState GetFailoverState(const std::string& failover_id) const;
    
    // Manual operations
    std::string InitiatePlannedFailover(const std::string& source_region,
                                        const std::string& target_region);
    bool PromoteRegion(const std::string& region_id);
    bool DemoteRegion(const std::string& region_id);
    
    // Validation
    bool ValidateFailoverReadiness(const std::string& target_region);
    std::vector<std::string> GetFailoverCandidates() const;
    
    // Statistics
    struct Stats {
        int64_t failovers_initiated = 0;
        int64_t failovers_completed = 0;
        int64_t failovers_failed = 0;
        int64_t avg_failover_time_ms = 0;
        int64_t last_failover_time_ms = 0;
    };
    Stats GetStats() const;
    
    // Callbacks
    using FailoverCallback = std::function<void(const std::string&, FailoverState)>;
    void OnFailoverStateChange(FailoverCallback cb);
    
private:
    Config config_;
    GlobalConsensusEngine* consensus_ = nullptr;
    std::atomic<bool&gt; running_{false};
    
    struct FailoverContext {
        std::string failover_id;
        std::string failed_region;
        std::string target_region;
        FailoverType type;
        FailoverState state = FailoverState::IDLE;
        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point end_time;
        std::string error_message;
    };
    
    mutable std::mutex failovers_mutex_;
    std::map<std::string, FailoverContext> failovers_;
    
    FailoverCallback on_state_change_;
    
    std::atomic<int64_t> failovers_initiated_{0};
    std::atomic<int64_t> failovers_completed_{0};
    std::atomic<int64_t> failovers_failed_{0};
    std::atomic<int64_t> total_failover_time_ms_{0};
    
    void ExecuteFailover(FailoverContext& ctx);
    bool ValidateTargetRegion(const std::string& region_id);
    bool SynchronizeState(const std::string& source, const std::string& target);
    bool UpdateDNS(const std::string& failover_id);
    bool VerifyFailover(const std::string& region_id);
};

// ============================================================================
// Backup Orchestrator
// ============================================================================

class BackupOrchestrator {
public:
    struct Config {
        int max_concurrent_backups = 3;
        int backup_timeout_ms = 3600000;  // 1 hour
        bool verify_backups = true;
        bool cross_region_replication = true;
        int replication_delay_minutes = 60;
    };
    
    explicit BackupOrchestrator(const Config& config);
    ~BackupOrchestrator();
    
    bool Initialize();
    void Shutdown();
    
    // Policy management
    bool CreatePolicy(const BackupPolicy& policy);
    bool UpdatePolicy(const std::string& policy_id, const BackupPolicy& policy);
    bool DeletePolicy(const std::string& policy_id);
    std::vector<BackupPolicy> GetPolicies() const;
    
    // Backup operations
    std::string TriggerBackup(const std::string& policy_id);
    bool CancelBackup(const std::string& job_id);
    BackupJob GetBackupStatus(const std::string& job_id) const;
    
    // Restore operations
    std::string InitiateRestore(const std::string& backup_id,
                                 const std::string& target_region);
    bool CancelRestore(const std::string& restore_id);
    
    // Cross-region replication
    bool ReplicateBackup(const std::string& backup_id,
                         const std::string& source_region,
                         const std::string& target_region);
    
    // Retention management
    bool EnforceRetention(const std::string& policy_id);
    std::vector<BackupJob> GetExpiredBackups(const std::string& policy_id) const;
    bool DeleteBackup(const std::string& backup_id);
    
    // Statistics
    struct Stats {
        int64_t backups_completed = 0;
        int64_t backups_failed = 0;
        int64_t restores_completed = 0;
        int64_t bytes_backed_up = 0;
        double avg_backup_time_ms = 0.0;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::thread scheduler_thread_;
    
    mutable std::mutex policies_mutex_;
    std::map<std::string, BackupPolicy> policies_;
    
    mutable std::mutex jobs_mutex_;
    std::map<std::string, BackupJob> jobs_;
    
    std::atomic<int64_t> backups_completed_{0};
    std::atomic<int64_t> backups_failed_{0};
    std::atomic<int64_t> restores_completed_{0};
    std::atomic<int64_t> bytes_backed_up_{0};
    std::atomic<int64_t> total_backup_time_ms_{0};
    
    void SchedulerLoop();
    bool ExecuteBackup(BackupJob& job);
    bool ExecuteRestore(const std::string& backup_id, const std::string& target_region);
    std::vector<std::string> ParseSchedule(const std::string& schedule);
};

// ============================================================================
// Split-Brain Detector
// ============================================================================

class SplitBrainDetector {
public:
    struct Config {
        int partition_detection_threshold = 3;
        int reconciliation_timeout_ms = 60000;
        bool auto_reconcile = true;
    };
    
    explicit SplitBrainDetector(const Config& config);
    
    bool Initialize(GlobalConsensusEngine* consensus);
    
    // Detection
    bool DetectPartition(const std::vector<std::string>& regions);
    bool DetectSplitBrain(const std::map<std::string, std::string>& leader_claims);
    
    // Reconciliation
    bool InitiateReconciliation(const std::vector<std::string>& partitioned_regions);
    bool ForceReconciliation(const std::string& authoritative_region);
    
    // Quarantine
    bool QuarantineRegion(const std::string& region_id);
    bool UnquarantineRegion(const std::string& region_id);
    std::vector<std::string> GetQuarantinedRegions() const;
    
private:
    Config config_;
    GlobalConsensusEngine* consensus_ = nullptr;
    
    mutable std::mutex quarantine_mutex_;
    std::set<std::string> quarantined_regions_;
    
    bool ReconcileLogs(const std::string& region1, const std::string& region2);
    bool MergeState(const std::string& authoritative, const std::string& divergent);
};

} // namespace Federation
} // namespace Sovereign
