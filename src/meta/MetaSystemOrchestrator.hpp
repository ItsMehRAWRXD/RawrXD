// Phase T.1/5: Meta-System Orchestrator
// RawrXD Meta-System Orchestrator - Unified management of distributed instances

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace Meta {

// Instance types in the meta-system
enum class InstanceType {
    PRIMARY,        // Primary coordinator
    SECONDARY,      // Secondary coordinator
    WORKER,         // Worker node
    EDGE,           // Edge instance
    GATEWAY,        // Gateway instance
    BACKUP,         // Backup instance
    ANALYTICS,      // Analytics instance
    CUSTOM          // Custom type
};

// Instance status
enum class InstanceStatus {
    ONLINE,         // Fully operational
    DEGRADED,       // Reduced capacity
    OFFLINE,        // Not available
    MAINTENANCE,    // Under maintenance
    SYNCING,        // Synchronizing state
    RECOVERING      // Recovering from failure
};

// Meta-system instance
struct MetaInstance {
    std::string id;
    std::string name;
    InstanceType type;
    InstanceStatus status;
    
    // Network
    std::string endpoint;
    std::string region;
    std::string zone;
    std::chrono::milliseconds latency_to_primary;
    
    // Capabilities
    uint64_t compute_capacity;
    uint64_t memory_capacity;
    uint64_t storage_capacity;
    std::vector<std::string> supported_workloads;
    
    // Current load
    double cpu_utilization;
    double memory_utilization;
    uint32_t active_tasks;
    uint64_t requests_per_second;
    
    // Metadata
    std::string version;
    std::chrono::system_clock::time_point joined_at;
    std::chrono::system_clock::time_point last_heartbeat;
    std::unordered_map<std::string, std::string> labels;
    
    // Health
    double health_score;
    uint32_t consecutive_failures;
    std::vector<std::string> active_alerts;
};

// Workload assignment
struct WorkloadAssignment {
    std::string workload_id;
    std::string workload_type;
    std::string source_instance;
    std::string target_instance;
    
    // Requirements
    uint64_t required_compute;
    uint64_t required_memory;
    std::chrono::seconds max_duration;
    std::vector<std::string> required_capabilities;
    
    // Priority
    enum class Priority {
        CRITICAL,
        HIGH,
        NORMAL,
        LOW,
        BACKGROUND
    } priority;
    
    // State
    enum class State {
        PENDING,
        ASSIGNED,
        RUNNING,
        COMPLETED,
        FAILED,
        MIGRATING
    } state;
    
    std::chrono::system_clock::time_point assigned_at;
    std::chrono::system_clock::time_point started_at;
    std::chrono::system_clock::time_point completed_at;
    
    // Results
    bool success;
    std::string output;
    std::string error_message;
    std::chrono::milliseconds execution_time;
};

// Global state snapshot
struct GlobalStateSnapshot {
    std::string snapshot_id;
    std::chrono::system_clock::time_point timestamp;
    
    // Instance states
    std::unordered_map<std::string, MetaInstance> instances;
    
    // Aggregated metrics
    uint64_t total_compute_capacity;
    uint64_t total_memory_capacity;
    uint64_t total_storage_capacity;
    
    double average_cpu_utilization;
    double average_memory_utilization;
    uint64_t total_active_tasks;
    double total_throughput_rps;
    
    // Health
    uint32_t healthy_instances;
    uint32_t degraded_instances;
    uint32_t offline_instances;
    double global_health_score;
    
    // Workloads
    uint64_t pending_workloads;
    uint64_t running_workloads;
    uint64_t completed_workloads_last_hour;
};

// Synchronization operation
struct SyncOperation {
    std::string id;
    std::string operation_type;  // "state", "config", "model", "knowledge"
    
    // Source and target
    std::string source_instance;
    std::vector<std::string> target_instances;
    
    // Data
    std::string data_hash;
    uint64_t data_size;
    std::chrono::system_clock::time_point data_timestamp;
    
    // State
    enum class State {
        PENDING,
        IN_PROGRESS,
        COMPLETED,
        FAILED,
        CONFLICT
    } state;
    
    std::chrono::system_clock::time_point started_at;
    std::chrono::system_clock::time_point completed_at;
    
    // Progress
    uint32_t targets_completed;
    uint32_t targets_failed;
    std::vector<std::string> conflict_instances;
};

// Meta-system orchestrator interface
class IMetaSystemOrchestrator {
public:
    virtual ~IMetaSystemOrchestrator() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Instance management
    virtual std::string RegisterInstance(const MetaInstance& instance) = 0;
    virtual bool UnregisterInstance(const std::string& instance_id) = 0;
    virtual bool UpdateInstance(const MetaInstance& instance) = 0;
    virtual std::optional<MetaInstance> GetInstance(const std::string& instance_id) = 0;
    virtual std::vector<MetaInstance> ListInstances(InstanceStatus status = InstanceStatus::ONLINE) = 0;
    virtual std::vector<MetaInstance> GetInstancesByType(InstanceType type) = 0;
    virtual std::vector<MetaInstance> GetInstancesByRegion(const std::string& region) = 0;
    
    // Heartbeat and health
    virtual bool SendHeartbeat(const std::string& instance_id) = 0;
    virtual bool ProcessHeartbeat(const std::string& instance_id) = 0;
    virtual std::vector<std::string> GetStaleInstances(std::chrono::seconds threshold) = 0;
    virtual bool MarkInstanceDegraded(const std::string& instance_id, const std::string& reason) = 0;
    virtual bool MarkInstanceHealthy(const std::string& instance_id) = 0;
    
    // Workload management
    virtual std::string SubmitWorkload(const WorkloadAssignment& workload) = 0;
    virtual bool CancelWorkload(const std::string& workload_id) = 0;
    virtual bool MigrateWorkload(const std::string& workload_id, const std::string& target_instance) = 0;
    virtual std::optional<WorkloadAssignment> GetWorkload(const std::string& workload_id) = 0;
    virtual std::vector<WorkloadAssignment> ListWorkloads(WorkloadAssignment::State state) = 0;
    virtual std::vector<WorkloadAssignment> GetWorkloadsForInstance(const std::string& instance_id) = 0;
    
    // Scheduling
    virtual std::string ScheduleWorkload(const WorkloadAssignment& workload) = 0;
    virtual bool RescheduleWorkloads(const std::string& instance_id) = 0;
    virtual std::optional<std::string> SelectInstanceForWorkload(const WorkloadAssignment& workload) = 0;
    virtual std::vector<std::string> DistributeWorkloads(const std::vector<WorkloadAssignment>& workloads) = 0;
    
    // Global state
    virtual GlobalStateSnapshot CaptureGlobalState() = 0;
    virtual bool RestoreGlobalState(const GlobalStateSnapshot& snapshot) = 0;
    virtual std::vector<GlobalStateSnapshot> GetStateHistory(std::chrono::hours lookback = std::chrono::hours(24)) = 0;
    
    // Synchronization
    virtual std::string InitiateSync(const SyncOperation& operation) = 0;
    virtual bool CancelSync(const std::string& sync_id) = 0;
    virtual std::optional<SyncOperation> GetSyncStatus(const std::string& sync_id) = 0;
    virtual bool ResolveConflict(const std::string& sync_id, const std::string& winning_instance) = 0;
    
    // Failover
    virtual bool InitiateFailover(const std::string& failed_instance) = 0;
    virtual bool PromoteToPrimary(const std::string& instance_id) = 0;
    virtual std::optional<std::string> GetPrimaryInstance() = 0;
    virtual std::vector<std::string> GetBackupInstances() = 0;
    
    // Statistics
    virtual struct MetaSystemStatistics {
        uint32_t total_instances;
        uint32_t online_instances;
        uint32_t degraded_instances;
        uint32_t offline_instances;
        uint64_t total_workloads_submitted;
        uint64_t total_workloads_completed;
        uint64_t total_workloads_failed;
        uint64_t total_migrations;
        uint64_t total_failovers;
        double average_workload_duration_ms;
        double global_health_score;
        std::unordered_map<InstanceType, uint32_t> instances_by_type;
        std::unordered_map<std::string, uint32_t> instances_by_region;
    } GetStatistics() = 0;
};

// Local meta-system orchestrator
class LocalMetaSystemOrchestrator : public IMetaSystemOrchestrator {
public:
    LocalMetaSystemOrchestrator();
    ~LocalMetaSystemOrchestrator() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string RegisterInstance(const MetaInstance& instance) override;
    bool UnregisterInstance(const std::string& instance_id) override;
    bool UpdateInstance(const MetaInstance& instance) override;
    std::optional<MetaInstance> GetInstance(const std::string& instance_id) override;
    std::vector<MetaInstance> ListInstances(InstanceStatus status = InstanceStatus::ONLINE) override;
    std::vector<MetaInstance> GetInstancesByType(InstanceType type) override;
    std::vector<MetaInstance> GetInstancesByRegion(const std::string& region) override;
    
    bool SendHeartbeat(const std::string& instance_id) override;
    bool ProcessHeartbeat(const std::string& instance_id) override;
    std::vector<std::string> GetStaleInstances(std::chrono::seconds threshold) override;
    bool MarkInstanceDegraded(const std::string& instance_id, const std::string& reason) override;
    bool MarkInstanceHealthy(const std::string& instance_id) override;
    
    std::string SubmitWorkload(const WorkloadAssignment& workload) override;
    bool CancelWorkload(const std::string& workload_id) override;
    bool MigrateWorkload(const std::string& workload_id, const std::string& target_instance) override;
    std::optional<WorkloadAssignment> GetWorkload(const std::string& workload_id) override;
    std::vector<WorkloadAssignment> ListWorkloads(WorkloadAssignment::State state) override;
    std::vector<WorkloadAssignment> GetWorkloadsForInstance(const std::string& instance_id) override;
    
    std::string ScheduleWorkload(const WorkloadAssignment& workload) override;
    bool RescheduleWorkloads(const std::string& instance_id) override;
    std::optional<std::string> SelectInstanceForWorkload(const WorkloadAssignment& workload) override;
    std::vector<std::string> DistributeWorkloads(const std::vector<WorkloadAssignment>& workloads) override;
    
    GlobalStateSnapshot CaptureGlobalState() override;
    bool RestoreGlobalState(const GlobalStateSnapshot& snapshot) override;
    std::vector<GlobalStateSnapshot> GetStateHistory(std::chrono::hours lookback = std::chrono::hours(24)) override;
    
    std::string InitiateSync(const SyncOperation& operation) override;
    bool CancelSync(const std::string& sync_id) override;
    std::optional<SyncOperation> GetSyncStatus(const std::string& sync_id) override;
    bool ResolveConflict(const std::string& sync_id, const std::string& winning_instance) override;
    
    bool InitiateFailover(const std::string& failed_instance) override;
    bool PromoteToPrimary(const std::string& instance_id) override;
    std::optional<std::string> GetPrimaryInstance() override;
    std::vector<std::string> GetBackupInstances() override;
    
    MetaSystemStatistics GetStatistics() override;
    
private:
    std::unordered_map<std::string, MetaInstance> instances_;
    std::unordered_map<std::string, WorkloadAssignment> workloads_;
    std::unordered_map<std::string, SyncOperation> sync_operations_;
    std::vector<GlobalStateSnapshot> state_history_;
    std::string primary_instance_id_;
    bool initialized_ = false;
    
    double CalculateInstanceScore(const MetaInstance& instance, const WorkloadAssignment& workload);
    bool CanInstanceAcceptWorkload(const MetaInstance& instance, const WorkloadAssignment& workload);
    void UpdateGlobalMetrics();
    void PruneStateHistory();
};

// Global meta-system orchestrator
extern std::unique_ptr<IMetaSystemOrchestrator> g_meta_system_orchestrator;

// Initialize meta-system orchestrator
bool InitializeMetaSystemOrchestrator(const std::string& config_path);
void ShutdownMetaSystemOrchestrator();
bool IsMetaSystemOrchestratorEnabled();

} // namespace Meta
} // namespace RawrXD
