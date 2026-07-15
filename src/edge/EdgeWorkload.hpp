/**
 * EdgeWorkload.hpp
 *
 * Phase R Batch 2/5: Edge Workload Management
 *
 * Container and workload orchestration for edge nodes with
 * resource constraints and offline capabilities.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>

namespace Edge {

// ============================================================================
// Forward Declarations
// ============================================================================

class EdgeWorkload;
class WorkloadScheduler;
class ContainerRuntime;
class EdgeOrchestrator;

// ============================================================================
// Workload Types
// ============================================================================

enum class WorkloadType {
    CONTAINER,
    WASM,
    NATIVE,
    PYTHON,
    INFERENCE,
    STREAM_PROCESSOR,
    CUSTOM
};

std::string WorkloadTypeToString(WorkloadType type);
WorkloadType WorkloadTypeFromString(const std::string& str);

// ============================================================================
// Workload State
// ============================================================================

enum class WorkloadState {
    PENDING,
    SCHEDULING,
    PULLING,
    STARTING,
    RUNNING,
    HEALTHY,
    DEGRADED,
    STOPPING,
    STOPPED,
    FAILED,
    UNKNOWN
};

// ============================================================================
// Resource Requirements
// ============================================================================

struct ResourceRequirements {
    uint32_t cpuMilliCores = 100;  // 100m = 0.1 cores
    uint64_t memoryBytes = 128 * 1024 * 1024;  // 128MB
    uint64_t storageBytes = 1 * 1024 * 1024 * 1024;  // 1GB
    std::optional<uint64_t> gpuMemoryBytes;
    uint32_t maxNetworkMbps = 100;
    
    // Limits
    uint32_t cpuLimitMilliCores = 1000;
    uint64_t memoryLimitBytes = 512 * 1024 * 1024;
    
    bool FitsOn(const NodeCapabilities& capabilities) const;
};

// ============================================================================
// Container Specification
// ============================================================================

struct ContainerSpec {
    std::string image;
    std::string tag = "latest";
    std::optional<std::string> registry;
    std::map<std::string, std::string> env;
    std::vector<std::string> command;
    std::vector<std::string> args;
    std::map<std::string, std::string> labels;
    
    struct PortMapping {
        uint16_t containerPort;
        std::optional<uint16_t> hostPort;
        std::string protocol = "tcp";
    };
    std::vector<PortMapping> ports;
    
    struct VolumeMount {
        std::string name;
        std::string mountPath;
        bool readOnly = false;
    };
    std::vector<VolumeMount> volumeMounts;
    
    struct HealthCheck {
        std::vector<std::string> command;
        std::chrono::seconds interval{30};
        std::chrono::seconds timeout{10};
        uint32_t retries = 3;
        std::chrono::seconds startPeriod{0};
    };
    std::optional<HealthCheck> healthCheck;
    
    bool privileged = false;
    std::optional<std::string> runtime;
};

// ============================================================================
// Edge Workload
// ============================================================================

class EdgeWorkload {
public:
    struct Config {
        std::string workloadId;
        std::string name;
        std::string description;
        WorkloadType type;
        std::string tenantId;
        std::optional<std::string> nodeId;  // If empty, will be scheduled
        
        // Workload specification
        ContainerSpec container;
        std::optional<std::string> wasmModule;
        std::optional<std::string> pythonScript;
        std::optional<std::string> nativeBinary;
        std::optional<std::string> customRuntime;
        
        // Resources
        ResourceRequirements resources;
        uint32_t replicas = 1;
        
        // Scheduling
        std::vector<std::string> nodeSelector;
        std::vector<std::string> requiredNodeLabels;
        std::map<std::string, std::string> affinity;
        std::map<std::string, std::string> antiAffinity;
        
        // Lifecycle
        std::optional<std::chrono::seconds> ttl;
        bool restartOnFailure = true;
        uint32_t maxRestarts = 3;
        
        // Networking
        bool hostNetwork = false;
        std::vector<std::string> dnsServers;
        std::map<std::string, std::string> dnsEntries;
        
        // Storage
        std::vector<std::string> persistentVolumes;
        bool ephemeralStorage = true;
        
        // Security
        std::vector<std::string> capabilities;
        bool readOnlyRootFilesystem = false;
        std::optional<uint32_t> runAsUser;
        std::optional<uint32_t> runAsGroup;
    };
    
    explicit EdgeWorkload(const Config& config);
    
    // Identity
    const std::string& GetWorkloadId() const { return config_.workloadId; }
    const std::string& GetName() const { return config_.name; }
    WorkloadType GetType() const { return config_.type; }
    const std::string& GetTenantId() const { return config_.tenantId; }
    
    // State
    WorkloadState GetState() const;
    void SetState(WorkloadState state);
    bool IsRunning() const;
    bool IsHealthy() const;
    bool CanBeScheduled() const;
    
    // Node assignment
    std::optional<std::string> GetAssignedNode() const;
    void AssignToNode(const std::string& nodeId);
    void UnassignFromNode();
    
    // Configuration
    const Config& GetConfig() const { return config_; }
    void UpdateConfig(const Config& config);
    
    // Resources
    const ResourceRequirements& GetResources() const { return config_.resources; }
    bool FitsOnNode(const EdgeNode& node) const;
    
    // Status
    struct Status {
        WorkloadState state;
        std::optional<std::string> nodeId;
        std::chrono::system_clock::time_point createdAt;
        std::optional<std::chrono::system_clock::time_point> startedAt;
        std::optional<std::chrono::system_clock::time_point> finishedAt;
        uint32_t restartCount;
        std::optional<std::string> containerId;
        std::optional<std::string> errorMessage;
        
        // Resource usage
        float cpuUsagePercent;
        uint64_t memoryUsageBytes;
        uint64_t storageUsageBytes;
        uint64_t networkRxBytes;
        uint64_t networkTxBytes;
    };
    Status GetStatus() const;
    void UpdateStatus(const Status& status);
    
    // Events
    using StateChangeHandler = std::function<void(WorkloadState, WorkloadState)>;
    void OnStateChange(StateChangeHandler handler);
    
    // Logs
    std::vector<std::string> GetLogs(uint32_t lines = 100) const;
    void StreamLogs(std::function<void(const std::string&)> callback);
    
private:
    Config config_;
    Status status_;
    WorkloadState state_;
    StateChangeHandler stateChangeHandler_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Workload Scheduler
// ============================================================================

class WorkloadScheduler {
public:
    struct Config {
        std::chrono::seconds scheduleInterval{10};
        bool enablePreemption = false;
        float preemptionThreshold = 0.9f;  // CPU/memory threshold
        bool enableBinPacking = true;
        bool enableSpread = false;
        uint32_t maxConcurrentSchedules = 10;
    };
    
    enum class SchedulingStrategy {
        BEST_FIT,      // Minimize resource fragmentation
        WORST_FIT,     // Spread across nodes
        FIRST_FIT,     // Fastest scheduling
        LOAD_AWARE,    // Consider current load
        LATENCY_BASED, // Consider network latency
        CUSTOM
    };
    
    explicit WorkloadScheduler(const Config& config);
    ~WorkloadScheduler();
    
    // Lifecycle
    bool Initialize(std::shared_ptr<EdgeRegistry> registry);
    void Shutdown();
    bool IsRunning() const;
    
    // Scheduling
    bool ScheduleWorkload(std::shared_ptr<EdgeWorkload> workload);
    bool RescheduleWorkload(const std::string& workloadId);
    void UnscheduleWorkload(const std::string& workloadId);
    
    // Strategy
    void SetStrategy(SchedulingStrategy strategy);
    void SetCustomStrategy(std::function<std::optional<std::string>(
        const EdgeWorkload&,
        const std::vector<std::shared_ptr<EdgeNode>>&)> strategy);
    
    // Queue management
    void EnqueueWorkload(std::shared_ptr<EdgeWorkload> workload);
    std::shared_ptr<EdgeWorkload> DequeueWorkload();
    std::vector<std::shared_ptr<EdgeWorkload>> GetPendingWorkloads() const;
    
    // Preemption
    std::vector<std::string> FindPreemptableWorkloads(
        const std::string& nodeId,
        const ResourceRequirements& required) const;
    bool PreemptWorkload(const std::string& workloadId);
    
    // Statistics
    struct SchedulerStats {
        uint64_t workloadsScheduled;
        uint64_t workloadsFailed;
        uint64_t workloadsPreempted;
        double averageScheduleTimeMs;
        std::map<std::string, uint64_t> schedulesByNode;
    };
    SchedulerStats GetStats() const;
    
private:
    Config config_;
    std::shared_ptr<EdgeRegistry> registry_;
    bool running_;
    
    SchedulingStrategy strategy_;
    std::function<std::optional<std::string>(
        const EdgeWorkload&,
        const std::vector<std::shared_ptr<EdgeNode>>&)> customStrategy_;
    
    std::queue<std::shared_ptr<EdgeWorkload>> pendingQueue_;
    mutable std::mutex queueMutex_;
    
    std::thread schedulerThread_;
    std::atomic<bool> stopScheduler_;
    
    SchedulerStats stats_;
    mutable std::mutex statsMutex_;
    
    void SchedulerLoop();
    std::optional<std::string> SelectNode(const EdgeWorkload& workload);
    std::optional<std::string> BestFit(const EdgeWorkload& workload,
                                           const std::vector<std::shared_ptr<EdgeNode>>& nodes);
    std::optional<std::string> WorstFit(const EdgeWorkload& workload,
                                           const std::vector<std::shared_ptr<EdgeNode>>& nodes);
    std::optional<std::string> FirstFit(const EdgeWorkload& workload,
                                           const std::vector<std::shared_ptr<EdgeNode>>& nodes);
    std::optional<std::string> LoadAware(const EdgeWorkload& workload,
                                           const std::vector<std::shared_ptr<EdgeNode>>& nodes);
};

// ============================================================================
// Container Runtime
// ============================================================================

class ContainerRuntime {
public:
    struct Config {
        std::string runtimeEndpoint;
        std::string dataRoot;
        std::string imageRegistry;
        bool enableImageCaching = true;
        size_t maxCacheSize = 10 * 1024 * 1024 * 1024;  // 10GB
    };
    
    explicit ContainerRuntime(const Config& config);
    ~ContainerRuntime();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Image management
    bool PullImage(const std::string& image, const std::string& tag);
    bool RemoveImage(const std::string& image, const std::string& tag);
    std::vector<std::string> ListImages() const;
    bool ImageExists(const std::string& image, const std::string& tag) const;
    
    // Container lifecycle
    std::string CreateContainer(const EdgeWorkload& workload);
    bool StartContainer(const std::string& containerId);
    bool StopContainer(const std::string& containerId, 
                       std::chrono::seconds timeout = std::chrono::seconds(30));
    bool RemoveContainer(const std::string& containerId);
    bool RestartContainer(const std::string& containerId);
    
    // Container queries
    struct ContainerInfo {
        std::string containerId;
        std::string name;
        std::string image;
        std::string state;
        std::chrono::system_clock::time_point createdAt;
        std::optional<std::chrono::system_clock::time_point> startedAt;
        float cpuUsagePercent;
        uint64_t memoryUsageBytes;
        uint64_t networkRxBytes;
        uint64_t networkTxBytes;
    };
    std::optional<ContainerInfo> GetContainerInfo(const std::string& containerId) const;
    std::vector<ContainerInfo> ListContainers() const;
    
    // Logs
    std::vector<std::string> GetContainerLogs(const std::string& containerId,
                                                 uint32_t lines = 100) const;
    void StreamContainerLogs(const std::string& containerId,
                             std::function<void(const std::string&)> callback);
    
    // Exec
    bool ExecInContainer(const std::string& containerId,
                         const std::vector<std::string>& command);
    
    // Stats
    struct RuntimeStats {
        uint32_t runningContainers;
        uint32_t totalContainers;
        uint64_t imagesSizeBytes;
        uint64_t containersSizeBytes;
        uint64_t cacheHits;
        uint64_t cacheMisses;
    };
    RuntimeStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    
    std::map<std::string, std::string> containerToWorkload_;
    mutable std::mutex mutex_;
    
    void* runtimeHandle_;  // Platform-specific runtime handle
};

// ============================================================================
// Edge Orchestrator
// ============================================================================

class EdgeOrchestrator {
public:
    struct Config {
        bool enableAutoHealing = true;
        std::chrono::seconds healthCheckInterval{30};
        uint32_t maxRestartsPerHour = 10;
        bool enableRollingUpdates = true;
        uint32_t rollingUpdateBatchSize = 1;
    };
    
    explicit EdgeOrchestrator(const Config& config);
    ~EdgeOrchestrator();
    
    // Lifecycle
    bool Initialize(std::shared_ptr<EdgeRegistry> registry,
                    std::shared_ptr<WorkloadScheduler> scheduler,
                    std::shared_ptr<ContainerRuntime> runtime);
    void Shutdown();
    bool IsInitialized() const;
    
    // Workload management
    std::string DeployWorkload(const EdgeWorkload::Config& config);
    bool UpdateWorkload(const std::string& workloadId,
                        const EdgeWorkload::Config& config);
    bool DeleteWorkload(const std::string& workloadId);
    bool ScaleWorkload(const std::string& workloadId, uint32_t replicas);
    
    // Operations
    bool StartWorkload(const std::string& workloadId);
    bool StopWorkload(const std::string& workloadId);
    bool RestartWorkload(const std::string& workloadId);
    
    // Queries
    std::shared_ptr<EdgeWorkload> GetWorkload(const std::string& workloadId) const;
    std::vector<std::shared_ptr<EdgeWorkload>> GetWorkloads() const;
    std::vector<std::shared_ptr<EdgeWorkload>> GetWorkloadsByNode(
        const std::string& nodeId) const;
    std::vector<std::shared_ptr<EdgeWorkload>> GetWorkloadsByTenant(
        const std::string& tenantId) const;
    
    // Health management
    void CheckWorkloadHealth(const std::string& workloadId);
    void HealWorkload(const std::string& workloadId);
    void MigrateWorkload(const std::string& workloadId, 
                         const std::string& targetNodeId);
    
    // Rolling updates
    bool RollingUpdate(const std::string& workloadId,
                       const EdgeWorkload::Config& newConfig);
    void PauseRollingUpdate(const std::string& workloadId);
    void ResumeRollingUpdate(const std::string& workloadId);
    void RollbackRollingUpdate(const std::string& workloadId);
    
    // Events
    using WorkloadEventHandler = std::function<void(const std::string& workloadId,
                                                     const std::string& event)>;
    void OnWorkloadDeployed(WorkloadEventHandler handler);
    void OnWorkloadDeleted(WorkloadEventHandler handler);
    void OnWorkloadFailed(WorkloadEventHandler handler);
    void OnWorkloadMigrated(WorkloadEventHandler handler);
    
    // Statistics
    struct OrchestratorStats {
        uint32_t totalWorkloads;
        uint32_t runningWorkloads;
        uint32_t failedWorkloads;
        uint64_t deployments;
        uint64_t updates;
        uint64_t deletions;
        uint64_t migrations;
        uint64_t healOperations;
    };
    OrchestratorStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    
    std::shared_ptr<EdgeRegistry> registry_;
    std::shared_ptr<WorkloadScheduler> scheduler_;
    std::shared_ptr<ContainerRuntime> runtime_;
    
    std::map<std::string, std::shared_ptr<EdgeWorkload>> workloads_;
    mutable std::mutex workloadsMutex_;
    
    std::thread healthCheckThread_;
    std::atomic<bool> stopHealthCheck_;
    
    WorkloadEventHandler onDeployed_;
    WorkloadEventHandler onDeleted_;
    WorkloadEventHandler onFailed_;
    WorkloadEventHandler onMigrated_;
    
    void HealthCheckLoop();
    void MonitorWorkloads();
    void HandleFailedWorkload(const std::string& workloadId);
};

} // namespace Edge
