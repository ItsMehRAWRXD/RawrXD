/**
 * FaultDetector.hpp
 *
 * Phase D.3 Batch 5/5: Fault Tolerance & Recovery
 *
 * Detects node failures and network partitions in the distributed cluster.
 * Provides fast failure detection with minimal false positives.
 */

#pragma once

#include "WorkScheduler.hpp"
#include <functional>
#include <set>

namespace Distributed {

// ============================================================================
// Forward Declarations
// ============================================================================

class FaultDetector;
class FailureDetector;
class PartitionDetector;
class RecoveryCoordinator;

// ============================================================================
// Fault Types
// ============================================================================

enum class FaultType {
    NODE_CRASH,         // Node process crashed
    NODE_UNRESPONSIVE,  // Node not responding to heartbeats
    NETWORK_PARTITION,  // Network partition detected
    SLOW_NODE,          // Node performing poorly
    RESOURCE_EXHAUSTION, // Node out of resources
    BYZANTINE_FAULT,    // Malicious/incorrect behavior
    DISK_FAILURE,       // Local storage failure
    MEMORY_CORRUPTION   // Memory corruption detected
};

std::string FaultTypeToString(FaultType type);

enum class FaultSeverity {
    WARNING,    // Degraded but functional
    CRITICAL,   // Service impacted
    FATAL       // Node unusable
};

// ============================================================================
// Fault Event
// ============================================================================

/**
 * Represents a detected fault.
 */
struct FaultEvent {
    std::string faultId;            // Unique fault ID
    FaultType type;                 // Type of fault
    FaultSeverity severity;         // Severity level
    std::string nodeId;             // Affected node
    std::string description;        // Human-readable description
    uint64_t timestamp;             // Detection timestamp
    uint64_t detectionTimeMs;       // Time to detect
    std::vector<std::string> witnesses; // Nodes that confirmed
    std::string evidence;           // Diagnostic data (JSON)
    bool isConfirmed;               // Confirmed by multiple detectors
    
    std::string ToJson() const;
    static FaultEvent FromJson(const std::string& json);
};

// ============================================================================
// Detector Configuration
// ============================================================================

/**
 * Configuration for fault detection.
 */
struct DetectorConfig {
    // Heartbeat settings
    uint64_t heartbeatIntervalMs = 1000;      // Send interval
    uint64_t heartbeatTimeoutMs = 5000;     // Timeout for response
    uint64_t suspicionThresholdMs = 10000;  // Time before marking suspected
    
    // Phi accrual settings
    double phiThreshold = 8.0;              // Phi value for failure detection
    uint32_t phiWindowSize = 1000;          // Sample window size
    
    // Gossip settings
    uint64_t gossipIntervalMs = 500;        // Gossip protocol interval
    uint32_t gossipFanout = 3;              // Nodes to gossip to
    
    // Confirmation settings
    uint32_t confirmationCount = 2;         // Witnesses needed to confirm
    uint64_t confirmationTimeoutMs = 5000;  // Time to wait for confirmation
    
    // Recovery settings
    bool autoRecover = true;                // Automatic recovery
    uint64_t recoveryDelayMs = 5000;        // Delay before recovery
    uint32_t maxRecoveryAttempts = 3;       // Max recovery retries
    
    // Monitoring
    bool enableMetrics = true;              // Collect metrics
    uint64_t metricsIntervalMs = 60000;     // Metrics collection interval
};

// ============================================================================
// Node Health
// ============================================================================

/**
 * Health status of a node.
 */
struct NodeHealth {
    enum class Status {
        HEALTHY,        // Normal operation
        SUSPECTED,      // Under suspicion
        UNHEALTHY,      // Confirmed unhealthy
        ISOLATED        // Network partitioned
    };
    
    std::string nodeId;
    Status status;
    float phiValue;                 // Phi accrual value
    uint64_t lastHeartbeat;         // Last heartbeat timestamp
    uint64_t lastHealthy;           // Last confirmed healthy
    uint32_t consecutiveMisses;     // Missed heartbeats
    uint32_t suspicionCount;        // Times suspected
    std::vector<std::string> symptoms; // Detected symptoms
    
    std::string ToJson() const;
};

// ============================================================================
// Phi Accrual Detector
// ============================================================================

/**
 * Phi accrual failure detector.
 * Uses statistical analysis of heartbeat arrival times.
 */
class PhiAccrualDetector {
public:
    explicit PhiAccrualDetector(const DetectorConfig& config);
    ~PhiAccrualDetector();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Report heartbeat arrival
    void ReportHeartbeat(const std::string& nodeId, uint64_t timestamp);
    
    // Calculate phi value
    double CalculatePhi(const std::string& nodeId) const;
    
    // Check if node is suspected
    bool IsSuspected(const std::string& nodeId) const;
    bool IsFailed(const std::string& nodeId) const;
    
    // Get node health
    std::optional<NodeHealth> GetNodeHealth(const std::string& nodeId) const;
    std::vector<NodeHealth> GetAllNodeHealth() const;
    
    // Remove node
    void RemoveNode(const std::string& nodeId);
    
private:
    DetectorConfig config_;
    
    struct HeartbeatHistory {
        std::deque<uint64_t> intervals;
        uint64_t lastTimestamp;
        double mean;
        double variance;
    };
    
    std::map<std::string, HeartbeatHistory> histories_;
    mutable std::mutex mutex_;
    
    // Statistics
    void UpdateStatistics(HeartbeatHistory& history, uint64_t interval);
    double CalculatePhiValue(const HeartbeatHistory& history, uint64_t now) const;
};

// ============================================================================
// Gossip Protocol
// ============================================================================

/**
 * Gossip-based failure detection.
 * Spreads suspicion information through gossip.
 */
class GossipProtocol {
public:
    GossipProtocol(
        std::shared_ptr<CommunicationManager> commManager,
        const DetectorConfig& config
    );
    ~GossipProtocol();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Spread information
    void SpreadSuspicion(const std::string& nodeId, const std::string& reason);
    void SpreadConfirmation(const FaultEvent& fault);
    void SpreadRecovery(const std::string& nodeId);
    
    // Get gossip state
    std::map<std::string, NodeHealth> GetGossipState() const;
    
    // Callbacks
    using SuspicionCallback = std::function<void(const std::string& nodeId, const std::string& reason)>;
    using ConfirmationCallback = std::function<void(const FaultEvent& fault)>;
    
    void OnSuspicion(SuspicionCallback callback);
    void OnConfirmation(ConfirmationCallback callback);
    
private:
    std::shared_ptr<CommunicationManager> commManager_;
    DetectorConfig config_;
    
    std::map<std::string, NodeHealth> gossipState_;
    mutable std::mutex mutex_;
    std::atomic<bool> running_{false};
    
    std::thread gossipThread_;
    
    SuspicionCallback suspicionCallback_;
    ConfirmationCallback confirmationCallback_;
    std::mutex callbackMutex_;
    
    // Gossip loop
    void GossipLoop();
    
    // Message handlers
    void HandleGossipMessage(const Message& message);
    void HandleSuspicion(const std::string& nodeId, const std::string& reason);
    void HandleConfirmation(const FaultEvent& fault);
    
    // Utility
    std::vector<std::string> SelectGossipTargets();
    void NotifySuspicion(const std::string& nodeId, const std::string& reason);
    void NotifyConfirmation(const FaultEvent& fault);
};

// ============================================================================
// Partition Detector
// ============================================================================

/**
 * Detects network partitions using consensus.
 */
class PartitionDetector {
public:
    PartitionDetector(
        std::shared_ptr<CommunicationManager> commManager,
        const DetectorConfig& config
    );
    ~PartitionDetector();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Check for partition
    bool IsPartitioned() const;
    bool IsInMajorityPartition() const;
    
    // Get partition view
    std::vector<std::string> GetReachableNodes() const;
    std::vector<std::string> GetUnreachableNodes() const;
    
    // Get partition size
    size_t GetPartitionSize() const;
    size_t GetTotalClusterSize() const;
    
    // Callbacks
    using PartitionCallback = std::function<void(bool isPartitioned, bool isMajority)>;
    void OnPartitionChange(PartitionCallback callback);
    
private:
    std::shared_ptr<CommunicationManager> commManager_;
    DetectorConfig config_;
    
    std::set<std::string> reachableNodes_;
    std::set<std::string> unreachableNodes_;
    mutable std::mutex mutex_;
    
    PartitionCallback partitionCallback_;
    std::mutex callbackMutex_;
    
    // Detection
    void DetectPartition();
    bool IsMajority(size_t partitionSize, size_t totalSize) const;
    
    // Notify
    void NotifyPartitionChange(bool isPartitioned, bool isMajority);
};

// ============================================================================
// Fault Detector
// ============================================================================

/**
 * Main fault detection coordinator.
 */
class FaultDetector {
public:
    using FaultCallback = std::function<void(const FaultEvent&)>;
    using RecoveryCallback = std::function<void(const std::string& nodeId)>;
    
    FaultDetector(
        std::shared_ptr<CommunicationManager> commManager,
        const DetectorConfig& config = DetectorConfig{}
    );
    ~FaultDetector();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Register node for monitoring
    void RegisterNode(const std::string& nodeId);
    void UnregisterNode(const std::string& nodeId);
    
    // Report heartbeat
    void ReportHeartbeat(const std::string& nodeId);
    void ReportHeartbeat(const std::string& nodeId, uint64_t timestamp);
    
    // Manual fault reporting
    void ReportFault(const FaultEvent& fault);
    void ReportSuspicion(const std::string& nodeId, const std::string& reason);
    
    // Query status
    std::vector<FaultEvent> GetActiveFaults() const;
    std::vector<FaultEvent> GetFaultHistory() const;
    std::optional<NodeHealth> GetNodeHealth(const std::string& nodeId) const;
    std::vector<NodeHealth> GetAllNodeHealth() const;
    
    // Confirmation
    void ConfirmFault(const std::string& faultId);
    void ResolveFault(const std::string& faultId);
    
    // Callbacks
    void OnFaultDetected(FaultCallback callback);
    void OnFaultConfirmed(FaultCallback callback);
    void OnFaultResolved(FaultCallback callback);
    void OnNodeRecovered(RecoveryCallback callback);
    
    // Status
    std::string GetStatusJson() const;
    bool IsHealthy() const;
    
private:
    std::shared_ptr<CommunicationManager> commManager_;
    DetectorConfig config_;
    
    std::unique_ptr<PhiAccrualDetector> phiDetector_;
    std::unique_ptr<GossipProtocol> gossip_;
    std::unique_ptr<PartitionDetector> partitionDetector_;
    
    std::map<std::string, FaultEvent> activeFaults_;
    std::vector<FaultEvent> faultHistory_;
    mutable std::mutex faultMutex_;
    
    FaultCallback faultDetectedCallback_;
    FaultCallback faultConfirmedCallback_;
    FaultCallback faultResolvedCallback_;
    RecoveryCallback nodeRecoveredCallback_;
    std::mutex callbackMutex_;
    
    std::atomic<bool> running_{false};
    std::thread detectionThread_;
    
    // Detection loop
    void DetectionLoop();
    
    // Internal handlers
    void HandleSuspectedNode(const std::string& nodeId, const std::string& reason);
    void HandleConfirmedFault(const FaultEvent& fault);
    void HandleNodeRecovery(const std::string& nodeId);
    
    // Utility
    std::string GenerateFaultId();
    void NotifyFaultDetected(const FaultEvent& fault);
    void NotifyFaultConfirmed(const FaultEvent& fault);
    void NotifyFaultResolved(const FaultEvent& fault);
    void NotifyNodeRecovered(const std::string& nodeId);
};

// ============================================================================
// Recovery Coordinator
// ============================================================================

/**
 * Coordinates recovery from faults.
 */
class RecoveryCoordinator {
public:
    enum class RecoveryAction {
        RESTART_NODE,       // Restart the failed node
        MIGRATE_TASKS,      // Migrate tasks to other nodes
        ELECT_NEW_LEADER,   // Trigger leader election
        SHRINK_CLUSTER,     // Remove node from cluster
        ALERT_OPERATOR      // Alert human operator
    };
    
    struct RecoveryPlan {
        std::string faultId;
        std::string nodeId;
        std::vector<RecoveryAction> actions;
        uint64_t estimatedTimeMs;
        bool requiresConfirmation;
    };
    
    struct RecoveryResult {
        bool success;
        std::string message;
        uint64_t durationMs;
        std::vector<std::string> completedActions;
    };
    
    RecoveryCoordinator(
        std::shared_ptr<CommunicationManager> commManager,
        std::shared_ptr<WorkScheduler> scheduler
    );
    ~RecoveryCoordinator();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Create recovery plan
    RecoveryPlan CreatePlan(const FaultEvent& fault);
    
    // Execute recovery
    RecoveryResult ExecuteRecovery(const RecoveryPlan& plan);
    
    // Specific recovery actions
    bool RestartNode(const std::string& nodeId);
    bool MigrateTasks(const std::string& fromNode, const std::vector<std::string>& taskIds);
    bool ElectNewLeader();
    bool ShrinkCluster(const std::string& nodeId);
    
    // Callbacks
    using RecoveryCallback = std::function<void(const RecoveryResult&)>;
    void OnRecoveryComplete(RecoveryCallback callback);
    
    // Status
    std::string GetStatusJson() const;
    bool IsRecovering() const;
    
private:
    std::shared_ptr<CommunicationManager> commManager_;
    std::shared_ptr<WorkScheduler> scheduler_;
    
    std::atomic<bool> recovering_{false};
    std::atomic<bool> running_{false};
    
    RecoveryCallback recoveryCallback_;
    std::mutex callbackMutex_;
    
    // Action implementations
    bool DoRestartNode(const std::string& nodeId);
    bool DoMigrateTasks(const std::string& fromNode, const std::vector<std::string>& taskIds);
    bool DoElectNewLeader();
    bool DoShrinkCluster(const std::string& nodeId);
    
    // Utility
    void NotifyRecoveryComplete(const RecoveryResult& result);
};

// ============================================================================
// Fault Tolerance Manager
// ============================================================================

/**
 * High-level fault tolerance management.
 */
class FaultToleranceManager {
public:
    FaultToleranceManager(
        std::shared_ptr<CommunicationManager> commManager,
        std::shared_ptr<WorkScheduler> scheduler,
        const DetectorConfig& config = DetectorConfig{}
    );
    ~FaultToleranceManager();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Node management
    void RegisterNode(const std::string& nodeId);
    void UnregisterNode(const std::string& nodeId);
    
    // Heartbeat
    void SendHeartbeat();
    void ReceiveHeartbeat(const std::string& nodeId);
    
    // Status
    bool IsNodeHealthy(const std::string& nodeId) const;
    bool IsClusterHealthy() const;
    std::string GetStatusJson() const;
    
    // Statistics
    uint64_t GetFaultCount() const;
    uint64_t GetRecoveryCount() const;
    float GetAvailability() const;
    
private:
    std::unique_ptr<FaultDetector> detector_;
    std::unique_ptr<RecoveryCoordinator> coordinator_;
    
    std::atomic<uint64_t> faultCount_{0};
    std::atomic<uint64_t> recoveryCount_{0};
    std::atomic<uint64_t> totalUptimeMs_{0};
};

} // namespace Distributed
