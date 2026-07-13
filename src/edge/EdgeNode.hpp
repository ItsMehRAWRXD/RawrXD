/**
 * EdgeNode.hpp
 *
 * Phase R Batch 1/5: Edge Node Management
 *
 * Edge node discovery, registration, and lifecycle management
 * for distributed edge computing scenarios.
 */

#pragma once

#include <cstring>
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

class EdgeNode;
class EdgeRegistry;
class EdgeDiscovery;
class EdgeSynchronizer;

// ============================================================================
// Node Types
// ============================================================================

enum class NodeType {
    GATEWAY,        // Edge gateway with cloud connectivity
    COMPUTE,        // Compute-only node
    STORAGE,        // Storage-focused node
    SENSOR,         // Sensor/IoT device
    ACTUATOR,       // Actuator/control device
    HYBRID          // Multi-purpose node
};

std::string NodeTypeToString(NodeType type);
NodeType NodeTypeFromString(const std::string& str);

// ============================================================================
// Node Capabilities
// ============================================================================

struct NodeCapabilities {
    // Compute
    uint32_t cpuCores;
    uint64_t memoryBytes;
    bool supportsGPU;
    uint64_t gpuMemoryBytes;
    std::string cpuArchitecture;
    
    // Storage
    uint64_t storageBytes;
    bool supportsSSD;
    
    // Network
    bool supportsWiFi;
    bool supportsEthernet;
    bool supportsCellular;
    bool supportsLoRa;
    bool supportsBLE;
    uint32_t maxBandwidthMbps;
    
    // Sensors
    std::vector<std::string> sensors;
    
    // Software
    std::vector<std::string> supportedRuntimes;
    std::vector<std::string> supportedContainers;
    std::string osVersion;
    
    // Power
    bool batteryPowered;
    std::optional<uint32_t> batteryCapacityMah;
    bool supportsPowerSaving;
    
    bool CanRunWorkload(const WorkloadRequirements& reqs) const;
};

// ============================================================================
// Node Status
// ============================================================================

struct NodeStatus {
    enum class State {
        OFFLINE,
        BOOTING,
        ONLINE,
        BUSY,
        DEGRADED,
        MAINTENANCE,
        SHUTTING_DOWN
    };
    
    State state;
    float cpuUsagePercent;
    float memoryUsagePercent;
    float storageUsagePercent;
    std::optional<float> batteryPercent;
    float temperatureCelsius;
    uint32_t activeWorkloads;
    uint64_t networkBytesIn;
    uint64_t networkBytesOut;
    std::chrono::system_clock::time_point lastSeen;
    std::optional<std::string> errorMessage;
    
    bool IsHealthy() const;
    bool IsAvailable() const;
};

// ============================================================================
// Edge Node
// ============================================================================

class EdgeNode {
public:
    struct Config {
        std::string nodeId;
        std::string name;
        std::string description;
        NodeType type;
        NodeCapabilities capabilities;
        std::string location;
        std::optional<std::string> region;
        std::optional<std::string> zone;
        std::vector<std::string> tags;
        std::map<std::string, std::string> metadata;
        std::string tenantId;
        std::optional<std::string> parentNodeId;
    };
    
    explicit EdgeNode(const Config& config);
    
    // Identity
    const std::string& GetNodeId() const { return config_.nodeId; }
    const std::string& GetName() const { return config_.name; }
    NodeType GetType() const { return config_.type; }
    const std::string& GetTenantId() const { return config_.tenantId; }
    
    // Capabilities
    const NodeCapabilities& GetCapabilities() const { return config_.capabilities; }
    bool HasCapability(const std::string& capability) const;
    
    // Status
    NodeStatus GetStatus() const;
    void UpdateStatus(const NodeStatus& status);
    bool IsOnline() const;
    bool IsHealthy() const;
    
    // Location
    const std::string& GetLocation() const { return config_.location; }
    std::optional<std::string> GetRegion() const { return config_.region; }
    std::optional<std::string> GetZone() const { return config_.zone; }
    
    // Hierarchy
    std::optional<std::string> GetParentNodeId() const { return config_.parentNodeId; }
    void SetParentNode(const std::string& parentId);
    std::vector<std::string> GetChildNodes() const;
    void AddChildNode(const std::string& childId);
    void RemoveChildNode(const std::string& childId);
    
    // Connectivity
    void UpdateLastSeen();
    std::chrono::seconds GetTimeSinceLastSeen() const;
    bool IsStale(std::chrono::seconds threshold = std::chrono::seconds(60)) const;
    
    // Workloads
    void AddWorkload(const std::string& workloadId);
    void RemoveWorkload(const std::string& workloadId);
    std::vector<std::string> GetActiveWorkloads() const;
    bool CanAcceptWorkload() const;
    
    // Configuration
    void UpdateConfig(const Config& config);
    const Config& GetConfig() const { return config_; }
    
    // Metadata
    void SetMetadata(const std::string& key, const std::string& value);
    std::optional<std::string> GetMetadata(const std::string& key) const;
    
private:
    Config config_;
    NodeStatus status_;
    std::vector<std::string> childNodes_;
    std::vector<std::string> activeWorkloads_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Edge Registry
// ============================================================================

class EdgeRegistry {
public:
    struct Config {
        std::chrono::seconds nodeTimeout{300};
        std::chrono::seconds heartbeatInterval{30};
        bool enableAutoDeregistration = true;
    };
    
    explicit EdgeRegistry(const Config& config);
    ~EdgeRegistry();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Registration
    bool RegisterNode(std::shared_ptr<EdgeNode> node);
    void DeregisterNode(const std::string& nodeId);
    bool IsRegistered(const std::string& nodeId) const;
    
    // Discovery
    std::shared_ptr<EdgeNode> GetNode(const std::string& nodeId) const;
    std::vector<std::shared_ptr<EdgeNode>> GetAllNodes() const;
    std::vector<std::shared_ptr<EdgeNode>> GetNodesByType(NodeType type) const;
    std::vector<std::shared_ptr<EdgeNode>> GetNodesByTenant(const std::string& tenantId) const;
    std::vector<std::shared_ptr<EdgeNode>> GetNodesByRegion(const std::string& region) const;
    std::vector<std::shared_ptr<EdgeNode>> GetNodesByTag(const std::string& tag) const;
    std::vector<std::shared_ptr<EdgeNode>> GetHealthyNodes() const;
    std::vector<std::shared_ptr<EdgeNode>> GetOnlineNodes() const;
    
    // Filtering
    using NodeFilter = std::function<bool(const EdgeNode&)>;
    std::vector<std::shared_ptr<EdgeNode>> FilterNodes(NodeFilter filter) const;
    
    // Selection
    std::optional<std::shared_ptr<EdgeNode>> SelectNodeForWorkload(
        const WorkloadRequirements& requirements) const;
    std::vector<std::shared_ptr<EdgeNode>> SelectNodesForWorkload(
        const WorkloadRequirements& requirements,
        uint32_t count) const;
    
    // Nearest node selection
    std::optional<std::shared_ptr<EdgeNode>> GetNearestNode(
        double latitude, double longitude) const;
    std::vector<std::shared_ptr<EdgeNode>> GetNodesInRadius(
        double latitude, double longitude, double radiusKm) const;
    
    // Statistics
    struct RegistryStats {
        uint32_t totalNodes;
        uint32_t onlineNodes;
        uint32_t offlineNodes;
        uint32_t healthyNodes;
        uint32_t degradedNodes;
        std::map<NodeType, uint32_t> nodesByType;
        std::map<std::string, uint32_t> nodesByRegion;
    };
    RegistryStats GetStats() const;
    
    // Events
    using NodeEventHandler = std::function<void(const std::string& nodeId,
                                                 const std::string& event)>;
    void OnNodeRegistered(NodeEventHandler handler);
    void OnNodeDeregistered(NodeEventHandler handler);
    void OnNodeOnline(NodeEventHandler handler);
    void OnNodeOffline(NodeEventHandler handler);
    void OnNodeStatusChanged(NodeEventHandler handler);
    
    // Maintenance
    void CleanupStaleNodes();
    void UpdateNodeStatus(const std::string& nodeId, const NodeStatus& status);
    
private:
    Config config_;
    bool initialized_;
    
    std::map<std::string, std::shared_ptr<EdgeNode>> nodes_;
    mutable std::mutex mutex_;
    
    std::thread cleanupThread_;
    std::atomic<bool> stopCleanup_;
    
    NodeEventHandler onRegistered_;
    NodeEventHandler onDeregistered_;
    NodeEventHandler onOnline_;
    NodeEventHandler onOffline_;
    NodeEventHandler onStatusChanged_;
    
    void CleanupLoop();
    void NotifyEvent(const std::string& nodeId, 
                     const std::string& event,
                     NodeEventHandler handler);
};

// ============================================================================
// Edge Discovery
// ============================================================================

class EdgeDiscovery {
public:
    struct Config {
        std::string multicastAddress;
        uint16_t multicastPort;
        std::chrono::seconds discoveryInterval{60};
        uint32_t maxDiscoveryAttempts = 3;
    };
    
    explicit EdgeDiscovery(const Config& config);
    ~EdgeDiscovery();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsRunning() const;
    
    // Discovery methods
    void StartDiscovery();
    void StopDiscovery();
    void DiscoverOnce();
    
    // Manual registration
    void RegisterManualNode(const std::string& address, uint16_t port);
    void UnregisterManualNode(const std::string& address);
    
    // Discovery results
    struct DiscoveredNode {
        std::string nodeId;
        std::string address;
        uint16_t port;
        NodeType type;
        NodeCapabilities capabilities;
        std::chrono::system_clock::time_point discoveredAt;
    };
    
    std::vector<DiscoveredNode> GetDiscoveredNodes() const;
    void ClearDiscoveredNodes();
    
    // Events
    using DiscoveryHandler = std::function<void(const DiscoveredNode&)>;
    void OnNodeDiscovered(DiscoveryHandler handler);
    void OnNodeLost(DiscoveryHandler handler);
    
private:
    Config config_;
    bool running_;
    
    std::vector<DiscoveredNode> discoveredNodes_;
    std::vector<std::pair<std::string, uint16_t>> manualNodes_;
    mutable std::mutex mutex_;
    
    std::thread discoveryThread_;
    
    DiscoveryHandler onDiscovered_;
    DiscoveryHandler onLost_;
    
    void DiscoveryLoop();
    void SendDiscoveryProbe();
    void ProcessDiscoveryResponse(const std::string& response,
                                   const std::string& fromAddress);
};

// ============================================================================
// Edge Synchronizer
// ============================================================================

class EdgeSynchronizer {
public:
    struct Config {
        std::chrono::seconds syncInterval{60};
        bool enableDeltaSync = true;
        uint32_t maxBatchSize = 1000;
        std::chrono::seconds conflictResolutionTimeout{30};
    };
    
    struct SyncItem {
        std::string key;
        std::string value;
        uint64_t version;
        std::chrono::system_clock::time_point timestamp;
        std::string sourceNode;
    };
    
    struct SyncConflict {
        std::string key;
        SyncItem localItem;
        SyncItem remoteItem;
        enum class Resolution { USE_LOCAL, USE_REMOTE, MERGE, MANUAL };
        Resolution resolution;
    };
    
    explicit EdgeSynchronizer(const Config& config);
    ~EdgeSynchronizer();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Data management
    void Put(const std::string& key, const std::string& value);
    std::optional<std::string> Get(const std::string& key) const;
    void Delete(const std::string& key);
    std::vector<std::string> GetKeys(const std::string& prefix = "") const;
    
    // Sync operations
    void SyncWithNode(const std::string& nodeId);
    void SyncWithCloud();
    void SyncAll();
    
    // Conflict resolution
    using ConflictResolver = std::function<SyncItem(const SyncConflict&)>;
    void SetConflictResolver(ConflictResolver resolver);
    std::vector<SyncConflict> GetPendingConflicts() const;
    void ResolveConflict(const std::string& key, const SyncItem& winningItem);
    
    // Sync status
    struct SyncStatus {
        std::chrono::system_clock::time_point lastSync;
        uint64_t itemsSynced;
        uint64_t conflictsResolved;
        uint64_t conflictsPending;
        bool inProgress;
        std::optional<std::string> error;
    };
    SyncStatus GetStatus() const;
    
    // Events
    using SyncHandler = std::function<void(const std::string& nodeId, 
                                            uint64_t itemsSynced)>;
    void OnSyncComplete(SyncHandler handler);
    void OnSyncConflict(std::function<void(const SyncConflict&)> handler);
    
private:
    Config config_;
    bool initialized_;
    
    std::map<std::string, SyncItem> localData_;
    mutable std::mutex dataMutex_;
    
    std::vector<SyncConflict> pendingConflicts_;
    mutable std::mutex conflictMutex_;
    
    ConflictResolver conflictResolver_;
    SyncStatus status_;
    mutable std::mutex statusMutex_;
    
    std::thread syncThread_;
    std::atomic<bool> stopSync_;
    
    SyncHandler onSyncComplete_;
    std::function<void(const SyncConflict&)> onConflict_;
    
    void SyncLoop();
    std::vector<SyncItem> GetChangesSince(uint64_t version) const;
    void ApplyRemoteChanges(const std::vector<SyncItem>& changes);
    SyncItem ResolveConflictInternal(const SyncConflict& conflict);
};

// ============================================================================
// Workload Requirements
// ============================================================================

struct WorkloadRequirements {
    uint32_t minCpuCores;
    uint64_t minMemoryBytes;
    uint64_t minStorageBytes;
    bool requiresGPU;
    uint64_t minGpuMemoryBytes;
    std::vector<std::string> requiredSensors;
    std::vector<std::string> requiredRuntimes;
    bool requiresBattery;
    uint32_t minBatteryPercent;
    std::optional<std::string> preferredRegion;
    std::vector<std::string> requiredTags;
    
    bool IsSatisfiedBy(const NodeCapabilities& capabilities) const;
};

} // namespace Edge
