/**
 * EdgeConnectivity.hpp
 *
 * Phase R Batch 4/5: Edge Connectivity & Sync
 *
 * Network resilience, offline-first capabilities, and cloud
 * synchronization for edge deployments.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <queue>

namespace Edge {

// ============================================================================
// Forward Declarations
// ============================================================================

class ConnectionManager;
class MessageQueue;
class DataSynchronizer;
class NetworkOptimizer;

// ============================================================================
// Connection Types
// ============================================================================

enum class ConnectionType {
    WIFI,
    ETHERNET,
    CELLULAR_4G,
    CELLULAR_5G,
    LORA,
    SATELLITE,
    MESH,
    BLE,
    OFFLINE
};

std::string ConnectionTypeToString(ConnectionType type);
ConnectionType ConnectionTypeFromString(const std::string& str);

// ============================================================================
// Connection Quality
// ============================================================================

struct ConnectionQuality {
    float bandwidthMbps;
    uint32_t latencyMs;
    float packetLossPercent;
    float jitterMs;
    int32_t signalStrengthDbm;
    bool isStable;
    std::chrono::system_clock::time_point measuredAt;
    
    bool IsSuitableForRealtime() const;
    bool IsSuitableForBulkTransfer() const;
    std::string GetQualityRating() const;  // excellent, good, fair, poor
};

// ============================================================================
// Connection Manager
// ============================================================================

class ConnectionManager {
public:
    struct Config {
        std::vector<ConnectionType> priorityOrder = {
            ConnectionType::ETHERNET,
            ConnectionType::WIFI,
            ConnectionType::CELLULAR_5G,
            ConnectionType::CELLULAR_4G,
            ConnectionType::MESH,
            ConnectionType::SATELLITE,
            ConnectionType::LORA
        };
        bool enableFailover = true;
        bool enableBonding = false;
        std::chrono::seconds healthCheckInterval{10};
        uint32_t failoverThreshold = 3;  // Failed checks before failover
    };
    
    struct Connection {
        std::string connectionId;
        ConnectionType type;
        std::string interfaceName;
        std::optional<std::string> ipAddress;
        bool isActive;
        bool isPrimary;
        ConnectionQuality quality;
        std::chrono::system_clock::time_point connectedAt;
        uint64_t bytesTransferred;
        uint32_t failedHealthChecks;
    };
    
    explicit ConnectionManager(const Config& config);
    ~ConnectionManager();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Connection management
    bool AddConnection(const Connection& connection);
    void RemoveConnection(const std::string& connectionId);
    void ActivateConnection(const std::string& connectionId);
    void DeactivateConnection(const std::string& connectionId);
    void SetPrimaryConnection(const std::string& connectionId);
    
    // Queries
    std::optional<Connection> GetConnection(const std::string& connectionId) const;
    std::vector<Connection> GetAllConnections() const;
    std::vector<Connection> GetActiveConnections() const;
    std::optional<Connection> GetPrimaryConnection() const;
    std::optional<Connection> GetBestConnection() const;
    
    // Status
    bool IsOnline() const;
    bool HasConnectivity(ConnectionType type) const;
    ConnectionQuality GetCurrentQuality() const;
    
    // Failover
    void EnableFailover(bool enabled);
    void TriggerManualFailover();
    
    // Bonding (multi-path)
    void EnableBonding(bool enabled);
    bool IsBondingEnabled() const;
    
    // Events
    using ConnectionEventHandler = std::function<void(const std::string& connectionId,
                                                        const std::string& event)>;
    void OnConnectionUp(ConnectionEventHandler handler);
    void OnConnectionDown(ConnectionEventHandler handler);
    void OnFailover(ConnectionEventHandler handler);
    void OnQualityChanged(std::function<void(const std::string&, const ConnectionQuality&)> handler);
    
    // Statistics
    struct ConnectionStats {
        uint64_t totalBytesTransferred;
        uint64_t totalBytesReceived;
        uint32_t failovers;
        uint32_t reconnections;
        std::chrono::seconds totalUptime;
        std::chrono::seconds totalDowntime;
    };
    ConnectionStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    
    std::map<std::string, Connection> connections_;
    mutable std::mutex connectionsMutex_;
    
    std::string primaryConnectionId_;
    mutable std::mutex primaryMutex_;
    
    std::thread healthCheckThread_;
    std::atomic<bool> stopHealthCheck_;
    
    ConnectionEventHandler onUp_;
    ConnectionEventHandler onDown_;
    ConnectionEventHandler onFailover_;
    std::function<void(const std::string&, const ConnectionQuality&)> onQualityChanged_;
    
    ConnectionStats stats_;
    mutable std::mutex statsMutex_;
    
    void HealthCheckLoop();
    void CheckConnectionHealth(Connection& connection);
    void PerformFailover();
    ConnectionQuality MeasureQuality(const Connection& connection);
};

// ============================================================================
// Message Queue
// ============================================================================

class MessageQueue {
public:
    struct Config {
        size_t maxQueueSize = 10000;
        size_t maxMessageSize = 1024 * 1024;  // 1MB
        bool persistent = true;
        std::string storagePath;
        std::chrono::seconds retentionPeriod{7 * 24 * 60 * 60};  // 7 days
        bool compressionEnabled = true;
        uint32_t deliveryAttempts = 3;
    };
    
    enum class Priority {
        LOW = 0,
        NORMAL = 1,
        HIGH = 2,
        CRITICAL = 3
    };
    
    struct Message {
        std::string messageId;
        std::string topic;
        std::vector<uint8_t> payload;
        Priority priority;
        std::chrono::system_clock::time_point timestamp;
        std::map<std::string, std::string> headers;
        std::optional<std::string> correlationId;
        std::optional<std::chrono::system_clock::time_point> expiresAt;
        uint32_t deliveryAttempts;
    };
    
    struct DeliveryResult {
        bool success;
        std::optional<std::string> error;
        std::chrono::milliseconds deliveryTime;
    };
    
    explicit MessageQueue(const Config& config);
    ~MessageQueue();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Publishing
    std::string Publish(const std::string& topic,
                        const std::vector<uint8_t>& payload,
                        Priority priority = Priority::NORMAL);
    std::string Publish(const std::string& topic,
                        const std::string& payload,
                        Priority priority = Priority::NORMAL);
    
    // Subscribing
    using MessageHandler = std::function<void(const Message&)>;
    std::string Subscribe(const std::string& topic, MessageHandler handler);
    std::string SubscribePattern(const std::string& pattern, MessageHandler handler);
    void Unsubscribe(const std::string& subscriptionId);
    
    // Queue management
    std::optional<Message> Dequeue(const std::string& topic);
    std::vector<Message> DequeueBatch(const std::string& topic, uint32_t maxMessages);
    void Acknowledge(const std::string& messageId);
    void NegativeAcknowledge(const std::string& messageId, const std::string& reason);
    
    // Dead letter queue
    std::vector<Message> GetDeadLetterMessages() const;
    void ReprocessDeadLetter(const std::string& messageId);
    void PurgeDeadLetterQueue();
    
    // Statistics
    struct QueueStats {
        uint64_t messagesPublished;
        uint64_t messagesDelivered;
        uint64_t messagesFailed;
        uint64_t messagesInQueue;
        uint64_t deadLetterCount;
        size_t storageSizeBytes;
    };
    QueueStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    
    struct Queue {
        std::deque<Message> messages;
        std::map<std::string, MessageHandler> subscribers;
    };
    
    std::map<std::string, Queue> queues_;
    mutable std::mutex queuesMutex_;
    
    std::deque<Message> deadLetterQueue_;
    mutable std::mutex dlqMutex_;
    
    QueueStats stats_;
    mutable std::mutex statsMutex_;
    
    void PersistQueue();
    void RestoreQueue();
    void ProcessDeadLetter(const Message& message);
};

// ============================================================================
// Data Synchronizer
// ============================================================================

class DataSynchronizer {
public:
    struct Config {
        std::chrono::seconds syncInterval{60};
        bool enableDeltaSync = true;
        bool enableCompression = true;
        uint32_t maxConcurrentSyncs = 5;
        std::chrono::seconds conflictResolutionTimeout{30};
        bool bidirectionalSync = true;
    };
    
    enum class SyncDirection {
        UPLOAD_ONLY,
        DOWNLOAD_ONLY,
        BIDIRECTIONAL
    };
    
    enum class ConflictResolution {
        SERVER_WINS,
        CLIENT_WINS,
        TIMESTAMP_WINS,
        CUSTOM
    };
    
    struct SyncItem {
        std::string key;
        std::vector<uint8_t> data;
        uint64_t version;
        std::chrono::system_clock::time_point timestamp;
        std::string checksum;
        bool deleted;
    };
    
    struct SyncConflict {
        std::string key;
        SyncItem localItem;
        SyncItem remoteItem;
        ConflictResolution resolution;
    };
    
    struct SyncResult {
        bool success;
        uint64_t itemsUploaded;
        uint64_t itemsDownloaded;
        uint64_t conflictsResolved;
        uint64_t conflictsPending;
        std::optional<std::string> error;
        std::chrono::milliseconds duration;
    };
    
    explicit DataSynchronizer(const Config& config);
    ~DataSynchronizer();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Data management
    void Put(const std::string& key, const std::vector<uint8_t>& data);
    void Put(const std::string& key, const std::string& data);
    std::optional<std::vector<uint8_t>> Get(const std::string& key) const;
    void Delete(const std::string& key);
    std::vector<std::string> GetKeys(const std::string& prefix = "") const;
    
    // Sync operations
    SyncResult Sync(SyncDirection direction = SyncDirection::BIDIRECTIONAL);
    std::future<SyncResult> SyncAsync(SyncDirection direction = SyncDirection::BIDIRECTIONAL);
    void SyncWithCallback(SyncDirection direction,
                          std::function<void(const SyncResult&)> callback);
    
    // Conflict resolution
    void SetConflictResolution(ConflictResolution resolution);
    void SetCustomConflictResolver(std::function<SyncItem(const SyncConflict&)> resolver);
    std::vector<SyncConflict> GetPendingConflicts() const;
    void ResolveConflict(const std::string& key, const SyncItem& winningItem);
    
    // Sync status
    struct SyncStatus {
        std::chrono::system_clock::time_point lastSync;
        std::optional<std::chrono::system_clock::time_point> nextScheduledSync;
        uint64_t pendingUploads;
        uint64_t pendingDownloads;
        bool inProgress;
        float syncProgress;
        std::optional<std::string> currentError;
    };
    SyncStatus GetStatus() const;
    
    // Pause/Resume
    void PauseSync();
    void ResumeSync();
    bool IsSyncPaused() const;
    
    // Events
    using SyncEventHandler = std::function<void(const SyncResult&)>;
    void OnSyncComplete(SyncEventHandler handler);
    void OnSyncConflict(std::function<void(const SyncConflict&)> handler);
    void OnSyncProgress(std::function<void(float progress)> handler);
    
    // Statistics
    struct SyncStats {
        uint64_t totalSyncs;
        uint64_t successfulSyncs;
        uint64_t failedSyncs;
        uint64_t totalItemsSynced;
        uint64_t totalConflicts;
        double averageSyncTimeMs;
        uint64_t bytesTransferred;
    };
    SyncStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    bool paused_;
    
    std::map<std::string, SyncItem> localData_;
    mutable std::mutex dataMutex_;
    
    std::vector<SyncConflict> pendingConflicts_;
    mutable std::mutex conflictMutex_;
    
    ConflictResolution conflictResolution_;
    std::function<SyncItem(const SyncConflict&)> customResolver_;
    
    SyncStatus status_;
    mutable std::mutex statusMutex_;
    
    SyncStats stats_;
    mutable std::mutex statsMutex_;
    
    std::thread syncThread_;
    std::atomic<bool> stopSync_;
    
    SyncEventHandler onComplete_;
    std::function<void(const SyncConflict&)> onConflict_;
    std::function<void(float)> onProgress_;
    
    void SyncLoop();
    SyncResult PerformSync(SyncDirection direction);
    std::vector<SyncItem> GetChangesSince(uint64_t version) const;
    void ApplyRemoteChanges(const std::vector<SyncItem>& changes);
    SyncItem ResolveConflictInternal(const SyncConflict& conflict);
    std::string ComputeChecksum(const std::vector<uint8_t>& data) const;
};

// ============================================================================
// Network Optimizer
// ============================================================================

class NetworkOptimizer {
public:
    struct Config {
        bool enableCompression = true;
        uint32_t compressionLevel = 6;  // 1-9
        bool enableBatching = true;
        std::chrono::milliseconds batchWindow{100};
        uint32_t maxBatchSize = 100;
        bool enableDeduplication = true;
        std::chrono::seconds dedupWindow{60};
        bool enablePrioritization = true;
    };
    
    explicit NetworkOptimizer(const Config& config);
    
    // Optimization
    std::vector<uint8_t> Compress(const std::vector<uint8_t>& data);
    std::vector<uint8_t> Decompress(const std::vector<uint8_t>& data);
    
    // Batching
    template<typename T>
    std::vector<std::vector<T>> CreateBatches(const std::vector<T>& items);
    
    // Deduplication
    bool IsDuplicate(const std::string& key);
    void MarkProcessed(const std::string& key);
    void ClearDedupCache();
    
    // Prioritization
    enum class TrafficPriority {
        BACKGROUND,
        NORMAL,
        INTERACTIVE,
        CRITICAL
    };
    
    void SetTrafficPriority(const std::string& endpoint, TrafficPriority priority);
    TrafficPriority GetTrafficPriority(const std::string& endpoint) const;
    
    // Protocol selection
    enum class Protocol {
        HTTP_1_1,
        HTTP_2,
        QUIC,
        WEBSOCKET,
        MQTT,
        COAP
    };
    
    Protocol SelectOptimalProtocol(const ConnectionQuality& quality) const;
    
    // Adaptive quality
    void UpdateQualityEstimate(const std::string& endpoint, 
                               const ConnectionQuality& quality);
    ConnectionQuality GetQualityEstimate(const std::string& endpoint) const;
    
    // Statistics
    struct OptimizerStats {
        uint64_t bytesCompressed;
        uint64_t bytesSavedByCompression;
        uint64_t batchesCreated;
        uint64_t itemsDeduplicated;
        uint64_t protocolSwitches;
    };
    OptimizerStats GetStats() const;
    
private:
    Config config_;
    
    std::set<std::string> dedupCache_;
    mutable std::mutex dedupMutex_;
    
    std::map<std::string, TrafficPriority> priorities_;
    mutable std::mutex priorityMutex_;
    
    std::map<std::string, ConnectionQuality> qualityEstimates_;
    mutable std::mutex qualityMutex_;
    
    OptimizerStats stats_;
    mutable std::mutex statsMutex_;
    
    void CleanupDedupCache();
};

// ============================================================================
// Offline Manager
// ============================================================================

class OfflineManager {
public:
    struct Config {
        bool enableOfflineMode = true;
        size_t maxOfflineStorage = 1024 * 1024 * 1024;  // 1GB
        std::chrono::hours maxOfflineDuration{168};  // 7 days
        bool queueOperations = true;
        bool syncOnReconnect = true;
        std::chrono::seconds syncDelayAfterReconnect{5};
    };
    
    enum class OfflineState {
        ONLINE,
        GOING_OFFLINE,
        OFFLINE,
        GOING_ONLINE,
        SYNCING
    };
    
    explicit OfflineManager(const Config& config);
    ~OfflineManager();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // State management
    void SetConnectivityState(bool connected);
    bool IsOnline() const;
    bool IsOffline() const;
    OfflineState GetState() const;
    std::chrono::seconds GetOfflineDuration() const;
    
    // Operation queuing
    using Operation = std::function<void()>;
    void QueueOperation(Operation op, bool highPriority = false);
    void ExecuteQueuedOperations();
    void ClearQueuedOperations();
    uint32_t GetQueuedOperationCount() const;
    
    // Data caching
    void CacheForOffline(const std::string& key, const std::vector<uint8_t>& data);
    std::optional<std::vector<uint8_t>> GetCachedData(const std::string& key) const;
    void InvalidateCache(const std::string& pattern);
    
    // Sync on reconnect
    void EnableSyncOnReconnect(bool enabled);
    void SetSyncDelay(std::chrono::seconds delay);
    
    // Events
    using StateChangeHandler = std::function<void(OfflineState, OfflineState)>;
    void OnStateChange(StateChangeHandler handler);
    void OnReconnect(std::function<void()> handler);
    
    // Statistics
    struct OfflineStats {
        uint64_t operationsQueued;
        uint64_t operationsExecuted;
        uint64_t operationsFailed;
        size_t cacheSize;
        uint32_t cacheItems;
        std::chrono::seconds totalOfflineTime;
        uint32_t reconnections;
    };
    OfflineStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    
    OfflineState state_;
    mutable std::mutex stateMutex_;
    
    bool connected_;
    std::chrono::system_clock::time_point offlineSince_;
    
    std::deque<Operation> operationQueue_;
    mutable std::mutex queueMutex_;
    
    std::map<std::string, std::vector<uint8_t>> cache_;
    mutable std::mutex cacheMutex_;
    
    StateChangeHandler onStateChange_;
    std::function<void()> onReconnect_;
    
    OfflineStats stats_;
    mutable std::mutex statsMutex_;
    
    std::thread syncThread_;
    std::atomic<bool> stopSync_;
    
    void TransitionToState(OfflineState newState);
    void HandleReconnection();
    void SyncLoop();
};

} // namespace Edge
