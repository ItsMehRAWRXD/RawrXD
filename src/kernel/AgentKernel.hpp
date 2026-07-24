// Sovereign Agent Kernel - The Orchestration Layer
// Transforms multiple autonomous agents from competing processes into coordinated workers
// under a single runtime brain with resource leasing and event-driven execution.
// ereh t'nerew ew 
// Architecture:
//   Models
//     |
//     v
//   Intent Layer
//     |
//     v
//   Agent Kernel (this file)
//     |
//     +--> Intent Queue
//     +--> Resource Scheduler
//     +--> Beacon Bus
//     +--> Memory Coordinator
//     +--> Transaction Manager
//     |
//     v
//   Native Runtime

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unordered_map>
#include <functional>
#include <chrono>

namespace RawrXD {
namespace Kernel {

// Forward declarations
class ResourceLease;
class BeaconEvent;
class IntentRequest;
class AgentSession;

// ============================================================================
// Core Types
// ============================================================================

using AgentId = uint64_t;
using IntentId = uint64_t;
using ResourceId = uint64_t;
using LeaseId = uint64_t;
using Timestamp = std::chrono::steady_clock::time_point;

// ============================================================================
// Resource Types - Everything that needs ownership
// ============================================================================

enum class ResourceType : uint32_t {
    TERMINAL = 0,           // Shell/terminal session
    COMPILER = 1,           // Compiler instance (cl.exe, clang, etc.)
    DEBUGGER = 2,           // Debugger attachment
    FILESYSTEM = 3,         // File write lock
    GPU = 4,                // GPU compute context
    KV_CACHE = 5,           // Model KV cache slot
    BUILD_SLOT = 6,         // Build system worker slot
    HOTPATCH = 7,           // Hotpatch aperture
    SYMBOL_TABLE = 8,       // SROT write lock
    TELEMETRY = 9,          // Telemetry ring buffer
    
    COUNT = 10
};

const char* ResourceTypeToString(ResourceType type);

// ============================================================================
// Resource Lease - Capability-based ownership with expiration
// ============================================================================

struct LeaseCapabilities {
    bool canRead : 1;
    bool canWrite : 1;
    bool canExecute : 1;
    bool canDelegate : 1;
    bool canTerminate : 1;
    uint32_t reserved : 27;
    
    static LeaseCapabilities FullAccess() {
        return {true, true, true, false, true, 0};
    }
    static LeaseCapabilities ReadOnly() {
        return {true, false, false, false, false, 0};
    }
};

class ResourceLease {
public:
    LeaseId leaseId;
    AgentId owner;
    ResourceType resourceType;
    ResourceId resourceId;
    LeaseCapabilities capabilities;
    Timestamp acquired;
    Timestamp expires;
    std::string purpose;        // Why this lease was acquired
    IntentId associatedIntent;  // Link to originating intent
    
    // Heartbeat tracking
    std::atomic<uint64_t> lastHeartbeat{0};
    std::atomic<bool> isActive{true};
    
    bool IsExpired() const;
    bool HasCapability(const std::string& cap) const;
    void Heartbeat();
    
    // Serialization for replay/debugging
    std::string ToJson() const;
};

// ============================================================================
// Beacon Event - Push-state instead of polling
// ============================================================================

enum class BeaconType : uint32_t {
    // Build events
    BUILD_STARTED = 0,
    BUILD_PROGRESS = 1,
    BUILD_COMPLETED = 2,
    BUILD_FAILED = 3,
    
    // Terminal events
    TERMINAL_OUTPUT = 4,
    TERMINAL_CLOSED = 5,
    
    // Resource events
    RESOURCE_ACQUIRED = 6,
    RESOURCE_RELEASED = 7,
    RESOURCE_CONTESTED = 8,  // Multiple agents want same resource
    
    // Intent events
    INTENT_QUEUED = 9,
    INTENT_STARTED = 10,
    INTENT_COMPLETED = 11,
    INTENT_FAILED = 12,
    INTENT_ROLLBACK = 13,
    
    // System events
    KERNEL_STARTED = 14,
    KERNEL_SHUTDOWN = 15,
    AGENT_REGISTERED = 16,
    AGENT_UNREGISTERED = 17,
    
    // Telemetry
    TELEMETRY_BATCH = 18,
    PERFORMANCE_SAMPLE = 19,
    
    // Custom
    CUSTOM = 20
};

struct BeaconEvent {
    uint64_t eventId;
    BeaconType type;
    Timestamp timestamp;
    AgentId sourceAgent;
    IntentId associatedIntent;
    
    // Event payload (type-specific)
    std::vector<uint8_t> payload;
    
    // Structured metadata
    std::unordered_map<std::string, std::string> metadata;
    
    // Serialization
    std::string ToJson() const;
    static BeaconEvent FromJson(const std::string& json);
};

// ============================================================================
// Intent Request - Enhanced with kernel routing
// ============================================================================

enum class IntentPriority : uint32_t {
    CRITICAL = 0,      // Emergency fixes, security patches
    HIGH = 1,          // User-facing blocking tasks
    NORMAL = 2,        // Standard operations
    LOW = 3,           // Background optimization
    BACKGROUND = 4     // Telemetry, cleanup
};

struct IntentRequest {
    IntentId intentId;
    AgentId sourceAgent;
    std::string intentType;     // "MODIFY_FUNCTION", "BUILD", "DEBUG", etc.
    IntentPriority priority;
    Timestamp submitted;
    
    // Required resources
    std::vector<ResourceType> requiredResources;
    std::vector<std::string> targetFiles;
    
    // Execution constraints
    uint32_t maxRetries;
    bool requiresHumanApproval;
    bool canBeBatched;
    std::chrono::milliseconds timeout;
    
    // Intent payload (from Intent ABI)
    std::vector<uint8_t> payload;
    
    // Current state
    enum class State {
        PENDING,
        QUEUED,
        WAITING_RESOURCES,
        EXECUTING,
        COMPLETED,
        FAILED,
        ROLLED_BACK
    } state;
    
    std::string ToJson() const;
};

// ============================================================================
// Agent Session - One "chat" or autonomous worker
// ============================================================================

class AgentSession {
public:
    AgentId agentId;
    std::string agentType;      // "PLANNER", "CODER", "DEBUGGER", "REFLECTOR"
    std::string modelBackend;   // "kimi", "moonshot", "local_gguf"
    Timestamp created;
    
    // Current state
    std::atomic<bool> isActive{true};
    std::atomic<bool> isExecuting{false};
    IntentId currentIntent{0};
    
    // Owned resources
    std::vector<LeaseId> activeLeases;
    mutable std::mutex leaseMutex;
    
    // Memory context
    std::vector<uint64_t> recentIntentHistory;
    std::unordered_map<std::string, std::string> contextCache;
    
    // Methods
    void AcquireLease(std::shared_ptr<ResourceLease> lease);
    void ReleaseLease(LeaseId leaseId);
    bool HasLease(ResourceType type) const;
    std::vector<std::shared_ptr<ResourceLease>> GetActiveLeases() const;
    
    // Telemetry
    uint64_t intentsCompleted{0};
    uint64_t intentsFailed{0};
    double averageExecutionTimeMs{0.0};
};

// ============================================================================
// Resource Scheduler - Centralized ownership manager
// ============================================================================

class ResourceScheduler {
public:
    static ResourceScheduler& Instance();
    
    // Lease management
    std::shared_ptr<ResourceLease> AcquireLease(
        AgentId agent,
        ResourceType type,
        ResourceId specificResource,
        LeaseCapabilities caps,
        std::chrono::seconds duration,
        const std::string& purpose,
        IntentId intent
    );
    
    bool ReleaseLease(LeaseId leaseId, AgentId agent);
    bool ExtendLease(LeaseId leaseId, std::chrono::seconds extension);
    
    // Query
    std::shared_ptr<ResourceLease> GetLease(LeaseId leaseId) const;
    std::vector<std::shared_ptr<ResourceLease>> GetLeasesForAgent(AgentId agent) const;
    std::vector<std::shared_ptr<ResourceLease>> GetLeasesForResource(ResourceType type) const;
    
    // Contention handling
    bool IsResourceAvailable(ResourceType type, ResourceId specificResource = 0) const;
    std::vector<AgentId> GetWaitingAgents(ResourceType type) const;
    
    // Emergency
    void EmergencyRevokeAll(AgentId agent);  // Kill all agent's leases
    void EmergencyRevokeResource(ResourceType type);  // Global lock
    
    // Maintenance
    void PruneExpiredLeases();
    void StartHeartbeatMonitor();
    void StopHeartbeatMonitor();
    
private:
    ResourceScheduler() = default;
    
    mutable std::mutex leasesMutex_;
    std::unordered_map<LeaseId, std::shared_ptr<ResourceLease>> leases_;
    std::unordered_map<ResourceType, std::vector<LeaseId>> resourceIndex_;
    std::atomic<LeaseId> nextLeaseId_{1};
    
    // Contention tracking
    std::unordered_map<ResourceType, std::queue<AgentId>> waitQueues_;
    mutable std::mutex waitQueueMutex_;
    
    // Background thread
    std::atomic<bool> monitorRunning_{false};
    std::thread monitorThread_;
};

// ============================================================================
// Beacon Bus - Event-driven state propagation
// ============================================================================

using BeaconHandler = std::function<void(const BeaconEvent&)>;

class BeaconBus {
public:
    static BeaconBus& Instance();
    
    // Publishing
    void Publish(BeaconEvent&& event);
    void Publish(BeaconType type, AgentId source, const std::string& jsonPayload);
    
    // Subscriptions
    uint64_t Subscribe(BeaconType type, BeaconHandler handler);
    uint64_t SubscribeAll(BeaconHandler handler);
    void Unsubscribe(uint64_t subscriptionId);
    
    // Query (for replay/debugging)
    std::vector<BeaconEvent> GetHistory(uint64_t maxEvents = 1000) const;
    std::vector<BeaconEvent> GetHistoryForAgent(AgentId agent, uint64_t maxEvents = 100) const;
    std::vector<BeaconEvent> GetHistoryForIntent(IntentId intent) const;
    
    // Control
    void Start();
    void Stop();
    void ClearHistory();
    
    // Statistics
    uint64_t GetTotalEventsPublished() const { return totalPublished_.load(); }
    uint64_t GetActiveSubscriptions() const;
    
private:
    BeaconBus() = default;
    void DispatchLoop();
    
    std::queue<BeaconEvent> eventQueue_;
    mutable std::mutex queueMutex_;
    std::condition_variable queueCv_;
    
    std::unordered_map<uint64_t, std::pair<BeaconType, BeaconHandler>> subscriptions_;
    std::unordered_map<uint64_t, BeaconHandler> globalSubscriptions_;
    mutable std::mutex subscriptionsMutex_;
    std::atomic<uint64_t> nextSubscriptionId_{1};
    
    // History
    std::vector<BeaconEvent> history_;
    mutable std::mutex historyMutex_;
    static constexpr size_t MAX_HISTORY = 10000;
    
    std::atomic<uint64_t> totalPublished_{0};
    std::atomic<bool> running_{false};
    std::thread dispatchThread_;
};

// ============================================================================
// Intent Queue - Priority queue with resource awareness
// ============================================================================

class IntentQueue {
public:
    static IntentQueue& Instance();
    
    // Queue management
    void Enqueue(IntentRequest&& intent);
    std::optional<IntentRequest> Dequeue();
    
    // Query
    size_t GetPendingCount() const;
    size_t GetCountForAgent(AgentId agent) const;
    std::vector<IntentRequest> GetPendingIntents() const;
    
    // Control
    void CancelIntent(IntentId intentId);
    void CancelAllForAgent(AgentId agent);
    void Reprioritize(IntentId intentId, IntentPriority newPriority);
    
    // Maintenance
    void PruneStaleIntents(std::chrono::minutes maxAge);
    
private:
    IntentQueue() = default;
    
    struct PriorityCompare {
        bool operator()(const IntentRequest& a, const IntentRequest& b) const {
            return static_cast<uint32_t>(a.priority) > static_cast<uint32_t>(b.priority);
        }
    };
    
    std::priority_queue<IntentRequest, std::vector<IntentRequest>, PriorityCompare> queue_;
    mutable std::mutex queueMutex_;
    std::condition_variable cv_;
    
    std::unordered_map<IntentId, Timestamp> intentTimestamps_;
    mutable std::mutex timestampMutex_;
};

// ============================================================================
// Agent Kernel - The Central Orchestrator
// ============================================================================

class AgentKernel {
public:
    static AgentKernel& Instance();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsRunning() const { return running_.load(); }
    
    // Agent management
    AgentId RegisterAgent(const std::string& type, const std::string& backend);
    void UnregisterAgent(AgentId agent);
    std::shared_ptr<AgentSession> GetAgent(AgentId agent) const;
    std::vector<AgentId> GetActiveAgents() const;
    
    // Intent submission (main entry point)
    IntentId SubmitIntent(AgentId agent, IntentRequest&& intent);
    
    // Execution control
    void PauseExecution();
    void ResumeExecution();
    void EmergencyStop(const std::string& reason);
    
    // Status
    struct KernelStatus {
        bool running;
        size_t activeAgents;
        size_t pendingIntents;
        size_t activeLeases;
        uint64_t totalIntentsProcessed;
        uint64_t totalEventsPublished;
        std::chrono::milliseconds uptime;
    };
    KernelStatus GetStatus() const;
    std::string GetStatusJson() const;
    
    // Configuration
    void SetMaxConcurrentAgents(size_t max);
    void SetIntentTimeout(std::chrono::seconds timeout);
    void SetLeaseHeartbeatInterval(std::chrono::seconds interval);
    
private:
    AgentKernel() = default;
    void MainLoop();
    void ProcessIntent(IntentRequest& intent);
    bool AcquireResourcesForIntent(IntentRequest& intent);
    void ReleaseResourcesForIntent(const IntentRequest& intent);
    
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    std::thread mainLoopThread_;
    
    // Agent registry
    std::unordered_map<AgentId, std::shared_ptr<AgentSession>> agents_;
    mutable std::mutex agentsMutex_;
    std::atomic<AgentId> nextAgentId_{1};
    std::atomic<size_t> maxConcurrentAgents_{10};
    
    // Statistics
    std::atomic<uint64_t> totalIntentsProcessed_{0};
    Timestamp startTime_;
    
    // Configuration
    std::chrono::seconds intentTimeout_{300};  // 5 minutes default
    std::chrono::seconds leaseHeartbeatInterval_{30};  // 30 seconds
};

// ============================================================================
// Convenience Macros
// ============================================================================

#define AGENT_KERNEL RawrXD::Kernel::AgentKernel::Instance()
#define RESOURCE_SCHEDULER RawrXD::Kernel::ResourceScheduler::Instance()
#define BEACON_BUS RawrXD::Kernel::BeaconBus::Instance()
#define INTENT_QUEUE RawrXD::Kernel::IntentQueue::Instance()

// Resource lease RAII helper
class ScopedResourceLease {
public:
    ScopedResourceLease(AgentId agent, ResourceType type, 
                        std::chrono::seconds duration, 
                        const std::string& purpose);
    ~ScopedResourceLease();
    
    bool IsValid() const { return lease_ != nullptr; }
    LeaseId GetLeaseId() const { return lease_ ? lease_->leaseId : 0; }
    
private:
    std::shared_ptr<ResourceLease> lease_;
};

// Beacon emission helper
#define EMIT_BEACON(type, payload) \
    RawrXD::Kernel::BeaconBus::Instance().Publish( \
        RawrXD::Kernel::BeaconType::type, 0, payload)

} // namespace Kernel
} // namespace RawrXD
