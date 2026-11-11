// Sovereign Agent Kernel - Orchestration Layer
// Transforms multiple autonomous agents from competing processes into coordinated workers
//
// Architecture:
//   Intent Queue -> Resource Scheduler -> Execution Fabric -> Beacon Router
//
// The "tank inside" becomes real when:
//   - One brain (agent scheduler) coordinates many workers
//   - Nerves (beacons) replace polling
//   - Muscles (execution ABI) enforce boundaries
//   - Immune system (guardrails) protect state
//   - Memory (repo graph) persists cognition
//   - Reflexes (hotpatch/runtime loop) enable self-modification

#pragma once

#include <cstdint>
#include <atomic>
#include <memory>
#include <vector>
#include <queue>
#include <unordered_map>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <string>

// Forward declarations
namespace RawrXD {
    namespace Intent { struct IntentRequest; }
    namespace Guardrails { class PatchFirewall; }
    namespace Hotpatch { class PatchTransaction; }
}

namespace RawrXD {
namespace Kernel {

// ============================================================================
// RESOURCE TYPES - What agents can lease
// ============================================================================

enum class ResourceType : uint32_t {
    TERMINAL = 0,       // Shell/command execution
    BUILD_SYSTEM,       // Compiler/linker
    DEBUGGER,           // Debug session
    FILESYSTEM,         // File operations
    GIT_REPOSITORY,     // Git operations
    MODEL_BACKEND,      // LLM inference
    MEMORY_REGION,      // Shared memory
    HOTPATCH_SLOT,      // Code modification slot
    
    COUNT
};

const char* ResourceTypeToString(ResourceType type);

// ============================================================================
// RESOURCE LEASE - Temporary ownership with automatic expiry
// ============================================================================

struct ResourceLease {
    uint64_t lease_id;
    uint64_t agent_id;
    ResourceType resource_type;
    uint32_t resource_instance;  // Which terminal/build slot/etc
    
    std::chrono::steady_clock::time_point acquired_at;
    std::chrono::steady_clock::time_point expires_at;
    
    std::atomic<bool> is_active{false};
    std::atomic<bool> heartbeat_received{false};
    
    // Lease conditions
    std::function<bool()> release_condition;  // Custom release check
    std::function<void()> on_expiry;          // Cleanup callback
    
    bool IsExpired() const;
    bool ShouldRelease() const;
    void Renew(std::chrono::seconds extension);
};

// ============================================================================
// AGENT REGISTRATION - Identity and capabilities
// ============================================================================

enum class AgentState : uint32_t {
    UNREGISTERED = 0,
    IDLE,               // Waiting for work
    SCHEDULING,         // Deciding what to do
    EXECUTING,          // Has resources, running
    BLOCKED,            // Waiting for resources
    OBSERVING,          // Watching another agent
    TERMINATED          // Finished or killed
};

struct AgentRegistration {
    uint64_t agent_id;
    std::string agent_name;
    std::string model_backend;  // "kimi", "gguf", "moonshot", etc
    
    AgentState state{AgentState::UNREGISTERED};
    
    // Capabilities this agent has been granted
    uint64_t capability_mask{0};
    
    // Current resources held
    std::vector<uint64_t> active_leases;
    
    // Task ownership
    std::string current_task_id;
    uint64_t current_intent_id{0};
    
    // Observability
    std::chrono::steady_clock::time_point registered_at;
    std::chrono::steady_clock::time_point last_heartbeat;
    
    // Statistics
    uint64_t intents_executed{0};
    uint64_t resources_acquired{0};
    uint64_t resources_released{0};
    
    bool IsStale() const;
};

// ============================================================================
// INTENT QUEUE ENTRY - Work to be done
// ============================================================================

enum class IntentPriority : uint32_t {
    CRITICAL = 0,       // Emergency operations
    HIGH,               // User-facing blocking
    NORMAL,             // Standard work
    LOW,                // Background tasks
    BACKGROUND          // Maintenance, indexing
};

struct IntentQueueEntry {
    uint64_t intent_id;
    uint64_t agent_id;
    std::string task_id;
    
    IntentPriority priority{IntentPriority::NORMAL};
    std::chrono::steady_clock::time_point queued_at;
    
    // The actual intent (stored as pointer to avoid copying)
    std::shared_ptr<Intent::IntentRequest> intent;
    
    // Required resources
    std::vector<ResourceType> required_resources;
    
    // Dependencies - must complete first
    std::vector<uint64_t> depends_on;
    
    // Execution
    std::function<void()> on_execute;
    std::function<void(bool success)> on_complete;
    
    // Comparison for priority queue
    bool operator<(const IntentQueueEntry& other) const;
};

// ============================================================================
// BEACON EVENT - Event-driven state changes
// ============================================================================

enum class BeaconType : uint32_t {
    // Build events
    BUILD_STARTED = 0,
    BUILD_STAGE_CHANGED,
    BUILD_COMPLETED,
    BUILD_FAILED,
    
    // File events
    FILE_MODIFIED,
    FILE_CREATED,
    FILE_DELETED,
    
    // Symbol events
    SYMBOL_DEFINED,
    SYMBOL_REFERENCED,
    SYMBOL_REMOVED,
    
    // Debug events
    BREAKPOINT_HIT,
    EXCEPTION_CAUGHT,
    STEP_COMPLETED,
    
    // Agent events
    AGENT_REGISTERED,
    AGENT_STATE_CHANGED,
    AGENT_TERMINATED,
    
    // Resource events
    RESOURCE_ACQUIRED,
    RESOURCE_RELEASED,
    RESOURCE_CONFLICT,
    
    // Intent events
    INTENT_QUEUED,
    INTENT_STARTED,
    INTENT_COMPLETED,
    INTENT_FAILED,
    
    // System events
    SYSTEM_STATE_CHANGED,
    HOTPATCH_APPLIED,
    ROLLBACK_TRIGGERED
};

struct BeaconEvent {
    uint64_t event_id;
    BeaconType type;
    uint64_t source_agent_id;
    uint64_t target_intent_id;
    
    std::chrono::steady_clock::time_point timestamp;
    
    // Payload - type-specific data
    std::unordered_map<std::string, std::string> string_data;
    std::unordered_map<std::string, int64_t> numeric_data;
    std::unordered_map<std::string, double> float_data;
    
    // Quick accessors
    std::string GetString(const std::string& key) const;
    int64_t GetNumeric(const std::string& key) const;
    double GetFloat(const std::string& key) const;
};

// Beacon subscriber callback
typedef std::function<void(const BeaconEvent&)> BeaconCallback;

// ============================================================================
// SOVEREIGN AGENT KERNEL - The orchestration microkernel
// ============================================================================

class SovereignAgentKernel {
public:
    static SovereignAgentKernel& Instance();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsRunning() const { return running_.load(); }
    
    // Agent Management
    uint64_t RegisterAgent(const std::string& name, 
                           const std::string& model_backend,
                           uint64_t capabilities);
    void UnregisterAgent(uint64_t agent_id);
    void UpdateAgentState(uint64_t agent_id, AgentState new_state);
    void AgentHeartbeat(uint64_t agent_id);
    
    AgentRegistration* GetAgent(uint64_t agent_id);
    std::vector<AgentRegistration*> GetActiveAgents();
    
    // Resource Management
    uint64_t AcquireResource(uint64_t agent_id, 
                             ResourceType type,
                             std::chrono::seconds lease_duration,
                             std::function<bool()> release_condition = nullptr);
    bool ReleaseResource(uint64_t lease_id);
    bool RenewLease(uint64_t lease_id, std::chrono::seconds extension);
    
    bool HasResource(uint64_t agent_id, ResourceType type);
    ResourceLease* GetLease(uint64_t lease_id);
    std::vector<ResourceLease*> GetAgentLeases(uint64_t agent_id);
    
    // Intent Queue
    uint64_t QueueIntent(std::shared_ptr<Intent::IntentRequest> intent,
                         uint64_t agent_id,
                         IntentPriority priority = IntentPriority::NORMAL,
                         std::vector<ResourceType> required_resources = {});
    
    bool CancelIntent(uint64_t intent_id);
    IntentQueueEntry* GetNextIntent();
    void MarkIntentComplete(uint64_t intent_id, bool success);
    
    // Beacon System (Event-Driven)
    uint64_t SubscribeToBeacon(BeaconType type, BeaconCallback callback);
    void UnsubscribeFromBeacon(uint64_t subscription_id);
    void EmitBeacon(const BeaconEvent& event);
    void EmitBeacon(BeaconType type, 
                    uint64_t source_agent_id = 0,
                    uint64_t target_intent_id = 0);
    
    // Scheduling
    void RunSchedulerLoop();  // Main scheduling thread
    void TriggerScheduler();   // Wake scheduler immediately
    
    // Statistics
    struct KernelStats {
        uint64_t total_agents_registered{0};
        uint64_t total_agents_active{0};
        uint64_t total_intents_queued{0};
        uint64_t total_intents_executed{0};
        uint64_t total_resources_leased{0};
        uint64_t total_beacons_emitted{0};
        
        double avg_intent_queue_time_ms{0.0};
        double avg_resource_wait_time_ms{0.0};
    };
    KernelStats GetStats() const;
    
    // Emergency
    void EmergencyStop(const std::string& reason);
    void EmergencyReleaseAllResources();
    void KillAllAgents();
    
private:
    SovereignAgentKernel() = default;
    ~SovereignAgentKernel() = default;
    
    SovereignAgentKernel(const SovereignAgentKernel&) = delete;
    SovereignAgentKernel& operator=(const SovereignAgentKernel&) = delete;
    
    // Internal scheduling
    void ProcessIntentQueue();
    void ProcessResourceLeases();
    void CleanupStaleAgents();
    void RouteBeacons();
    
    // State
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> next_agent_id_{1};
    std::atomic<uint64_t> next_lease_id_{1};
    std::atomic<uint64_t> next_intent_id_{1};
    std::atomic<uint64_t> next_event_id_{1};
    std::atomic<uint64_t> next_subscription_id_{1};
    
    // Agent registry
    std::unordered_map<uint64_t, std::unique_ptr<AgentRegistration>> agents_;
    mutable std::shared_mutex agents_mutex_;
    
    // Resource leases
    std::unordered_map<uint64_t, std::unique_ptr<ResourceLease>> leases_;
    std::unordered_map<ResourceType, std::vector<uint64_t>> resource_allocations_;
    mutable std::shared_mutex leases_mutex_;
    
    // Intent queue (priority queue)
    std::priority_queue<IntentQueueEntry> intent_queue_;
    std::unordered_map<uint64_t, IntentQueueEntry> intent_map_;
    mutable std::mutex intent_mutex_;
    std::condition_variable intent_cv_;
    
    // Beacon system
    std::unordered_map<uint64_t, std::pair<BeaconType, BeaconCallback>> beacon_subscribers_;
    std::queue<BeaconEvent> beacon_queue_;
    mutable std::mutex beacon_mutex_;
    std::condition_variable beacon_cv_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    KernelStats stats_;
    
    // Scheduler thread
    std::unique_ptr<std::thread> scheduler_thread_;
};

// ============================================================================
// CONVENIENCE MACROS
// ============================================================================

#define RAWR_KERNEL_INIT() \
    RawrXD::Kernel::SovereignAgentKernel::Instance().Initialize()

#define RAWR_KERNEL_SHUTDOWN() \
    RawrXD::Kernel::SovereignAgentKernel::Instance().Shutdown()

#define RAWR_REGISTER_AGENT(name, backend, caps) \
    RawrXD::Kernel::SovereignAgentKernel::Instance().RegisterAgent(name, backend, caps)

#define RAWR_ACQUIRE_RESOURCE(agent_id, type, duration) \
    RawrXD::Kernel::SovereignAgentKernel::Instance().AcquireResource(agent_id, type, duration)

#define RAWR_QUEUE_INTENT(intent, agent_id, priority) \
    RawrXD::Kernel::SovereignAgentKernel::Instance().QueueIntent(intent, agent_id, priority)

#define RAWR_EMIT_BEACON(type, agent_id) \
    RawrXD::Kernel::SovereignAgentKernel::Instance().EmitBeacon(type, agent_id)

} // namespace Kernel
} // namespace RawrXD
