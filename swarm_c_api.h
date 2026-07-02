// swarm_c_api.h
// C API for Phase 23 Distributed Swarm
// Network-aware orchestration for heterogeneous compute clusters
//
// Version: 1.0.0-Draft
// Date: 2026-06-30
// Status: Architecture Phase (Pending 24h Soak Validation)

#ifndef SWARM_C_API_H
#define SWARM_C_API_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Version Information
// =============================================================================

#define SWARM_API_VERSION_MAJOR 1
#define SWARM_API_VERSION_MINOR 0
#define SWARM_API_VERSION_PATCH 0

// =============================================================================
// Opaque Handles
// =============================================================================

typedef struct SwarmContext* SwarmHandle;
typedef struct SwarmNode* NodeHandle;
typedef struct SwarmSession* SessionHandle;
typedef struct SwarmShard* ShardHandle;

// =============================================================================
// Error Codes (Explicit, No Exceptions)
// =============================================================================

typedef enum {
    SWARM_OK = 0,
    SWARM_ERROR_NETWORK = -1,
    SWARM_ERROR_NODE_UNAVAILABLE = -2,
    SWARM_ERROR_TIMEOUT = -3,
    SWARM_ERROR_INVALID_CONTEXT = -4,
    SWARM_ERROR_SHARDING_FAILED = -5,
    SWARM_ERROR_MEMORY = -6,
    SWARM_ERROR_AUTHENTICATION = -7,
    SWARM_ERROR_QUOTA_EXCEEDED = -8,
    SWARM_ERROR_RING_BROKEN = -9,
    SWARM_ERROR_PARTITION = -10
} SwarmError;

// =============================================================================
// Hardware Types
// =============================================================================

typedef enum {
    HARDWARE_CPU_GENERIC = 1,
    HARDWARE_CPU_AVX2 = 2,
    HARDWARE_CPU_AVX512 = 3,
    HARDWARE_AMX_TILE = 4,
    HARDWARE_GPU_CUDA = 5,
    HARDWARE_GPU_VULKAN = 6,
    HARDWARE_NPU = 7,
    HARDWARE_REMOTE = 8
} HardwareType;

// =============================================================================
// Node Status
// =============================================================================

typedef enum {
    NODE_STATUS_HEALTHY = 0,
    NODE_STATUS_DEGRADED = 1,
    NODE_STATUS_OVERLOADED = 2,
    NODE_STATUS_SUSPECTED = 3,  // Phi accrual detected
    NODE_STATUS_FAILED = 4
} NodeStatus;

// =============================================================================
// Sharding Strategies
// =============================================================================

typedef enum {
    SHARDING_RING = 0,           // Recommended: O(1) communication
    SHARDING_SLIDING_WINDOW = 1,   // For temporal locality
    SHARDING_BLOCK = 2,          // Simple partitioning
    SHARDING_HASH = 3            // Content-based distribution
} ShardingStrategy;

// =============================================================================
// Configuration Structures
// =============================================================================

// Network address (IP:port)
typedef struct {
    char host[256];      // IP address or hostname
    uint16_t port;       // TCP/UDP port
    bool use_tls;        // Enable TLS 1.3
} SwarmAddress;

// Node configuration
typedef struct {
    const char* node_id;              // Unique identifier (UUID)
    SwarmAddress address;              // Network endpoint
    uint32_t context_capacity;         // Tokens this node can hold
    HardwareType hardware;             // AMX, AVX512, GPU, etc.
    uint32_t priority;                 // Lower = preferred for routing
    uint32_t replication_factor;       // Copies of data to maintain
} NodeConfig;

// Swarm configuration
typedef struct {
    const char* swarm_id;              // Unique swarm identifier
    uint32_t replication_factor;       // Default copies per shard
    uint32_t heartbeat_interval_ms;    // Default: 100ms
    uint32_t heartbeat_timeout_ms;     // Default: 500ms
    float phi_threshold;               // Failure detection (default: 8.0)
    ShardingStrategy sharding;         // Context distribution strategy
    bool enable_encryption;            // TLS for all traffic
    const char* cert_path;             // Certificate file path
    const char* key_path;              // Private key file path
} SwarmConfig;

// Session configuration
typedef struct {
    const char* session_id;            // Unique session identifier
    uint32_t max_context_tokens;       // Maximum context window
    float temperature;                 // Sampling temperature
    uint32_t top_k;                    // Top-k sampling
    float top_p;                       // Nucleus sampling
    bool stream_output;                // Enable streaming
} SessionConfig;

// =============================================================================
// Status Structures
// =============================================================================

// Node statistics
typedef struct {
    NodeStatus status;
    float current_tps;                 // Actual throughput
    float latency_p50_ms;              // P50 latency
    float latency_p99_ms;              // P99 latency
    uint32_t memory_usage_percent;     // 0-100
    uint32_t active_sessions;          // Current load
    uint64_t tokens_processed_total;
    uint64_t bytes_received;
    uint64_t bytes_sent;
    float phi_score;                     // Current phi accrual value
} NodeStats;

// Swarm statistics
typedef struct {
    uint32_t total_nodes;
    uint32_t healthy_nodes;
    uint32_t degraded_nodes;
    uint32_t suspected_nodes;
    uint32_t failed_nodes;
    float aggregate_tps;
    float average_latency_ms;
    uint64_t total_tokens_processed;
    uint64_t total_sessions;
    uint32_t active_shards;
} SwarmStats;

// Context shard information
typedef struct {
    uint32_t shard_id;
    uint32_t start_token;              // Inclusive
    uint32_t end_token;                // Exclusive
    NodeHandle primary_node;
    NodeHandle* replica_nodes;         // Array of replicas
    uint32_t replica_count;
    uint64_t last_access_time;         // For LRU eviction
    uint32_t access_count;             // For popularity tracking
} ShardInfo;

// =============================================================================
// Callback Types
// =============================================================================

// Inference completion callback
typedef void (*InferenceCallback)(
    SwarmError error,
    const float* output,
    uint32_t output_size,
    uint32_t tokens_generated,
    void* user_data
);

// Ring attention handoff callback
typedef void (*RingHandoffCallback)(
    uint32_t from_node_id,
    uint32_t to_node_id,
    const void* kv_cache_data,
    uint32_t kv_cache_size,
    void* user_data
);

// Node status change callback
typedef void (*NodeStatusCallback)(
    NodeHandle node,
    NodeStatus old_status,
    NodeStatus new_status,
    void* user_data
);

// Heartbeat received callback
typedef void (*HeartbeatCallback)(
    NodeHandle node,
    const NodeStats* stats,
    void* user_data
);

// =============================================================================
// Lifecycle Functions
// =============================================================================

// Create a new swarm context
// Returns SWARM_OK on success, error code otherwise
SwarmError Swarm_Create(const SwarmConfig* config, SwarmHandle* out_handle);

// Destroy swarm context and release all resources
// Blocks until all pending operations complete
SwarmError Swarm_Destroy(SwarmHandle handle);

// Get API version string
const char* Swarm_GetVersion(void);

// Get last error message for detailed diagnostics
const char* Swarm_GetLastError(void);

// =============================================================================
// Node Management
// =============================================================================

// Join a node to the swarm
// Node must be reachable via network
SwarmError Swarm_Join(SwarmHandle swarm, const NodeConfig* config, 
                       NodeHandle* out_node);

// Gracefully leave the swarm
// Transfers ownership of shards to other nodes
SwarmError Swarm_Leave(SwarmHandle swarm, NodeHandle node);

// Force remove a failed node
// Use only after node is confirmed dead
SwarmError Swarm_Remove(SwarmHandle swarm, NodeHandle node);

// Get node by ID
SwarmError Swarm_GetNodeById(SwarmHandle swarm, const char* node_id,
                              NodeHandle* out_node);

// Get all nodes in swarm
// out_nodes must be pre-allocated by caller
SwarmError Swarm_GetAllNodes(SwarmHandle swarm, NodeHandle* out_nodes,
                                uint32_t max_nodes, uint32_t* out_count);

// Get node statistics
SwarmError Swarm_GetNodeStats(NodeHandle node, NodeStats* out_stats);

// Subscribe to node status changes
SwarmError Swarm_SetNodeStatusCallback(SwarmHandle swarm,
                                        NodeStatusCallback callback,
                                        void* user_data);

// =============================================================================
// Session Management
// =============================================================================

// Create inference session
SwarmError Swarm_CreateSession(SwarmHandle swarm, const SessionConfig* config,
                                SessionHandle* out_session);

// Destroy session and free resources
SwarmError Swarm_DestroySession(SessionHandle session);

// Get session statistics
SwarmError Swarm_GetSessionStats(SessionHandle session, 
                                  uint32_t* out_tokens_used,
                                  uint32_t* out_tokens_remaining);

// =============================================================================
// Context Sharding
// =============================================================================

// Create a shard for token range
SwarmError Swarm_CreateShard(SwarmHandle swarm, uint32_t start_token,
                              uint32_t end_token, ShardHandle* out_shard);

// Get shard containing specific token
SwarmError Swarm_GetShardForToken(SwarmHandle swarm, uint32_t token_index,
                                   ShardHandle* out_shard);

// Get shard information
SwarmError Swarm_GetShardInfo(ShardHandle shard, ShardInfo* out_info);

// Rebalance shards across nodes
// Triggered automatically or manually
SwarmError Swarm_RebalanceShards(SwarmHandle swarm);

// Configure ring attention handoff
SwarmError Swarm_ConfigureRingAttention(SwarmHandle swarm,
                                         RingHandoffCallback callback,
                                         void* user_data);

// Pass KV-cache to next node in ring
SwarmError Swarm_PassKVCache(SwarmHandle swarm, uint32_t to_node_id,
                              const void* kv_cache_data, uint32_t kv_cache_size);

// =============================================================================
// Distributed Inference
// =============================================================================

// Run inference asynchronously (non-blocking)
// Callback invoked on completion or error
SwarmError Swarm_RunInferenceAsync(SwarmHandle swarm, SessionHandle session,
                                    const float* input, uint32_t input_size,
                                    float* output, uint32_t output_size,
                                    InferenceCallback callback, void* user_data);

// Run inference synchronously (blocking)
// Returns when complete or timeout
SwarmError Swarm_RunInferenceSync(SwarmHandle swarm, SessionHandle session,
                                     const float* input, uint32_t input_size,
                                     float* output, uint32_t output_size,
                                     uint32_t* out_tokens_generated,
                                     uint32_t timeout_ms);

// Cancel pending inference
SwarmError Swarm_CancelInference(SessionHandle session);

// Get optimal node for layer type (extends Phase 22 cost model)
SwarmError Swarm_GetOptimalNode(SwarmHandle swarm, uint32_t layer_id,
                                 NodeHandle* out_node);

// =============================================================================
// Telemetry & Monitoring
// =============================================================================

// Get swarm statistics
SwarmError Swarm_GetStats(SwarmHandle swarm, SwarmStats* out_stats);

// Subscribe to heartbeat events
SwarmError Swarm_SetHeartbeatCallback(SwarmHandle swarm,
                                       HeartbeatCallback callback,
                                       void* user_data);

// Enable detailed telemetry logging
SwarmError Swarm_EnableTelemetry(SwarmHandle swarm, const char* log_path);

// Disable telemetry
SwarmError Swarm_DisableTelemetry(SwarmHandle swarm);

// =============================================================================
// Fault Tolerance
// =============================================================================

// Configure automatic failover
SwarmError Swarm_ConfigureFailover(SwarmHandle swarm, bool enable,
                                    uint32_t max_retries);

// Manually trigger shard recovery after node failure
SwarmError Swarm_RecoverShard(SwarmHandle swarm, ShardHandle shard);

// Check if swarm can tolerate N failures
SwarmError Swarm_CheckResilience(SwarmHandle swarm, uint32_t failure_count,
                                  bool* out_can_tolerate);

// Enter emergency mode (single-node fallback)
SwarmError Swarm_EnterEmergencyMode(SwarmHandle swarm, NodeHandle fallback_node);

// Exit emergency mode and resume distributed operation
SwarmError Swarm_ExitEmergencyMode(SwarmHandle swarm);

// =============================================================================
// Utility Functions
// =============================================================================

// Convert error code to string
const char* Swarm_ErrorToString(SwarmError error);

// Convert hardware type to string
const char* Swarm_HardwareToString(HardwareType hardware);

// Convert status to string
const char* Swarm_StatusToString(NodeStatus status);

// Get current time in nanoseconds (for timestamps)
uint64_t Swarm_GetTimestampNs(void);

// Calculate phi score for failure detection
float Swarm_CalculatePhi(uint64_t last_heartbeat_ns, 
                          float mean_interval_ms,
                          float variance_ms);

#ifdef __cplusplus
}
#endif

#endif // SWARM_C_API_H