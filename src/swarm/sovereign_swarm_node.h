// =============================================================================
// sovereign_swarm_node.h
// Phase 23A: Swarm Networking Layer
// Hybrid broker-based + P2P architecture
// =============================================================================

#ifndef SOVEREIGN_SWARM_NODE_H
#define SOVEREIGN_SWARM_NODE_H

#include "../bindings/sovereign_c_api.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Version & Constants
// =============================================================================

#define SWARM_PROTOCOL_VERSION 0x0100  // 1.0
#define SWARM_MAGIC 0x5357524D         // 'SWRM'

// Default ports
#define SWARM_HEAD_PORT 5555
#define SWARM_WORKER_BASE_PORT 5556
#define SWARM_RING_PORT_BASE 6000

// Timeouts (milliseconds)
#define SWARM_HEARTBEAT_INTERVAL_MS 1000
#define SWARM_HEARTBEAT_TIMEOUT_MS 3000
#define SWARM_CONNECT_TIMEOUT_MS 5000
#define SWARM_REQUEST_TIMEOUT_MS 30000

// =============================================================================
// Opaque Handles
// =============================================================================

typedef struct SwarmNode* swarm_node_t;
typedef struct SwarmContext* swarm_context_t;
typedef struct SwarmMessage* swarm_message_t;

// =============================================================================
// Node Types
// =============================================================================

typedef enum {
    SWARM_NODE_HEAD = 0x01,      // Orchestrator
    SWARM_NODE_WORKER = 0x02,   // Compute worker
    SWARM_NODE_EDGE = 0x03,    // Speculative edge
    SWARM_NODE_RELAY = 0x04    // Message relay (optional)
} swarm_node_type_t;

// =============================================================================
// Message Types (Binary Protocol)
// =============================================================================

typedef enum {
    // Control (0x01-0x0F)
    MSG_HEARTBEAT = 0x01,
    MSG_HEARTBEAT_ACK = 0x02,
    MSG_JOIN = 0x03,
    MSG_JOIN_ACK = 0x04,
    MSG_LEAVE = 0x05,
    MSG_ELECTION = 0x06,
    MSG_ELECTION_VOTE = 0x07,
    MSG_ELECTION_RESULT = 0x08,
    
    // Configuration (0x10-0x1F)
    MSG_MODEL_CONFIG = 0x10,
    MSG_LAYER_ASSIGN = 0x11,
    MSG_TOPOLOGY_UPDATE = 0x12,
    
    // Inference (0x20-0x2F)
    MSG_INFERENCE_REQ = 0x20,
    MSG_INFERENCE_RESP = 0x21,
    MSG_ACTIVATION_FWD = 0x22,
    MSG_ACTIVATION_BWD = 0x23,
    
    // KV Cache (0x30-0x3F)
    MSG_KV_CACHE_RING = 0x30,    // Ring attention pass
    MSG_KV_CACHE_REQ = 0x31,
    MSG_KV_CACHE_RESP = 0x32,
    
    // Speculative (0x40-0x4F)
    MSG_SPEC_DRAFT = 0x40,
    MSG_SPEC_VERIFY = 0x41,
    MSG_SPEC_ACCEPT = 0x42,
    
    // Error (0xF0-0xFF)
    MSG_ERROR = 0xF0,
    MSG_SHUTDOWN = 0xFF
} swarm_msg_type_t;

// =============================================================================
// Message Header (16 bytes, packed)
// =============================================================================

typedef struct __attribute__((packed)) {
    uint32_t magic;              // 0x5357524D
    uint16_t version;          // Protocol version
    uint16_t msg_type;         // Message type
    uint64_t sequence_id;      // Unique message ID
    uint64_t timestamp_ns;     // Nanosecond timestamp
    uint32_t payload_len;      // Payload size in bytes
    uint32_t checksum;           // CRC32 of payload
} swarm_msg_header_t;

// =============================================================================
// Node Configuration
// =============================================================================

typedef struct {
    char node_id[64];            // Unique node identifier
    swarm_node_type_t type;      // Node type
    char address[256];           // IP:port
    uint32_t num_gpus;           // Available GPUs
    uint64_t memory_bytes;       // Available memory
    uint32_t max_layers;         // Max layers this node can handle
    uint32_t* layer_range;       // Assigned layer range [start, end]
    uint32_t layer_count;        // Number of layers in range
} swarm_node_config_t;

// =============================================================================
// Swarm Configuration
// =============================================================================

typedef struct {
    char swarm_name[128];
    uint32_t num_workers;
    uint32_t num_edge_nodes;
    int enable_speculative;
    int enable_ring_attention;
    int use_rdma;                // Use RDMA if available
    int use_compression;         // Compress KV cache transfers
    float compression_ratio;     // Target compression ratio
} swarm_config_t;

// =============================================================================
// Callbacks
// =============================================================================

typedef void (*swarm_msg_callback_t)(
    swarm_node_t sender,
    swarm_msg_type_t type,
    const void* payload,
    size_t payload_len,
    void* user_data);

typedef void (*swarm_error_callback_t)(
    swarm_node_t node,
    int error_code,
    const char* error_msg,
    void* user_data);

typedef void (*swarm_heartbeat_callback_t)(
    swarm_node_t node,
    int is_alive,
    double latency_ms,
    void* user_data);

// =============================================================================
// Lifecycle
// =============================================================================

SOVEREIGN_API swarm_context_t swarm_context_create(const swarm_config_t* config);
SOVEREIGN_API void swarm_context_destroy(swarm_context_t ctx);

SOVEREIGN_API swarm_node_t swarm_node_create(
    swarm_context_t ctx,
    const swarm_node_config_t* config);
SOVEREIGN_API void swarm_node_destroy(swarm_node_t node);

// =============================================================================
// Connection Management
// =============================================================================

SOVEREIGN_API int swarm_node_connect(
    swarm_node_t node,
    const char* endpoint);
SOVEREIGN_API int swarm_node_disconnect(swarm_node_t node);
SOVEREIGN_API int swarm_node_is_connected(swarm_node_t node);

// Head-specific
SOVEREIGN_API int swarm_head_start(swarm_node_t head, uint16_t port);
SOVEREIGN_API int swarm_head_accept_worker(swarm_node_t head, swarm_node_t* worker);
SOVEREIGN_API int swarm_head_broadcast(
    swarm_node_t head,
    swarm_msg_type_t type,
    const void* payload,
    size_t payload_len);

// Worker-specific
SOVEREIGN_API int swarm_worker_join(
    swarm_node_t worker,
    const char* head_endpoint);
SOVEREIGN_API int swarm_worker_leave(swarm_node_t worker);

// =============================================================================
// Messaging
// =============================================================================

SOVEREIGN_API int swarm_send(
    swarm_node_t sender,
    swarm_node_t recipient,
    swarm_msg_type_t type,
    const void* payload,
    size_t payload_len);

SOVEREIGN_API int swarm_send_async(
    swarm_node_t sender,
    swarm_node_t recipient,
    swarm_msg_type_t type,
    const void* payload,
    size_t payload_len);

SOVEREIGN_API int swarm_recv(
    swarm_node_t node,
    swarm_msg_header_t* header,
    void** payload,
    size_t* payload_len,
    int timeout_ms);

// =============================================================================
// Ring Operations (P2P)
// =============================================================================

SOVEREIGN_API int swarm_ring_connect(
    swarm_node_t node,
    const char* prev_endpoint,
    const char* next_endpoint);

SOVEREIGN_API int swarm_ring_pass_kv_cache(
    swarm_node_t node,
    const void* kv_data,
    size_t data_len,
    uint32_t seq_start,
    uint32_t seq_end);

SOVEREIGN_API int swarm_ring_recv_kv_cache(
    swarm_node_t node,
    void** kv_data,
    size_t* data_len,
    uint32_t* seq_start,
    uint32_t* seq_end,
    int timeout_ms);

// =============================================================================
// Speculative Decoding (Edge-Head)
// =============================================================================

SOVEREIGN_API int swarm_edge_submit_draft(
    swarm_node_t edge,
    const uint32_t* draft_tokens,
    uint32_t num_tokens,
    float* probabilities);

SOVEREIGN_API int swarm_head_verify_draft(
    swarm_node_t head,
    const uint32_t* draft_tokens,
    uint32_t num_tokens,
    uint32_t* verified_tokens,
    uint32_t* num_verified);

// =============================================================================
// Event Loop & Callbacks
// =============================================================================

SOVEREIGN_API int swarm_node_start_event_loop(swarm_node_t node);
SOVEREIGN_API int swarm_node_stop_event_loop(swarm_node_t node);

SOVEREIGN_API int swarm_node_set_msg_callback(
    swarm_node_t node,
    swarm_msg_type_t type,
    swarm_msg_callback_t callback,
    void* user_data);

SOVEREIGN_API int swarm_node_set_error_callback(
    swarm_node_t node,
    swarm_error_callback_t callback,
    void* user_data);

SOVEREIGN_API int swarm_node_set_heartbeat_callback(
    swarm_node_t node,
    swarm_heartbeat_callback_t callback,
    void* user_data);

// =============================================================================
// Leader Election
// =============================================================================

SOVEREIGN_API int swarm_start_election(swarm_node_t node);
SOVEREIGN_API int swarm_vote_for(swarm_node_t node, const char* candidate_id);
SOVEREIGN_API int swarm_become_head(swarm_node_t node);

// =============================================================================
// Utilities
// =============================================================================

SOVEREIGN_API uint32_t swarm_crc32(const void* data, size_t len);
SOVEREIGN_API int swarm_validate_header(const swarm_msg_header_t* header);
SOVEREIGN_API void swarm_print_message(const swarm_msg_header_t* header);

SOVEREIGN_API int swarm_get_node_stats(
    swarm_node_t node,
    uint64_t* msgs_sent,
    uint64_t* msgs_recv,
    uint64_t* bytes_sent,
    uint64_t* bytes_recv,
    double* avg_latency_ms);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_SWARM_NODE_H
