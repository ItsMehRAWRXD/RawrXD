// =============================================================================
// sovereign_swarm_node.cpp
// Phase 23A: Swarm Networking Implementation
// ZeroMQ-based hybrid broker + P2P architecture
// =============================================================================

#include "sovereign_swarm_node.h"
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cassert.h>
#include <chrono>
#include <math.h>

// ZeroMQ includes (would need zmq.h in actual build)
// For now, we create the structure that will use ZMQ

// =============================================================================
// Internal Structures
// =============================================================================

struct SwarmContext {
    swarm_config_t config;
    void* zmq_context;  // zmq_ctx_t*
    int is_initialized;
};

struct SwarmNode {
    SwarmContext* ctx;
    swarm_node_config_t config;
    
    // ZeroMQ sockets
    void* dealer_socket;    // For async messaging
    void* router_socket;    // Head only: accept workers
    void* pair_prev;        // Ring: previous node
    void* pair_next;        // Ring: next node
    void* req_socket;       // For synchronous requests
    void* sub_socket;       // For broadcasts
    void* pub_socket;       // Head only: broadcast
    
    // State
    int is_connected;
    int is_running;
    uint64_t sequence_counter;
    
    // Statistics
    uint64_t msgs_sent;
    uint64_t msgs_recv;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    double total_latency_ms;
    uint64_t latency_samples;
    
    // Callbacks
    struct {
        swarm_msg_callback_t msg_cb[256];  // One per message type
        void* msg_user_data[256];
        swarm_error_callback_t error_cb;
        void* error_user_data;
        swarm_heartbeat_callback_t heartbeat_cb;
        void* heartbeat_user_data;
    } callbacks;
    
    // Threading
    void* event_thread;
    int stop_event_loop;
};

// =============================================================================
// CRC32 Implementation
// =============================================================================

static const uint32_t CRC32_TABLE[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

SOVEREIGN_API uint32_t swarm_crc32(const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < len; i++) {
        crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }
    
    return crc ^ 0xFFFFFFFF;
}

// =============================================================================
// Context Management
// =============================================================================

SOVEREIGN_API swarm_context_t swarm_context_create(const swarm_config_t* config) {
    if (!config) return nullptr;
    
    auto* ctx = new SwarmContext();
    ctx->config = *config;
    ctx->is_initialized = 1;
    ctx->zmq_context = nullptr;  // Would call zmq_ctx_new()
    
    return reinterpret_cast<swarm_context_t>(ctx);
}

SOVEREIGN_API void swarm_context_destroy(swarm_context_t ctx) {
    if (!ctx) return;
    
    auto* c = reinterpret_cast<SwarmContext*>(ctx);
    // Would call zmq_ctx_term(c->zmq_context);
    delete c;
}

// =============================================================================
// Node Management
// =============================================================================

SOVEREIGN_API swarm_node_t swarm_node_create(
    swarm_context_t ctx,
    const swarm_node_config_t* config) {
    
    if (!ctx || !config) return nullptr;
    
    auto* node = new SwarmNode();
    node->ctx = reinterpret_cast<SwarmContext*>(ctx);
    node->config = *config;
    node->is_connected = 0;
    node->is_running = 0;
    node->sequence_counter = 0;
    node->msgs_sent = 0;
    node->msgs_recv = 0;
    node->bytes_sent = 0;
    node->bytes_recv = 0;
    node->total_latency_ms = 0;
    node->latency_samples = 0;
    node->stop_event_loop = 0;
    
    // Initialize callbacks
    memset(&node->callbacks, 0, sizeof(node->callbacks));
    
    // Would create ZMQ sockets here
    node->dealer_socket = nullptr;
    node->router_socket = nullptr;
    node->pair_prev = nullptr;
    node->pair_next = nullptr;
    node->req_socket = nullptr;
    node->sub_socket = nullptr;
    node->pub_socket = nullptr;
    
    return reinterpret_cast<swarm_node_t>(node);
}

SOVEREIGN_API void swarm_node_destroy(swarm_node_t node) {
    if (!node) return;
    
    auto* n = reinterpret_cast<SwarmNode*>(node);
    
    // Stop event loop
    n->stop_event_loop = 1;
    
    // Would close ZMQ sockets here
    // zmq_close(n->dealer_socket);
    // etc.
    
    delete n;
}

// =============================================================================
// Connection Management
// =============================================================================

SOVEREIGN_API int swarm_node_connect(swarm_node_t node, const char* endpoint) {
    if (!node || !endpoint) return -1;
    
    auto* n = reinterpret_cast<SwarmNode*>(node);
    
    // Would connect ZMQ socket
    // zmq_connect(n->dealer_socket, endpoint);
    
    n->is_connected = 1;
    return 0;
}

SOVEREIGN_API int swarm_node_disconnect(swarm_node_t node) {
    if (!node) return -1;
    
    auto* n = reinterpret_cast<SwarmNode*>(node);
    n->is_connected = 0;
    return 0;
}

SOVEREIGN_API int swarm_node_is_connected(swarm_node_t node) {
    if (!node) return 0;
    auto* n = reinterpret_cast<SwarmNode*>(node);
    return n->is_connected;
}

// =============================================================================
// Head Operations
// =============================================================================

SOVEREIGN_API int swarm_head_start(swarm_node_t head, uint16_t port) {
    if (!head) return -1;
    
    auto* n = reinterpret_cast<SwarmNode*>(head);
    if (n->config.type != SWARM_NODE_HEAD) return -1;
    
    // Would bind router socket
    // char endpoint[256];
    // snprintf(endpoint, sizeof(endpoint), "tcp://*:%d", port);
    // zmq_bind(n->router_socket, endpoint);
    // zmq_bind(n->pub_socket, endpoint + 1);  // port + 1 for pub
    
    return 0;
}

SOVEREIGN_API int swarm_head_broadcast(
    swarm_node_t head,
    swarm_msg_type_t type,
    const void* payload,
    size_t payload_len) {
    
    if (!head) return -1;
    
    auto* n = reinterpret_cast<SwarmNode*>(head);
    if (n->config.type != SWARM_NODE_HEAD) return -1;
    
    // Would send via pub socket
    // zmq_send(n->pub_socket, header, sizeof(header), ZMQ_SNDMORE);
    // zmq_send(n->pub_socket, payload, payload_len, 0);
    
    n->msgs_sent++;
    n->bytes_sent += payload_len + sizeof(swarm_msg_header_t);
    
    return 0;
}

// =============================================================================
// Worker Operations
// =============================================================================

SOVEREIGN_API int swarm_worker_join(
    swarm_node_t worker,
    const char* head_endpoint) {
    
    if (!worker || !head_endpoint) return -1;
    
    auto* n = reinterpret_cast<SwarmNode*>(worker);
    if (n->config.type != SWARM_NODE_WORKER) return -1;
    
    // Would connect to head
    // zmq_connect(n->dealer_socket, head_endpoint);
    
    // Send JOIN message
    swarm_msg_header_t header = {};
    header.magic = SWARM_MAGIC;
    header.version = SWARM_PROTOCOL_VERSION;
    header.msg_type = MSG_JOIN;
    header.sequence_id = ++n->sequence_counter;
    header.timestamp_ns = 0;  // Would get actual timestamp
    header.payload_len = sizeof(swarm_node_config_t);
    header.checksum = swarm_crc32(&n->config, sizeof(n->config));
    
    // Would send
    // zmq_send(n->dealer_socket, &header, sizeof(header), ZMQ_SNDMORE);
    // zmq_send(n->dealer_socket, &n->config, sizeof(n->config), 0);
    
    return 0;
}

SOVEREIGN_API int swarm_worker_leave(swarm_node_t worker) {
    if (!worker) return -1;
    
    auto* n = reinterpret_cast<SwarmNode*>(worker);
    
    // Send LEAVE message
    // ...
    
    return swarm_node_disconnect(worker);
}

// =============================================================================
// Messaging
// =============================================================================

SOVEREIGN_API int swarm_send(
    swarm_node_t sender,
    swarm_node_t recipient,
    swarm_msg_type_t type,
    const void* payload,
    size_t payload_len) {
    
    if (!sender) return -1;
    
    auto* n = reinterpret_cast<SwarmNode*>(sender);
    
    // Build header
    swarm_msg_header_t header = {};
    header.magic = SWARM_MAGIC;
    header.version = SWARM_PROTOCOL_VERSION;
    header.msg_type = type;
    header.sequence_id = ++n->sequence_counter;
    header.timestamp_ns = 0;  // Would get actual timestamp
    header.payload_len = (uint32_t)payload_len;
    header.checksum = payload ? swarm_crc32(payload, payload_len) : 0;
    
    // Would send via dealer socket
    // zmq_send(n->dealer_socket, &header, sizeof(header), ZMQ_SNDMORE);
    // zmq_send(n->dealer_socket, payload, payload_len, 0);
    
    n->msgs_sent++;
    n->bytes_sent += payload_len + sizeof(header);
    
    return 0;
}

SOVEREIGN_API int swarm_validate_header(const swarm_msg_header_t* header) {
    if (!header) return -1;
    
    if (header->magic != SWARM_MAGIC) return -1;
    if (header->version != SWARM_PROTOCOL_VERSION) return -1;
    if (header->payload_len > 1024 * 1024 * 1024) return -1;  // Max 1GB
    
    return 0;
}

// =============================================================================
// Statistics
// =============================================================================

SOVEREIGN_API int swarm_get_node_stats(
    swarm_node_t node,
    uint64_t* msgs_sent,
    uint64_t* msgs_recv,
    uint64_t* bytes_sent,
    uint64_t* bytes_recv,
    double* avg_latency_ms) {
    
    if (!node) return -1;
    
    auto* n = reinterpret_cast<SwarmNode*>(node);
    
    if (msgs_sent) *msgs_sent = n->msgs_sent;
    if (msgs_recv) *msgs_recv = n->msgs_recv;
    if (bytes_sent) *bytes_sent = n->bytes_sent;
    if (bytes_recv) *bytes_recv = n->bytes_recv;
    if (avg_latency_ms) {
        *avg_latency_ms = (n->latency_samples > 0) 
            ? n->total_latency_ms / n->latency_samples 
            : 0.0;
    }
    
    return 0;
}

// =============================================================================
// Utilities
// =============================================================================

SOVEREIGN_API void swarm_print_message(const swarm_msg_header_t* header) {
    if (!header) return;
    
    printf("Swarm Message:\n");
    printf("  Magic: 0x%08X (%s)\n", header->magic, 
           header->magic == SWARM_MAGIC ? "VALID" : "INVALID");
    printf("  Version: 0x%04X\n", header->version);
    printf("  Type: 0x%04X\n", header->msg_type);
    printf("  Sequence: %llu\n", (unsigned long long)header->sequence_id);
    printf("  Payload: %u bytes\n", header->payload_len);
    printf("  Checksum: 0x%08X\n", header->checksum);
}
