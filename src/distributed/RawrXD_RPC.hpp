#pragma once
#include <cstdint>
#include <cstring>
#include <vector>

namespace RawrXD {
namespace Distributed {

// Command enum for type-safe handler registration
enum class RawrCommand : uint16_t {
    // Phase 1: Swarm Discovery & Heartbeat
    CMD_NODE_DISCOVER       = 0x01,
    CMD_NODE_ACKNOWLEDGE    = 0x02,
    CMD_HEARTBEAT_PING      = 0x03,
    CMD_HEARTBEAT_PONG      = 0x04,
    CMD_RING_RECONFIGURE    = 0x05,
    
    // Phase 2: Orchestration & Batching
    CMD_INFERENCE_REQ       = 0x11,
    CMD_INFERENCE_ACK       = 0x12,
    CMD_KV_CACHE_SYNC       = 0x13,
    CMD_EXPERT_ROUTE_REQ    = 0x14,
    CMD_EXPERT_ROUTE_ACK    = 0x15,
    
    // Phase 3: Tensor Transport
    CMD_TENSOR_XFER_START   = 0x21,
    CMD_TENSOR_XFER_CHUNK   = 0x22,
    CMD_TENSOR_XFER_FINISH  = 0x23,
    CMD_ALL_REDUCE_PARTIAL  = 0x24,
    CMD_ALL_REDUCE_COMPLETE = 0x25,
    CMD_ALL_GATHER_REQ      = 0x26,
    CMD_WEIGHT_HOTPATCH     = 0x27,
    CMD_SYNC_BARRIER_ENTER  = 0x28,
    CMD_SYNC_BARRIER_RELEASE= 0x29,
    CMD_PANIC_ABORT         = 0x2A,
    
    // Extended commands for handler framework
    CMD_NODE_ANNOUNCE       = 0x31,
    CMD_TOPOLOGY_SYNC       = 0x32,
    CMD_INFERENCE_REQUEST   = 0x33,
    CMD_INFERENCE_RESPONSE  = 0x34,
    CMD_INFERENCE_STREAM    = 0x35,
    CMD_INFERENCE_CANCEL    = 0x36,
    CMD_LOAD_BALANCE        = 0x37,
    CMD_TENSOR_SHARD        = 0x38,
    CMD_KVCACHE_OFFLOAD     = 0x39,
    CMD_KVCACHE_FETCH       = 0x3A,
    CMD_ALLGATHER_TENSORS   = 0x3B,
    CMD_ALLREDUCE_GRADIENTS = 0x3C,
    CMD_CHECKPOINT_SAVE     = 0x3D,
    CMD_CHECKPOINT_LOAD     = 0x3E,
    CMD_CONFIG_UPDATE       = 0x3F,
    CMD_METRICS_REPORT      = 0x40
};

// Legacy constants (kept for backward compatibility)
// Phase 1: Swarm Discovery & Heartbeat
constexpr uint32_t CMD_NODE_DISCOVER       = 0x1001;
constexpr uint32_t CMD_NODE_ACKNOWLEDGE    = 0x1002;
constexpr uint32_t CMD_HEARTBEAT_PING      = 0x1003;
constexpr uint32_t CMD_HEARTBEAT_PONG      = 0x1004;
constexpr uint32_t CMD_RING_RECONFIGURE    = 0x1005;

// Phase 2: Orchestration & Batching
constexpr uint32_t CMD_INFERENCE_REQ       = 0x2001;
constexpr uint32_t CMD_INFERENCE_ACK       = 0x2002;
constexpr uint32_t CMD_KV_CACHE_SYNC       = 0x2003;
constexpr uint32_t CMD_EXPERT_ROUTE_REQ    = 0x2004;
constexpr uint32_t CMD_EXPERT_ROUTE_ACK    = 0x2005;

// Phase 3: Tensor Transport (Zero-Copy Data Plane)
constexpr uint32_t CMD_TENSOR_XFER_START   = 0x3001;
constexpr uint32_t CMD_TENSOR_XFER_CHUNK   = 0x3002;
constexpr uint32_t CMD_TENSOR_XFER_FINISH  = 0x3003;
constexpr uint32_t CMD_ALL_REDUCE_PARTIAL  = 0x3004;
constexpr uint32_t CMD_ALL_REDUCE_COMPLETE = 0x3005;
constexpr uint32_t CMD_ALL_GATHER_REQ      = 0x3006;
constexpr uint32_t CMD_WEIGHT_HOTPATCH     = 0x3007;
constexpr uint32_t CMD_SYNC_BARRIER_ENTER  = 0x3008;
constexpr uint32_t CMD_SYNC_BARRIER_RELEASE= 0x3009;
constexpr uint32_t CMD_PANIC_ABORT         = 0x300A;

// Flags for Packet Routing
constexpr uint16_t FLAG_ASYNC     = 0x01; // Fire and forget
constexpr uint16_t FLAG_SYNC      = 0x02; // Requires ACK
constexpr uint16_t FLAG_BARRIER   = 0x04; // Halt execution until ring resolves
constexpr uint16_t FLAG_URGENT    = 0x08; // Bypass standard queue (e.g., Panics)
constexpr uint16_t FLAG_BROADCAST = 0x10; // Broadcast to all nodes
constexpr uint16_t FLAG_MULTICAST = 0x20; // Multicast to ring subset

// Magic constant for packet validation
constexpr uint64_t RAWRXD_MAGIC = 0x5241575258443031ULL; // 'RAWRXD01'

#pragma pack(push, 1) // Strict 1-byte alignment to prevent padding issues across differing compilers/nodes
struct RawrPacketHeader {
    uint64_t magic;      // 'RAWRXD01' - Fast validation
    uint32_t cmd;        // Enum command (e.g., CMD_TENSOR_XFER_CHUNK)
    uint32_t seq;        // Sequence number for UDP packet ordering
    uint32_t len;        // Payload length (tensor chunk size)
    uint16_t flags;      // Bitmask routing instructions
    uint16_t node_id;    // Source node identifier in the ring
};
#pragma pack(pop)

// Validation check to ensure header stays exactly 24 bytes
static_assert(sizeof(RawrPacketHeader) == 24, "RawrPacketHeader must be exactly 24 bytes for IOCP alignment");

// Full packet with payload buffer for received data (max 64KB UDP packet)
struct RawrPacket {
    RawrPacketHeader header;
    std::vector<uint8_t> payload;
    
    // Convenience accessors
    uint64_t magic() const { return header.magic; }
    uint32_t cmd() const { return header.cmd; }
    uint32_t seq() const { return header.seq; }
    uint32_t len() const { return header.len; }
    uint16_t flags() const { return header.flags; }
    uint16_t node_id() const { return header.node_id; }
    
    void set_magic(uint64_t m) { header.magic = m; }
    void set_cmd(uint32_t c) { header.cmd = c; }
    void set_seq(uint32_t s) { header.seq = s; }
    void set_len(uint32_t l) { header.len = l; }
    void set_flags(uint16_t f) { header.flags = f; }
    void set_node_id(uint16_t n) { header.node_id = n; }
    
    bool validate() const { return header.magic == RAWRXD_MAGIC; }
};

// =============================================================================
// Node Information Structure
// =============================================================================
#pragma pack(push, 1)
struct NodeInfo {
    uint16_t node_id;                // 2 bytes - Unique node identifier
    uint16_t status;                 // 2 bytes - Node status flags
    uint32_t ip_address;             // 4 bytes - IPv4 address (network byte order)
    uint16_t data_port;              // 2 bytes - Data plane port
    uint16_t control_port;           // 2 bytes - Control plane port
    uint32_t queue_depth;            // 4 bytes - Current inference queue depth
    uint32_t max_batch_size;         // 4 bytes - Maximum batch size supported
    uint64_t vram_capacity;          // 8 bytes - Available VRAM in bytes
    // Total: 28 bytes so far
    
    // Status flags
    static constexpr uint16_t STATUS_ONLINE = 0x0001;
    static constexpr uint16_t STATUS_BUSY = 0x0002;
    static constexpr uint16_t STATUS_DEGRADED = 0x0004;
    static constexpr uint16_t STATUS_OFFLINE = 0x0008;
    static constexpr uint16_t STATUS_MASTER = 0x8000;
    
    bool isOnline() const { return (status & STATUS_ONLINE) != 0; }
    bool isBusy() const { return (status & STATUS_BUSY) != 0; }
    bool isMaster() const { return (status & STATUS_MASTER) != 0; }
};
static_assert(sizeof(NodeInfo) == 28, "NodeInfo must be 28 bytes");

// =============================================================================
// Payload Structures for Specific Commands
// =============================================================================

// CMD_NODE_DISCOVER / CMD_NODE_ACKNOWLEDGE payload
struct NodeDiscoverPayload {
    NodeInfo node_info;              // 28 bytes
    uint64_t timestamp;              // 8 bytes - Discovery timestamp
    uint32_t capabilities;           // 4 bytes - Feature flags
    uint32_t reserved;               // 4 bytes
    // Total: 44 bytes
};
static_assert(sizeof(NodeDiscoverPayload) == 44, "NodeDiscoverPayload must be 44 bytes");

// CMD_HEARTBEAT_PING / CMD_HEARTBEAT_PONG payload
struct HeartbeatPayload {
    uint64_t timestamp;                // Send timestamp
    uint32_t queue_depth;            // Current queue depth
    uint32_t latency_us;             // Last operation latency
    uint64_t tokens_processed;       // Total tokens processed
    uint64_t vram_available;         // Available VRAM
};
static_assert(sizeof(HeartbeatPayload) == 32, "HeartbeatPayload must be 32 bytes");

// CMD_RING_RECONFIGURE payload
struct RingReconfigurePayload {
    uint16_t master_node;            // New master node ID
    uint16_t node_count;             // Number of nodes in ring
    uint32_t reserved;
    // Followed by array of NodeInfo structures
};
static_assert(sizeof(RingReconfigurePayload) == 8, "RingReconfigurePayload must be 8 bytes");

// CMD_INFERENCE_REQ payload
struct InferenceRequestPayload {
    uint64_t request_id;             // 8 bytes - Unique request ID
    uint32_t batch_size;             // 4 bytes - Number of sequences
    uint32_t seq_length;             // 4 bytes - Sequence length
    uint32_t model_id;               // 4 bytes - Model identifier
    uint32_t expert_mask;            // 4 bytes - MoE expert selection mask
    uint16_t priority;               // 2 bytes - Request priority
    uint16_t flags;                  // 2 bytes - Request flags
    // Total: 28 bytes
    // Token data follows in payload
};
static_assert(sizeof(InferenceRequestPayload) == 28, "InferenceRequestPayload must be 28 bytes");

// CMD_INFERENCE_ACK payload
struct InferenceAckPayload {
    uint64_t request_id;             // Request ID being acknowledged
    uint8_t accepted;                // 1 = accepted, 0 = rejected
    uint8_t reserved[7];
    uint64_t estimated_completion;   // Estimated completion time
};
static_assert(sizeof(InferenceAckPayload) == 24, "InferenceAckPayload must be 24 bytes");

// CMD_KV_CACHE_SYNC payload
struct KVCacheSyncPayload {
    uint64_t cache_id;               // Cache identifier
    uint16_t source_node;            // Source node ID
    uint16_t target_node;            // Target node ID
    uint32_t layer_count;            // Number of layers to sync
    uint64_t byte_size;              // Total cache size in bytes
};
static_assert(sizeof(KVCacheSyncPayload) == 24, "KVCacheSyncPayload must be 24 bytes");

// CMD_EXPERT_ROUTE_REQ / CMD_EXPERT_ROUTE_ACK payload
struct ExpertRoutePayload {
    uint32_t expert_id;              // Expert identifier
    uint16_t source_node;            // Requesting node
    uint16_t target_node;            // Target node for expert
    uint8_t ready;                   // 1 = ready, 0 = not ready
    uint8_t reserved[3];
    uint32_t load_estimate;          // Estimated load
};
static_assert(sizeof(ExpertRoutePayload) == 16, "ExpertRoutePayload must be 16 bytes");

// CMD_TENSOR_XFER_START payload
struct TensorTransferStartPayload {
    uint64_t tensor_id;              // 8 bytes - Unique tensor ID
    uint32_t shape[4];               // 16 bytes - Tensor shape (B, S, H, D)
    uint16_t data_type;              // 2 bytes - Data type (Q4, Q8, FP16, etc.)
    uint16_t compression;            // 2 bytes - Compression type
    uint32_t total_chunks;           // 4 bytes - Total chunks expected
    uint32_t chunk_size;             // 4 bytes - Chunk size in bytes
    uint64_t total_bytes;            // 8 bytes - Total tensor size
    // Total: 44 bytes
};
static_assert(sizeof(TensorTransferStartPayload) == 44, "TensorTransferStartPayload must be 44 bytes");

// CMD_TENSOR_XFER_CHUNK payload
struct TensorTransferChunkPayload {
    uint64_t tensor_id;              // Parent tensor ID
    uint32_t chunk_index;            // Chunk sequence number
    uint32_t chunk_size;             // Actual chunk size
    uint32_t crc32;                  // Chunk checksum
    uint32_t reserved;
    // Raw tensor data follows (up to 64KB - header - this struct)
};
static_assert(sizeof(TensorTransferChunkPayload) == 24, "TensorTransferChunkPayload must be 24 bytes");

// CMD_TENSOR_XFER_FINISH payload
struct TensorTransferFinishPayload {
    uint64_t tensor_id;              // Tensor ID
    uint8_t success;                 // 1 = success, 0 = failure
    uint8_t reserved[7];
    uint32_t total_chunks_received;  // Verification
    uint32_t crc32_final;            // Final checksum
};
static_assert(sizeof(TensorTransferFinishPayload) == 24, "TensorTransferFinishPayload must be 24 bytes");

// CMD_ALL_REDUCE_PARTIAL payload
struct AllReducePartialPayload {
    uint64_t reduce_id;              // Reduction operation ID
    uint32_t step;                   // Ring step number
    uint32_t total_steps;            // Total ring steps
    uint16_t data_type;              // Data type
    uint16_t reserved;
    uint32_t element_count;          // Number of elements
    // Partial sum data follows
};
static_assert(sizeof(AllReducePartialPayload) == 24, "AllReducePartialPayload must be 24 bytes");

// CMD_ALL_REDUCE_COMPLETE payload
struct AllReduceCompletePayload {
    uint64_t reduce_id;              // Reduction operation ID
    uint16_t completing_node;        // Node that completed
    uint16_t reserved;
    uint32_t crc32;                  // Verification checksum
    uint64_t timestamp;              // Completion timestamp
};
static_assert(sizeof(AllReduceCompletePayload) == 24, "AllReduceCompletePayload must be 24 bytes");

// CMD_ALL_GATHER_REQ payload
struct AllGatherPayload {
    uint64_t gather_id;              // 8 bytes - Gather operation ID
    uint32_t element_count;          // 4 bytes - Number of elements per node
    uint32_t data_type;              // 4 bytes - Data type
    uint16_t requesting_node;        // 2 bytes - Node requesting gather
    uint16_t reserved;               // 2 bytes
    // Total: 20 bytes
    // Data follows
};
static_assert(sizeof(AllGatherPayload) == 20, "AllGatherPayload must be 20 bytes");

// CMD_WEIGHT_HOTPATCH payload
struct WeightHotpatchPayload {
    uint32_t model_id;               // Model identifier
    uint32_t layer_id;               // Layer being patched
    uint64_t version;                // New weight version
    uint64_t byte_size;              // Size of weight delta
    uint32_t crc32;                  // Integrity check
    uint32_t reserved;
};
static_assert(sizeof(WeightHotpatchPayload) == 32, "WeightHotpatchPayload must be 32 bytes");

// CMD_SYNC_BARRIER_ENTER / CMD_SYNC_BARRIER_RELEASE payload
struct BarrierPayload {
    uint64_t barrier_id;             // Barrier identifier
    uint32_t expected_nodes;         // Nodes required
    uint32_t arrived_nodes;          // Nodes arrived so far
    uint64_t timeout_us;             // Timeout in microseconds
    uint64_t timestamp;              // Enter/Release timestamp
};
static_assert(sizeof(BarrierPayload) == 32, "BarrierPayload must be 32 bytes");

// CMD_PANIC_ABORT payload
struct PanicAbortPayload {
    uint16_t source_node;            // Node initiating panic
    uint16_t error_code;             // Error code
    uint32_t reserved;
    char message[256];               // Error message (null-terminated)
};
static_assert(sizeof(PanicAbortPayload) == 264, "PanicAbortPayload must be 264 bytes");

// CMD_ERROR payload (generic error response)
struct ErrorPayload {
    uint16_t error_code;             // Error code
    uint16_t source_command;         // Command that failed
    uint32_t reserved;
    char message[256];               // Error message
};
static_assert(sizeof(ErrorPayload) == 264, "ErrorPayload must be 264 bytes");

#pragma pack(pop)

// =============================================================================
// Protocol Constants (RAWRXD_MAGIC already defined above)
// =============================================================================

constexpr uint16_t RAWRXD_PROTOCOL_VERSION = 1;
constexpr uint16_t RAWRXD_DEFAULT_PORT = 9091;
constexpr uint16_t RAWRXD_DATA_PORT = 9092;
constexpr size_t RAWRXD_MAX_PAYLOAD_SIZE = 65488; // 64KB - 24 byte header - 16 byte padding
constexpr size_t RAWRXD_CACHE_LINE_SIZE = 64;

// =============================================================================
// CRC32 Calculation (for packet integrity)
// =============================================================================

inline uint32_t calculate_crc32(const void* data, size_t length) {
    // Simple CRC32 implementation
    // In production, use hardware-accelerated CRC32 if available
    static const uint32_t crc_table[256] = {
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
    
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    uint32_t crc = 0xffffffff;
    for (size_t i = 0; i < length; ++i) {
        crc = crc_table[(crc ^ bytes[i]) & 0xff] ^ (crc >> 8);
    }
    return crc ^ 0xffffffff;
}

// =============================================================================
// Packet Builder Functions
// =============================================================================

inline RawrPacket build_packet(uint32_t cmd, uint16_t node_id, uint32_t seq, uint16_t flags) {
    RawrPacket pkt{};
    pkt.set_magic(RAWRXD_MAGIC);
    pkt.set_cmd(cmd);
    pkt.set_seq(seq);
    pkt.set_len(0);
    pkt.set_flags(flags);
    pkt.set_node_id(node_id);
    return pkt;
}

inline RawrPacket build_node_discover(const NodeInfo& info, uint16_t node_id, uint32_t seq) {
    RawrPacket pkt = build_packet(CMD_NODE_DISCOVER, node_id, seq, FLAG_ASYNC);
    NodeDiscoverPayload payload{};
    payload.node_info = info;
    payload.timestamp = 0; // Caller should set
    payload.capabilities = 0;
    payload.reserved = 0;
    
    pkt.set_len(sizeof(payload));
    // Copy payload after header (at offset 24)
    pkt.payload.resize(sizeof(payload));
    memcpy(pkt.payload.data(), &payload, sizeof(payload));
    return pkt;
}

inline RawrPacket build_node_acknowledge(uint16_t node_id, uint32_t seq, const NodeInfo& responder_info) {
    RawrPacket pkt = build_packet(CMD_NODE_ACKNOWLEDGE, node_id, seq, FLAG_SYNC);
    NodeDiscoverPayload payload{};
    payload.node_info = responder_info;
    payload.timestamp = 0;
    payload.capabilities = 0;
    payload.reserved = 0;
    
    pkt.set_len(sizeof(payload));
    pkt.payload.resize(sizeof(payload));
    memcpy(pkt.payload.data(), &payload, sizeof(payload));
    return pkt;
}

inline RawrPacket build_heartbeat_ping(uint16_t node_id, uint32_t seq) {
    return build_packet(CMD_HEARTBEAT_PING, node_id, seq, FLAG_ASYNC);
}

inline RawrPacket build_heartbeat_pong(uint16_t node_id, uint32_t seq, uint32_t queue_depth, uint64_t timestamp) {
    RawrPacket pkt = build_packet(CMD_HEARTBEAT_PONG, node_id, seq, FLAG_ASYNC);
    HeartbeatPayload payload{};
    payload.timestamp = timestamp;
    payload.queue_depth = queue_depth;
    payload.latency_us = 0;
    payload.tokens_processed = 0;
    payload.vram_available = 0;
    
    pkt.set_len(sizeof(payload));
    pkt.payload.resize(sizeof(payload));
    memcpy(pkt.payload.data(), &payload, sizeof(payload));
    return pkt;
}

inline RawrPacket build_ring_reconfigure(uint16_t master_node, uint16_t node_id, uint32_t seq) {
    RawrPacket pkt = build_packet(CMD_RING_RECONFIGURE, node_id, seq, FLAG_BARRIER | FLAG_SYNC);
    RingReconfigurePayload payload{};
    payload.master_node = master_node;
    payload.node_count = 0; // Caller should set
    payload.reserved = 0;
    
    pkt.set_len(sizeof(payload));
    pkt.payload.resize(sizeof(payload));
    memcpy(pkt.payload.data(), &payload, sizeof(payload));
    return pkt;
}

inline RawrPacket build_inference_request(uint16_t node_id, uint32_t seq, const InferenceRequestPayload& req) {
    RawrPacket pkt = build_packet(CMD_INFERENCE_REQ, node_id, seq, FLAG_SYNC);
    pkt.set_len(sizeof(req));
    pkt.payload.resize(sizeof(req));
    memcpy(pkt.payload.data(), &req, sizeof(req));
    return pkt;
}

inline RawrPacket build_inference_ack(uint16_t node_id, uint32_t seq, uint64_t request_id, bool accepted) {
    RawrPacket pkt = build_packet(CMD_INFERENCE_ACK, node_id, seq, FLAG_SYNC);
    InferenceAckPayload payload{};
    payload.request_id = request_id;
    payload.accepted = accepted ? 1 : 0;
    memset(payload.reserved, 0, sizeof(payload.reserved));
    payload.estimated_completion = 0;
    
    pkt.set_len(sizeof(payload));
    pkt.payload.resize(sizeof(payload));
    memcpy(pkt.payload.data(), &payload, sizeof(payload));
    return pkt;
}

inline RawrPacket build_kv_cache_sync(uint16_t node_id, uint32_t seq, uint64_t cache_id, uint16_t target_node) {
    RawrPacket pkt = build_packet(CMD_KV_CACHE_SYNC, node_id, seq, FLAG_SYNC);
    KVCacheSyncPayload payload{};
    payload.cache_id = cache_id;
    payload.source_node = node_id;
    payload.target_node = target_node;
    payload.layer_count = 0; // Caller should set
    payload.byte_size = 0;   // Caller should set
    
    pkt.set_len(sizeof(payload));
    pkt.payload.resize(sizeof(payload));
    memcpy(pkt.payload.data(), &payload, sizeof(payload));
    return pkt;
}

inline RawrPacket build_expert_route_req(uint16_t node_id, uint32_t seq, uint32_t expert_id, uint16_t target_node) {
    RawrPacket pkt = build_packet(CMD_EXPERT_ROUTE_REQ, node_id, seq, FLAG_SYNC);
    ExpertRoutePayload payload{};
    payload.expert_id = expert_id;
    payload.source_node = node_id;
    payload.target_node = target_node;
    payload.ready = 0;
    memset(payload.reserved, 0, sizeof(payload.reserved));
    payload.load_estimate = 0;
    
    pkt.set_len(sizeof(payload));
    pkt.payload.resize(sizeof(payload));
    memcpy(pkt.payload.data(), &payload, sizeof(payload));
    return pkt;
}

inline RawrPacket build_expert_route_ack(uint16_t node_id, uint32_t seq, uint32_t expert_id, bool ready) {
    RawrPacket pkt = build_packet(CMD_EXPERT_ROUTE_ACK, node_id, seq, FLAG_SYNC);
    ExpertRoutePayload payload{};
    payload.expert_id = expert_id;
    payload.source_node = node_id;
    payload.target_node = 0;
    payload.ready = ready ? 1 : 0;
    memset(payload.reserved, 0, sizeof(payload.reserved));
    payload.load_estimate = 0;
    
    pkt.set_len(sizeof(payload));
    pkt.payload.resize(sizeof(payload));
    memcpy(pkt.payload.data(), &payload, sizeof(payload));
    return pkt;
}

inline RawrPacket build_tensor_xfer_start(uint16_t node_id, uint32_t seq, const TensorTransferStartPayload& xfer) {
    RawrPacket pkt = build_packet(CMD_TENSOR_XFER_START, node_id, seq, FLAG_SYNC);
    pkt.set_len(sizeof(xfer));
    pkt.payload.resize(sizeof(xfer));
    memcpy(pkt.payload.data(), &xfer, sizeof(xfer));
    return pkt;
}

inline RawrPacket build_tensor_xfer_chunk(uint16_t node_id, uint32_t seq, const TensorTransferChunkPayload& chunk) {
    RawrPacket pkt = build_packet(CMD_TENSOR_XFER_CHUNK, node_id, seq, FLAG_ASYNC);
    pkt.set_len(sizeof(chunk));
    pkt.payload.resize(sizeof(chunk));
    memcpy(pkt.payload.data(), &chunk, sizeof(chunk));
    return pkt;
}

inline RawrPacket build_tensor_xfer_finish(uint16_t node_id, uint32_t seq, uint64_t tensor_id, bool success) {
    RawrPacket pkt = build_packet(CMD_TENSOR_XFER_FINISH, node_id, seq, FLAG_SYNC);
    TensorTransferFinishPayload payload{};
    payload.tensor_id = tensor_id;
    payload.success = success ? 1 : 0;
    memset(payload.reserved, 0, sizeof(payload.reserved));
    payload.total_chunks_received = 0;
    payload.crc32_final = 0;
    
    pkt.set_len(sizeof(payload));
    pkt.payload.resize(sizeof(payload));
    memcpy(pkt.payload.data(), &payload, sizeof(payload));
    return pkt;
}

inline RawrPacket build_all_reduce_partial(uint16_t node_id, uint32_t seq, const AllReducePartialPayload& reduce) {
    RawrPacket pkt = build_packet(CMD_ALL_REDUCE_PARTIAL, node_id, seq, FLAG_SYNC);
    pkt.set_len(sizeof(reduce));
    pkt.payload.resize(sizeof(reduce));
    memcpy(pkt.payload.data(), &reduce, sizeof(reduce));
    return pkt;
}

inline RawrPacket build_all_reduce_complete(uint16_t node_id, uint32_t seq, uint64_t reduce_id) {
    RawrPacket pkt = build_packet(CMD_ALL_REDUCE_COMPLETE, node_id, seq, FLAG_BROADCAST | FLAG_SYNC);
    AllReduceCompletePayload payload{};
    payload.reduce_id = reduce_id;
    payload.completing_node = node_id;
    payload.reserved = 0;
    payload.crc32 = 0;
    payload.timestamp = 0;
    
    pkt.set_len(sizeof(payload));
    pkt.payload.resize(sizeof(payload));
    memcpy(pkt.payload.data(), &payload, sizeof(payload));
    return pkt;
}

inline RawrPacket build_all_gather_req(uint16_t node_id, uint32_t seq, uint64_t gather_id, uint32_t element_count) {
    RawrPacket pkt = build_packet(CMD_ALL_GATHER_REQ, node_id, seq, FLAG_SYNC);
    AllGatherPayload payload{};
    payload.gather_id = gather_id;
    payload.element_count = element_count;
    payload.data_type = 0; // Caller should set
    payload.requesting_node = node_id;
    payload.reserved = 0;
    
    pkt.set_len(sizeof(payload));
    pkt.payload.resize(sizeof(payload));
    memcpy(pkt.payload.data(), &payload, sizeof(payload));
    return pkt;
}

inline RawrPacket build_weight_hotpatch(uint16_t node_id, uint32_t seq, uint32_t model_id, uint64_t version) {
    RawrPacket pkt = build_packet(CMD_WEIGHT_HOTPATCH, node_id, seq, FLAG_URGENT | FLAG_SYNC);
    WeightHotpatchPayload payload{};
    payload.model_id = model_id;
    payload.layer_id = 0; // Caller should set
    payload.version = version;
    payload.byte_size = 0; // Caller should set
    payload.crc32 = 0;
    payload.reserved = 0;
    
    pkt.set_len(sizeof(payload));
    pkt.payload.resize(sizeof(payload));
    memcpy(pkt.payload.data(), &payload, sizeof(payload));
    return pkt;
}

inline RawrPacket build_sync_barrier_enter(uint16_t node_id, uint32_t seq, uint64_t barrier_id, uint32_t expected_nodes) {
    RawrPacket pkt = build_packet(CMD_SYNC_BARRIER_ENTER, node_id, seq, FLAG_BARRIER | FLAG_SYNC);
    BarrierPayload payload{};
    payload.barrier_id = barrier_id;
    payload.expected_nodes = expected_nodes;
    payload.arrived_nodes = 0;
    payload.timeout_us = 1000000; // 1 second default
    payload.timestamp = 0;
    
    pkt.set_len(sizeof(payload));
    pkt.payload.resize(sizeof(payload));
    memcpy(pkt.payload.data(), &payload, sizeof(payload));
    return pkt;
}

inline RawrPacket build_sync_barrier_release(uint16_t node_id, uint32_t seq, uint64_t barrier_id) {
    RawrPacket pkt = build_packet(CMD_SYNC_BARRIER_RELEASE, node_id, seq, FLAG_BROADCAST | FLAG_SYNC);
    BarrierPayload payload{};
    payload.barrier_id = barrier_id;
    payload.expected_nodes = 0;
    payload.arrived_nodes = 0;
    payload.timeout_us = 0;
    payload.timestamp = 0;
    
    pkt.set_len(sizeof(payload));
    pkt.payload.resize(sizeof(payload));
    memcpy(pkt.payload.data(), &payload, sizeof(payload));
    return pkt;
}

inline RawrPacket build_panic_abort(uint16_t node_id, uint32_t seq, const char* reason) {
    RawrPacket pkt = build_packet(CMD_PANIC_ABORT, node_id, seq, FLAG_URGENT | FLAG_BROADCAST);
    PanicAbortPayload payload{};
    payload.source_node = node_id;
    payload.error_code = 0xFFFF; // General panic
    payload.reserved = 0;
    strncpy(payload.message, reason, sizeof(payload.message) - 1);
    payload.message[sizeof(payload.message) - 1] = '\0';
    
    pkt.set_len(sizeof(payload));
    pkt.payload.resize(sizeof(payload));
    memcpy(pkt.payload.data(), &payload, sizeof(payload));
    return pkt;
}

inline RawrPacket build_error(uint16_t node_id, uint32_t seq, uint16_t error_code, uint16_t source_cmd, const char* message) {
    RawrPacket pkt = build_packet(0xFFFE, node_id, seq, FLAG_SYNC); // CMD_ERROR
    ErrorPayload payload{};
    payload.error_code = error_code;
    payload.source_command = source_cmd;
    payload.reserved = 0;
    strncpy(payload.message, message, sizeof(payload.message) - 1);
    payload.message[sizeof(payload.message) - 1] = '\0';
    
    pkt.set_len(sizeof(payload));
    pkt.payload.resize(sizeof(payload));
    memcpy(pkt.payload.data(), &payload, sizeof(payload));
    return pkt;
}

inline RawrPacket build_ack(uint16_t node_id, uint32_t seq) {
    return build_packet(0xFFFF, node_id, seq, FLAG_SYNC); // CMD_ACK
}

// =============================================================================
// Packet Validation
// =============================================================================

inline bool validate_packet(const RawrPacket& pkt) {
    return pkt.magic() == RAWRXD_MAGIC;
}

inline bool is_valid_command(uint32_t cmd) {
    switch (cmd) {
        case CMD_NODE_DISCOVER:
        case CMD_NODE_ACKNOWLEDGE:
        case CMD_HEARTBEAT_PING:
        case CMD_HEARTBEAT_PONG:
        case CMD_RING_RECONFIGURE:
        case CMD_INFERENCE_REQ:
        case CMD_INFERENCE_ACK:
        case CMD_KV_CACHE_SYNC:
        case CMD_EXPERT_ROUTE_REQ:
        case CMD_EXPERT_ROUTE_ACK:
        case CMD_TENSOR_XFER_START:
        case CMD_TENSOR_XFER_CHUNK:
        case CMD_TENSOR_XFER_FINISH:
        case CMD_ALL_REDUCE_PARTIAL:
        case CMD_ALL_REDUCE_COMPLETE:
        case CMD_ALL_GATHER_REQ:
        case CMD_WEIGHT_HOTPATCH:
        case CMD_SYNC_BARRIER_ENTER:
        case CMD_SYNC_BARRIER_RELEASE:
        case CMD_PANIC_ABORT:
        case 0xFFFE: // CMD_ERROR
        case 0xFFFF: // CMD_ACK
            return true;
        default:
            return false;
    }
}

inline const char* command_to_string(uint32_t cmd) {
    switch (cmd) {
        case CMD_NODE_DISCOVER: return "NODE_DISCOVER";
        case CMD_NODE_ACKNOWLEDGE: return "NODE_ACKNOWLEDGE";
        case CMD_HEARTBEAT_PING: return "HEARTBEAT_PING";
        case CMD_HEARTBEAT_PONG: return "HEARTBEAT_PONG";
        case CMD_RING_RECONFIGURE: return "RING_RECONFIGURE";
        case CMD_INFERENCE_REQ: return "INFERENCE_REQ";
        case CMD_INFERENCE_ACK: return "INFERENCE_ACK";
        case CMD_KV_CACHE_SYNC: return "KV_CACHE_SYNC";
        case CMD_EXPERT_ROUTE_REQ: return "EXPERT_ROUTE_REQ";
        case CMD_EXPERT_ROUTE_ACK: return "EXPERT_ROUTE_ACK";
        case CMD_TENSOR_XFER_START: return "TENSOR_XFER_START";
        case CMD_TENSOR_XFER_CHUNK: return "TENSOR_XFER_CHUNK";
        case CMD_TENSOR_XFER_FINISH: return "TENSOR_XFER_FINISH";
        case CMD_ALL_REDUCE_PARTIAL: return "ALL_REDUCE_PARTIAL";
        case CMD_ALL_REDUCE_COMPLETE: return "ALL_REDUCE_COMPLETE";
        case CMD_ALL_GATHER_REQ: return "ALL_GATHER_REQ";
        case CMD_WEIGHT_HOTPATCH: return "WEIGHT_HOTPATCH";
        case CMD_SYNC_BARRIER_ENTER: return "SYNC_BARRIER_ENTER";
        case CMD_SYNC_BARRIER_RELEASE: return "SYNC_BARRIER_RELEASE";
        case CMD_PANIC_ABORT: return "PANIC_ABORT";
        case 0xFFFE: return "ERROR";
        case 0xFFFF: return "ACK";
        default: return "UNKNOWN";
    }
}

// End of RawrXD_RPC.hpp

} // namespace Distributed
} // namespace RawrXD

