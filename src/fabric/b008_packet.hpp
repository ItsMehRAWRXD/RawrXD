#pragma once
//=============================================================================
// B008 Fabric Packet - VAL-031.3 Distributed Fabric
// Robust packet format with versioning, CRC, and session management
//=============================================================================

#include <cstdint>
#include <cstddef>
#include <cstring>

namespace RawrXD {
namespace Fabric {

// Protocol version
constexpr uint16_t B008_PROTOCOL_VERSION = 1;

// Magic number: 'B008' in little-endian
constexpr uint32_t B008_PACKET_MAGIC = 0x42303038; // 'B008'

// Packet opcodes (Phase 1: handshake only)
enum class Opcode : uint16_t {
    // Phase 1: Connection establishment
    HELLO = 1,          // Client -> Server: initiate handshake
    HELLO_ACK = 2,      // Server -> Client: accept handshake
    
    // Phase 1: Keepalive
    PING = 3,           // Bidirectional: heartbeat request
    PONG = 4,           // Bidirectional: heartbeat response
    
    // Phase 1: Teardown
    GOODBYE = 5,        // Graceful disconnect
    
    // Phase 1: Error
    ERROR = 6,          // Protocol error
    
    // Phase 2: Metadata operations (future)
    QUERY_TENSOR = 100,
    TENSOR_FOUND = 101,
    TENSOR_MISS = 102,
    
    // Phase 3: Data operations (future)
    FETCH_BLOCK = 200,
    PUSH_BLOCK = 201,
    ACK = 202
};

// Fabric capabilities (64-bit bitmask)
enum FabricCapability : uint64_t {
    CAP_NONE = 0,
    CAP_AVX512 = 1ull << 0,       // AVX-512 kernels supported
    CAP_IOCP = 1ull << 1,         // Windows IOCP transport
    CAP_VULKAN = 1ull << 2,       // Vulkan compute available
    CAP_RDMA = 1ull << 3,         // RDMA capable
    CAP_COMPRESSION = 1ull << 4,  // Supports compression
    CAP_ENCRYPTION = 1ull << 5,   // Supports encryption
    CAP_RESIDENCY_PLANNER = 1ull << 6,  // Has tensor residency planner
    CAP_JUKEBOX = 1ull << 7       // Has jukebox streaming
};

// Session states
enum class SessionState : uint8_t {
    DISCONNECTED = 0,
    CONNECTING = 1,
    HANDSHAKE = 2,
    ESTABLISHED = 3,
    ACTIVE = 4,
    CLOSING = 5
};

// Error codes
enum class FabricError : uint32_t {
    NONE = 0,
    INVALID_MAGIC = 1,
    VERSION_MISMATCH = 2,
    INVALID_OPCODE = 3,
    CRC_FAILURE = 4,
    SESSION_EXPIRED = 5,
    UNAUTHORIZED = 6,
    RESOURCE_EXHAUSTED = 7,
    TIMEOUT = 8
};

// B008 Fabric Packet Header
// 32 bytes - cache line aligned
#pragma pack(push, 1)
struct PacketHeader {
    uint32_t magic;         // 'B008' (4 bytes)
    uint16_t version;       // Protocol version (2 bytes)
    uint16_t opcode;        // Opcode (2 bytes)
    
    uint32_t payload_size;  // Payload length (4 bytes)
    
    uint32_t sequence;      // Sequence number (4 bytes)
    uint32_t session;       // Session ID (4 bytes)
    
    uint32_t crc32;         // CRC32 of header+payload (4 bytes)
    uint32_t reserved;      // Padding to 32 bytes (4 bytes)
    
    // Initialize with defaults
    void Init(Opcode op, uint32_t seq = 0, uint32_t sess = 0) {
        magic = B008_PACKET_MAGIC;
        version = B008_PROTOCOL_VERSION;
        opcode = static_cast<uint16_t>(op);
        payload_size = 0;
        sequence = seq;
        session = sess;
        crc32 = 0;
        reserved = 0;
    }
    
    // Verify magic
    bool IsValidMagic() const {
        return magic == B008_PACKET_MAGIC;
    }
    
    // Verify version compatibility
    bool IsVersionCompatible() const {
        // Major version must match, minor can differ
        return (version & 0xFF00) == (B008_PROTOCOL_VERSION & 0xFF00);
    }
};
#pragma pack(pop)

static_assert(sizeof(PacketHeader) == 32, "PacketHeader must be 32 bytes");

// HELLO payload (client -> server)
struct HelloPayload {
    uint64_t capabilities;      // FabricCapability bitmask
    uint32_t max_packet_size;   // Maximum packet size accepted
    uint32_t heartbeat_interval_ms;  // Desired heartbeat interval
    uint8_t node_id;            // Client's node ID
    uint8_t reserved[7];        // Padding
};
static_assert(sizeof(HelloPayload) == 24, "HelloPayload must be 24 bytes");

// HELLO_ACK payload (server -> client)
struct HelloAckPayload {
    uint64_t capabilities;      // Server capabilities (intersection)
    uint32_t session_id;        // Assigned session ID
    uint32_t max_packet_size;   // Server's max packet size
    uint32_t heartbeat_interval_ms;  // Negotiated heartbeat
    uint16_t status;            // 0 = success, non-zero = error code
    uint8_t reserved[6];        // Padding
};
static_assert(sizeof(HelloAckPayload) == 32, "HelloAckPayload must be 32 bytes");

// PING/PONG payload
struct PingPayload {
    uint64_t timestamp;         // Sender's timestamp (for RTT)
    uint64_t padding;           // Reserved
};
static_assert(sizeof(PingPayload) == 16, "PingPayload must be 16 bytes");

// ERROR payload
struct ErrorPayload {
    uint32_t error_code;        // FabricError
    uint32_t context;           // Context (e.g., sequence that failed)
    char message[56];           // Human-readable message
};
static_assert(sizeof(ErrorPayload) == 64, "ErrorPayload must be 64 bytes");

// CRC32 calculation (simple implementation)
inline uint32_t CalcCRC32(const void* data, size_t len) {
    // Simple CRC32 - in production use hardware-accelerated CRC32
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < len; i++) {
        crc ^= bytes[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    
    return ~crc;
}

// Calculate CRC for packet
inline uint32_t CalcPacketCRC(const PacketHeader& header, const void* payload) {
    uint32_t crc = CalcCRC32(&header, sizeof(header) - sizeof(header.crc32));
    if (payload && header.payload_size > 0) {
        crc = CalcCRC32(payload, header.payload_size);
    }
    return crc;
}

// Fabric packet
struct Packet {
    PacketHeader header;
    void* payload;  // Owned by caller, not Packet
    
    Packet() : payload(nullptr) {
        memset(&header, 0, sizeof(header));
    }
    
    // Initialize HELLO packet
    void InitHello(uint8_t node_id, uint64_t caps, uint32_t max_packet = 65536) {
        header.Init(Opcode::HELLO);
        header.payload_size = sizeof(HelloPayload);
        
        // Allocate and fill payload
        HelloPayload* hello = new HelloPayload();
        hello->capabilities = caps;
        hello->max_packet_size = max_packet;
        hello->heartbeat_interval_ms = 5000;  // 5 seconds default
        hello->node_id = node_id;
        memset(hello->reserved, 0, sizeof(hello->reserved));
        
        payload = hello;
        header.crc32 = CalcPacketCRC(header, payload);
    }
    
    // Initialize HELLO_ACK packet
    void InitHelloAck(uint32_t session_id, uint64_t caps, uint16_t status = 0) {
        header.Init(Opcode::HELLO_ACK);
        header.session = session_id;
        header.payload_size = sizeof(HelloAckPayload);
        
        HelloAckPayload* ack = new HelloAckPayload();
        ack->capabilities = caps;
        ack->session_id = session_id;
        ack->max_packet_size = 65536;
        ack->heartbeat_interval_ms = 5000;
        ack->status = status;
        memset(ack->reserved, 0, sizeof(ack->reserved));
        
        payload = ack;
        header.crc32 = CalcPacketCRC(header, payload);
    }
    
    // Initialize PING packet
    void InitPing(uint32_t session, uint32_t seq) {
        header.Init(Opcode::PING, seq, session);
        header.payload_size = sizeof(PingPayload);
        
        PingPayload* ping = new PingPayload();
        ping->timestamp = GetTickCount64();
        ping->padding = 0;
        
        payload = ping;
        header.crc32 = CalcPacketCRC(header, payload);
    }
    
    // Initialize PONG packet
    void InitPong(uint32_t session, uint32_t seq, uint64_t ping_timestamp) {
        header.Init(Opcode::PONG, seq, session);
        header.payload_size = sizeof(PingPayload);
        
        PingPayload* pong = new PingPayload();
        pong->timestamp = ping_timestamp;  // Echo back
        pong->padding = GetTickCount64();    // Our timestamp
        
        payload = pong;
        header.crc32 = CalcPacketCRC(header, payload);
    }
    
    // Initialize GOODBYE packet
    void InitGoodbye(uint32_t session, uint32_t seq) {
        header.Init(Opcode::GOODBYE, seq, session);
        header.payload_size = 0;
        header.crc32 = CalcPacketCRC(header, nullptr);
    }
    
    // Initialize ERROR packet
    void InitError(FabricError code, uint32_t context, const char* msg) {
        header.Init(Opcode::ERROR);
        header.payload_size = sizeof(ErrorPayload);
        
        ErrorPayload* err = new ErrorPayload();
        err->error_code = static_cast<uint32_t>(code);
        err->context = context;
        strncpy(err->message, msg, sizeof(err->message) - 1);
        err->message[sizeof(err->message) - 1] = '\0';
        
        payload = err;
        header.crc32 = CalcPacketCRC(header, payload);
    }
    
    // Verify packet integrity
    bool Verify() const {
        if (!header.IsValidMagic()) return false;
        if (!header.IsVersionCompatible()) return false;
        
        uint32_t expected_crc = CalcPacketCRC(header, payload);
        return header.crc32 == expected_crc;
    }
    
    // Cleanup payload
    void Cleanup() {
        if (payload) {
            delete[] static_cast<uint8_t*>(payload);
            payload = nullptr;
        }
    }
};

} // namespace Fabric
} // namespace RawrXD
