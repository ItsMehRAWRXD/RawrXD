#pragma once
//=============================================================================
// B008 Fabric Packet - VAL-031.3 Distributed Fabric
// 16-byte fixed header for cache-line alignment
//=============================================================================

#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace Fabric {

// Packet commands
enum class PacketCmd : uint8_t {
    PING = 0,       // Handshake request
    PONG = 1,       // Handshake response
    FETCH = 2,      // Request block from remote
    PUSH = 3,       // Send block to remote
    ACK = 4,        // Acknowledge receipt
    HEARTBEAT = 5,  // Keepalive
    DIR_SYNC = 6,   // Directory sync
    ERROR = 7       // Error response
};

// Packet flags
enum PacketFlags : uint16_t {
    FLAG_NONE = 0,
    FLAG_COMPRESSED = 1,    // Payload is compressed
    FLAG_ENCRYPTED = 2,     // Payload is encrypted
    FLAG_URGENT = 4,        // High priority
    FLAG_BROADCAST = 8      // Send to all nodes
};

// B008 Fabric Packet Header
// Fixed 16-byte size for MASM-friendly parsing
#pragma pack(push, 1)
struct PacketHeader {
    uint64_t block_id;      // Block identifier (8 bytes)
    uint8_t command;        // PacketCmd (1 byte)
    uint8_t node_id;        // Source node (1 byte)
    uint16_t flags;         // PacketFlags (2 bytes)
    uint16_t payload_len;   // Payload length (2 bytes)
    uint16_t checksum;      // Simple checksum (2 bytes)
    
    // Calculate checksum over header
    uint16_t CalcChecksum() const {
        const uint8_t* data = reinterpret_cast<const uint8_t*>(this);
        uint32_t sum = 0;
        // Sum all bytes except checksum field itself
        for (size_t i = 0; i < offsetof(PacketHeader, checksum); i++) {
            sum += data[i];
        }
        return static_cast<uint16_t>(sum & 0xFFFF);
    }
    
    // Verify checksum
    bool VerifyChecksum() const {
        return checksum == CalcChecksum();
    }
    
    // Set checksum
    void SetChecksum() {
        checksum = CalcChecksum();
    }
};
#pragma pack(pop)

static_assert(sizeof(PacketHeader) == 16, "PacketHeader must be exactly 16 bytes");

// Maximum payload size (256MB block chunks)
constexpr size_t MAX_PAYLOAD_SIZE = 256 * 1024 * 1024;

// Fabric packet with payload
struct Packet {
    PacketHeader header;
    void* payload;  // Owned by caller, not Packet
    
    Packet() : payload(nullptr) {
        memset(&header, 0, sizeof(header));
    }
    
    // Initialize as PING
    void InitPing(uint8_t src_node) {
        header.block_id = 0;
        header.command = static_cast<uint8_t>(PacketCmd::PING);
        header.node_id = src_node;
        header.flags = FLAG_NONE;
        header.payload_len = 0;
        header.SetChecksum();
    }
    
    // Initialize as PONG
    void InitPong(uint8_t src_node, uint64_t ping_block_id) {
        header.block_id = ping_block_id;
        header.command = static_cast<uint8_t>(PacketCmd::PONG);
        header.node_id = src_node;
        header.flags = FLAG_NONE;
        header.payload_len = 0;
        header.SetChecksum();
    }
    
    // Initialize as FETCH request
    void InitFetch(uint64_t block, uint8_t src_node) {
        header.block_id = block;
        header.command = static_cast<uint8_t>(PacketCmd::FETCH);
        header.node_id = src_node;
        header.flags = FLAG_NONE;
        header.payload_len = 0;
        header.SetChecksum();
    }
    
    // Initialize as PUSH (block data)
    void InitPush(uint64_t block, uint8_t src_node, uint16_t data_len) {
        header.block_id = block;
        header.command = static_cast<uint8_t>(PacketCmd::PUSH);
        header.node_id = src_node;
        header.flags = FLAG_NONE;
        header.payload_len = data_len;
        header.SetChecksum();
    }
};

} // namespace Fabric
} // namespace RawrXD
