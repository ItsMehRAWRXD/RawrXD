#pragma once

#include <cstdint>

namespace RawrXD {
namespace Fabric {

// ============================================================================
// Fabric Operations
// ============================================================================
enum class FabricOp : uint32_t {
    LOOKUP_TENSOR = 1,      // Query tensor location
    ACQUIRE_LEASE = 2,      // Request access lease
    RELEASE_LEASE = 3,      // Return lease
    INVALIDATE = 4,         // Invalidate cached entry
    MIGRATE_REQUEST = 5,    // Request tensor migration
    HEARTBEAT = 6,          // Node health check
    FLOW_CONTROL = 7        // Backpressure signal
};

// ============================================================================
// Fabric Message Header (64-byte aligned)
// ============================================================================
struct alignas(64) FabricMessageHeader {
    uint64_t magic;             // 0x524157524D454D46 "RAWRMEMF"
    uint32_t version;           // Protocol version = 1
    FabricOp op;                // Operation type
    uint32_t sequence;          // Request sequence number
    uint64_t timestamp;         // Origin timestamp (μs)
    uint32_t payloadSize;       // Bytes following header
    uint32_t checksum;          // CRC32 of payload
    uint32_t srcNodeId;         // Source node
    uint32_t dstNodeId;         // Destination node
    uint32_t reserved[8];       // Padding to 64 bytes
    
    FabricMessageHeader() 
        : magic(0x524157524D454D46ULL)
        , version(1)
        , op(FabricOp::LOOKUP_TENSOR)
        , sequence(0)
        , timestamp(0)
        , payloadSize(0)
        , checksum(0)
        , srcNodeId(0)
        , dstNodeId(0) {
        for (int i = 0; i < 8; i++) reserved[i] = 0;
    }
};

// ============================================================================
// Payload Structures (Cache-line friendly)
// ============================================================================

// LOOKUP_TENSOR Request/Response
struct alignas(32) LookupTensorRequest {
    uint64_t tensorId;
    uint32_t priority;        // 0-255, higher = more urgent
    uint32_t pad;
};

struct alignas(64) LookupTensorResponse {
    uint64_t tensorId;
    uint64_t offset;            // Local offset if resident
    uint32_t size;              // Tensor size
    uint32_t nodeId;            // Owning node
    uint32_t residency;         // ResidencyState as uint32
    uint32_t version;
    uint64_t latencyUs;         // Expected access latency
    uint32_t status;            // 0=FOUND, 1=NOT_FOUND, 2=MIGRATING
    uint32_t pad[3];
};

// ACQUIRE_LEASE Request/Response
struct alignas(32) AcquireLeaseRequest {
    uint64_t tensorId;
    uint32_t durationMs;        // Lease duration
    uint32_t pad;
};

struct alignas(32) AcquireLeaseResponse {
    uint64_t tensorId;
    uint32_t version;
    uint64_t expiryUs;
    uint32_t status;            // 0=SUCCESS, 1=DENIED, 2=EXPIRED
    uint32_t pad;
};

// RELEASE_LEASE Request/Response
struct alignas(32) ReleaseLeaseRequest {
    uint64_t tensorId;
    uint32_t version;
    uint32_t pad;
};

struct alignas(16) ReleaseLeaseResponse {
    uint64_t tensorId;
    uint32_t status;            // 0=SUCCESS, 1=INVALID_LEASE
    uint32_t pad;
};

// INVALIDATE (one-way)
struct alignas(32) InvalidateMessage {
    uint64_t tensorId;
    uint32_t version;           // Version that is now invalid
    uint32_t newNodeId;         // New owner (if migrated)
};

// MIGRATE_REQUEST
struct alignas(32) MigrateRequest {
    uint64_t tensorId;
    uint32_t targetNodeId;
    uint32_t priority;
};

struct alignas(16) MigrateResponse {
    uint64_t tensorId;
    uint32_t status;            // 0=ACCEPTED, 1=REJECTED
    uint32_t pad;
};

// HEARTBEAT
struct alignas(32) HeartbeatMessage {
    uint32_t nodeId;
    uint32_t loadPercent;       // 0-100
    uint64_t uptimeUs;
    uint32_t tensorCount;
    uint32_t pad;
};

// FLOW_CONTROL
struct alignas(32) FlowControlMessage {
    uint32_t nodeId;
    uint32_t windowSize;        // Available receive buffer
    uint32_t backpressure;      // 0-255 (255 = stop)
    uint32_t lastAckSequence;
};

// ============================================================================
// Unified Fabric Message
// ============================================================================
struct alignas(128) FabricMessage {
    FabricMessageHeader header;
    
    union {
        LookupTensorRequest lookupReq;
        LookupTensorResponse lookupResp;
        AcquireLeaseRequest leaseReq;
        AcquireLeaseResponse leaseResp;
        ReleaseLeaseRequest releaseReq;
        ReleaseLeaseResponse releaseResp;
        InvalidateMessage invalidate;
        MigrateRequest migrateReq;
        MigrateResponse migrateResp;
        HeartbeatMessage heartbeat;
        FlowControlMessage flowControl;
    } payload;
    
    FabricMessage() = default;
};

// Compile-time size checks
static_assert(sizeof(FabricMessageHeader) == 64, "Header must be 64 bytes");
static_assert(sizeof(LookupTensorResponse) == 64, "Lookup response must be 64 bytes");
static_assert(sizeof(FabricMessage) == 128, "Message must be 128 bytes");

} // namespace Fabric
} // namespace RawrXD
