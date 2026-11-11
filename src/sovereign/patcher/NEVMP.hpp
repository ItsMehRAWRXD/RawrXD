#pragma once
#include <cstdint>
#include <cstddef>

// =============================================================================
// NEVMP (Neural Vector Memory Patch) Format Specification v1.0
// Formal ABI for Sovereign Substrate Patch Distribution
// =============================================================================

#define NEVMP_MAGIC         0x4E564D50u  // 'NVMP' in little-endian
#define NEVMP_VERSION       0x00010000u  // v1.0.0.0
#define NEVMP_HEADER_SIZE   64           // Cache-line aligned

#pragma pack(push, 1)

// =============================================================================
// NEVMP_Header - 64-byte fixed-size header
// Ensures cache-line alignment for zero-overhead SIMD validation
// =============================================================================
struct alignas(64) NEVMP_Header {
    // Core Identification (8 bytes)
    uint32_t magic;              // 0x00: 0x4E564D50 ('NVMP')
    uint32_t version;            // 0x04: Schema version (0x00010000)
    
    // Patch Metadata (24 bytes)
    uint64_t epoch_id;           // 0x08: Monotonic patch ID for rollback
    uint64_t vector_count;       // 0x10: Number of delta-encoded vectors
    uint64_t payload_size;       // 0x18: Size of encoded delta block
    
    // Integrity & Targeting (16 bytes)
    uint64_t checksum;           // 0x20: CRC64-ISO of payload
    uint64_t target_addr;        // 0x28: Memory aperture offset (or absolute)
    
    // Reserved / Future Use (16 bytes)
    uint8_t  padding[16];        // 0x30: Must be zero
    
    // -------------------------------------------------------------------------
    // Validation Methods
    // -------------------------------------------------------------------------
    bool IsValid() const noexcept {
        return magic == NEVMP_MAGIC && 
               version == NEVMP_VERSION &&
               vector_count > 0 &&
               payload_size > 0 &&
               payload_size == (vector_count * sizeof(double));
    }
    
    // Calculate expected payload checksum (CRC64-ISO)
    static uint64_t CalculateChecksum(const void* payload, size_t size);
    
    // Verify payload integrity
    bool VerifyPayload(const void* payload) const {
        return checksum == CalculateChecksum(payload, payload_size);
    }
};

// Ensure 64-byte alignment
static_assert(sizeof(NEVMP_Header) == 64, "NEVMP_Header must be exactly 64 bytes");
static_assert(alignof(NEVMP_Header) == 64, "NEVMP_Header must be 64-byte aligned");

// =============================================================================
// NEVMP_Patch - Complete patch structure (header + payload)
// =============================================================================
struct NEVMP_Patch {
    NEVMP_Header header;
    // Payload follows immediately (delta-encoded vectors)
    // double payload[header.vector_count];
    
    // Access payload data
    const double* GetPayload() const {
        return reinterpret_cast<const double*>(
            reinterpret_cast<const uint8_t*>(this) + sizeof(NEVMP_Header)
        );
    }
    
    double* GetPayload() {
        return reinterpret_cast<double*>(
            reinterpret_cast<uint8_t*>(this) + sizeof(NEVMP_Header)
        );
    }
    
    // Total size including header and payload
    size_t GetTotalSize() const {
        return sizeof(NEVMP_Header) + header.payload_size;
    }
};

#pragma pack(pop)

// =============================================================================
// NEVMP_Status - Operation result codes
// =============================================================================
enum class NEVMP_Status : int32_t {
    OK = 0,                      // Success
    ERR_INVALID_MAGIC = -1,      // Magic number mismatch
    ERR_INVALID_VERSION = -2,  // Version mismatch
    ERR_INVALID_CHECKSUM = -3, // Payload integrity failure
    ERR_INVALID_PAYLOAD = -4,  // Payload size/count mismatch
    ERR_MEMORY_ALLOC = -5,     // Failed to allocate aperture
    ERR_APPLY_FAILED = -6,     // HotPatcher application failed
    ERR_ROLLBACK_FAILED = -7,  // Rollback operation failed
};

// Convert status to string
const char* NEVMP_StatusToString(NEVMP_Status status);
