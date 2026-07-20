#pragma once
//=============================================================================
// B008 Format - Execution-Oriented Model Representation
// VAL-030.1 Minimum Implementation
//
// B008 is not GGUF. B008 is the execution format.
// The Jukebox does not know GGUF. It only knows:
//   "give me block #12345"
//=============================================================================

#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace B008 {

// Block states for the residency lifecycle
enum class BlockState : uint32_t
{
    COLD      = 0,  // On disk only
    LOADING   = 1,  // IO in progress
    READY     = 2,  // In RAM, ready for compute
    COMPUTING = 3,  // Currently being used by kernel
    EVICTING  = 4   // Marked for removal
};

// Quantization types (subset of GGUF types)
enum class QuantType : uint32_t
{
    Q4_0    = 2,   // 4-bit, legacy
    Q4_1    = 3,   // 4-bit, with offsets
    Q5_0    = 6,   // 5-bit
    Q5_1    = 7,   // 5-bit, with offsets
    Q8_0    = 8,   // 8-bit
    Q2_K    = 10,  // 2-bit K-quant
    Q3_K    = 11,  // 3-bit K-quant
    Q4_K    = 12,  // 4-bit K-quant
    Q5_K    = 13,  // 5-bit K-quant
    Q6_K    = 14,  // 6-bit K-quant
    Q8_K    = 15,  // 8-bit K-quant
    IQ4_XS  = 24,  // 4-bit importance
    IQ4_NL  = 29   // 4-bit non-linear
};

// B008 Block Descriptor
// The fundamental unit of the B008 memory fabric
// Size: 64 bytes (cache line aligned)
struct alignas(64) Block
{
    uint64_t tensor_id;         // Which tensor this block belongs to
    uint64_t block_id;          // Block index within tensor
    
    uint64_t file_offset;       // Offset in B008 file
    
    uint32_t compressed_size;   // Size on disk (may be compressed)
    uint32_t uncompressed_size; // Size in RAM
    
    QuantType quant_type;       // How to interpret bytes
    uint32_t alignment;         // Required alignment (usually 64)
    
    volatile BlockState state;  // Current residency state
    uint32_t pad;               // Padding to 8-byte boundary
    
    uint64_t ram_address;       // Physical address when resident
    uint64_t last_used;         // Timestamp for LRU eviction
    
    // Constructor for initialization
    Block() : tensor_id(0), block_id(0), file_offset(0),
              compressed_size(0), uncompressed_size(0),
              quant_type(QuantType::Q4_0), alignment(64),
              state(BlockState::COLD), pad(0),
              ram_address(0), last_used(0) {}
};
static_assert(sizeof(Block) == 64, "B008::Block must be 64 bytes");

// B008 Header
// Located at offset 0 in the B008 file
struct Header
{
    char     magic[4];          // "B008"
    uint32_t version;           // Format version (1)
    
    uint64_t tensor_count;      // Number of tensors
    uint64_t block_count;       // Total blocks in file
    
    uint64_t weight_offset;     // Where weight data begins
    uint64_t index_offset;      // Where block index begins
    
    uint32_t min_block_size;    // Smallest block (bytes)
    uint32_t max_block_size;    // Largest block (bytes)
    
    uint32_t flags;             // Feature flags
    uint32_t reserved;          // Padding
    
    // Feature flags
    static constexpr uint32_t FLAG_COMPRESSED = 0x0001;
    static constexpr uint32_t FLAG_ENCRYPTED  = 0x0002;
    static constexpr uint32_t FLAG_CHECKSUM   = 0x0004;
};
static_assert(sizeof(Header) == 64, "B008::Header must be 64 bytes");

// Tensor Descriptor
// Maps tensor_id to its constituent blocks
struct TensorDesc
{
    uint64_t tensor_id;
    uint64_t first_block;       // First block index
    uint32_t block_count;       // Number of blocks
    uint32_t pad;
    
    // For quick lookup: which kernel types need this tensor
    uint64_t kernel_mask;       // Bitmask of KernelType
};
static_assert(sizeof(TensorDesc) == 32, "B008::TensorDesc must be 32 bytes");

// Kernel types for dependency tracking
enum class KernelType : uint32_t
{
    NONE          = 0,
    ATTENTION_Q   = 1,
    ATTENTION_K   = 2,
    ATTENTION_V   = 3,
    ATTENTION_O   = 4,
    FFN_GATE      = 5,
    FFN_UP        = 6,
    FFN_DOWN      = 7,
    NORM          = 8,
    EMBEDDING     = 9,
    LM_HEAD       = 10
};

// Residency Policy
// Configurable block sizing based on storage characteristics
struct ResidencyPolicy
{
    uint32_t min_block;         // Minimum block size (e.g., 64KB)
    uint32_t preferred_block;   // Preferred block size (e.g., 256MB)
    uint32_t max_block;         // Maximum block size (e.g., 1GB)
    
    uint32_t lookahead;         // How many blocks to prefetch ahead
    
    // Calculate optimal block size based on measured bandwidth
    static uint32_t CalculateOptimalBlock(
        double read_bandwidth_gbps,    // Measured NVMe bandwidth
        double kernel_latency_ms       // Average kernel execution time
    ) {
        // Target: fill buffer in < half kernel time
        double target_ms = kernel_latency_ms / 2.0;
        double bytes = (read_bandwidth_gbps * 1e9) * (target_ms / 1000.0);
        return static_cast<uint32_t>(bytes);
    }
};

// Block Index Entry
// Lightweight lookup for the Jukebox
struct BlockIndexEntry
{
    uint64_t file_offset;
    uint32_t size;
    uint32_t state;  // Cached copy of Block::state
};

} // namespace B008
} // namespace RawrXD
