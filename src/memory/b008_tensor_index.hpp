//=============================================================================
// B008 Tensor Index - Block-Oriented 800B Runtime
// Transforms 800B model into B008 block-addressable database
// Zero-dependency interface to MASM bit-reversal routines
//=============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace Memory {

//=============================================================================
// B008 Block Structure
// The fundamental unit of the block-oriented runtime
//=============================================================================
#pragma pack(push, 1)
struct B008Block {
    uint64_t    tensor_id;          // Original tensor identifier
    uint64_t    b008_id;            // Bit-reversed B008 identifier
    uint64_t    file_offset;        // Offset in GGUF file
    uint32_t    size;               // Block size (128KB - 4MB)
    uint16_t    quant_type;         // Quantization format
    uint16_t    alignment;          // Memory alignment requirement
    uint32_t    state;              // Residency state
    uint64_t    last_used;          // Timestamp for LRU
    void*       ram_address;        // Physical RAM location (if resident)
    uint32_t    checksum;             // CRC32 for integrity
    uint32_t    execution_hint;     // Kernel affinity hint
};
#pragma pack(pop)

// Block states
enum class B008State : uint32_t {
    COLD        = 0,    // On disk only
    LOADING     = 1,    // Async IO in progress
    RESIDENT    = 2,    // In RAM, ready
    COMPUTING   = 3,    // Currently being used
    EVICTING    = 4,    // Being written back / freed
    SPECULATIVE = 5     // Prefetched but not yet needed
};

// Execution hints for NUMA/GPU awareness
enum class ExecutionTarget : uint32_t {
    CPU_AVX512  = 0,
    CPU_AMX     = 1,
    GPU_VULKAN  = 2,
    GPU_ROCM    = 3,
    GPU_CUDA    = 4,
    FABRIC      = 5     // Remote node
};

//=============================================================================
// B008 Index Header
// Maps the entire model as a block-addressable database
//=============================================================================
#pragma pack(push, 1)
struct B008Index {
    // Magic and version
    uint32_t    magic;              // 'B008'
    uint32_t    version;            // 1
    
    // Model dimensions
    uint64_t    total_params;       // 800B, etc.
    uint64_t    total_blocks;       // Number of B008 blocks
    uint64_t    block_size;         // Default block size (256MB)
    
    // Memory layout
    uint64_t    hot_cache_size;     // 8GB
    uint64_t    triple_window_size; // 768MB
    uint64_t    emergency_size;     // 2GB
    
    // Execution hints
    uint32_t    preferred_target;  // ExecutionTarget
    uint32_t    lookahead_depth;    // Prefetch depth
    
    // Block directory follows
    // B008Block blocks[total_blocks];
};
#pragma pack(pop)

constexpr uint32_t B008_MAGIC = 0x42303038;  // 'B008'
constexpr uint32_t B008_VERSION = 1;

//=============================================================================
// Residency Policy
// Adaptive block sizing based on storage and kernel cadence
//=============================================================================
struct ResidencyPolicy {
    size_t      min_block;          // 128KB minimum
    size_t      target_block;       // 256MB default
    size_t      max_block;          // 1GB maximum
    
    uint32_t    lookahead_depth;    // 2-3 kernels ahead
    uint32_t    prefetch_threshold; // Start prefetch at % completion
    
    // Storage-specific tuning
    struct StorageProfile {
        uint32_t    sequential_read_mbps;
        uint32_t    random_read_iops;
        uint32_t    latency_us;
        size_t      optimal_block_size;
    };
    
    static StorageProfile Gen4_NVMe() {
        return { 7000, 1000000, 10, 256 * 1024 * 1024 };  // 256MB
    }
    
    static StorageProfile Gen5_NVMe() {
        return { 14000, 2000000, 8, 512 * 1024 * 1024 };  // 512MB
    }
    
    static StorageProfile RAID_NVMe() {
        return { 28000, 4000000, 5, 1024 * 1024 * 1024 }; // 1GB
    }
};

//=============================================================================
// Tensor Block with GGUF Metadata
// Direct consumption of GGUF tensor metadata
//=============================================================================
struct TensorBlock {
    uint64_t    tensor_id;          // Unique identifier
    uint64_t    file_offset;        // In GGUF
    uint32_t    size;               // Actual tensor size
    uint16_t    quant_type;         // GGUF quant type
    uint16_t    alignment;          // Required alignment
    
    // B008 mapping
    uint64_t    b008_block_start;   // First B008 block
    uint32_t    b008_block_count;   // Number of blocks
    
    // Residency
    B008State   state;
    void*       ram_address;
    
    // Execution affinity
    ExecutionTarget consumer;
};

//=============================================================================
// B008 Runtime Interface
// C++ wrapper around MASM bit-reversal routines
//=============================================================================
class B008Runtime {
public:
    // MASM routine declarations (extern "C")
    extern "C" {
        uint16_t Reverse16Bit(uint16_t value);
        uint16_t Reverse16Bit_Unrolled(uint16_t value);
        uint16_t Reverse16Bit_Lookup(uint16_t value);
        uint64_t B008_TransformTensorID(uint64_t tensor_id);
        uint64_t B008_GetBlockAddress(uint64_t tensor_id, size_t block_size);
    }
    
    // Transform tensor ID to B008 address space
    static uint64_t TransformTensorID(uint64_t tensor_id) {
        return B008_TransformTensorID(tensor_id);
    }
    
    // Calculate block address for given tensor
    static uint64_t GetBlockAddress(uint64_t tensor_id, size_t block_size) {
        return B008_GetBlockAddress(tensor_id, block_size);
    }
    
    // Fast bit-reversal for 16-bit values
    static uint16_t BitReverse16(uint16_t value) {
        return Reverse16Bit_Lookup(value);  // O(1) table lookup
    }
    
    // Initialize B008 index from GGUF
    bool InitializeFromGGUF(const wchar_t* gguf_path);
    
    // Get block for tensor access
    B008Block* GetBlock(uint64_t tensor_id);
    
    // Prefetch blocks for upcoming kernels
    void PrefetchBlocks(const uint64_t* tensor_ids, uint32_t count);
    
    // Mark block as resident after IO complete
    void MarkResident(uint64_t block_id, void* ram_address);
    
    // Evict block (LRU)
    void EvictBlock(uint64_t block_id);
    
private:
    B008Index*      index_;         // Block directory
    B008Block*      blocks_;        // Block array
    uint64_t        block_count_;
    
    // Residency table
    void**          residency_map_;   // tensor_id -> ram_address
    
    // Policy
    ResidencyPolicy policy_;
};

//=============================================================================
// Kernel Dependency Graph
// Maps inference graph to memory scheduler
//=============================================================================
struct KernelNode {
    uint32_t        kernel_id;      // Unique ID
    uint32_t        type;           // Attention, FFN, etc.
    uint32_t        layer_id;       // Transformer layer
    
    // Dependencies
    uint32_t*       dependencies;   // Kernel IDs we depend on
    uint32_t        dep_count;
    
    // Tensor requirements
    uint64_t*       required_tensors;
    uint32_t        tensor_count;
    
    // Execution
    uint64_t        estimated_us;  // Predicted compute time
    ExecutionTarget target;         // Where to run
};

class KernelDependencyGraph {
public:
    void Initialize(int num_layers);
    
    // Get next kernels after current completes
    std::vector<uint32_t> GetNextKernels(uint32_t current_kernel);
    
    // Get tensors needed by kernel
    std::vector<uint64_t> GetRequiredTensors(uint32_t kernel_id);
    
    // Predict execution path with probability
    std::vector<std::pair<uint32_t, float>> PredictPath(
        uint32_t current_kernel,
        int depth
    );
    
private:
    std::vector<KernelNode> nodes_;
    
    // Adjacency matrix for fast lookup
    std::vector<std::vector<uint32_t>> adjacency_;
};

//=============================================================================
// B008 Tensor Residency Planner
// Unified planner with B008 addressing
//=============================================================================
class B008ResidencyPlanner {
public:
    bool Initialize(
        const wchar_t* model_path,
        const ResidencyPolicy& policy
    );
    
    // Main entry: execute kernel with automatic prefetching
    bool ExecuteKernel(
        uint32_t kernel_id,
        void* input,
        void* output
    );
    
    // Notify planner that kernel is starting
    void NotifyKernelStart(uint32_t kernel_id);
    
    // Notify planner that kernel completed
    void NotifyKernelComplete(uint32_t kernel_id, uint64_t actual_us);
    
    // Get prefetch plan for upcoming kernels
    std::vector<uint64_t> GetPrefetchPlan(
        uint32_t current_kernel,
        uint32_t lookahead
    );
    
    // Statistics
    struct Stats {
        uint64_t    kernels_executed;
        uint64_t    blocks_prefetched;
        uint64_t    cache_hits;
        uint64_t    cache_misses;
        uint64_t    emergency_fetches;
        double      prefetch_accuracy;  // predicted vs actual
        double      hit_rate;
    };
    
    Stats GetStats() const;
    
private:
    B008Runtime           runtime_;
    KernelDependencyGraph graph_;
    ResidencyPolicy       policy_;
    
    // Triple buffer state
    struct TripleBuffer {
        void*       buffers[3];
        uint32_t    compute_idx;
        uint32_t    ready_idx;
        uint32_t    prefetch_idx;
    } triple_buffer_;
    
    // Statistics
    Stats stats_;
};

} // namespace Memory
} // namespace RawrXD
