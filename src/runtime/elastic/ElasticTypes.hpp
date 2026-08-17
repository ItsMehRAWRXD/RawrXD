#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <atomic>

namespace RawrXD {
namespace Elastic {

// ============================================================================
// ElasticTypes.hpp
// Core types for the RawrXD Elastic execution subsystem.
//
// Architecture-adaptive: Dense, Native MoE, Hybrid.
// No dense->MoE conversion. No fake quantization formats.
// ============================================================================

// ----------------------------------------------------------------------------
// Architecture classification
// ----------------------------------------------------------------------------
enum class ModelArchitectureType : uint8_t {
    Unknown = 0,
    Dense   = 1,   // Standard dense transformer (Llama, Mistral, Phi, Qwen dense)
    NativeMoE = 2, // Native Mixture-of-Experts (Mixtral, Qwen-MoE, etc.)
    Hybrid  = 3    // Dense attention + MoE MLP, or other mixed layouts
};

// ----------------------------------------------------------------------------
// Residency tier (mirrors Memory::MemoryTier but Elastic-specific)
// ----------------------------------------------------------------------------
enum class ElasticResidencyTier : uint8_t {
    Cold   = 0,  // On disk, not mapped
    Warm   = 1,  // CPU mmap resident (page cache / RAM)
    Hot    = 2,  // GPU VRAM resident
    Pinned = 3   // GPU VRAM resident, non-evictable (current layer)
};

// ----------------------------------------------------------------------------
// Compute block: the unit of residency for both dense and MoE paths.
// For dense: a column-slice or tile of a weight matrix.
// For MoE: a single expert's weight tensors.
// ----------------------------------------------------------------------------
struct ComputeBlock {
    uint32_t block_id = 0;
    std::string name;                 // Primary GGUF tensor name
    std::vector<std::string> aux_names; // Additional tensors (scales, biases)
    std::vector<uint64_t> shape;       // Tensor dimensions
    uint64_t file_offset = 0;         // Offset in the GGUF file
    uint64_t byte_size = 0;           // Exact bytes on disk
    uint64_t num_weights = 0;         // Scalar weight count (for arithmetic intensity)
    uint32_t ggml_type = 0;           // GGML type enum
    bool is_expert = false;           // True if this is a native MoE expert
    uint32_t layer_idx = 0;           // Which transformer layer
    uint32_t expert_idx = 0;          // Expert index within layer (MoE only)
};

// ----------------------------------------------------------------------------
// Mutable residency state (separated from immutable ComputeBlock)
// ----------------------------------------------------------------------------
struct BlockResidencyState {
    std::atomic<ElasticResidencyTier> state{ElasticResidencyTier::Cold};
    std::atomic<uint64_t> last_access_tick{0};
    std::atomic<uint64_t> access_count{0};
    std::atomic<bool> pinned{false};
    void* cpu_mapped_ptr = nullptr;   // CPU mmap view (if Warm)
    uint64_t cpu_mapped_size = 0;     // Actual mapped view size (page-aligned)
    void* gpu_buffer = nullptr;       // Opaque GPU handle (if Hot/Pinned)
    uint64_t gpu_buffer_size = 0;     // Actual GPU allocation size

    BlockResidencyState() = default;
    BlockResidencyState(BlockResidencyState&& other) noexcept
        : state(other.state.load(std::memory_order_relaxed))
        , last_access_tick(other.last_access_tick.load(std::memory_order_relaxed))
        , access_count(other.access_count.load(std::memory_order_relaxed))
        , pinned(other.pinned.load(std::memory_order_relaxed))
        , cpu_mapped_ptr(other.cpu_mapped_ptr)
        , cpu_mapped_size(other.cpu_mapped_size)
        , gpu_buffer(other.gpu_buffer)
        , gpu_buffer_size(other.gpu_buffer_size) {
        other.cpu_mapped_ptr = nullptr;
        other.gpu_buffer = nullptr;
    }
    BlockResidencyState& operator=(BlockResidencyState&& other) noexcept {
        if (this != &other) {
            state.store(other.state.load(std::memory_order_relaxed), std::memory_order_relaxed);
            last_access_tick.store(other.last_access_tick.load(std::memory_order_relaxed), std::memory_order_relaxed);
            access_count.store(other.access_count.load(std::memory_order_relaxed), std::memory_order_relaxed);
            pinned.store(other.pinned.load(std::memory_order_relaxed), std::memory_order_relaxed);
            cpu_mapped_ptr = other.cpu_mapped_ptr;
            cpu_mapped_size = other.cpu_mapped_size;
            gpu_buffer = other.gpu_buffer;
            gpu_buffer_size = other.gpu_buffer_size;
            other.cpu_mapped_ptr = nullptr;
            other.gpu_buffer = nullptr;
        }
        return *this;
    }
    BlockResidencyState(const BlockResidencyState&) = delete;
    BlockResidencyState& operator=(const BlockResidencyState&) = delete;
};

// ----------------------------------------------------------------------------
// DSS block lifecycle
// ----------------------------------------------------------------------------
enum class DssBlockState : uint8_t {
    ObserveOnly = 0,   // Collecting activation statistics
    Candidate   = 1,   // Sufficient data, evaluating skip safety
    Validated   = 2,   // Skip proven safe within error bound
    Specialized = 3,   // Actively skipping in production
    ForcedActive = 4   // Override: always execute (correctness fallback)
};

// ----------------------------------------------------------------------------
// DSS profiler record (per block, per layer)
// ----------------------------------------------------------------------------
struct DssProfilerRecord {
    uint32_t block_id = 0;
    uint32_t layer_idx = 0;
    uint64_t total_invocations = 0;
    uint64_t skipped_invocations = 0;
    double   avg_activation_magnitude = 0.0;
    double   max_activation_magnitude = 0.0;
    double   min_activation_magnitude = 0.0;
    double   avg_contribution_error = 0.0;  // |dense - specialized|
    double   max_contribution_error = 0.0;
    DssBlockState dss_state = DssBlockState::ObserveOnly;
    float    confidence = 0.0f;  // 0..1
};

// ----------------------------------------------------------------------------
// Elastic metrics (honest, measurable)
// ----------------------------------------------------------------------------
struct ElasticMetrics {
    double physical_bpw = 0.0;          // Actual GGUF storage density
    double active_compute_ratio = 1.0;   // executed / eligible computation
    double effective_bpw = 0.0;          // physical_bpw * active_compute_ratio
    uint64_t physical_bytes = 0;         // Total GGUF file bytes
    uint64_t resident_vram_bytes = 0;    // Currently in GPU VRAM
    uint64_t peak_vram_bytes = 0;        // High watermark
    uint64_t host_mmap_bytes = 0;        // CPU mapped views
    uint64_t streamed_bytes = 0;       // Bytes transferred CPU->GPU
    uint64_t evicted_bytes = 0;        // Bytes evicted from GPU
    uint64_t dss_skipped_blocks = 0;     // Blocks skipped this inference
    uint64_t dss_executed_blocks = 0;    // Blocks executed this inference
    uint64_t native_moe_active_experts = 0; // Active experts in last MoE dispatch
    uint64_t native_moe_total_experts = 0;  // Total experts available in last MoE dispatch
    double   dss_validation_error = 0.0; // Max |dense - dss| observed

    // Proof instrumentation: ElasticEngine → Transformer forward path telemetry
    uint64_t elastic_matmul_calls = 0;      // Total ExecuteMatMul calls attempted
    uint64_t elastic_hits = 0;              // Successful elastic dispatch (residency + router)
    uint64_t elastic_misses = 0;            // Elastic could not index or dispatch tensor
    uint64_t elastic_page_in_bytes = 0;     // Total bytes paged in from CPU mmap → GPU
    uint64_t elastic_vulkan_dispatches = 0; // Router dispatched through Vulkan GEMM
    uint64_t elastic_cpu_fallbacks = 0;     // Router fell back to CPU matmul
    uint64_t elastic_prefetch_hits = 0;     // Prefetched layer was actually used
    uint64_t elastic_evictions = 0;         // Blocks evicted from GPU by residency manager
};

// ----------------------------------------------------------------------------
// Architecture profile (output of detection)
// ----------------------------------------------------------------------------
struct ArchitectureProfile {
    ModelArchitectureType type = ModelArchitectureType::Unknown;
    uint32_t total_layers = 0;
    uint32_t num_experts = 0;            // Per layer (MoE)
    uint32_t active_experts_per_token = 0; // Top-K (MoE)
    uint64_t total_tensor_bytes = 0;
    bool supports_dss = false;           // Dense models can use DSS
    std::vector<ComputeBlock> blocks;    // All compute blocks discovered
};

// ----------------------------------------------------------------------------
// Elastic configuration
// ----------------------------------------------------------------------------
struct ElasticConfig {
    bool enable_dss = false;
    bool enable_prefetch = true;
    uint32_t prefetch_lookahead = 3;
    uint32_t moe_top_k = 2;
    float dss_activation_threshold = 0.01f;
    float dss_max_acceptable_error = 0.05f;
    uint64_t dss_min_observations = 100;
    uint64_t dss_max_observations = 10000;
    uint64_t vram_budget_bytes = 0; // 0 = auto-detect from hardware
    uint32_t max_concurrent_transfers = 2;
    float target_utilization = 0.90f;
    float prefetch_ceiling = 0.95f;
    float emergency_reserve = 0.03f;
};

} // namespace Elastic
} // namespace RawrXD
