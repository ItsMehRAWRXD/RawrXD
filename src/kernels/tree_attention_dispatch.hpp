//============================================================================
// tree_attention_dispatch.hpp
//
// VAL-032: Kernel ABI Wrapper - ISA-agnostic dispatch layer
//
// Provides unified interface for tree attention operations:
//   - Automatic ISA selection (AVX-512, AVX2, Scalar)
//   - Telemetry integration
//   - B008 residency fabric hooks
//============================================================================

#pragma once
#include <cstdint>
#include <cstddef>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Kernels {

//============================================================================
// Forward Declarations
//============================================================================
namespace Memory {
    class TensorResidencyPlanner;
}

//============================================================================
// Kernel Configuration
//============================================================================
struct TreeAttentionConfig {
    uint32_t max_candidates = 16;        // 4x4 tree structure
    uint32_t embedding_dim = 64;         // Query/key dimension
    float acceptance_threshold = 0.6f;   // Draft prob multiplier
    bool enable_telemetry = true;        // Cycle counting
    bool enable_residency_hooks = true;  // B008 integration
};

//============================================================================
// Telemetry Structure
//============================================================================
struct SpeculativeTelemetry {
    uint64_t candidates_verified = 0;      // Total candidates processed
    uint64_t tokens_accepted = 0;        // Accepted tokens
    uint64_t tokens_rejected = 0;        // Rejected tokens
    uint64_t verify_cycles = 0;          // Cycles in verification
    uint64_t kv_invalidation_cycles = 0; // Cycles in KV cleanup
    uint64_t residency_events = 0;       // B008 residency updates
    
    float GetAcceptanceRate() const {
        uint64_t total = tokens_accepted + tokens_rejected;
        return total > 0 ? (float)tokens_accepted / total : 0.0f;
    }
    
    void Reset() {
        candidates_verified = 0;
        tokens_accepted = 0;
        tokens_rejected = 0;
        verify_cycles = 0;
        kv_invalidation_cycles = 0;
        residency_events = 0;
    }
};

//============================================================================
// Verification Result
//============================================================================
struct VerificationResult {
    uint32_t acceptance_mask;      // 16 bits: 1 = accept
    uint32_t rejection_mask;       // 16 bits: 1 = reject
    uint32_t accepted_count;       // Number of accepted tokens
    uint32_t first_reject_idx;     // First rejection position (or 16)
    float* output_probs;           // Verified probabilities (caller-owned)
};

//============================================================================
// Kernel Function Pointers (ABI)
//============================================================================
using VerifyFunc = uint32_t (*)(  // Returns acceptance mask
    const float* candidate_logits,  // rcx: 16 x 64 floats
    const float* draft_logits,      // rdx: 16 x 64 floats
    const float* tree_mask,         // r8:  validity + draft probs
    float* output_probs,            // r9:  output buffer
    uint32_t num_candidates,        // [rsp+40]: must be 16
    float acceptance_threshold      // xmm3: threshold
);

using InvalidateKVFunc = void (*)( // No return
    uint8_t* kv_cache_base,         // rcx: base pointer
    uint32_t rejection_mask,        // rdx: 16-bit mask
    uint32_t entry_size             // r8:  bytes per entry
);

using HasAVX512Func = int (*)();   // Returns 1 if supported

//============================================================================
// Kernel Dispatch Table
//============================================================================
struct TreeAttentionKernel {
    VerifyFunc verify;                    // Main verification
    InvalidateKVFunc invalidate_kv;       // KV cache cleanup
    HasAVX512Func has_avx512;             // Feature detection
    const char* name;                     // "AVX-512", "AVX2", "Scalar"
    uint32_t version;                     // Kernel version
};

//============================================================================
// Kernel Selector
//============================================================================
class TreeAttentionDispatcher {
public:
    // Initialize with best available kernel
    static TreeAttentionKernel SelectKernel();
    
    // Force specific kernel (for testing)
    static TreeAttentionKernel GetAVX512Kernel();
    static TreeAttentionKernel GetScalarKernel();
    
private:
    static bool DetectAVX512();
};

//============================================================================
// Integration Layer
//============================================================================
class SpeculativeExecutionEngine {
public:
    explicit SpeculativeExecutionEngine(
        const TreeAttentionConfig& config = {}
    );
    
    ~SpeculativeExecutionEngine();
    
    // Disable copy/move
    SpeculativeExecutionEngine(const SpeculativeExecutionEngine&) = delete;
    SpeculativeExecutionEngine& operator=(const SpeculativeExecutionEngine&) = delete;
    
    // Core API
    VerificationResult VerifyCandidates(
        const float* query,              // 64-dim query vector
        const float* key_cache,        // 16 x 64 key vectors
        const float* tree_mask,        // Metadata buffer
        float* output_probs            // Output buffer
    );
    
    void InvalidateRejectedKV(
        uint8_t* kv_cache_base,
        uint32_t rejection_mask
    );
    
    // Residency fabric integration
    void SetResidencyPlanner(Memory::TensorResidencyPlanner* planner);
    void PrefetchDraftTensors(const std::vector<std::string>& tensor_ids);
    void PromoteAcceptedKV(uint32_t acceptance_mask);
    void DowngradeRejectedKV(uint32_t rejection_mask);
    
    // Telemetry
    const SpeculativeTelemetry& GetTelemetry() const { return telemetry_; }
    void ResetTelemetry() { telemetry_.Reset(); }
    
    // Configuration
    const TreeAttentionConfig& GetConfig() const { return config_; }
    const TreeAttentionKernel& GetKernel() const { return kernel_; }
    
private:
    TreeAttentionConfig config_;
    TreeAttentionKernel kernel_;
    SpeculativeTelemetry telemetry_;
    
    // B008 residency fabric
    Memory::TensorResidencyPlanner* residency_planner_ = nullptr;
    
    // Internal buffers (aligned)
    std::unique_ptr<float, AlignedDeleter> aligned_query_;
    std::unique_ptr<float, AlignedDeleter> aligned_keys_;
    std::unique_ptr<float, AlignedDeleter> aligned_mask_;
    std::unique_ptr<float, AlignedDeleter> aligned_output_;
    
    // Cycle timing
    uint64_t ReadTSC();
    
    // Aligned allocation helper
    static void* aligned_alloc(size_t size, size_t alignment = 64);
    static void aligned_free(void* ptr);
    
    // Custom deleter for unique_ptr
    struct AlignedDeleter {
        void operator()(void* ptr) const {
            aligned_free(ptr);
        }
    };
};

//============================================================================
// C-compatible exports for ASM interop
//============================================================================
extern "C" {
    // Kernel exports (from intrinsics or ASM)
    __declspec(dllexport) uint32_t TreeAttentionVerify_AVX512_Export(
        const float* candidate_logits,
        const float* draft_logits,
        const float* tree_mask,
        float* output_probs,
        uint32_t num_candidates,
        float acceptance_threshold
    );
    
    __declspec(dllexport) void KVCacheInvalidate_AVX512_Export(
        uint8_t* kv_cache_base,
        uint32_t rejection_mask,
        uint32_t entry_size
    );
    
    __declspec(dllexport) int HasAVX512F_Export();
    __declspec(dllexport) uint64_t ReadTSC_Export();
}

} // namespace Kernels
} // namespace RawrXD
