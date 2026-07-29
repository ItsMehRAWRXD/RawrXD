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
#include <cstdlib>
#include <vector>
#include <string>

#ifdef _MSC_VER
#include <intrin.h>  // For _mm_lfence, __rdtsc on MSVC
#endif

// Platform export macros
#if defined(_MSC_VER)
    #define RAWRXD_EXPORT __declspec(dllexport)
#else
    #define RAWRXD_EXPORT __attribute__((visibility("default")))
#endif

namespace RawrXD {
namespace Kernels {

// Custom deleter for aligned memory (must be before class that uses it)
struct AlignedDeleter {
    void operator()(void* ptr) const {
#ifdef _MSC_VER
        _aligned_free(ptr);
#else
        free(ptr);
#endif
    }
};

//============================================================================
// CPU Capability Detection
//============================================================================
struct CPUCapabilities {
    bool hasAVX512F = false;      // Foundation
    bool hasAVX512VL = false;     // Vector Length extensions
    bool hasAVX512DQ = false;     // Double/Quadword
    bool hasAVX512BW = false;     // Byte/Word
    bool osSupportsZMM = false;   // XCR0 ZMM state
    
    bool IsFullySupported() const {
        return hasAVX512F && osSupportsZMM;
    }
};

CPUCapabilities DetectCPUCapabilities();

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
// ABI: Windows x64 calling convention
// RCX = candidate_logits, RDX = draft_logits, R8 = tree_mask, R9 = output_probs
// Stack: [rsp+40] = num_candidates, [rsp+48] = acceptance_threshold
using VerifyFunc = uint32_t (*)(  // Returns acceptance mask
    const float* candidate_logits,
    const float* draft_logits,
    const float* tree_mask,
    float* output_probs,
    uint32_t num_candidates,
    float acceptance_threshold
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
enum class ISA : uint32_t {
    Scalar = 0,
    AVX2 = 1,
    AVX512 = 2
};

struct TreeAttentionKernel {
    VerifyFunc verify;                    // Main verification
    InvalidateKVFunc invalidate_kv;       // KV cache cleanup
    HasAVX512Func has_avx512;             // Feature detection
    const char* name;                     // "AVX-512", "AVX2", "Scalar"
    uint32_t version;                     // Kernel version
    ISA isa_level;                        // ISA classification
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
    static TreeAttentionKernel GetAVX2Kernel();
    static TreeAttentionKernel GetScalarKernel();
    
    // Runtime feature detection (public for testing)
    static bool DetectAVX512();
    static bool DetectAVX2();
    static bool DetectSSE42();
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
    
    // Cycle timing with serialization
    uint64_t ReadTSC() {
#ifdef _MSC_VER
        _mm_lfence();
        uint64_t tsc = __rdtsc();
        _mm_lfence();
        return tsc;
#else
        uint32_t eax, edx;
        __asm__ __volatile__ (
            "lfence\n"
            "rdtsc\n"
            "lfence\n"
            : "=a"(eax), "=d"(edx)
            :: "memory"
        );
        return ((uint64_t)edx << 32) | eax;
#endif
    }
    
    // Aligned allocation helper
    static void* aligned_alloc(size_t size, size_t alignment = 64);
    static void aligned_free(void* ptr);
};

//============================================================================
// C-compatible exports for ASM interop
//============================================================================
extern "C" {
    // Kernel exports (from intrinsics or ASM)
    RAWRXD_EXPORT uint32_t TreeAttentionVerify_AVX512_Export(
        const float* candidate_logits,
        const float* draft_logits,
        const float* tree_mask,
        float* output_probs,
        uint32_t num_candidates,
        float acceptance_threshold
    );
    
    RAWRXD_EXPORT void KVCacheInvalidate_AVX512_Export(
        uint8_t* kv_cache_base,
        uint32_t rejection_mask,
        uint32_t entry_size
    );
    
    RAWRXD_EXPORT int HasAVX512F_Export();
    RAWRXD_EXPORT uint64_t ReadTSC_Export();
}

} // namespace Kernels
} // namespace RawrXD
