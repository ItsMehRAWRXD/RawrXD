#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>

// ═══════════════════════════════════════════════════════════════════════════════
// VAL-032: Tree Attention Verification Kernel Interface
// ═══════════════════════════════════════════════════════════════════════════════
// Production-ready ABI for speculative tree attention verification
// Addresses all ABI compliance issues from review feedback
// ═══════════════════════════════════════════════════════════════════════════════

namespace RawrXD {

// ═══════════════════════════════════════════════════════════════════════════════
// Export Macros (Cross-platform)
// ═══════════════════════════════════════════════════════════════════════════════
#if defined(_MSC_VER)
    #define RAWRXD_EXPORT __declspec(dllexport)
    #define RAWRXD_IMPORT __declspec(dllimport)
#else
    #define RAWRXD_EXPORT __attribute__((visibility("default")))
    #define RAWRXD_IMPORT
#endif

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════
static constexpr uint32_t TREE_MAX_CANDIDATES = 16;     // Fixed 4x4 tree structure
static constexpr uint32_t HEAD_DIM = 64;               // Attention head dimension
static constexpr float SCALE_FACTOR = 0.125f;          // 1/sqrt(64)

// ═══════════════════════════════════════════════════════════════════════════════
// Verification Result Structure
// ═══════════════════════════════════════════════════════════════════════════════
// Caller owns output_probs buffer - kernel only writes to it, doesn't manage it
struct VerificationResult {
    uint32_t acceptance_mask;      // Bitmask of accepted candidates
    uint32_t rejection_mask;       // Bitmask of rejected candidates  
    uint32_t accepted_count;       // Number of accepted candidates
    uint32_t first_reject_idx;     // Index of first rejection (for early exit)
    
    const float* output_probs;     // Caller-owned buffer - kernel writes, doesn't own
    
    // Default constructor
    VerificationResult() 
        : acceptance_mask(0)
        , rejection_mask(0)
        , accepted_count(0)
        , first_reject_idx(TREE_MAX_CANDIDATES)
        , output_probs(nullptr) {}
};

// ═══════════════════════════════════════════════════════════════════════════════
// Kernel Configuration
// ═══════════════════════════════════════════════════════════════════════════════
struct TreeAttentionConfig {
    uint32_t head_dim = HEAD_DIM;
    uint32_t max_candidates = TREE_MAX_CANDIDATES;
    float acceptance_threshold = 0.5f;
    bool use_avx512 = true;      // Prefer AVX-512 if available
    bool use_avx2 = true;        // Fallback to AVX2
    
    // Validation
    bool IsValid() const {
        return head_dim == HEAD_DIM && 
               max_candidates == TREE_MAX_CANDIDATES;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// CPU Feature Detection
// ═══════════════════════════════════════════════════════════════════════════════
namespace cpuid {

// CPUID leaf 1 ECX flags
inline bool HasOSXSAVE() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 27)) != 0;
}

// XGETBV - check ZMM state is enabled
inline bool HasZMMState() {
    if (!HasOSXSAVE()) return false;
    uint64_t xcr0 = _xgetbv(0);
    return (xcr0 & 0xE0) == 0xE0;  // Check ZMM state bits
}

// CPUID leaf 7 EBX flags - AVX512F
inline bool HasAVX512F() {
    int cpuInfo[4];
    __cpuidex(cpuInfo, 7, 0);
    return (cpuInfo[1] & (1 << 16)) != 0;
}

// CPUID leaf 1 ECX flags - AVX2
inline bool HasAVX2() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 28)) != 0;  // AVX
}

// Complete AVX-512 detection
inline bool DetectAVX512() {
    return HasAVX512F() && HasZMMState();
}

// AVX2 detection
inline bool DetectAVX2() {
    return HasAVX2();
}

} // namespace cpuid

// ═══════════════════════════════════════════════════════════════════════════════
// External Assembly Functions
// ═══════════════════════════════════════════════════════════════════════════════
extern "C" {

// ═══════════════════════════════════════════════════════════════════════════════
// TreeAttentionVerify_AVX512_Export
// 
// Windows x64 ABI:
//   RCX  = candidate_logits      (float* [num_candidates, head_dim])
//   RDX  = draft_logits            (float* [num_candidates, head_dim])  
//   R8   = tree_mask               (uint8_t* [num_candidates, num_candidates])
//   R9   = output_probs            (float* [num_candidates])
//   [RSP+40] = num_candidates      (uint32_t) - must be TREE_MAX_CANDIDATES (16)
//   [RSP+48] = acceptance_threshold (float)
//
// Returns: acceptance_mask (uint32_t with bits set for accepted candidates)
// ═══════════════════════════════════════════════════════════════════════════════
RAWRXD_EXPORT uint32_t TreeAttentionVerify_AVX512_Export(
    const float* candidate_logits,  // RCX
    const float* draft_logits,      // RDX
    const uint8_t* tree_mask,       // R8
    float* output_probs,            // R9
    uint32_t num_candidates,        // [RSP+40] - must be 16
    float acceptance_threshold        // [RSP+48]
);

// AVX2 fallback version
RAWRXD_EXPORT uint32_t TreeAttentionVerify_AVX2_Export(
    const float* candidate_logits,
    const float* draft_logits,
    const uint8_t* tree_mask,
    float* output_probs,
    uint32_t num_candidates,
    float acceptance_threshold
);

// Scalar reference implementation
RAWRXD_EXPORT uint32_t TreeAttentionVerify_Scalar_Export(
    const float* candidate_logits,
    const float* draft_logits,
    const uint8_t* tree_mask,
    float* output_probs,
    uint32_t num_candidates,
    float acceptance_threshold
);

} // extern "C"

// ═══════════════════════════════════════════════════════════════════════════════
// C++ Wrapper Class
// ═══════════════════════════════════════════════════════════════════════════════
class TreeAttentionVerifier {
public:
    explicit TreeAttentionVerifier(const TreeAttentionConfig& cfg = {});
    
    // Main verification interface
    VerificationResult Verify(
        const float* candidate_logits,
        const float* draft_logits,
        const uint8_t* tree_mask,
        float* output_probs,
        uint32_t num_candidates,
        float acceptance_threshold
    );
    
    // Check if AVX-512 is available and usable
    static bool IsAVX512Supported();
    
    // Check if AVX2 is available
    static bool IsAVX2Supported();
    
    // Get current configuration
    const TreeAttentionConfig& GetConfig() const { return config_; }
    
    // Get last error message
    const std::string& GetLastError() const { return last_error_; }

private:
    TreeAttentionConfig config_;
    std::string last_error_;
    
    // Internal dispatch
    using VerifyFunc = uint32_t (*)(
        const float*,
        const float*,
        const uint8_t*,
        float*,
        uint32_t,
        float
    );
    
    VerifyFunc GetDispatchFunction();
};

// ═══════════════════════════════════════════════════════════════════════════════
// Inline Implementation
// ═══════════════════════════════════════════════════════════════════════════════
inline TreeAttentionVerifier::TreeAttentionVerifier(const TreeAttentionConfig& cfg)
    : config_(cfg)
{
    if (!config_.IsValid()) {
        last_error_ = "Invalid configuration: head_dim must be 64, max_candidates must be 16";
    }
}

inline bool TreeAttentionVerifier::IsAVX512Supported() {
    return cpuid::DetectAVX512();
}

inline bool TreeAttentionVerifier::IsAVX2Supported() {
    return cpuid::DetectAVX2();
}

inline TreeAttentionVerifier::VerifyFunc TreeAttentionVerifier::GetDispatchFunction() {
    if (config_.use_avx512 && IsAVX512Supported()) {
        return TreeAttentionVerify_AVX512_Export;
    }
    if (config_.use_avx2 && IsAVX2Supported()) {
        return TreeAttentionVerify_AVX2_Export;
    }
    return TreeAttentionVerify_Scalar_Export;
}

inline VerificationResult TreeAttentionVerifier::Verify(
    const float* candidate_logits,
    const float* draft_logits,
    const uint8_t* tree_mask,
    float* output_probs,
    uint32_t num_candidates,
    float acceptance_threshold
) {
    VerificationResult result;
    
    // Validate num_candidates
    if (num_candidates != TREE_MAX_CANDIDATES) {
        last_error_ = "num_candidates must be exactly " + 
                      std::to_string(TREE_MAX_CANDIDATES);
        return result;
    }
    
    // Validate pointers
    if (!candidate_logits || !draft_logits || !tree_mask || !output_probs) {
        last_error_ = "Null pointer passed to Verify";
        return result;
    }
    
    // Get dispatch function
    VerifyFunc func = GetDispatchFunction();
    if (!func) {
        last_error_ = "No suitable kernel implementation available";
        return result;
    }
    
    // Call kernel
    uint32_t acceptance_mask = func(
        candidate_logits,
        draft_logits,
        tree_mask,
        output_probs,
        num_candidates,
        acceptance_threshold
    );
    
    // Populate result
    result.acceptance_mask = acceptance_mask;
    result.rejection_mask = ~acceptance_mask & ((1u << num_candidates) - 1);
    result.output_probs = output_probs;
    
    // Count accepted
    result.accepted_count = __popcnt(acceptance_mask);
    
    // Find first rejection
    for (uint32_t i = 0; i < num_candidates; i++) {
        if (!(acceptance_mask & (1u << i))) {
            result.first_reject_idx = i;
            break;
        }
    }
    
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TSC Serialization (for accurate cycle timing)
// ═══════════════════════════════════════════════════════════════════════════════
namespace timing {

// Serialize instruction stream before RDTSC
inline void SerializeTSC() {
    _mm_lfence();
    _mm_sfence();
}

// Read serialized TSC
inline uint64_t ReadTSC() {
    SerializeTSC();
    return __rdtsc();
}

// Measure cycles for a function call
template<typename Func, typename... Args>
inline uint64_t MeasureCycles(Func&& func, Args&&... args) {
    uint64_t start = ReadTSC();
    func(std::forward<Args>(args)...);
    uint64_t end = ReadTSC();
    return end - start;
}

} // namespace timing

} // namespace RawrXD
