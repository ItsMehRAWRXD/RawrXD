// ============================================================================
// KimiK2Config.hpp — K2-001 Architecture Contract
// Populated from GGUF metadata, not hard-coded constants.
// Supports: Kimi K2-Instruct-0905 and compatible DeepSeek-MLA-MoE variants.
// ============================================================================
#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>

namespace Deep2 {

// ============================================================================
// Architecture Family — decoupled from single GGUF metadata spelling
// Handles: "kimi_k2", "deepseek2", "deepseek_v2", "deepseek_v3"
// ============================================================================
enum class ArchitectureFamily {
    Unknown,
    Llama,              // Standard Llama-style dense transformer
    DeepSeekMLA_MoE,   // DeepSeek-V3 / Kimi K2 MLA + MoE
    KimiK2,             // Explicit Kimi K2 variant (0905, etc.)
};

// ============================================================================
// KimiK2Config — Canonical model configuration populated from GGUF metadata
// ============================================================================
struct KimiK2Config {
    // Architecture identity
    ArchitectureFamily family = ArchitectureFamily::Unknown;
    std::string modelType;           // e.g. "kimi_k2", "deepseek2"
    std::string architecture;        // GGUF architecture string
    uint32_t    version = 0;         // Model revision (e.g. 0905)

    // Core dimensions
    uint32_t hiddenDim = 0;
    uint32_t numLayers = 0;
    uint32_t numHeads = 0;
    uint32_t numKVHeads = 0;

    // MLA dimensions (critical correctness boundary)
    uint32_t qLoraRank = 0;          // e.g. 1536
    uint32_t kvLoraRank = 0;         // e.g. 512 (compressed KV latent)
    uint32_t qkNopeHeadDim = 0;      // e.g. 128 (non-RoPE key head dim)
    uint32_t qkRopeHeadDim = 0;      // e.g. 64 (RoPE key head dim)
    uint32_t vHeadDim = 0;           // e.g. 128

    // MoE dimensions
    uint32_t numExperts = 0;         // e.g. 384
    uint32_t expertsPerToken = 0;    // e.g. 8
    uint32_t sharedExperts = 0;      // e.g. 1
    uint32_t moeIntermediateSize = 0;// e.g. 2048 (per-expert FFN dim)

    // Vocabulary / context
    uint32_t vocabSize = 0;          // e.g. 163840
    uint32_t maxPosition = 0;        // e.g. 262144

    // Routing semantics (Kimi-specific, not generic top-k softmax)
    std::string scoringFunc = "sigmoid";     // "sigmoid" | "softmax"
    std::string topkMethod = "noaux_tc";     // "noaux_tc" | "greedy" | "group_limited"
    uint32_t    topkGroup = 1;               // e.g. 1
    bool        normTopkProb = true;         // Normalize selected probabilities
    float       routedScalingFactor = 2.827f;// Expert output scaling

    // Normalization / RoPE
    float    normRmsEps = 1e-5f;
    float    ropeTheta = 50000.0f;
    float    ropeScalingFactor = 64.0f;
    float    ropeScalingYarnLogMultiplier = 0.1f;
    uint32_t ropeScalingOriginalMax = 0;

    // Quantization
    uint32_t globalFileType = 0;     // GGUF file_type enum
    bool     tieEmbeddings = false;

    // Shard info
    uint32_t numShards = 1;
    uint32_t currentShard = 0;

    // Validation
    bool     valid = false;
    std::string error;

    // Convenience: total kv_a_mqa output dimension = kvLoraRank + qkRopeHeadDim
    uint32_t kvAMqaOutDim() const { return kvLoraRank + qkRopeHeadDim; }

    // Convenience: check if config represents a valid Kimi K2 / DeepSeek MLA-MoE
    bool IsMLAMoE() const {
        return (family == ArchitectureFamily::KimiK2 ||
                family == ArchitectureFamily::DeepSeekMLA_MoE) &&
               qLoraRank > 0 && kvLoraRank > 0 && numExperts > 0;
    }

    // Convenience: per-layer selected expert weight footprint (raw quantized)
    // gate + up + down for expertsPerToken selected experts
    // Returns approximate bytes; actual depends on quantization type
    uint64_t SelectedExpertWeightsBytesPerLayer() const {
        uint64_t gateElems = static_cast<uint64_t>(moeIntermediateSize) * hiddenDim;
        uint64_t upElems   = static_cast<uint64_t>(moeIntermediateSize) * hiddenDim;
        uint64_t downElems = static_cast<uint64_t>(hiddenDim) * moeIntermediateSize;
        uint64_t totalElems = (gateElems + upElems + downElems) * expertsPerToken;
        // Conservative: assume ~1 byte/element (actual Q4_K_M ≈ 0.5, Q6_K ≈ 0.75)
        return totalElems;
    }

    // Full expert tensor size (all numExperts experts, one layer)
    // For residency budgeting: this is what we AVOID materializing
    uint64_t FullExpertTensorBytesPerLayer() const {
        return SelectedExpertWeightsBytesPerLayer() / expertsPerToken * numExperts;
    }

    // Memory accounting: active weight residency is SEPARATE from
    // KV cache, activations, GEMM workspace, staging buffers, etc.
    // The 4-8 GB target refers to WEIGHT residency only.
    struct MemoryBudget {
        uint64_t weightResidencyBytes = 0;      // 4-8 GB target
        uint64_t kvCacheBytes = 0;              // 256K context MLA KV cache
        uint64_t activationBytes = 0;           // Layer activations
        uint64_t gemmWorkspaceBytes = 0;          // GEMM/Vulkan temporaries
        uint64_t stagingBytes = 0;              // DMA/upload staging
        uint64_t runtimeBytes = 0;              // Tokenizer, router, metadata

        uint64_t Total() const {
            return weightResidencyBytes + kvCacheBytes + activationBytes
                 + gemmWorkspaceBytes + stagingBytes + runtimeBytes;
        }
    };
};

// ============================================================================
// Populate KimiK2Config from GGUF metadata key-value pairs
// Returns config.valid=false with config.error on mismatch.
// ============================================================================
KimiK2Config ParseKimiK2ConfigFromGGUF(const std::unordered_map<std::string, std::string>& metadata);

// ============================================================================
// Detect architecture family from GGUF metadata
// Handles: "kimi_k2", "deepseek2", "deepseek_v2", "deepseek_v3"
// ============================================================================
ArchitectureFamily DetectArchitectureFamily(const std::unordered_map<std::string, std::string>& metadata);

// ============================================================================
// Validate config against known-good K2 0905 parameters
// Returns false with detailed error if any critical dimension mismatches.
// ============================================================================
bool ValidateKimiK2Config(const KimiK2Config& config, std::string& error);

} // namespace Deep2
