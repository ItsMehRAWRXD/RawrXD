#pragma once

#include <string>
#include <vector>

namespace rawrxd {
namespace compatibility {

// Capability-driven model description
// Runtime branches on capabilities rather than architecture names
struct ModelCapabilities {
    // Position encoding
    bool usesRope = false;
    bool usesYarn = false;           // Yet Another RoPE extension
    bool usesAlibi = false;
    bool usesAbsolute = false;       // Traditional absolute position encoding
    
    // RoPE variants
    bool usesLongRope = false;       // Phi-3 style long context scaling
    bool usesNTKScaling = false;     // Neural Tangent Kernel scaling
    bool usesDynamicScaling = false; // Dynamic position interpolation
    
    // Attention mechanisms
    bool usesSlidingWindow = false;
    bool usesGQA = false;            // Grouped Query Attention
    bool usesMQA = false;            // Multi-Query Attention
    bool usesFlashAttention = false;
    bool usesPagedAttention = false;
    
    // Architecture features
    bool usesMoE = false;            // Mixture of Experts
    bool usesParallelFFN = false;    // Parallel feed-forward networks
    bool usesQKNorm = false;         // QK normalization (Gemma 2)
    bool usesPreNorm = false;        // Pre-normalization
    bool usesPostNorm = false;       // Post-normalization
    
    // Context and memory
    bool supportsLongContext = false;
    int maxContextLength = 4096;
    int slidingWindowSize = 0;
    
    // Tokenization
    bool usesByteFallback = false;
    bool usesSentencePiece = false;
    bool usesTiktoken = false;
    bool usesBPE = false;
    
    // Multimodal
    bool supportsVision = false;
    bool supportsAudio = false;
    
    // Quantization support
    bool supportsQ4 = true;
    bool supportsQ5 = true;
    bool supportsQ6 = true;
    bool supportsQ8 = true;
    bool supportsFP16 = true;
    bool supportsINT8 = false;
    
    // Helper methods
    std::string GetRoPEVariant() const {
        if (usesYarn) return "yarn";
        if (usesLongRope) return "long_rope";
        if (usesNTKScaling) return "ntk";
        if (usesDynamicScaling) return "dynamic";
        if (usesRope) return "standard";
        return "none";
    }
    
    std::string GetAttentionType() const {
        if (usesGQA) return "gqa";
        if (usesMQA) return "mqa";
        return "mha";  // Multi-head attention
    }
    
    std::string GetPositionEncoding() const {
        if (usesAlibi) return "alibi";
        if (usesYarn) return "yarn";
        if (usesLongRope) return "long_rope";
        if (usesRope) return "rope";
        if (usesAbsolute) return "absolute";
        return "none";
    }
    
    bool RequiresSpecialAttention() const {
        return usesAlibi || usesYarn || usesLongRope || usesMoE || usesSlidingWindow;
    }
};

// Capability detector - extracts capabilities from model config
class CapabilityDetector {
public:
    static ModelCapabilities DetectFromConfig(const ModelConfig& config);
    static ModelCapabilities DetectFromGGUF(const std::string& gguf_path);
    
    // Validate capabilities against runtime support
    static std::vector<std::string> ValidateCapabilities(const ModelCapabilities& caps);
    
    // Get required kernels for capabilities
    static std::vector<std::string> GetRequiredKernels(const ModelCapabilities& caps);
    
    // Check if runtime supports these capabilities
    static bool IsSupported(const ModelCapabilities& caps);
};

// Capability-based kernel selector
class CapabilityKernelSelector {
public:
    static std::string SelectAttentionKernel(const ModelCapabilities& caps);
    static std::string SelectRoPEKernel(const ModelCapabilities& caps);
    static std::string SelectMatMulKernel(const ModelCapabilities& caps);
    static std::string SelectFFNKernel(const ModelCapabilities& caps);
    
    // Get full kernel configuration from capabilities
    static KernelConfig BuildKernelConfig(const ModelCapabilities& caps);
};

} // namespace compatibility
} // namespace rawrxd
